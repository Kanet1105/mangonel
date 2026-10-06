//! Bounded multi-producer, multi-consumer rings whose
//! items are written and read in place.
//!
//! Each side moves through three steps: claim a range of
//! slots by advancing its head, read or write the slots,
//! then commit by advancing its tail. Commits land in
//! claim order, so a side whose claim is behind an
//! uncommitted one waits for it.

use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crossbeam_utils::{Backoff, CachePadded};

use crate::Error;

#[derive(Clone)]
pub struct Ring<T> {
    inner: Arc<RingInner<T>>,
}

struct RingInner<T> {
    size: usize,
    mask: usize,
    /// Producers' claim position: everything below is
    /// claimed by some producer.
    producer_head: CachePadded<AtomicUsize>,
    /// Producers' commit position: everything below is
    /// readable.
    producer_tail: CachePadded<AtomicUsize>,
    /// Consumers' claim position: everything below is
    /// claimed by some consumer.
    consumer_head: CachePadded<AtomicUsize>,
    /// Consumers' commit position: everything below is
    /// free again.
    consumer_tail: CachePadded<AtomicUsize>,
    /// Filled with `T::default()` until a producer writes
    /// the slot.
    slots: Box<[UnsafeCell<T>]>,
}

// SAFETY: A head compare-and-swap grants each slot to one
// thread at a time, and the tails' Release/Acquire pairs
// order one grant's accesses before the next. So the
// slots behave like a `Mutex<T>` per slot: shared access
// needs only `T: Send`.
unsafe impl<T: Send> Sync for RingInner<T> {}
// SAFETY: Moving `RingInner` moves the items in it, which
// is sound for `T: Send`.
unsafe impl<T: Send> Send for RingInner<T> {}

impl<T: Default> Ring<T> {
    /// A ring holding up to `size` items, which must be a
    /// power of two. Every slot starts as `T::default()`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSize`] if `size` is not a power of
    /// two.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(64)?;
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn new(size: usize) -> Result<Self, Error> {
        if !size.is_power_of_two() {
            return Err(Error::InvalidSize(size));
        }

        let index = || CachePadded::new(AtomicUsize::new(0));

        Ok(Self {
            inner: Arc::new(RingInner {
                size,
                mask: size - 1,
                producer_head: index(),
                producer_tail: index(),
                consumer_head: index(),
                consumer_tail: index(),
                slots: (0..size).map(|_| UnsafeCell::new(T::default())).collect(),
            }),
        })
    }
}

impl<T> Ring<T> {
    fn slot(&self, index: usize) -> *mut T {
        self.inner.slots[index & self.inner.mask].get()
    }

    fn validate_batch_size(&self, batch_size: usize) -> Result<(), Error> {
        let ring_size = self.inner.size;
        if batch_size == 0 || batch_size > ring_size {
            return Err(Error::InvalidBatchSize {
                batch_size,
                ring_size,
            });
        }

        Ok(())
    }

    fn compute_claim_size(
        &self,
        batch_size: usize,
        available: usize,
        exact: bool,
    ) -> Result<usize, Error> {
        let size = if exact {
            batch_size
        } else {
            batch_size.min(available)
        };
        if size == 0 || size > available {
            return Err(Error::Insufficient {
                requested: batch_size,
                available,
            });
        }

        Ok(size)
    }

    fn claim_write(&self, batch_size: usize, exact: bool) -> Result<(usize, usize), Error> {
        self.validate_batch_size(batch_size)?;

        let head = &self.inner.producer_head;
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            let available = self
                .inner
                .consumer_tail
                .load(Ordering::Acquire)
                .wrapping_add(self.inner.size)
                .wrapping_sub(index);

            let size = self.compute_claim_size(batch_size, available, exact)?;

            match head.compare_exchange_weak(
                index,
                index.wrapping_add(size),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok((size, index)),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    fn write_at(&self, index: usize, value: T) {
        // SAFETY: The caller holds an uncommitted write
        // claim on `index`, so no other producer writes
        // this slot and no consumer can claim it until the
        // commit.
        unsafe { *self.slot(index) = value };
    }

    fn commit_write(&self, size: usize, index: usize) {
        let tail = &self.inner.producer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(size), Ordering::Release);
    }

    fn claim_read(&self, batch_size: usize, exact: bool) -> Result<(usize, usize), Error> {
        self.validate_batch_size(batch_size)?;

        let head = &self.inner.consumer_head;
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            let available = self
                .inner
                .producer_tail
                .load(Ordering::Acquire)
                .wrapping_sub(index);

            let size = self.compute_claim_size(batch_size, available, exact)?;

            match head.compare_exchange_weak(
                index,
                index.wrapping_add(size),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok((size, index)),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    fn read_at(&self, index: usize) -> &T {
        // SAFETY: The caller holds an uncommitted read
        // claim on `index`. The producer's commit
        // happened-before that claim, and no producer can
        // claim the slot again until this read is
        // committed.
        unsafe { &*self.slot(index) }
    }

    fn commit_read(&self, size: usize, index: usize) {
        let tail = &self.inner.consumer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(size), Ordering::Release);
    }

    /// Grants as many free slots as are available, up to
    /// `batch_size`, for writing. Readers see them once the
    /// grant is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::Insufficient`] if no slot is free.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let mut grant = ring.write_up_to(4)?;
    /// grant.write(1)?;
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn write_up_to(&self, batch_size: usize) -> Result<WriteGrant<'_, T>, Error> {
        let (size, index) = self.claim_write(batch_size, false)?;

        Ok(WriteGrant::new(self, size, index))
    }

    /// Grants exactly `batch_size` free slots for writing,
    /// or none. Readers see them once the grant is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::Insufficient`] if fewer than `batch_size`
    ///   slots are free.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let mut grant = ring.write_exact(1)?;
    /// grant.write(1)?;
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn write_exact(&self, batch_size: usize) -> Result<WriteGrant<'_, T>, Error> {
        let (size, index) = self.claim_write(batch_size, true)?;

        Ok(WriteGrant::new(self, size, index))
    }

    /// Grants as many committed items as are available, up
    /// to `batch_size`, for reading. Their slots are freed
    /// once the grant is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::Insufficient`] if no item is available.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// ring.write_exact(1)?.write(7)?;
    ///
    /// let mut grant = ring.read_up_to(4)?;
    /// assert_eq!(*grant.read()?, 7);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn read_up_to(&self, batch_size: usize) -> Result<ReadGrant<'_, T>, Error> {
        let (size, index) = self.claim_read(batch_size, false)?;

        Ok(ReadGrant::new(self, size, index))
    }

    /// Grants exactly `batch_size` committed items for
    /// reading, or none. Their slots are freed once the
    /// grant is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::Insufficient`] if fewer than `batch_size`
    ///   items are available.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// ring.write_exact(1)?.write(7)?;
    ///
    /// let mut grant = ring.read_exact(1)?;
    /// assert_eq!(*grant.read()?, 7);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn read_exact(&self, batch_size: usize) -> Result<ReadGrant<'_, T>, Error> {
        let (size, index) = self.claim_read(batch_size, true)?;

        Ok(ReadGrant::new(self, size, index))
    }
}

pub struct WriteGrant<'a, T> {
    ring: &'a Ring<T>,
    size: usize,
    start: usize,
    end: usize,
    current: usize,
}

impl<'a, T> Drop for WriteGrant<'a, T> {
    /// Commits the whole claim. Slots never written still
    /// publish whatever they held before.
    fn drop(&mut self) {
        let written = self.current.wrapping_sub(self.start);
        if written != self.size {
            eprintln!(
                "warning: write grant dropped after writing {written} of {} granted slots; \
                 consumers will read stale values",
                self.size
            );
        }

        self.ring.commit_write(self.size, self.start);
    }
}

impl<'a, T> WriteGrant<'a, T> {
    fn new(ring: &'a Ring<T>, size: usize, index: usize) -> Self {
        Self {
            ring,
            size,
            start: index,
            end: index.wrapping_add(size),
            current: index,
        }
    }

    /// Writes `value` into the next granted slot. Readers
    /// see it once this `WriteGrant` is dropped.
    ///
    /// # Errors
    ///
    /// [`Error::GrantExhausted`] if every granted slot has
    /// been written.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let mut grant = ring.write_exact(1)?;
    /// grant.write(7)?;
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn write(&mut self, value: T) -> Result<(), Error> {
        if self.current == self.end {
            return Err(Error::GrantExhausted(self.size));
        }

        self.ring.write_at(self.current, value);
        self.current = self.current.wrapping_add(1);

        Ok(())
    }
}

pub struct ReadGrant<'a, T> {
    ring: &'a Ring<T>,
    size: usize,
    start: usize,
    end: usize,
    current: usize,
}

impl<'a, T> Drop for ReadGrant<'a, T> {
    /// Commits the whole claim. Items never read are
    /// skipped and their slots freed for producers.
    fn drop(&mut self) {
        let read = self.current.wrapping_sub(self.start);
        if read != self.size {
            eprintln!(
                "warning: read grant dropped after reading {read} of {} granted items; \
                 the rest are lost",
                self.size
            );
        }

        self.ring.commit_read(self.size, self.start);
    }
}

impl<'a, T> ReadGrant<'a, T> {
    fn new(ring: &'a Ring<T>, size: usize, index: usize) -> Self {
        Self {
            ring,
            size,
            start: index,
            end: index.wrapping_add(size),
            current: index,
        }
    }

    /// The item in the next granted slot. Its slot is
    /// freed for producers once this `ReadGrant` is dropped,
    /// so the reference cannot outlive it.
    ///
    /// # Errors
    ///
    /// [`Error::GrantExhausted`] if every granted slot has
    /// been read.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// ring.write_exact(1)?.write(7)?;
    ///
    /// let mut grant = ring.read_exact(1)?;
    /// assert_eq!(*grant.read()?, 7);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn read(&mut self) -> Result<&T, Error> {
        if self.current == self.end {
            return Err(Error::GrantExhausted(self.size));
        }

        let value = self.ring.read_at(self.current);
        self.current = self.current.wrapping_add(1);

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_powers_of_two() {
        for size in [1, 2, 64, 1024] {
            let ring = Ring::<u64>::new(size).unwrap();
            assert_eq!(ring.inner.size, size);
            assert_eq!(ring.inner.mask, size - 1);
            assert_eq!(ring.inner.slots.len(), size);
        }
    }

    #[test]
    fn new_rejects_invalid_sizes() {
        for size in [0, 3, 100, usize::MAX] {
            assert!(matches!(
                Ring::<u64>::new(size),
                Err(Error::InvalidSize(s)) if s == size
            ));
        }
    }
}
