//! Bounded multi-producer, multi-consumer rings whose
//! items are written and read in place.
//!
//! Each side moves through three steps: claim a range of
//! slots by advancing its head, read or write the slots,
//! then commit by advancing its tail. Commits land in
//! claim order, so a side whose claim is behind an
//! uncommitted one waits for it.
//!
//! # Examples
//!
//! ```
//! use mangonel_ring::mpmc::Ring;
//!
//! let ring = Ring::<u32>::new(8)?;
//!
//! let start = ring.claim_write(1)?;
//! ring.write_at(start, 1);
//! ring.commit_write(start, 1);
//!
//! let start = ring.claim_read(1)?;
//! assert_eq!(*ring.read_at(start), 1);
//! ring.commit_read(start, 1);
//! # Ok::<(), mangonel_ring::Error>(())
//! ```

use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crossbeam_utils::{Backoff, CachePadded};

use crate::Error;

/// A bounded ring shared by any number of producers and
/// consumers. Cloning gives another handle to the same
/// ring.
///
/// # Examples
///
/// ```
/// use mangonel_ring::mpmc::Ring;
///
/// let ring = Ring::<u64>::new(1024)?;
/// let other = ring.clone();
/// # Ok::<(), mangonel_ring::Error>(())
/// ```
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

    /// The slot that the cursor position `index` maps to.
    fn slot(&self, index: usize) -> *mut T {
        self.inner.slots[index & self.inner.mask].get()
    }

    /// Claims `batch_size` free slots for writing and
    /// returns the position of the first. The claim covers
    /// `[start, start + batch_size)`, wrapping, and must be
    /// committed with [`commit_write`](Self::commit_write).
    ///
    /// All or nothing: it never claims fewer slots than
    /// asked for.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::InsufficientSpace`] if fewer than
    ///   `batch_size` slots are free.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let start = ring.claim_write(2)?;
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn claim_write(&self, batch_size: usize) -> Result<usize, Error> {
        let ring_size = self.inner.size;
        if batch_size == 0 || batch_size > ring_size {
            return Err(Error::InvalidBatchSize {
                batch_size,
                ring_size,
            });
        }

        let head = &self.inner.producer_head;
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            let available = self
                .inner
                .consumer_tail
                .load(Ordering::Acquire)
                .wrapping_add(ring_size)
                .wrapping_sub(index);
            if available < batch_size {
                return Err(Error::InsufficientSpace {
                    requested: batch_size,
                    available,
                });
            }

            match head.compare_exchange_weak(
                index,
                index.wrapping_add(batch_size),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(index),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    /// Writes `value` into the slot at position `index`.
    /// The old value is dropped in place.
    ///
    /// # Safety
    ///
    /// `index` must lie in a range this caller claimed
    /// with [`claim_write`](Self::claim_write) and has not
    /// yet committed. Anything else can race with another
    /// producer writing the slot or a consumer reading it.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let start = ring.claim_write(1)?;
    /// ring.write_at(start, 42);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn write_at(&self, index: usize, value: T) {
        // SAFETY: The caller holds an uncommitted write
        // claim on `index`, so no other producer writes
        // this slot and no consumer can claim it until the
        // commit.
        unsafe { *self.slot(index) = value };
    }

    /// Publishes the claim `[index, index + batch_size)`
    /// to consumers. Waits, yielding after a while, until
    /// every earlier write claim has been committed, so
    /// commits land in claim order.
    ///
    /// A claim that is never committed blocks every later
    /// producer here.
    ///
    /// # Safety
    ///
    /// `index` and `batch_size` must be exactly what was
    /// passed to and returned by one
    /// [`claim_write`](Self::claim_write), every slot in it
    /// must have been written, and it must be committed
    /// only once. A larger range would let consumers read
    /// slots another producer is still writing.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let start = ring.claim_write(1)?;
    /// ring.write_at(start, 42);
    /// ring.commit_write(start, 1);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn commit_write(&self, index: usize, batch_size: usize) {
        let tail = &self.inner.producer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(batch_size), Ordering::Release);
    }

    /// Claims `batch_size` committed items for reading and
    /// returns the position of the first. The claim covers
    /// `[start, start + batch_size)`, wrapping, and must be
    /// committed with [`commit_read`](Self::commit_read).
    ///
    /// All or nothing: it never claims fewer items than
    /// asked for.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidBatchSize`] if `batch_size` is 0
    ///   or larger than the ring.
    /// - [`Error::InsufficientItems`] if fewer than
    ///   `batch_size` items are committed and unclaimed.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// assert!(ring.claim_read(1).is_err());
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn claim_read(&self, batch_size: usize) -> Result<usize, Error> {
        let ring_size = self.inner.size;
        if batch_size == 0 || batch_size > ring_size {
            return Err(Error::InvalidBatchSize {
                batch_size,
                ring_size,
            });
        }

        let head = &self.inner.consumer_head;
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            let available = self
                .inner
                .producer_tail
                .load(Ordering::Acquire)
                .wrapping_sub(index);
            if available < batch_size {
                return Err(Error::InsufficientItems {
                    requested: batch_size,
                    available,
                });
            }

            match head.compare_exchange_weak(
                index,
                index.wrapping_add(batch_size),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(index),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    /// A reference to the item in the slot at position
    /// `index`.
    ///
    /// # Safety
    ///
    /// `index` must lie in a range this caller claimed
    /// with [`claim_read`](Self::claim_read) and has not
    /// yet committed, and the reference must be dropped
    /// before [`commit_read`](Self::commit_read). After the
    /// commit a producer may overwrite the slot while the
    /// reference is still alive.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let start = ring.claim_write(1)?;
    /// ring.write_at(start, 9);
    /// ring.commit_write(start, 1);
    ///
    /// let start = ring.claim_read(1)?;
    /// assert_eq!(*ring.read_at(start), 9);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn read_at(&self, index: usize) -> &T {
        // SAFETY: The caller holds an uncommitted read
        // claim on `index`. The producer's commit
        // happened-before that claim, and no producer can
        // claim the slot again until this read is
        // committed.
        unsafe { &*self.slot(index) }
    }

    /// Frees the claim `[index, index + batch_size)` for
    /// producers to reuse. Waits, yielding after a while,
    /// until every earlier read claim has been committed,
    /// so commits land in claim order.
    ///
    /// A claim that is never committed blocks every later
    /// consumer here.
    ///
    /// # Safety
    ///
    /// `index` and `batch_size` must be exactly what was
    /// passed to and returned by one
    /// [`claim_read`](Self::claim_read), it must be
    /// committed only once, and no reference from
    /// [`read_at`](Self::read_at) into it may be used
    /// afterwards. A larger range would let producers
    /// overwrite slots another consumer is still reading.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::mpmc::Ring;
    ///
    /// let ring = Ring::<u32>::new(8)?;
    /// let start = ring.claim_write(1)?;
    /// ring.write_at(start, 9);
    /// ring.commit_write(start, 1);
    ///
    /// let start = ring.claim_read(1)?;
    /// ring.commit_read(start, 1);
    /// # Ok::<(), mangonel_ring::Error>(())
    /// ```
    pub fn commit_read(&self, index: usize, batch_size: usize) {
        let tail = &self.inner.consumer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(batch_size), Ordering::Release);
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
