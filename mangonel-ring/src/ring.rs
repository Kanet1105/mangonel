use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crossbeam_utils::{Backoff, CachePadded};

use crate::{BulkRead, BulkWrite, Error};

pub const DEFAULT_RING_SIZE: usize = 4096;

#[derive(Clone)]
pub struct Ring<T> {
    inner: Arc<RingInner<T>>,
}

struct RingInner<T> {
    size: usize,
    mask: usize,
    producer_head: CachePadded<AtomicUsize>,
    producer_tail: CachePadded<AtomicUsize>,
    consumer_head: CachePadded<AtomicUsize>,
    consumer_tail: CachePadded<AtomicUsize>,
    /// `None` until written, and again once read.
    slots: Box<[UnsafeCell<Option<T>>]>,
}

// SAFETY: the head/tail indices give each slot one owner at
// a time, so `T` only moves between threads and is never
// shared.
unsafe impl<T: Send> Sync for RingInner<T> {}

impl<T> Default for Ring<T> {
    fn default() -> Self {
        Self::new(DEFAULT_RING_SIZE)
            .expect("Default ring size is not the power of two. This is a bug.")
    }
}

impl<T> Ring<T> {
    /// A ring of `size` slots.
    ///
    /// # Errors
    ///
    /// [`Error::IsNotPowerOfTwo`] if `size` is not a power
    /// of two.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::{Error, Ring};
    ///
    /// let ring = Ring::<u64>::new(64)?;
    /// assert!(matches!(
    ///     Ring::<u64>::new(100),
    ///     Err(Error::IsNotPowerOfTwo(100))
    /// ));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn new(size: usize) -> Result<Self, Error> {
        if !size.is_power_of_two() {
            return Err(Error::IsNotPowerOfTwo(size));
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
                slots: (0..size).map(|_| UnsafeCell::new(None)).collect(),
            }),
        })
    }

    fn validate_claim_size(&self, n: usize) -> Result<usize, Error> {
        if n == 0 {
            return Err(Error::ZeroClaimSize);
        }

        Ok(self.inner.size.min(n))
    }

    /// Claims up to `n` free slots for writing. Dropping
    /// the grant publishes them, and later grants wait
    /// for that, so drop it promptly.
    ///
    /// # Errors
    ///
    /// [`Error::ZeroClaimSize`] if `n` is 0, or
    /// [`Error::RingIsFull`] if no slot is free.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::{Error, Ring};
    ///
    /// let ring = Ring::new(4)?;
    /// let mut grant = ring.bulk_write(4)?;
    /// for value in [1, 2, 3, 4] {
    ///     grant.write(value)?;
    /// }
    /// drop(grant);
    /// assert!(matches!(ring.bulk_write(1), Err(Error::RingIsFull)));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn bulk_write(&self, n: usize) -> Result<BulkWrite<'_, T>, Error> {
        let want = self.validate_claim_size(n)?;
        let ring_size = self.inner.size;
        let head = &self.inner.producer_head;
        let tail = &self.inner.consumer_tail;
        // Acquire pairs with the head CAS's Release, so the
        // tail read below is no older than the last claimer's.
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            // Acquire pairs with commit_read's Release: consumers
            // are done with the slots before we overwrite them.
            let available = tail
                .load(Ordering::Acquire)
                .wrapping_add(ring_size)
                .wrapping_sub(index);

            let n = available.min(want);
            if n == 0 {
                return Err(Error::RingIsFull);
            }

            match head.compare_exchange(
                index,
                index.wrapping_add(n),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(BulkWrite::new(self, n, index)),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    /// Claims up to `n` published slots for reading.
    /// Dropping the grant frees them, dropping any
    /// value left unread, and later grants wait for
    /// that, so drop it promptly.
    ///
    /// # Errors
    ///
    /// [`Error::ZeroClaimSize`] if `n` is 0, or
    /// [`Error::RingIsEmpty`] if no slot is published.
    ///
    /// # Examples
    ///
    /// ```
    /// use mangonel_ring::{Error, Ring};
    ///
    /// let ring = Ring::new(4)?;
    /// let mut grant = ring.bulk_write(2)?;
    /// grant.write(1)?;
    /// grant.write(2)?;
    /// drop(grant);
    ///
    /// let mut grant = ring.bulk_read(4)?;
    /// assert_eq!(grant.read(), Some(1));
    /// assert_eq!(grant.read(), Some(2));
    /// assert_eq!(grant.read(), None);
    /// drop(grant);
    /// assert!(matches!(ring.bulk_read(1), Err(Error::RingIsEmpty)));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn bulk_read(&self, n: usize) -> Result<BulkRead<'_, T>, Error> {
        let want = self.validate_claim_size(n)?;
        let head = &self.inner.consumer_head;
        let tail = &self.inner.producer_tail;
        // Acquire pairs with the head CAS's Release, so the
        // tail read below is no older than the last claimer's.
        let mut index = head.load(Ordering::Acquire);
        let backoff = Backoff::new();
        loop {
            // Acquire pairs with commit_write's Release: the slot
            // writes are visible before we read them.
            let available = tail.load(Ordering::Acquire).wrapping_sub(index);

            let n = available.min(want);
            if n == 0 {
                return Err(Error::RingIsEmpty);
            }

            match head.compare_exchange(
                index,
                index.wrapping_add(n),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(BulkRead::new(self, n, index)),
                Err(current) => index = current,
            }
            backoff.spin();
        }
    }

    /// # Safety
    ///
    /// The pointer may be dereferenced only while the caller's
    /// grant claims `index`, with no other reference into the
    /// slot alive.
    pub(crate) unsafe fn slot(&self, index: usize) -> *mut Option<T> {
        self.inner.slots[index & self.inner.mask].get()
    }

    /// Publishes the `n` slots claimed at `index`, once
    /// earlier claims are published.
    pub(crate) fn commit_write(&self, n: usize, index: usize) {
        let tail = &self.inner.producer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(n), Ordering::Release);
    }

    /// Frees the `n` slots claimed at `index`, dropping
    /// any value left unread, once earlier claims are
    /// freed.
    pub(crate) fn commit_read(&self, n: usize, index: usize) {
        for offset in 0..n {
            let item = unsafe { &mut *self.slot(index.wrapping_add(offset)) };
            item.take();
        }

        let tail = &self.inner.consumer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(n), Ordering::Release);
    }
}
