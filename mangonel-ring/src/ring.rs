use std::{
    cell::UnsafeCell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crossbeam_utils::{Backoff, CachePadded};

use crate::{BulkRead, BulkWrite, Error};

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

impl<T> Clone for Ring<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
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
    /// # Deadlocks
    ///
    /// A thread holding two write grants must drop them
    /// in claim order, or the later one waits forever;
    /// locals at the end of a scope drop in the reverse
    /// order. A grant that is never dropped blocks every
    /// later one.
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
    /// # Deadlocks
    ///
    /// A thread holding two read grants must drop them
    /// in claim order, or the later one waits forever;
    /// locals at the end of a scope drop in the reverse
    /// order. A grant that is never dropped blocks every
    /// later one.
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

    /// The slot at `index`. Dereference it only while the
    /// caller's grant claims `index`, with no other
    /// reference into the slot alive.
    pub(crate) fn slot(&self, index: usize) -> *mut Option<T> {
        self.inner.slots[index & self.inner.mask].get()
    }

    /// Publishes the grant's slots, once earlier grants
    /// are published. Called by the grant's `Drop`.
    pub(crate) fn commit_write(&self, bulk_write: &BulkWrite<'_, T>) {
        let tail = &self.inner.producer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != bulk_write.start() {
            backoff.snooze();
        }
        tail.store(bulk_write.end(), Ordering::Release);
    }

    /// Frees the grant's slots, dropping any value left
    /// unread, once earlier grants are freed. Called by
    /// the grant's `Drop`.
    pub(crate) fn commit_read(&self, bulk_read: &BulkRead<'_, T>) {
        let mut index = bulk_read.current();
        while index != bulk_read.end() {
            // SAFETY: the claim keeps producers off the slot
            // until the tail store below.
            unsafe { *self.slot(index) = None };
            index = index.wrapping_add(1);
        }

        let tail = &self.inner.consumer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != bulk_read.start() {
            backoff.snooze();
        }
        tail.store(bulk_read.end(), Ordering::Release);
    }
}
