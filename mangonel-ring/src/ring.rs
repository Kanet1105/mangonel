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

    pub(crate) fn slot(&self, index: usize) -> *mut Option<T> {
        self.inner.slots[index & self.inner.mask].get()
    }

    /// # Safety
    ///
    /// `(n, index)` must come from `claim_write`, with all
    /// `n` slots written.
    pub(crate) fn commit_write(&self, n: usize, index: usize) {
        let tail = &self.inner.producer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(n), Ordering::Release);
    }

    /// # Safety
    ///
    /// `(n, index)` must come from `claim_read`, and no
    /// reference from `read_at` into those slots may be
    /// used afterwards.
    pub(crate) fn commit_read(&self, n: usize, index: usize) {
        let tail = &self.inner.consumer_tail;
        let backoff = Backoff::new();
        while tail.load(Ordering::Acquire) != index {
            backoff.snooze();
        }
        tail.store(index.wrapping_add(n), Ordering::Release);
    }
}
