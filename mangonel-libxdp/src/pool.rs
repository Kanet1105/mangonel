use std::{
    cell::UnsafeCell,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

/// MPMC ring of frame addresses, split head/tail style (as
/// DPDK's `rte_ring`): claim a range, touch its slots,
/// commit. Every grant must be committed exactly once;
/// commits land in claim order, so an uncommitted grant
/// stalls the ring. Clones share one ring.
#[derive(Clone)]
pub struct FramePool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    size: u32,
    mask: u32,
    /// Producers' claim cursor.
    producer_head: CacheAligned<AtomicU32>,
    /// Producers' commit watermark: consumers may read
    /// positions strictly below it.
    producer_tail: CacheAligned<AtomicU32>,
    /// Consumers' claim cursor.
    consumer_head: CacheAligned<AtomicU32>,
    /// Consumers' commit watermark: producers may write
    /// positions strictly below it plus `size`.
    consumer_tail: CacheAligned<AtomicU32>,
    slots: Box<[UnsafeCell<u64>]>,
}

// SAFETY: A head CAS grants a range to exactly one thread,
// and the tail's Release/Acquire pair orders the access
// windows, so no two threads touch a cell concurrently.
unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

impl FramePool {
    pub fn new(size: usize) -> Self {
        assert!(
            size.is_power_of_two() && size <= 1 << 30,
            "The pool size '{size}' is not a power of two within 2^30."
        );

        let size = u32::try_from(size).expect("The assert above bounds the size. This is a bug.");
        let slots = (0..size).map(|_| UnsafeCell::new(0_u64)).collect();

        Self {
            inner: Arc::new(PoolInner {
                size,
                mask: size - 1,
                producer_head: CacheAligned(AtomicU32::new(0)),
                producer_tail: CacheAligned(AtomicU32::new(0)),
                consumer_head: CacheAligned(AtomicU32::new(0)),
                consumer_tail: CacheAligned(AtomicU32::new(0)),
                slots,
            }),
        }
    }

    fn slot(&self, position: u32) -> *mut u64 {
        self.inner.slots[(position & self.inner.mask) as usize].get()
    }

    /// Truncation matches the cursors' `u32` wrap.
    #[expect(clippy::cast_possible_truncation)]
    fn position(index: usize) -> u32 {
        index as u32
    }

    /// All-or-nothing: grants the whole burst (capped at
    /// the ring size) or `None`. `write_at` every granted
    /// index, then `commit_write` the grant.
    pub fn claim_write(&self, size: u32) -> Option<(u32, u32)> {
        if size == 0 {
            return None;
        }

        let size = size.min(self.inner.size);
        let mut head = self.inner.producer_head.load(Ordering::Relaxed);
        loop {
            // Acquire pairs with commit_read's Release: those
            // reads finished before we overwrite.
            let free_until = self
                .inner
                .consumer_tail
                .load(Ordering::Acquire)
                .wrapping_add(self.inner.size);
            if free_until.wrapping_sub(head) < size {
                return None;
            }

            match self.inner.producer_head.compare_exchange_weak(
                head,
                head.wrapping_add(size),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some((size, head));
                }
                Err(current) => head = current,
            }
        }
    }

    /// Invisible to consumers until `commit_write`.
    pub fn write_at(&self, index: usize, value: u64) {
        // SAFETY: The slot is owned by this producer between
        // claim_write and commit_write.
        unsafe { *self.slot(Self::position(index)) = value };
    }

    /// Publishes a write grant; `(index, size)` must match
    /// the claim. Waits for earlier grants to commit.
    pub fn commit_write(&self, index: usize, size: u32) {
        let index = Self::position(index);
        while self.inner.producer_tail.load(Ordering::Acquire) != index {
            std::hint::spin_loop();
        }

        self.inner
            .producer_tail
            .store(index.wrapping_add(size), Ordering::Release);
    }

    /// Grants up to `size` committed positions, or `None`.
    /// `read_at` every granted index, then `commit_read`
    /// the grant.
    pub fn claim_read(&self, size: u32) -> Option<(u32, u32)> {
        if size == 0 {
            return None;
        }

        let size = size.min(self.inner.size);
        let mut head = self.inner.consumer_head.load(Ordering::Relaxed);
        loop {
            // Acquire pairs with commit_write's Release: the
            // slot contents are visible.
            let committed = self.inner.producer_tail.load(Ordering::Acquire);
            // In [0, size] regardless of u32 wrap.
            let available = committed.wrapping_sub(head);
            let filled = size.min(available);
            if filled == 0 {
                return None;
            }

            match self.inner.consumer_head.compare_exchange_weak(
                head,
                head.wrapping_add(filled),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some((filled, head));
                }
                Err(current) => head = current,
            }
        }
    }

    /// Owned by this consumer until `commit_read`.
    pub fn read_at(&self, index: usize) -> u64 {
        // SAFETY: The slot is owned by this consumer between
        // claim_read and commit_read.
        unsafe { *self.slot(Self::position(index)) }
    }

    /// Frees a read grant for producers; `(index, size)`
    /// must match the claim. Waits for earlier grants to
    /// commit.
    pub fn commit_read(&self, index: usize, size: u32) {
        let index = Self::position(index);
        while self.inner.consumer_tail.load(Ordering::Acquire) != index {
            std::hint::spin_loop();
        }

        self.inner
            .consumer_tail
            .store(index.wrapping_add(size), Ordering::Release);
    }
}

/// Pads to a cache line so the cursors do not share one.
#[repr(align(64))]
struct CacheAligned<T>(T);

impl<T> Deref for CacheAligned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::FramePool;

    /// Refusals, the oversized-claim cap, commit
    /// visibility, and roundtrips across laps.
    #[test]
    fn protocol() {
        let pool = FramePool::new(4);
        assert_eq!(pool.claim_read(4), None);

        // Oversized requests cap at the ring size.
        let (available, index) = pool.claim_write(5).unwrap();
        assert_eq!(available, 4);
        for offset in 0..available {
            pool.write_at((index + offset) as usize, u64::from(offset));
        }
        // Uncommitted writes are invisible; a full ring
        // refuses.
        assert_eq!(pool.claim_read(4), None);
        pool.commit_write(index as usize, available);
        assert_eq!(pool.claim_write(1), None);

        let (filled, index) = pool.claim_read(4).unwrap();
        assert_eq!(filled, 4);
        for offset in 0..filled {
            assert_eq!(pool.read_at((index + offset) as usize), u64::from(offset));
        }
        pool.commit_read(index as usize, filled);

        // Values survive the cursors wrapping around laps.
        for lap in 1_u64..100 {
            let (available, index) = pool.claim_write(3).unwrap();
            assert_eq!(available, 3);
            for offset in 0..available {
                pool.write_at((index + offset) as usize, lap * 10 + u64::from(offset));
            }
            pool.commit_write(index as usize, available);

            let (filled, index) = pool.claim_read(3).unwrap();
            assert_eq!(filled, 3);
            for offset in 0..filled {
                assert_eq!(
                    pool.read_at((index + offset) as usize),
                    lap * 10 + u64::from(offset)
                );
            }
            pool.commit_read(index as usize, filled);
        }
    }

    #[test]
    fn mpmc_stress() {
        const PRODUCERS: usize = 2;
        const CONSUMERS: usize = 2;
        const PER_PRODUCER: u64 = 10_000;
        const BURST: u32 = 4;

        let pool = FramePool::new(64);
        let count = AtomicUsize::new(0);
        let sum = AtomicU64::new(0);

        std::thread::scope(|scope| {
            for producer in 0..PRODUCERS as u64 {
                let pool = &pool;
                scope.spawn(move || {
                    let mut sent = 0;
                    while sent < PER_PRODUCER {
                        let want = BURST.min(u32::try_from(PER_PRODUCER - sent).unwrap_or(BURST));
                        let Some((available, index)) = pool.claim_write(want) else {
                            std::hint::spin_loop();

                            continue;
                        };
                        for offset in 0..available {
                            let value = producer * PER_PRODUCER + sent + u64::from(offset);
                            pool.write_at(index as usize + offset as usize, value);
                        }
                        pool.commit_write(index as usize, available);

                        sent += u64::from(available);
                    }
                });
            }

            for _ in 0..CONSUMERS {
                let (pool, count, sum) = (&pool, &count, &sum);
                scope.spawn(move || {
                    let total = PRODUCERS * usize::try_from(PER_PRODUCER).unwrap();
                    while count.load(Ordering::Relaxed) < total {
                        let Some((filled, index)) = pool.claim_read(BURST) else {
                            std::hint::spin_loop();

                            continue;
                        };
                        for offset in 0..filled {
                            let value = pool.read_at(index as usize + offset as usize);
                            sum.fetch_add(value, Ordering::Relaxed);
                        }
                        pool.commit_read(index as usize, filled);

                        count.fetch_add(filled as usize, Ordering::Relaxed);
                    }
                });
            }
        });

        let total = PRODUCERS as u64 * PER_PRODUCER;
        assert_eq!(count.load(Ordering::Relaxed) as u64, total);
        // Each producer sent a distinct contiguous range;
        // the grand total checks nothing was lost or
        // duplicated.
        assert_eq!(sum.load(Ordering::Relaxed), total * (total - 1) / 2);
    }
}
