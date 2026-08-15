use std::{
    cell::UnsafeCell,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

/// MPMC ring of frame addresses in the split head/tail
/// style (as DPDK's `rte_ring`): each side claims a range
/// by CASing its head, touches the slots, then commits by
/// advancing its tail in claim order. The opposite side
/// trusts only the tail, so a claimed-but-uncommitted
/// range is never visible to it.
///
/// The commit step is explicit, mirroring the xsk rings:
/// [`Self::commit_write`] after writes, [`Self::commit_read`] after
/// reads. Every grant must be committed exactly once with
/// its own `(index, count)`, after touching every slot in
/// it — a grant that never commits stalls the ring for
/// good, because later commits wait for it in claim order.
///
/// Positions wrap in `u32` like the xsk cursors; slot
/// lookups mask into range.
///
/// A cheaply clonable handle, like [`crate::Umem`]:
/// clones share one ring, which is how workers share the
/// pool.
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

// SAFETY: Slot values are plain u64s. A successful head
// CAS grants a position range to exactly one thread, and
// the range becomes visible to the opposite side only
// through the tail store after that thread is done; the
// tail's Release/Acquire pair orders the two access
// windows so no two threads touch a cell concurrently.
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

    /// Truncating to `u32` is exactly the wrap the cursors
    /// use, so an offset index computed in `usize` lands on
    /// the same position.
    #[allow(clippy::cast_possible_truncation)]
    fn position(index: usize) -> u32 {
        index as u32
    }

    /// All-or-nothing, like the xsk producer's `reserve`:
    /// `Some((available, index))` grants the whole burst
    /// (capped at the ring size), `None` grants nothing.
    /// Touch every granted index with [`Self::write_at`],
    /// then commit the grant with [`Self::commit_write`].
    pub fn claim_write(&self, size: u32) -> Option<(u32, u32)> {
        if size == 0 {
            return None;
        }

        // A burst can never exceed the ring itself.
        let size = size.min(self.inner.size);
        let mut head = self.inner.producer_head.load(Ordering::Relaxed);
        loop {
            // Slots are writable up to one lap past the reads
            // the consumers have committed. The Acquire pairs
            // with the Release in commit_read, so those reads have
            // finished before we overwrite.
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

    /// Writes `value` into the slot at `index`. Not
    /// visible to consumers until [`Self::commit_write`] commits
    /// the grant.
    pub fn write_at(&self, index: usize, value: u64) {
        // SAFETY: The slot is owned by this producer between
        // claim_write and commit_write; no reference outlives the
        // call.
        unsafe { *self.slot(Self::position(index)) = value };
    }

    /// Commits a write grant, publishing its positions to
    /// consumers. Same contract as [`Self::commit_read`].
    pub fn commit_write(&self, index: usize, size: u32) {
        let index = Self::position(index);
        while self.inner.producer_tail.load(Ordering::Acquire) != index {
            std::hint::spin_loop();
        }

        self.inner
            .producer_tail
            .store(index.wrapping_add(size), Ordering::Release);
    }

    /// Up to `size`, like the xsk consumer's `peek`:
    /// `Some((filled, index))` grants committed positions,
    /// `None` means nothing is readable. Touch every
    /// granted index with [`Self::read_at`], then commit
    /// the grant with [`Self::commit_read`].
    pub fn claim_read(&self, size: u32) -> Option<(u32, u32)> {
        if size == 0 {
            return None;
        }

        // A burst can never exceed the ring itself.
        let size = size.min(self.inner.size);
        let mut head = self.inner.consumer_head.load(Ordering::Relaxed);
        loop {
            // Only committed writes are readable. The Acquire
            // pairs with the Release in commit_write, making the
            // slot contents visible.
            let committed = self.inner.producer_tail.load(Ordering::Acquire);
            // In [0, size] regardless of u32 wrap.
            let available = committed.wrapping_sub(head);
            let filled = size.min(available);
            if filled == 0 {
                return None;
            }

            // The claim itself publishes nothing; the tails
            // carry the data ordering.
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

    /// Reads the slot at `index`. The slot stays owned by
    /// this consumer until [`Self::commit_read`] commits the
    /// grant.
    pub fn read_at(&self, index: usize) -> u64 {
        // SAFETY: The slot is owned by this consumer between
        // claim_read and commit_read; no reference outlives the
        // call.
        unsafe { *self.slot(Self::position(index)) }
    }

    /// Commits a read grant, freeing its positions for
    /// producers. `(index, size)` must be exactly
    /// what [`Self::claim_read`] granted. Commits land in
    /// claim order, so this waits for earlier grants —
    /// which is why every grant must commit promptly.
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

/// Pads to a cache line so the cursors do not share one:
/// an update to any cursor would otherwise invalidate the
/// others' cached lines on every operation.
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

    /// Empty and full refusals, the oversized-claim cap,
    /// commit visibility, and value roundtrips across 100
    /// laps of a small ring.
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
