//! The bucket → worker table every I/O thread dispatches
//! through.
//!
//! A frame's flow hash picks a bucket, and the bucket names
//! a worker. The hash never changes, so moving load means
//! reassigning buckets: a store into this table, read with
//! a relaxed load on every packet. A move may briefly
//! reorder a flow's frames still queued for its old worker.

use std::sync::atomic::{AtomicU16, Ordering};

/// Enough buckets per worker that moving one shifts a small
/// share of the load.
pub const DEFAULT_BUCKET_COUNT: usize = 256;

pub struct Buckets {
    workers: Box<[AtomicU16]>,
    mask: usize,
    worker_count: usize,
}

impl Buckets {
    /// `count` buckets, a power of two, dealt round-robin
    /// over `worker_count` workers.
    pub fn new(count: usize, worker_count: usize) -> Self {
        assert!(
            count.is_power_of_two(),
            "The bucket count '{count}' is not a power of two."
        );
        assert!(
            (1..=usize::from(u16::MAX)).contains(&worker_count),
            "The worker count '{worker_count}' is outside 1..=65535."
        );

        let workers = (0..count)
            .map(|bucket| AtomicU16::new(index(bucket % worker_count)))
            .collect();

        Self {
            workers,
            mask: count - 1,
            worker_count,
        }
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// The bucket `hash` falls in.
    pub fn bucket(&self, hash: u32) -> usize {
        hash as usize & self.mask
    }

    /// The worker `bucket` is assigned to.
    pub fn worker(&self, bucket: usize) -> usize {
        usize::from(self.workers[bucket].load(Ordering::Relaxed))
    }

    /// Moves `bucket` to `worker`. Visible to every I/O
    /// thread on its next packet from that bucket.
    pub fn assign(&self, bucket: usize, worker: usize) {
        assert!(
            worker < self.worker_count,
            "Worker {worker} is outside the {} this table was built for.",
            self.worker_count
        );
        self.workers[bucket].store(index(worker), Ordering::Relaxed);
    }
}

/// `new` bounds every worker index by `u16::MAX`.
fn index(worker: usize) -> u16 {
    u16::try_from(worker).expect("Worker indices fit u16, as checked in new. This is a bug.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deals_round_robin_and_reassigns() {
        let buckets = Buckets::new(8, 3);
        let dealt: Vec<usize> = (0..8).map(|bucket| buckets.worker(bucket)).collect();
        assert_eq!(dealt, [0, 1, 2, 0, 1, 2, 0, 1]);

        buckets.assign(5, 0);
        assert_eq!(buckets.worker(5), 0);
        assert_eq!(buckets.bucket(0xffff_fffd), 5);
    }

    #[test]
    #[should_panic(expected = "outside the 3")]
    fn rejects_unknown_workers() {
        Buckets::new(8, 3).assign(0, 3);
    }
}
