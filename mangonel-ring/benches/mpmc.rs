//! Throughput of `mpmc::Ring<u64>` against a
//! `Mutex<VecDeque<u64>>` and crossbeam's `ArrayQueue`, a
//! Vyukov-style bounded queue with a sequence number per
//! slot.
//!
//! Each iteration moves `ITEMS` values from the producers
//! to the consumers, `batch` at a time where the queue
//! allows it, and checks their sum so nothing is lost or
//! duplicated. Thread spawning is excluded from the timing.
//! Threads waiting on a full or empty queue back off and
//! then yield, so runs with more threads than CPUs still
//! make progress.

use std::{
    collections::VecDeque,
    hint::black_box,
    sync::{
        Barrier, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use crossbeam_queue::ArrayQueue;
use crossbeam_utils::Backoff;
use mangonel_ring::mpmc::Ring;

/// Slots in every queue.
const CAPACITY: usize = 1024;

/// Values moved per iteration, split evenly across the
/// producers.
const ITEMS: u64 = 1 << 18;

/// `(producers, consumers)` pairs to run.
const THREADS: [(u64, u64); 3] = [(2, 2), (4, 4), (8, 8)];

/// Most values a producer or consumer moves per call.
const BATCHES: [usize; 3] = [1, 32, 128];

/// A bounded queue of `u64` shared by every thread.
trait Queue: Sync {
    fn new() -> Self;

    /// Pushes `next..end`, at most `batch` of them, and
    /// returns how many were pushed.
    fn push_batch(&self, next: u64, end: u64, batch: usize) -> u64;

    /// Pops at most `batch` values and returns how many,
    /// and their sum.
    fn pop_batch(&self, batch: usize) -> (u64, u64);
}

impl Queue for Ring<u64> {
    fn new() -> Self {
        Ring::new(CAPACITY).unwrap()
    }

    fn push_batch(&self, next: u64, end: u64, batch: usize) -> u64 {
        let want = batch.min(usize::try_from(end - next).unwrap_or(usize::MAX));
        let Ok(mut grant) = self.write_up_to(want) else {
            return 0;
        };

        let mut pushed = 0;
        while grant.write(next + pushed).is_ok() {
            pushed += 1;
        }

        pushed
    }

    fn pop_batch(&self, batch: usize) -> (u64, u64) {
        let Ok(mut grant) = self.read_up_to(batch) else {
            return (0, 0);
        };

        let (mut popped, mut sum) = (0, 0);
        while let Ok(value) = grant.read() {
            popped += 1;
            sum += *value;
        }

        (popped, sum)
    }
}

impl Queue for Mutex<VecDeque<u64>> {
    fn new() -> Self {
        Mutex::new(VecDeque::with_capacity(CAPACITY))
    }

    fn push_batch(&self, next: u64, end: u64, batch: usize) -> u64 {
        let mut items = self.lock().unwrap();
        let free = u64::try_from(CAPACITY - items.len()).unwrap();
        let batch = u64::try_from(batch).unwrap();
        let count = free.min(batch).min(end - next);
        items.extend(next..next + count);

        count
    }

    fn pop_batch(&self, batch: usize) -> (u64, u64) {
        let mut items = self.lock().unwrap();
        let count = items.len().min(batch);
        let sum = items.drain(..count).sum();

        (u64::try_from(count).unwrap(), sum)
    }
}

/// No batch operations: every value is its own push or
/// pop.
impl Queue for ArrayQueue<u64> {
    fn new() -> Self {
        ArrayQueue::new(CAPACITY)
    }

    fn push_batch(&self, next: u64, end: u64, batch: usize) -> u64 {
        let mut pushed = 0;
        for value in (next..end).take(batch) {
            if self.push(value).is_err() {
                break;
            }
            pushed += 1;
        }

        pushed
    }

    fn pop_batch(&self, batch: usize) -> (u64, u64) {
        let (mut popped, mut sum) = (0, 0);
        for _ in 0..batch {
            let Some(value) = self.pop() else {
                break;
            };
            popped += 1;
            sum += value;
        }

        (popped, sum)
    }
}

/// Moves `ITEMS` values through a fresh `Q` and returns
/// the time from all threads starting to all finishing.
fn run<Q: Queue>(producers: u64, consumers: u64, batch: usize) -> Duration {
    let queue = Q::new();
    let popped = AtomicU64::new(0);
    let sum = AtomicU64::new(0);
    let per_producer = ITEMS / producers;
    let barrier = Barrier::new(usize::try_from(producers + consumers + 1).unwrap());

    let start = thread::scope(|scope| {
        for producer in 0..producers {
            let (queue, barrier) = (&queue, &barrier);
            scope.spawn(move || {
                let end = (producer + 1) * per_producer;
                let mut next = producer * per_producer;
                let backoff = Backoff::new();
                barrier.wait();
                while next < end {
                    match queue.push_batch(next, end, batch) {
                        0 => backoff.snooze(),
                        pushed => {
                            next += pushed;
                            backoff.reset();
                        }
                    }
                }
            });
        }

        for _ in 0..consumers {
            let (queue, barrier, popped, sum) = (&queue, &barrier, &popped, &sum);
            scope.spawn(move || {
                let mut local = 0;
                let backoff = Backoff::new();
                barrier.wait();
                while popped.load(Ordering::Relaxed) < ITEMS {
                    match queue.pop_batch(batch) {
                        (0, _) => backoff.snooze(),
                        (count, values) => {
                            popped.fetch_add(count, Ordering::Relaxed);
                            local += values;
                            backoff.reset();
                        }
                    }
                }
                sum.fetch_add(local, Ordering::Relaxed);
            });
        }

        barrier.wait();
        Instant::now()
    });
    let elapsed = start.elapsed();

    assert_eq!(black_box(sum.into_inner()), ITEMS * (ITEMS - 1) / 2);

    elapsed
}

fn throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpmc");
    group.throughput(Throughput::Elements(ITEMS));

    for (producers, consumers) in THREADS {
        for batch in BATCHES {
            let parameter = format!("{producers}p{consumers}c/batch{batch}");
            group.bench_function(BenchmarkId::new("ring", &parameter), |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| run::<Ring<u64>>(producers, consumers, batch))
                        .sum()
                });
            });
            group.bench_function(BenchmarkId::new("mutex_vecdeque", &parameter), |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| run::<Mutex<VecDeque<u64>>>(producers, consumers, batch))
                        .sum()
                });
            });
            group.bench_function(BenchmarkId::new("array_queue", &parameter), |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| run::<ArrayQueue<u64>>(producers, consumers, batch))
                        .sum()
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, throughput);
criterion_main!(benches);
