//! `Ring` against crossbeam's `ArrayQueue` (Vyukov's
//! bounded MPMC queue) and a `Mutex<VecDeque>`, all at the
//! same capacity. Each queue moves bursts of up to `burst`
//! values: `Ring` claims a burst at once, `ArrayQueue`
//! loops over single operations, and the mutex holds the
//! lock per burst.

use std::{
    collections::VecDeque,
    hint::{black_box, spin_loop},
    sync::{Barrier, Mutex},
    thread,
    time::{Duration, Instant},
};

use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use crossbeam_queue::ArrayQueue;
use mangonel_ring::Ring;

const CAPACITY: usize = 1024;
const BURSTS: [usize; 2] = [1, 32];
const TOPOLOGIES: [(usize, usize); 3] = [(1, 1), (2, 2), (4, 4)];
/// Divisible by every producer and consumer count.
const ITEMS_PER_ITER: usize = 4096;

trait Queue: Sync {
    /// Pushes up to `n` values, returning how many fit.
    fn push_burst(&self, n: usize) -> usize;

    /// Pops up to `n` values, returning how many there
    /// were.
    fn pop_burst(&self, n: usize) -> usize;
}

impl Queue for Ring<usize> {
    fn push_burst(&self, n: usize) -> usize {
        let Ok(mut grant) = self.bulk_write(n) else {
            return 0;
        };
        let size = grant.size();
        for value in 0..size {
            grant.write(value).expect("the grant has room");
        }

        size
    }

    fn pop_burst(&self, n: usize) -> usize {
        let Ok(mut grant) = self.bulk_read(n) else {
            return 0;
        };
        let mut popped = 0;
        while let Some(value) = grant.read() {
            black_box(value);
            popped += 1;
        }

        popped
    }
}

impl Queue for ArrayQueue<usize> {
    fn push_burst(&self, n: usize) -> usize {
        let mut pushed = 0;
        while pushed < n && self.push(pushed).is_ok() {
            pushed += 1;
        }

        pushed
    }

    fn pop_burst(&self, n: usize) -> usize {
        let mut popped = 0;
        while popped < n {
            let Some(value) = self.pop() else {
                break;
            };
            black_box(value);
            popped += 1;
        }

        popped
    }
}

struct MutexQueue {
    inner: Mutex<VecDeque<usize>>,
}

impl MutexQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(CAPACITY)),
        }
    }
}

impl Queue for MutexQueue {
    fn push_burst(&self, n: usize) -> usize {
        let mut queue = self.inner.lock().unwrap();
        let n = n.min(CAPACITY - queue.len());
        for value in 0..n {
            queue.push_back(value);
        }

        n
    }

    fn pop_burst(&self, n: usize) -> usize {
        let mut queue = self.inner.lock().unwrap();
        let n = n.min(queue.len());
        for _ in 0..n {
            black_box(queue.pop_front());
        }

        n
    }
}

/// Moves `items` values through `queue` and times it from
/// the moment every thread is ready.
fn transfer<Q: Queue>(
    queue: &Q,
    producers: usize,
    consumers: usize,
    burst: usize,
    items: usize,
) -> Duration {
    let barrier = Barrier::new(producers + consumers + 1);
    thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..producers {
            handles.push(s.spawn(|| {
                barrier.wait();
                let mut left = items / producers;
                while left > 0 {
                    let pushed = queue.push_burst(burst.min(left));
                    if pushed == 0 {
                        spin_loop();
                    }
                    left -= pushed;
                }
            }));
        }
        // Each consumer takes a fixed share, so none needs to
        // learn when the others are done.
        for _ in 0..consumers {
            handles.push(s.spawn(|| {
                barrier.wait();
                let mut left = items / consumers;
                while left > 0 {
                    let popped = queue.pop_burst(burst.min(left));
                    if popped == 0 {
                        spin_loop();
                    }
                    left -= popped;
                }
            }));
        }

        barrier.wait();
        let start = Instant::now();
        for handle in handles {
            handle.join().unwrap();
        }

        start.elapsed()
    })
}

fn single_thread(c: &mut Criterion) {
    for burst in BURSTS {
        let mut group = c.benchmark_group(format!("single_thread/burst{burst}"));
        group.throughput(Throughput::Elements(burst as u64));
        round_trip(&mut group, "ring", Ring::new(CAPACITY).unwrap(), burst);
        round_trip(&mut group, "array_queue", ArrayQueue::new(CAPACITY), burst);
        round_trip(&mut group, "mutex_vecdeque", MutexQueue::new(), burst);
        group.finish();
    }
}

fn round_trip<Q: Queue>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    queue: Q,
    burst: usize,
) {
    group.bench_function(name, |b| {
        b.iter(|| {
            assert_eq!(queue.push_burst(burst), burst);
            assert_eq!(queue.pop_burst(burst), burst);
        });
    });
}

fn mpmc(c: &mut Criterion) {
    for (producers, consumers) in TOPOLOGIES {
        for burst in BURSTS {
            let mut group =
                c.benchmark_group(format!("mpmc/{producers}p{consumers}c/burst{burst}"));
            group.throughput(Throughput::Elements(ITEMS_PER_ITER as u64));
            group.sample_size(20);
            group.measurement_time(Duration::from_secs(3));
            let shape = (producers, consumers, burst);
            throughput(&mut group, "ring", Ring::new(CAPACITY).unwrap(), shape);
            throughput(&mut group, "array_queue", ArrayQueue::new(CAPACITY), shape);
            throughput(&mut group, "mutex_vecdeque", MutexQueue::new(), shape);
            group.finish();
        }
    }
}

fn throughput<Q: Queue>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    queue: Q,
    (producers, consumers, burst): (usize, usize, usize),
) {
    group.bench_function(name, |b| {
        b.iter_custom(|iters| {
            let items = ITEMS_PER_ITER * usize::try_from(iters).unwrap();

            transfer(&queue, producers, consumers, burst, items)
        });
    });
}

criterion_group!(benches, single_thread, mpmc);
criterion_main!(benches);
