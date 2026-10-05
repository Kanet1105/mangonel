//! Bounded single-producer, single-consumer rings that hand
//! batches between the I/O thread and the workers.
//!
//! Each side keeps its own cursor locally and a cached copy
//! of the other side's, so a batch touches the shared
//! cursors at most twice. Dropping an endpoint closes the
//! ring; the other side sees it once it has taken
//! everything that was pushed.

use std::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

/// A ring holding up to `capacity` items, which must be a
/// power of two.
pub fn channel<T: Send>(capacity: usize) -> (Producer<T>, Consumer<T>) {
    assert!(
        capacity.is_power_of_two(),
        "The ring capacity '{capacity}' is not a power of two."
    );

    let shared = Arc::new(Shared {
        slots: (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect(),
        mask: capacity - 1,
        head: CachePadded(AtomicUsize::new(0)),
        tail: CachePadded(AtomicUsize::new(0)),
        producer_closed: AtomicBool::new(false),
        consumer_closed: AtomicBool::new(false),
    });

    (
        Producer {
            shared: shared.clone(),
            tail: 0,
            head: 0,
        },
        Consumer {
            shared,
            head: 0,
            tail: 0,
        },
    )
}

/// The pushing end. `Send`, not `Clone`.
pub struct Producer<T> {
    shared: Arc<Shared<T>>,
    /// Next position to write; mirrors `shared.tail`.
    tail: usize,
    /// Last seen consumer position.
    head: usize,
}

impl<T> Drop for Producer<T> {
    fn drop(&mut self) {
        // Release: every push happens before the consumer
        // sees the ring closed.
        self.shared.producer_closed.store(true, Ordering::Release);
    }
}

impl<T: Send> Producer<T> {
    /// Moves as many items from the front of `items` as
    /// fit, and returns how many moved. The rest stay
    /// in `items`.
    pub fn push_from(&mut self, items: &mut Vec<T>) -> usize {
        let capacity = self.shared.slots.len();
        if items.len() > capacity - self.tail.wrapping_sub(self.head) {
            // Acquire pairs with the consumer's Release:
            // its reads of these slots are
            // done.
            self.head = self.shared.head.load(Ordering::Acquire);
        }
        let count = items
            .len()
            .min(capacity - self.tail.wrapping_sub(self.head));

        for (offset, item) in items.drain(..count).enumerate() {
            let slot = self.shared.slot(self.tail.wrapping_add(offset));
            // SAFETY: Positions in [tail, head + capacity)
            // are free, and only this producer writes them.
            unsafe { (*slot).write(item) };
        }
        self.tail = self.tail.wrapping_add(count);
        // Release: the writes above happen before the
        // consumer reads the new tail.
        self.shared.tail.store(self.tail, Ordering::Release);

        count
    }

    /// Whether the consumer has gone, so nothing pushed
    /// will be taken.
    pub fn is_closed(&self) -> bool {
        self.shared.consumer_closed.load(Ordering::Acquire)
    }
}

/// The taking end. `Send`, not `Clone`.
pub struct Consumer<T> {
    shared: Arc<Shared<T>>,
    /// Next position to read; mirrors `shared.head`.
    head: usize,
    /// Last seen producer position.
    tail: usize,
}

impl<T> Drop for Consumer<T> {
    fn drop(&mut self) {
        self.shared.consumer_closed.store(true, Ordering::Release);
    }
}

impl<T: Send> Consumer<T> {
    /// Appends up to `max` items to `out` and returns how
    /// many.
    pub fn pop_into(&mut self, out: &mut Vec<T>, max: usize) -> usize {
        if self.tail.wrapping_sub(self.head) < max {
            // Acquire pairs with the producer's Release:
            // the slot contents are visible.
            self.tail = self.shared.tail.load(Ordering::Acquire);
        }
        let count = max.min(self.tail.wrapping_sub(self.head));

        out.reserve(count);
        for offset in 0..count {
            let slot = self.shared.slot(self.head.wrapping_add(offset));
            // SAFETY: Positions in [head, tail) were
            // written and published by the
            // producer, and each is read
            // exactly once before head passes it.
            out.push(unsafe { (*slot).assume_init_read() });
        }
        self.head = self.head.wrapping_add(count);
        // Release: the reads above finish before the
        // producer reuses these slots.
        self.shared.head.store(self.head, Ordering::Release);

        count
    }

    /// Whether the producer has gone and every item it
    /// pushed has been taken: nothing more will arrive.
    pub fn is_finished(&mut self) -> bool {
        // Closed first: the Acquire makes every push
        // visible to the tail load that follows.
        if !self.shared.producer_closed.load(Ordering::Acquire) {
            return false;
        }
        self.tail = self.shared.tail.load(Ordering::Acquire);

        self.tail == self.head
    }
}

struct Shared<T> {
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    /// Consumer's position: everything below is free again.
    head: CachePadded<AtomicUsize>,
    /// Producer's position: everything below is readable.
    tail: CachePadded<AtomicUsize>,
    producer_closed: AtomicBool,
    consumer_closed: AtomicBool,
}

// SAFETY: Each slot is touched by one side at a time: the
// producer writes only free slots and the consumer reads
// only published ones, ordered by the cursors'
// Release/Acquire pairs. Items move between threads, hence
// `T: Send`.
unsafe impl<T: Send> Sync for Shared<T> {}
unsafe impl<T: Send> Send for Shared<T> {}

impl<T> Drop for Shared<T> {
    /// Both endpoints are gone, so this has the ring to
    /// itself: drop whatever was pushed but never taken.
    fn drop(&mut self) {
        let head = *self.head.get_mut();
        let tail = *self.tail.get_mut();
        for position in 0..tail.wrapping_sub(head) {
            let slot = self.slot(head.wrapping_add(position));
            // SAFETY: Published and never read.
            unsafe { (*slot).assume_init_drop() };
        }
    }
}

impl<T> Shared<T> {
    fn slot(&self, position: usize) -> *mut MaybeUninit<T> {
        self.slots[position & self.mask].get()
    }
}

/// Pads to a cache line so the two cursors do not share
/// one.
#[repr(align(64))]
struct CachePadded<T>(T);

impl<T> Deref for CachePadded<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn batches_keep_order_across_wraps() {
        let (mut tx, mut rx) = channel::<u64>(8);
        let mut out = Vec::new();
        let mut next = 0;
        for _ in 0..50 {
            let mut batch: Vec<u64> = (next..next + 5).collect();
            assert_eq!(tx.push_from(&mut batch), 5);
            next += 5;
            assert_eq!(rx.pop_into(&mut out, 8), 5);
        }
        assert_eq!(out, (0..next).collect::<Vec<_>>());
    }

    #[test]
    fn a_full_ring_keeps_the_rest() {
        let (mut tx, mut rx) = channel::<u8>(4);
        let mut batch = vec![1, 2, 3, 4, 5, 6];
        assert_eq!(tx.push_from(&mut batch), 4);
        assert_eq!(batch, [5, 6]);

        let mut out = Vec::new();
        assert_eq!(rx.pop_into(&mut out, 2), 2);
        assert_eq!(tx.push_from(&mut batch), 2);
        assert_eq!(rx.pop_into(&mut out, 10), 4);
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn closing_is_seen_after_draining() {
        let (mut tx, mut rx) = channel::<u8>(4);
        tx.push_from(&mut vec![7]);
        assert!(!rx.is_finished());
        drop(tx);
        assert!(!rx.is_finished());
        rx.pop_into(&mut Vec::new(), 4);
        assert!(rx.is_finished());

        let (tx, rx) = channel::<u8>(4);
        drop(rx);
        assert!(tx.is_closed());
    }

    #[test]
    fn untaken_items_are_dropped_with_the_ring() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Counted;
        impl Drop for Counted {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (mut tx, mut rx) = channel::<Counted>(4);
        tx.push_from(&mut vec![Counted, Counted, Counted]);
        rx.pop_into(&mut Vec::new(), 1);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
        drop((tx, rx));
        assert_eq!(DROPS.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn threads_hand_over_everything_once() {
        const TOTAL: u64 = 200_000;
        let (mut tx, mut rx) = channel::<u64>(64);

        let producer = std::thread::spawn(move || {
            let mut next = 0;
            let mut batch = Vec::new();
            while next < TOTAL {
                batch.extend(next..(next + 16).min(TOTAL));
                next = (next + 16).min(TOTAL);
                while !batch.is_empty() {
                    tx.push_from(&mut batch);
                    std::hint::spin_loop();
                }
            }
        });

        let mut out = Vec::new();
        while !rx.is_finished() {
            rx.pop_into(&mut out, 32);
        }
        producer.join().unwrap();
        assert_eq!(out, (0..TOTAL).collect::<Vec<_>>());
    }
}
