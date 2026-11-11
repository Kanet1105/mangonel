//! The transmit threads: each owns one queue of the device
//! and fills it with the packet as fast as the tx ring
//! drains.

use std::{
    sync::atomic::{
        AtomicBool,
        AtomicU64,
        Ordering,
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use mangonel_libxdp::{
    XdpDescriptor,
    XdpSocket,
};

use crate::packet::Template;

/// How long a thread keeps its socket alive after its last
/// packet, for the interface to take what is still queued.
const LINGER: Duration = Duration::from_millis(100);

/// The destination ports one thread cycles through: every
/// `stride`th of the range from its own offset, so no two
/// threads send the same flow, as no two queues of a
/// hashing NIC would carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ports {
    first: u16,
    count: u32,
    /// Where in the range this thread starts over.
    start: u32,
    stride: u32,
    /// Where in the range the next port is.
    next: u32,
}

impl Ports {
    /// The share of `count` ports from `first` up that falls
    /// to `thread` of `threads`. The range must end by the
    /// last port there is.
    pub(crate) fn new(first: u16, count: u32, thread: u32, threads: u32) -> Self {
        // With more threads than ports the surplus share.
        let start = thread % count;

        Self {
            first,
            count,
            start,
            stride: threads,
            next: start,
        }
    }

    /// The port of the next packet.
    pub(crate) fn next(&mut self) -> u16 {
        let offset = self.next;
        self.next = match offset.checked_add(self.stride) {
            Some(next) if next < self.count => next,
            _ => self.start,
        };

        u16::try_from(u32::from(self.first) + offset)
            .expect("The port range ends by the last port. This is a bug.")
    }
}

/// What one thread sends, on what, and until when.
pub(crate) struct Job<'a> {
    pub(crate) socket: XdpSocket,
    pub(crate) template: &'a Template,
    pub(crate) ports: Ports,
    /// Packets handed to the interface at a time.
    pub(crate) batch: usize,
    /// Packets to send in all, when there is a limit.
    pub(crate) quota: Option<u64>,
    /// Counts what has been handed to the interface.
    pub(crate) sent: &'a AtomicU64,
    pub(crate) stop: &'a AtomicBool,
}

/// Sends until the quota is met or `stop` is set, and
/// returns how long that took.
pub(crate) fn transmit(job: Job<'_>) -> Duration {
    let Job {
        mut socket,
        template,
        mut ports,
        batch,
        quota,
        sent,
        stop,
    } = job;
    let length = u32::try_from(template.len())
        .expect("A packet no longer than an MTU fits a u32. This is a bug.");
    let mut frames: Vec<XdpDescriptor> = (0..batch).map(|_| XdpDescriptor::default()).collect();
    let mut arrived: Vec<XdpDescriptor> = (0..batch).map(|_| XdpDescriptor::default()).collect();
    let mut left = quota;
    let started = Instant::now();

    // Nothing is ordered against the flag: a batch more or
    // less before stopping makes no difference.
    while !stop.load(Ordering::Relaxed) && left != Some(0) {
        recycle(&mut socket, &mut arrived);

        let want = left.map_or(batch, |left| {
            batch.min(usize::try_from(left).unwrap_or(batch))
        });
        // Short when the pool is: frames sent come back to
        // it only as the interface completes them.
        let ready = socket.allocate(&mut frames[..want]) as usize;
        for frame in &mut frames[..ready] {
            frame.set_length(length);
            template.write(frame.data_mut(), ports.next());
        }
        // Fewer when the tx ring is full. The rest go back to
        // the pool rather than wait.
        let taken = socket.send(&mut frames[..ready]) as usize;
        socket.drop(&mut frames[taken..ready]);

        let taken = u64::try_from(taken).unwrap_or(u64::MAX);
        // Only this thread writes, and readers want a figure,
        // not an ordering.
        sent.fetch_add(taken, Ordering::Relaxed);
        left = left.map(|left| left.saturating_sub(taken));
    }
    let elapsed = started.elapsed();

    // What is still on the tx ring leaves only while the
    // socket lives and is kicked.
    let deadline = Instant::now() + LINGER;
    while Instant::now() < deadline {
        let _ = socket.send(&mut []);
        recycle(&mut socket, &mut arrived);
        thread::sleep(Duration::from_millis(1));
    }

    elapsed
}

/// Returns completed frames to the pool, which is the only
/// thing receiving does for a sender, and drops whatever
/// arrived on the queue: nothing here answers it.
fn recycle(socket: &mut XdpSocket, arrived: &mut [XdpDescriptor]) {
    let count = socket.receive(arrived) as usize;
    socket.drop(&mut arrived[..count]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(ports: &mut Ports, count: usize) -> Vec<u16> {
        (0..count).map(|_| ports.next()).collect()
    }

    #[test]
    fn one_thread_cycles_through_every_port() {
        let mut ports = Ports::new(9000, 3, 0, 1);
        assert_eq!(
            take(&mut ports, 7),
            [9000, 9001, 9002, 9000, 9001, 9002, 9000]
        );

        let mut fixed = Ports::new(9000, 1, 0, 1);
        assert_eq!(take(&mut fixed, 3), [9000, 9000, 9000]);
    }

    #[test]
    fn threads_split_the_ports_between_them() {
        let mut seen = std::collections::HashSet::new();
        for thread in 0..3 {
            let mut ports = Ports::new(100, 10, thread, 3);
            let share: std::collections::HashSet<u16> = take(&mut ports, 20).into_iter().collect();
            // Nobody else's, and the same ones again after the
            // range ends.
            assert!(
                share.iter().all(|port| seen.insert(*port)),
                "thread {thread}"
            );
            assert!(share.iter().all(|port| (100..110).contains(port)));
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn more_threads_than_ports_share_them() {
        for thread in 0..5 {
            let mut ports = Ports::new(7, 2, thread, 5);
            let expected = 7 + u16::try_from(thread % 2).unwrap();
            assert_eq!(take(&mut ports, 3), [expected; 3]);
        }
    }

    #[test]
    fn the_range_may_end_at_the_last_port() {
        let mut ports = Ports::new(u16::MAX - 1, 2, 0, 1);
        assert_eq!(take(&mut ports, 3), [u16::MAX - 1, u16::MAX, u16::MAX - 1]);
    }
}
