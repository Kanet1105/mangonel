//! The I/O thread: owns AF_XDP sockets, receives frames,
//! hands each to a worker by flow, and sends back whatever
//! the workers return.
//!
//! It never processes a packet. Per frame it reads only
//! the headers the flow hash needs, so workers can be added
//! without regard to how many queues each NIC has, and load
//! is balanced by reassigning [`Buckets`] rather than
//! queues.
//!
//! Each I/O thread talks to each worker over a pair of
//! [`spsc`] rings, a [`WorkerLink`]. Nothing
//! blocks: a full ring or a full transmit queue drops the
//! frames that did not fit and counts them.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use mangonel_libxdp::{XdpDescriptor, XdpSocket};
use mangonel_ring::spsc::{self, Consumer, Producer};

use crate::{Buckets, flow::flow_hash};

/// An interface, as the I/O threads and workers number
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortId(pub u16);

/// A frame in flight between an I/O thread and a worker.
pub struct Packet<F = XdpDescriptor> {
    pub frame: F,
    /// Towards a worker, the port the frame arrived on.
    /// Back from one, the port to send it out of.
    pub port: PortId,
}

/// One worker's connection to one I/O thread.
///
/// The worker takes frames from `inbound` and returns every
/// one through `outbound`, to be sent or dropped. A frame
/// must go back to the I/O thread it came from: that
/// thread's sockets share the umem it lives in.
///
/// When `inbound` reports [`Consumer::is_finished`], the
/// I/O thread is stopping and nothing more will come; drop
/// the link once everything taken has been returned.
pub struct WorkerLink<F = XdpDescriptor> {
    pub inbound: Consumer<Packet<F>>,
    pub outbound: Producer<Packet<F>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoConfig {
    /// Most frames taken from one socket or one worker per
    /// pass.
    pub batch: usize,
    /// Slots in each ring to and from a worker; a power of
    /// two, at least `batch`.
    pub ring_capacity: usize,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            batch: 64,
            ring_capacity: 1024,
        }
    }
}

/// What an I/O thread did with the frames it saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoStats {
    /// Frames received from the sockets.
    pub received: u64,
    /// Frames handed to a worker.
    pub dispatched: u64,
    /// Frames dropped because a worker's ring was full, or
    /// the worker was gone.
    pub dispatch_dropped: u64,
    /// Frames queued for transmit.
    pub sent: u64,
    /// Frames dropped because a transmit ring was full.
    pub send_dropped: u64,
    /// Frames a worker sent to a port this thread has no
    /// socket on.
    pub unroutable: u64,
}

/// A running I/O thread. Dropping it stops it as
/// [`Self::stop`] does.
pub struct IoThread {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<IoStats>>,
}

impl Drop for IoThread {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::Relaxed);
            if thread.join().is_err() && !thread::panicking() {
                panic!("I/O thread panicked");
            }
        }
    }
}

impl IoThread {
    /// Starts an I/O thread over `sockets`, each tagged
    /// with the port it is bound to, and returns one
    /// [`WorkerLink`] per worker in `buckets`.
    ///
    /// The sockets must share one umem (bind the first,
    /// [`bind_shared`](mangonel_libxdp::bind_shared) the
    /// rest), so a frame received on any of them can be
    /// sent on any other. Each port's first socket is
    /// the one it sends on; give this thread a socket
    /// on every port its workers may send to.
    pub fn spawn(
        name: &str,
        sockets: Vec<(PortId, XdpSocket)>,
        buckets: Arc<Buckets>,
        config: IoConfig,
    ) -> io::Result<(Self, Vec<WorkerLink>)> {
        let links = sockets
            .into_iter()
            .map(|(port, socket)| (port, SocketLink::new(socket, config.batch)))
            .collect();

        spawn(name, links, buckets, config)
    }

    /// Stops receiving, closes every worker's inbound ring,
    /// keeps sending what the workers return until each has
    /// hung up, then drops the sockets.
    ///
    /// Blocks until then, so the workers must keep running
    /// until their inbound rings finish.
    pub fn stop(mut self) -> IoStats {
        let thread = self
            .thread
            .take()
            .expect("The thread is only taken here and in Drop. This is a bug.");
        self.stop.store(true, Ordering::Relaxed);

        thread
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    }
}

/// What the loop needs from a socket. The trait lets tests
/// stand in plain buffers for AF_XDP sockets, which need
/// root.
pub(crate) trait Link: Send {
    type Frame: Send + 'static;

    /// Appends up to `max` received frames to `out`.
    fn receive(&mut self, out: &mut Vec<Self::Frame>, max: usize);

    /// Queues frames from the front of `frames` for
    /// transmit, removing them, and returns how many. The
    /// rest stay.
    fn send(&mut self, frames: &mut Vec<Self::Frame>) -> usize;

    /// The frame from its Ethernet header onwards.
    fn data(frame: &Self::Frame) -> &[u8];

    /// Recycles every frame in `frames`, leaving it empty.
    fn discard(frames: &mut Vec<Self::Frame>);
}

struct SocketLink {
    socket: XdpSocket,
    /// Receive buffer; every slot is empty between calls.
    slots: Vec<XdpDescriptor>,
}

impl SocketLink {
    fn new(socket: XdpSocket, batch: usize) -> Self {
        Self {
            socket,
            slots: (0..batch).map(|_| XdpDescriptor::default()).collect(),
        }
    }
}

impl Link for SocketLink {
    type Frame = XdpDescriptor;

    fn receive(&mut self, out: &mut Vec<XdpDescriptor>, max: usize) {
        let max = max.min(self.slots.len());
        let count = self.socket.receive(&mut self.slots[..max]) as usize;
        out.extend(self.slots[..count].iter_mut().map(std::mem::take));
    }

    fn send(&mut self, frames: &mut Vec<XdpDescriptor>) -> usize {
        // Every frame here is live, so consumed is sent.
        let sent = self.socket.send(frames) as usize;
        frames.drain(..sent);

        sent
    }

    fn data(frame: &XdpDescriptor) -> &[u8] {
        frame.data()
    }

    fn discard(frames: &mut Vec<XdpDescriptor>) {
        XdpDescriptor::drop_all(frames);
        frames.clear();
    }
}

pub(crate) fn spawn<L: Link + 'static>(
    name: &str,
    links: Vec<(PortId, L)>,
    buckets: Arc<Buckets>,
    config: IoConfig,
) -> io::Result<(IoThread, Vec<WorkerLink<L::Frame>>)> {
    let (io_loop, workers) = IoLoop::new(links, buckets, config);
    let stop = io_loop.stop.clone();
    let thread = thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || io_loop.run())?;

    Ok((
        IoThread {
            stop,
            thread: Some(thread),
        },
        workers,
    ))
}

struct IoLoop<L: Link> {
    links: Vec<(PortId, L)>,
    /// By port number: the link that sends out of it.
    egress_link: Vec<Option<usize>>,
    buckets: Arc<Buckets>,
    to_workers: Vec<Producer<Packet<L::Frame>>>,
    from_workers: Vec<Consumer<Packet<L::Frame>>>,
    batch: usize,
    stop: Arc<AtomicBool>,
    stats: IoStats,
    // Scratch, kept to reuse their allocations.
    received: Vec<L::Frame>,
    /// By worker: frames bound for it this pass.
    staged: Vec<Vec<Packet<L::Frame>>>,
    returned: Vec<Packet<L::Frame>>,
    /// By link: frames to send on it this pass.
    egress: Vec<Vec<L::Frame>>,
    rejected: Vec<L::Frame>,
}

impl<L: Link> IoLoop<L> {
    fn new(
        links: Vec<(PortId, L)>,
        buckets: Arc<Buckets>,
        config: IoConfig,
    ) -> (Self, Vec<WorkerLink<L::Frame>>) {
        assert!(
            !links.is_empty(),
            "An I/O thread needs at least one socket."
        );
        assert!(config.batch > 0, "The batch size must be positive.");
        assert!(
            config.ring_capacity.is_power_of_two() && config.ring_capacity >= config.batch,
            "The ring capacity '{}' is not a power of two of at least the batch size '{}'.",
            config.ring_capacity,
            config.batch
        );

        let ports = links
            .iter()
            .map(|(port, _)| usize::from(port.0) + 1)
            .max()
            .unwrap_or(0);
        let mut egress_link = vec![None; ports];
        for (index, (port, _)) in links.iter().enumerate() {
            egress_link[usize::from(port.0)].get_or_insert(index);
        }

        let mut to_workers = Vec::new();
        let mut from_workers = Vec::new();
        let workers = (0..buckets.worker_count())
            .map(|_| {
                let (to_worker, inbound) = spsc::channel(config.ring_capacity);
                let (outbound, from_worker) = spsc::channel(config.ring_capacity);
                to_workers.push(to_worker);
                from_workers.push(from_worker);

                WorkerLink { inbound, outbound }
            })
            .collect();

        let io_loop = Self {
            egress: links.iter().map(|_| Vec::new()).collect(),
            links,
            egress_link,
            staged: to_workers.iter().map(|_| Vec::new()).collect(),
            buckets,
            to_workers,
            from_workers,
            batch: config.batch,
            stop: Arc::new(AtomicBool::new(false)),
            stats: IoStats::default(),
            received: Vec::new(),
            returned: Vec::new(),
            rejected: Vec::new(),
        };

        (io_loop, workers)
    }

    fn run(mut self) -> IoStats {
        while !self.stop.load(Ordering::Relaxed) {
            let received = self.receive();
            let returned = self.transmit();
            if !received && !returned {
                std::hint::spin_loop();
            }
        }

        // Closing the inbound rings tells the workers
        // nothing more is coming; keep sending what
        // they return until each has hung up, so no
        // frame is stranded when the sockets and
        // their umem go.
        self.to_workers.clear();
        loop {
            self.transmit();
            if self.from_workers.iter_mut().all(Consumer::is_finished) {
                break;
            }
            std::hint::spin_loop();
        }

        self.stats
    }

    /// Receives a batch from every socket and dispatches
    /// it. Returns whether anything arrived.
    fn receive(&mut self) -> bool {
        let mut any = false;
        for (port, link) in &mut self.links {
            link.receive(&mut self.received, self.batch);
            if self.received.is_empty() {
                continue;
            }
            any = true;
            self.stats.received += count(self.received.len());

            for frame in self.received.drain(..) {
                let bucket = self.buckets.bucket(flow_hash(L::data(&frame)));
                self.staged[self.buckets.worker(bucket)].push(Packet { frame, port: *port });
            }
        }

        for (ring, packets) in self.to_workers.iter_mut().zip(&mut self.staged) {
            if packets.is_empty() {
                continue;
            }
            // A worker that hung up would never take them.
            let pushed = if ring.is_closed() {
                0
            } else {
                ring.push_from(packets)
            };
            self.stats.dispatched += count(pushed);
            if !packets.is_empty() {
                self.stats.dispatch_dropped += count(packets.len());
                self.rejected
                    .extend(packets.drain(..).map(|packet| packet.frame));
                L::discard(&mut self.rejected);
            }
        }

        any
    }

    /// Sends what the workers returned. Returns whether
    /// they returned anything.
    fn transmit(&mut self) -> bool {
        for ring in &mut self.from_workers {
            ring.pop_into(&mut self.returned, self.batch);
        }
        if self.returned.is_empty() {
            return false;
        }

        for Packet { frame, port } in self.returned.drain(..) {
            match self.egress_link.get(usize::from(port.0)).copied().flatten() {
                Some(link) => self.egress[link].push(frame),
                None => {
                    self.stats.unroutable += 1;
                    self.rejected.push(frame);
                }
            }
        }
        L::discard(&mut self.rejected);

        for ((_, link), frames) in self.links.iter_mut().zip(&mut self.egress) {
            if frames.is_empty() {
                continue;
            }
            self.stats.sent += count(link.send(frames));
            // Tail drop: a full transmit ring is
            // congestion, and holding frames
            // back would only grow it.
            if !frames.is_empty() {
                self.stats.send_dropped += count(frames.len());
                L::discard(frames);
            }
        }

        true
    }
}

fn count(frames: usize) -> u64 {
    u64::try_from(frames).expect("A batch size fits u64. This is a bug.")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::flow::tests::ipv4_frame;

    /// A socket made of buffers: frames come from
    /// `incoming`, and at most `room` per call go to
    /// `sent`.
    struct FakeLink {
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        room: usize,
    }

    impl Link for FakeLink {
        type Frame = Vec<u8>;

        fn receive(&mut self, out: &mut Vec<Vec<u8>>, max: usize) {
            let mut incoming = self.incoming.lock().unwrap();
            let count = max.min(incoming.len());
            out.extend(incoming.drain(..count));
        }

        fn send(&mut self, frames: &mut Vec<Vec<u8>>) -> usize {
            let count = self.room.min(frames.len());
            self.sent.lock().unwrap().extend(frames.drain(..count));
            count
        }

        fn data(frame: &Vec<u8>) -> &[u8] {
            frame
        }

        fn discard(frames: &mut Vec<Vec<u8>>) {
            frames.clear();
        }
    }

    struct Port {
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    fn port(id: u16, room: usize) -> ((PortId, FakeLink), Port) {
        let incoming = Arc::new(Mutex::new(VecDeque::new()));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let link = FakeLink {
            incoming: incoming.clone(),
            sent: sent.clone(),
            room,
        };
        ((PortId(id), link), Port { incoming, sent })
    }

    /// One frame per flow: TCP from 10.0.0.x to 1.1.1.1.
    fn flows(count: u8) -> Vec<Vec<u8>> {
        (0..count)
            .map(|host| ipv4_frame(6, [10, 0, 0, host], [1, 1, 1, 1], (40000, 443), 0))
            .collect()
    }

    fn config(batch: usize, ring_capacity: usize) -> IoConfig {
        IoConfig {
            batch,
            ring_capacity,
        }
    }

    #[test]
    fn frames_go_to_their_bucket_worker() {
        let (link, lan) = port(0, 64);
        let buckets = Arc::new(Buckets::new(16, 3));
        let (mut io, mut workers) = IoLoop::new(vec![link], buckets.clone(), config(64, 64));

        let frames = flows(40);
        lan.incoming.lock().unwrap().extend(frames.iter().cloned());
        assert!(io.receive());
        assert_eq!(io.stats.dispatched, 40);

        for (index, worker) in workers.iter_mut().enumerate() {
            let mut got = Vec::new();
            worker.inbound.pop_into(&mut got, 64);
            for packet in got {
                let bucket = buckets.bucket(flow_hash(&packet.frame));
                assert_eq!(buckets.worker(bucket), index);
                assert_eq!(packet.port, PortId(0));
            }
        }
    }

    #[test]
    fn returned_frames_leave_by_their_port() {
        let (wan_link, wan) = port(0, 64);
        let (lan_link, lan) = port(3, 64);
        let buckets = Arc::new(Buckets::new(4, 1));
        let (mut io, mut workers) = IoLoop::new(vec![wan_link, lan_link], buckets, config(64, 64));

        wan.incoming.lock().unwrap().extend(flows(5));
        io.receive();

        // The worker routes four frames to the LAN and one
        // to a port this thread has no socket on.
        let worker = &mut workers[0];
        let mut packets = Vec::new();
        worker.inbound.pop_into(&mut packets, 64);
        for (index, packet) in packets.iter_mut().enumerate() {
            packet.port = if index == 0 { PortId(9) } else { PortId(3) };
        }
        worker.outbound.push_from(&mut packets);

        assert!(io.transmit());
        assert_eq!(lan.sent.lock().unwrap().len(), 4);
        assert!(wan.sent.lock().unwrap().is_empty());
        assert_eq!((io.stats.sent, io.stats.unroutable), (4, 1));
    }

    #[test]
    fn overflow_is_dropped_and_counted() {
        let (link, lan) = port(0, 2);
        let buckets = Arc::new(Buckets::new(4, 1));
        let (mut io, mut workers) = IoLoop::new(vec![link], buckets, config(8, 8));

        // Ring of 8: the second batch of 8 does not fit.
        lan.incoming.lock().unwrap().extend(flows(16));
        io.receive();
        io.receive();
        assert_eq!(io.stats.received, 16);
        assert_eq!((io.stats.dispatched, io.stats.dispatch_dropped), (8, 8));

        // Transmit room of 2: the other 6 are tail-dropped.
        let worker = &mut workers[0];
        let mut packets = Vec::new();
        worker.inbound.pop_into(&mut packets, 8);
        worker.outbound.push_from(&mut packets);
        io.transmit();
        assert_eq!((io.stats.sent, io.stats.send_dropped), (2, 6));
    }

    #[test]
    fn a_departed_worker_gets_nothing() {
        let (link, lan) = port(0, 64);
        let buckets = Arc::new(Buckets::new(4, 1));
        let (mut io, workers) = IoLoop::new(vec![link], buckets, config(8, 8));
        drop(workers);

        lan.incoming.lock().unwrap().extend(flows(3));
        io.receive();
        assert_eq!((io.stats.dispatched, io.stats.dispatch_dropped), (0, 3));
    }

    /// End to end on a real thread: echo workers bounce
    /// every frame to the LAN, and stopping waits for them
    /// to return everything.
    #[test]
    fn stop_drains_the_workers() {
        let (wan_link, wan) = port(0, 64);
        let (lan_link, lan) = port(1, 64);
        let buckets = Arc::new(Buckets::new(16, 2));
        let (io, workers) = spawn("io-test", vec![wan_link, lan_link], buckets, config(16, 64))
            .expect("spawn the I/O thread");

        let echoes: Vec<_> = workers
            .into_iter()
            .map(|mut link| {
                thread::spawn(move || {
                    let mut packets = Vec::new();
                    while !link.inbound.is_finished() {
                        link.inbound.pop_into(&mut packets, 16);
                        for packet in &mut packets {
                            packet.port = PortId(1);
                        }
                        while !packets.is_empty() {
                            link.outbound.push_from(&mut packets);
                        }
                    }
                })
            })
            .collect();

        wan.incoming.lock().unwrap().extend(flows(200));
        while !wan.incoming.lock().unwrap().is_empty() {
            thread::yield_now();
        }

        let stats = io.stop();
        for echo in echoes {
            echo.join().unwrap();
        }
        assert_eq!(stats.received, 200);
        assert_eq!(stats.dispatched + stats.dispatch_dropped, 200);
        assert_eq!(stats.sent + stats.send_dropped, stats.dispatched);
        assert_eq!(lan.sent.lock().unwrap().len() as u64, stats.sent);
    }
}
