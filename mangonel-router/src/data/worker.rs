//! A worker: one queue index on every port, driven by one
//! pinned thread that receives, decides and sends by
//! itself.

use std::{
    mem,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
    },
    time::Instant,
};

use mangonel_libxdp::{
    XdpConfig,
    XdpDescriptor,
    XdpSocket,
    bind,
};

use crate::{
    control::{
        MacAddr,
        Reader,
    },
    data::{
        Error,
        frame::Output,
        pipeline::{
            Pipeline,
            Shared,
        },
    },
};

/// Frames taken from one port per pass, which bounds how
/// long a busy port keeps the others waiting.
const BURST: usize = 64;

/// What one worker has done with frames so far.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) received: AtomicU64,
    pub(crate) sent: AtomicU64,
    pub(crate) dropped: AtomicU64,
}

impl Counters {
    /// Counts `count` more frames, when there are any: an
    /// idle pass writes nothing.
    fn add(counter: &AtomicU64, count: usize) {
        if count > 0 {
            // Only this worker writes, and readers want a
            // figure, not an ordering.
            counter.fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
    }
}

/// Drives one queue index on every port.
pub(crate) struct Worker {
    /// In the data plane's port order.
    sockets: Vec<XdpSocket>,
    pipeline: Pipeline<XdpDescriptor>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

impl Worker {
    /// Binds queue `index` on each of `ports`, given by
    /// name and MAC.
    pub(crate) fn bind(
        index: usize,
        ports: &[(String, MacAddr)],
        config: XdpConfig,
        reader: Reader,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        counters: Arc<Counters>,
    ) -> Result<Self, Error> {
        let queue = u32::try_from(index).expect("A queue index fits a u32. This is a bug.");
        let sockets = ports
            .iter()
            .map(|(name, _)| {
                bind(name, queue, config).map_err(|error| Error::Bind(name.clone(), queue, error))
            })
            .collect::<Result<_, Error>>()?;
        let macs: Vec<MacAddr> = ports.iter().map(|(_, mac)| *mac).collect();

        Ok(Self {
            sockets,
            pipeline: Pipeline::new(index, &macs, reader, shared, Instant::now()),
            stop,
            counters,
        })
    }

    /// Forwards until stopped or the control panel is gone.
    pub(crate) fn run(mut self) {
        let mut received: Vec<XdpDescriptor> =
            (0..BURST).map(|_| XdpDescriptor::default()).collect();
        let mut output = Output::new(self.sockets.len());
        // Nothing is ordered against the flag: a pass more
        // or less before stopping makes no difference.
        while !self.stop.load(Ordering::Relaxed) && self.pipeline.begin() {
            let now = Instant::now();
            for ingress in 0..self.sockets.len() {
                // Every socket is received on every pass,
                // traffic or not: this is also what returns
                // its sent frames to the pool.
                let count = self.sockets[ingress].receive(&mut received) as usize;
                Counters::add(&self.counters.received, count);
                for slot in &mut received[..count] {
                    let frame = mem::take(slot);
                    let mut allocate = || allocate(&mut self.sockets[0]);
                    self.pipeline
                        .handle(ingress, frame, now, &mut allocate, &mut output);
                }
            }
            let mut allocate = || allocate(&mut self.sockets[0]);
            self.pipeline.finish(now, &mut allocate, &mut output);

            for (socket, frames) in self.sockets.iter_mut().zip(&mut output.send) {
                if frames.is_empty() {
                    continue;
                }
                let sent = socket.send(frames) as usize;
                Counters::add(&self.counters.sent, sent);
                // What a full ring cannot take is dropped
                // rather than held, so a stalled port stalls
                // no other.
                frames.drain(..sent);
                output.drop.append(frames);
            }
            if !output.drop.is_empty() {
                Counters::add(&self.counters.dropped, output.drop.len());
                self.sockets[0].drop(&mut output.drop);
                output.drop.clear();
            }
        }
    }
}

/// A frame out of the pool for the pipeline to build in.
/// Any socket reaches the one pool.
fn allocate(socket: &mut XdpSocket) -> Option<XdpDescriptor> {
    let mut frame = [XdpDescriptor::default()];

    (socket.allocate(&mut frame) == 1).then(|| mem::take(&mut frame[0]))
}
