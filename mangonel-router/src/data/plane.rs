//! The data plane: a pinned worker per queue index, bound
//! to that queue on every port.
//!
//! Every port is set to the same number of queues: as many
//! as the port with the fewest can have, and no more than
//! there are cores to run them. Worker `i` then owns queue
//! `i` of every port and shares no queue with another
//! worker, so each frame is received, decided and sent by
//! one thread.

use std::{
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc,
    },
    thread::{
        self,
        JoinHandle,
    },
};

use mangonel_libxdp::XdpConfig;
use mangonel_nic::nic::Nic;

use crate::{
    control::{
        MacAddr,
        Reader,
    },
    data::{
        Error,
        cores,
        pipeline::Shared,
        worker::{
            Counters,
            Worker,
        },
    },
};

/// The workers and the flag that stops them. Dropping it
/// stops and joins every worker.
pub(crate) struct DataPlane {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    /// The core each worker is pinned to, by worker index.
    cores: Vec<usize>,
    counters: Vec<Arc<Counters>>,
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            // A worker that panicked has said why already.
            let _ = worker.join();
        }
    }
}

impl DataPlane {
    /// Sets every one of `nics` to as many queues as the
    /// most constrained one, the cores and `limit` allow,
    /// then spawns a worker per queue index, each pinned to
    /// its own core and reading its configuration through
    /// `reader`.
    pub(crate) fn new(
        mut nics: Vec<Nic>,
        reader: &Reader,
        limit: Option<u32>,
    ) -> Result<Self, Error> {
        let cores = plan(&mut nics, limit)?;
        let ports: Vec<(String, MacAddr)> = nics
            .iter()
            .map(|nic| (nic.name().to_owned(), MacAddr(nic.mac())))
            .collect();
        let defaults = XdpConfig::default();
        let config = XdpConfig {
            frame_count: u32::try_from(ports.len() * cores.len())
                .ok()
                .and_then(|sockets| defaults.frames_for(sockets))
                .ok_or(Error::TooManyFrames)?,
            ..defaults
        };
        let shared = Arc::new(Shared::new(ports.len()));

        let mut plane = Self {
            stop: Arc::default(),
            workers: Vec::with_capacity(cores.len()),
            cores: cores.clone(),
            counters: Vec::with_capacity(cores.len()),
        };
        for (index, core) in cores.into_iter().enumerate() {
            let counters = Arc::<Counters>::default();
            plane.counters.push(counters.clone());
            let (ports, reader) = (ports.clone(), reader.clone());
            let (shared, stop) = (shared.clone(), plane.stop.clone());
            // On an error the plane is dropped, which stops
            // the workers already running.
            plane.workers.push(spawn_worker(index, core, move || {
                Worker::bind(index, &ports, config, reader, shared, stop, counters)
            })?);
        }

        Ok(plane)
    }

    /// The core each worker is pinned to, by worker index.
    pub(crate) fn cores(&self) -> &[usize] {
        &self.cores
    }

    /// What each worker has counted so far, by worker index.
    pub(crate) fn counters(&self) -> &[Arc<Counters>] {
        &self.counters
    }

    /// Whether every worker is still forwarding.
    pub(crate) fn is_running(&self) -> bool {
        self.workers.iter().all(|worker| !worker.is_finished())
    }
}

/// Sets every NIC to as many queues as the most constrained
/// one, the cores and `limit` allow, and picks a core for
/// each queue.
fn plan(nics: &mut [Nic], limit: Option<u32>) -> Result<Vec<usize>, Error> {
    let narrowest = nics
        .iter()
        .min_by_key(|nic| queue_limit(nic))
        .ok_or(Error::NoPorts)?;
    let queues = queue_limit(narrowest);
    if queues == 0 {
        return Err(Error::NoQueues(narrowest.name().to_owned()));
    }
    let cores = cores::available(numa_node(nics))?;
    if cores.is_empty() {
        return Err(Error::NoCores);
    }

    let workers = worker_count(queues, cores.len(), limit);
    for nic in nics.iter_mut() {
        level(nic, workers)?;
    }

    Ok(cores.into_iter().take(workers as usize).collect())
}

/// How many workers run: one per queue the narrowest port
/// can have, as far as the cores and `limit` go.
fn worker_count(queues: u32, cores: usize, limit: Option<u32>) -> u32 {
    queues
        .min(u32::try_from(cores).unwrap_or(u32::MAX))
        .min(limit.unwrap_or(u32::MAX))
}

/// Sets `nic` to `queues` receive and transmit queues.
fn level(nic: &mut Nic, queues: u32) -> Result<(), Error> {
    // A matching count skips the call, which needs
    // CAP_NET_ADMIN and drops the link.
    if nic.rx_queues() == queues && nic.tx_queues() == queues {
        return Ok(());
    }

    match nic.set_queue_count(queues) {
        Ok(()) => {}
        // A driver with no say over its queues still works
        // if none would be left unbound: frames arriving on
        // a queue no worker owns bypass the gateway. Spare
        // transmit queues only sit idle.
        Err(error) if error.is_unsupported() && nic.rx_queues() == queues => {}
        Err(error) => return Err(Error::QueueCount(nic.name().to_owned(), queues, error)),
    }
    // A driver may round what it was asked for.
    if nic.rx_queues() != queues || nic.tx_queues() < queues {
        return Err(Error::QueueMismatch {
            name: nic.name().to_owned(),
            rx: nic.rx_queues(),
            tx: nic.tx_queues(),
            wanted: queues,
        });
    }

    Ok(())
}

/// The most queues `nic` can bind both rings on: its
/// channel maximum in the layout it runs now, which is the
/// one `Nic::set_queue_count` asks in, or its current count
/// when the driver does not say.
fn queue_limit(nic: &Nic) -> u32 {
    match nic.channels() {
        Some(channels) if channels.combined > 0 => channels.max_combined,
        Some(channels) if channels.max_rx.min(channels.max_tx) > 0 => {
            channels.max_rx.min(channels.max_tx)
        }
        _ => nic.xdp_queues(),
    }
}

/// The node every NIC that reports one shares. `None` when
/// none reports one or they disagree, and then any core
/// will do.
fn numa_node(nics: &[Nic]) -> Option<i32> {
    let mut nodes = nics
        .iter()
        .filter_map(Nic::numa_node)
        .filter(|node| *node >= 0);
    let first = nodes.next()?;

    nodes.all(|node| node == first).then_some(first)
}

/// Spawns worker `index` pinned to `core`, where `bind`
/// makes it; returns once it is bound.
fn spawn_worker(
    index: usize,
    core: usize,
    bind: impl FnOnce() -> Result<Worker, Error> + Send + 'static,
) -> Result<JoinHandle<()>, Error> {
    let (ready_sender, ready) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name(format!("worker-{index}"))
        .spawn(move || {
            // Pinned first, so the rings a bind allocates
            // are touched on the core that drives them.
            let worker = cores::pin(core)
                .map_err(|error| Error::Pin(index, core, error))
                .and_then(|()| bind());
            // The spawner waits on this, so it is listening.
            match worker {
                Ok(worker) => {
                    let _ = ready_sender.send(Ok(()));
                    worker.run();
                }
                Err(error) => {
                    let _ = ready_sender.send(Err(error));
                }
            }
        })
        .map_err(|error| Error::Spawn(index, error))?;

    ready.recv().unwrap_or(Err(Error::Startup(index)))?;

    Ok(worker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_are_bounded_by_queues_cores_and_the_limit() {
        assert_eq!(worker_count(4, 8, None), 4);
        assert_eq!(worker_count(8, 3, None), 3);
        assert_eq!(worker_count(8, 8, Some(2)), 2);
        assert_eq!(worker_count(1, 8, Some(4)), 1);
        assert_eq!(worker_count(8, usize::MAX, None), 8);
    }

    #[test]
    fn the_loopback_reports_a_queue_to_plan_with() {
        let nic = Nic::open("lo").unwrap();
        assert!(queue_limit(&nic) >= 1);
        assert_eq!(numa_node(&[nic]), None);
    }
}
