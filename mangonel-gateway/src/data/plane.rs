//! The data plane: a pinned worker per queue index, on the
//! NICs' NUMA node, bound to that queue on every NIC.

use std::{
    fs,
    io,
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

use core_affinity::CoreId;
use mangonel_libxdp::XdpConfig;
use mangonel_nic::nic::Nic;
use mangonel_ring::Ring;

use crate::{
    control::{
        MacAddr,
        Reader,
    },
    data::{
        Error,
        worker::{
            HANDOFF_DEPTH,
            Handoff,
            Handoffs,
            Worker,
        },
    },
};

/// The workers and the flag that stops them. Dropping it
/// stops and joins every worker.
pub struct DataPlane {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        self.stop();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() && !thread::panicking() {
                panic!("A worker thread panicked.");
            }
        }
    }
}

impl DataPlane {
    /// Sets every NIC to as many queues as the most
    /// constrained one can bind, then spawns a worker per
    /// queue index, each pinned to its own physical core on
    /// the NICs' NUMA node and reading its configuration
    /// through `reader`.
    pub fn new(mut nics: Vec<Nic>, reader: Reader) -> Result<Self, Error> {
        let cores = plan(&mut nics)?;
        let workers = cores.len();
        let ports: Vec<(String, MacAddr)> = nics
            .iter()
            .map(|nic| (nic.name().to_owned(), MacAddr(nic.mac())))
            .collect();
        let sockets = u32::try_from(ports.len() * workers).unwrap_or(u32::MAX);
        let defaults = XdpConfig::default();
        let config = XdpConfig {
            frame_count: defaults
                .frames_for(sockets)
                .expect("A socket per NIC and core overflows the frame count. This is a bug."),
            ..defaults
        };
        // From each worker to each other, by index.
        let rings: Vec<Vec<Ring<Handoff>>> = (0..workers)
            .map(|_| {
                (0..workers)
                    .map(|_| {
                        Ring::new(HANDOFF_DEPTH)
                            .expect("HANDOFF_DEPTH is a power of two. This is a bug.")
                    })
                    .collect()
            })
            .collect();

        let mut plane = Self {
            stop: Arc::default(),
            workers: Vec::with_capacity(workers),
        };
        for (index, core) in cores.into_iter().enumerate() {
            let handoffs = Handoffs {
                inbox: (0..workers)
                    .filter(|&from| from != index)
                    .map(|from| rings[from][index].clone())
                    .collect(),
                outbox: rings[index].clone(),
            };
            let (ports, reader, stop) = (ports.clone(), reader.clone(), plane.stop.clone());
            plane.workers.push(spawn_worker(index, core, move || {
                Worker::bind(index, &ports, config, reader, handoffs, stop)
            })?);
        }

        Ok(plane)
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Tells every worker to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Sets every NIC to as many queues as the most constrained
/// one can bind, and picks a core near them for each queue.
fn plan(nics: &mut [Nic]) -> Result<Vec<usize>, Error> {
    let narrowest = nics
        .iter()
        .min_by_key(|nic| queue_limit(nic))
        .ok_or(Error::NoNics)?;
    let queues = queue_limit(narrowest);
    if queues == 0 {
        return Err(Error::NoQueues(narrowest.name().to_owned()));
    }

    let cores = cores(numa_node(nics)?)?;
    if cores.is_empty() {
        return Err(Error::NoCores);
    }

    let worker_count = queues.min(u32::try_from(cores.len()).unwrap_or(u32::MAX));
    for nic in nics.iter_mut() {
        // A matching count skips the call, which needs
        // CAP_NET_ADMIN and drops the link.
        if nic.rx_queues() != worker_count || nic.tx_queues() != worker_count {
            nic.set_queue_count(worker_count)
                .map_err(|error| Error::QueueCount(nic.name().to_owned(), worker_count, error))?;
        }
    }

    Ok(cores.into_iter().take(worker_count as usize).collect())
}

/// The most queues `nic` can bind both rings on: its
/// channel maximum, or its current count when the driver
/// does not say.
fn queue_limit(nic: &Nic) -> u32 {
    match nic.channels() {
        Some(channels) if channels.max_combined > 0 => channels.max_combined,
        Some(channels) => channels.max_rx.min(channels.max_tx),
        None => nic.xdp_queues(),
    }
}

/// The node every NIC that reports one shares; `None` when
/// none does.
fn numa_node(nics: &[Nic]) -> Result<Option<i32>, Error> {
    let mut nodes = nics
        .iter()
        .filter_map(Nic::numa_node)
        .filter(|node| *node >= 0);
    let Some(first) = nodes.next() else {
        return Ok(None);
    };

    match nodes.find(|node| *node != first) {
        Some(other) => Err(Error::NumaMismatch(first, other)),
        None => Ok(Some(first)),
    }
}

/// One CPU per physical core, on `node` when given, that
/// this process may run on. CPU 0's core is left to the
/// OS.
fn cores(node: Option<i32>) -> Result<Vec<usize>, Error> {
    let allowed: Vec<usize> = core_affinity::get_core_ids()
        .unwrap_or_default()
        .into_iter()
        .map(|core| core.id)
        .collect();
    let candidates = match node {
        Some(node) => read_cpu_list(format!("/sys/devices/system/node/node{node}/cpulist"))?,
        None => allowed.clone(),
    };

    let mut cores = Vec::new();
    // CPU 0 stays in `allowed`, so the check below skips
    // its twin as well.
    let candidates = candidates
        .into_iter()
        .filter(|cpu| *cpu != 0 && allowed.contains(cpu));
    for cpu in candidates {
        let siblings = read_cpu_list(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))?;
        // The lowest allowed sibling stands for its core.
        if siblings
            .into_iter()
            .find(|sibling| allowed.contains(sibling))
            == Some(cpu)
        {
            cores.push(cpu);
        }
    }

    Ok(cores)
}

fn read_cpu_list(path: String) -> Result<Vec<usize>, Error> {
    let list = fs::read_to_string(&path).map_err(|error| Error::Sysfs(path.clone(), error))?;

    cpu_list(&list).ok_or_else(|| Error::Sysfs(path, io::ErrorKind::InvalidData.into()))
}

/// Parses a kernel CPU list such as `0-3,8,16-19`.
fn cpu_list(list: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for range in list.trim().split(',').filter(|range| !range.is_empty()) {
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        cpus.extend(start.parse::<usize>().ok()?..=end.parse().ok()?);
    }

    Some(cpus)
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
            let worker = if core_affinity::set_for_current(CoreId { id: core }) {
                bind()
            } else {
                Err(Error::Pin(index, core))
            };
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
