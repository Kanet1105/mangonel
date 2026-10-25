//! The data plane: a pinned worker per queue index, on the
//! NICs' NUMA node.

use std::{
    fs, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

use core_affinity::CoreId;
use mangonel_nic::nic::Nic;

use crate::data::Error;

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
    /// the NICs' NUMA node.
    pub fn new(mut nics: Vec<Nic>) -> Result<Self, Error> {
        let narrowest = nics
            .iter()
            .min_by_key(|nic| queue_limit(nic))
            .ok_or(Error::NoNics)?;
        let queues = queue_limit(narrowest);
        if queues == 0 {
            return Err(Error::NoQueues(narrowest.name().to_owned()));
        }

        let cores = cores(numa_node(&nics)?)?;
        if cores.is_empty() {
            return Err(Error::NoCores);
        }

        let worker_count = queues.min(u32::try_from(cores.len()).unwrap_or(u32::MAX));
        for nic in &mut nics {
            // A matching count skips the call, which needs
            // CAP_NET_ADMIN and drops the link.
            if nic.rx_queues() != worker_count || nic.tx_queues() != worker_count {
                nic.set_queue_count(worker_count).map_err(|error| {
                    Error::QueueCount(nic.name().to_owned(), worker_count, error)
                })?;
            }
        }

        let mut plane = Self {
            stop: Arc::default(),
            workers: Vec::with_capacity(worker_count as usize),
        };
        for (index, &core) in cores.iter().take(worker_count as usize).enumerate() {
            plane.workers.push(spawn_worker(index, core)?);
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

/// Spawns worker `index` pinned to `core`; returns once it
/// is pinned.
fn spawn_worker(index: usize, core: usize) -> Result<JoinHandle<()>, Error> {
    let (pinned_sender, pinned) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name(format!("worker-{index}"))
        .spawn(move || {
            let is_pinned = core_affinity::set_for_current(CoreId { id: core });
            // The spawner waits on this, so it is listening.
            let _ = pinned_sender.send(is_pinned);
        })
        .map_err(|error| Error::Spawn(index, error))?;

    if !pinned.recv().unwrap_or(false) {
        return Err(Error::Pin(index, core));
    }

    Ok(worker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(cpu_list("3,19\n"), Some(vec![3, 19]));
        assert_eq!(cpu_list("0-2,8-9"), Some(vec![0, 1, 2, 8, 9]));
        assert_eq!(cpu_list("\n"), Some(vec![]));
        assert_eq!(cpu_list("0-x"), None);
    }

    #[test]
    fn rejects_no_nics() {
        assert!(matches!(DataPlane::new(vec![]), Err(Error::NoNics)));
    }

    #[test]
    fn loopback_gets_one_worker() {
        // lo has one queue and no channel info or NUMA node.
        let plane = DataPlane::new(vec![Nic::open("lo").unwrap()]).unwrap();
        assert_eq!(plane.worker_count(), 1);
    }

    #[test]
    fn picks_one_cpu_per_physical_core() {
        let cores = cores(None).unwrap();
        for &cpu in &cores {
            let siblings = read_cpu_list(format!(
                "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
            ))
            .unwrap();
            let picked = siblings.iter().filter(|sibling| cores.contains(sibling));
            assert_eq!(picked.count(), 1);
            assert!(!siblings.contains(&0));
        }
    }
}
