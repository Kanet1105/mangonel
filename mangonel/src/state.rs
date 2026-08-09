use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
};

use mangonel_libxdp::{Binding, Umem, XdpError, bind, bind_with_umem};
use mangonel_nic::nic::{self, Nic};

use crate::{
    config::Config,
    net::{Fib, Router},
    worker,
};

/// The daemon's data plane: at most one running
/// [`DataPlane`].
pub struct State {
    data_plane: Mutex<Option<DataPlane>>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            data_plane: Mutex::new(None),
        }
    }

    /// Brings the router up from `config`: sets each
    /// interface to `workers` queues (`ethtool -L`),
    /// binds WAN and LAN into one shared umem, and
    /// spawns a pinned worker per queue forwarding both
    /// directions. Replaces any running data plane, so it
    /// doubles as reload.
    ///
    /// With `[routing]` in the config the workers route at
    /// L3 (parse, TTL, MAC rewrite, drop unresolved);
    /// without it they forward unchanged (L2).
    pub fn run(&self, config: &Config) -> Result<(), StateError> {
        let wan = &config.data_plane.wan;
        let lan = &config.data_plane.lan;
        let workers = config.data_plane.workers;

        let mut data_plane = self.lock();
        // Tear the old data plane down first: dropping it stops
        // and joins its workers and unloads their XDP programs,
        // so the queue-count change and rebind start clean.
        *data_plane = None;

        // Queue count is a link-cycling ioctl, and a socket
        // refuses to bind while it shrinks a queue, so set it
        // before binding. A driver that cannot set channels
        // (veth, loopback, many virtuals) keeps its own queue
        // count — the `workers` request is best-effort there.
        for interface in [wan, lan] {
            match Nic::open(interface)?.set_queue_count(workers) {
                Ok(()) => {}
                Err(error) if error.is_unsupported() => {
                    tracing::warn!(interface, "driver cannot set queues; using its own count");
                }
                Err(error) => return Err(error.into()),
            }
        }

        // The routing state, built before binding so a bad
        // [routing] config fails without leaving XDP loaded.
        // Shared read-only across workers.
        let router = match &config.routing {
            Some(routing) => {
                let fib = Fib::parse(&routing.lan_prefix, &routing.wan_gateway)?;
                let wan_mac = Nic::open(wan)?.mac();
                let lan_mac = Nic::open(lan)?.mac();

                Some(Arc::new(Router::new(fib, wan_mac, lan_mac)))
            }
            None => None,
        };

        // Two interfaces share the umem, so a frame received on
        // one and transmitted on the other never leaves it.
        let Binding {
            sockets: wan_sockets,
            pools,
            umem,
            zero_copy,
        } = bind(wan, 2)?;
        let lan_sockets = bind_with_umem(lan, &umem)?;
        if wan_sockets.len() != lan_sockets.len() {
            return Err(StateError::QueueMismatch {
                wan: wan_sockets.len(),
                lan: lan_sockets.len(),
            });
        }

        let cores = worker::allowed_cores().ok_or(StateError::NoCores)?;
        let running = Arc::new(AtomicBool::new(true));
        let mut wan_counters = Vec::with_capacity(wan_sockets.len());
        let mut lan_counters = Vec::with_capacity(lan_sockets.len());
        let mut handles = Vec::with_capacity(wan_sockets.len());
        for (index, ((wan_socket, lan_socket), pool)) in wan_sockets
            .into_iter()
            .zip(lan_sockets)
            .zip(pools)
            .enumerate()
        {
            let wan_counter = Arc::new(AtomicU64::new(0));
            let lan_counter = Arc::new(AtomicU64::new(0));
            let core = worker::assign_core(&cores, index);
            let handle = thread::spawn({
                let running = running.clone();
                let wan_counter = wan_counter.clone();
                let lan_counter = lan_counter.clone();
                let router = router.clone();
                let umem = umem.clone();
                move || {
                    // Pinned inside the thread: affinity is per-thread
                    // and cannot be set from outside.
                    assert!(
                        core_affinity::set_for_current(core),
                        "Failed to pin a worker to core {}. This is a bug.",
                        core.id
                    );
                    worker::forward(
                        wan_socket,
                        lan_socket,
                        pool,
                        umem,
                        router,
                        &running,
                        &wan_counter,
                        &lan_counter,
                    );
                }
            });
            wan_counters.push(wan_counter);
            lan_counters.push(lan_counter);
            handles.push(handle);
        }

        *data_plane = Some(DataPlane {
            running,
            handles,
            wan: wan.clone(),
            lan: lan.clone(),
            wan_counters,
            lan_counters,
            zero_copy,
            _umem: umem,
        });

        Ok(())
    }

    /// Stops the data plane, if any; for shutdown.
    pub fn stop(&self) {
        *self.lock() = None;
    }

    /// Per-interface counter snapshot: WAN then LAN, each
    /// with one entry per queue. Empty when no data plane
    /// is running.
    pub fn status(&self) -> Vec<InterfaceStatus> {
        match &*self.lock() {
            None => Vec::new(),
            Some(data_plane) => vec![
                InterfaceStatus {
                    interface: data_plane.wan.clone(),
                    zero_copy: data_plane.zero_copy,
                    queues: snapshot(&data_plane.wan_counters),
                },
                InterfaceStatus {
                    interface: data_plane.lan.clone(),
                    zero_copy: data_plane.zero_copy,
                    queues: snapshot(&data_plane.lan_counters),
                },
            ],
        }
    }

    /// Every interface the host has, with the properties
    /// that decide whether — and how well — it can be a
    /// data-plane interface, and whether the running
    /// data plane uses it.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>, StateError> {
        let running = self.lock();
        let uses = |name: &str| {
            running
                .as_ref()
                .is_some_and(|data_plane| data_plane.wan == name || data_plane.lan == name)
        };
        let mut interfaces = Vec::new();
        for name in Nic::list()? {
            let nic = Nic::open(&name)?;
            interfaces.push(InterfaceInfo {
                attached: uses(&name),
                index: nic.index(),
                mac: nic.mac(),
                mtu: nic.mtu(),
                up: nic.is_up(),
                running: nic.is_running(),
                xdp_queues: nic.xdp_queues(),
                numa_node: nic.numa_node(),
                driver: nic.driver().map(|driver| driver.name.clone()),
                name,
            });
        }
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(interfaces)
    }

    fn lock(&self) -> MutexGuard<'_, Option<DataPlane>> {
        // Recover a poisoned lock rather than propagating the
        // panic: run replaces the data plane wholesale, so the
        // Option is always in a consistent state, and one bad
        // operation must not brick the control plane.
        self.data_plane
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn snapshot(counters: &[Arc<AtomicU64>]) -> Vec<u64> {
    counters
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .collect()
}

/// The running data plane: the shared umem, the per-queue
/// forwarding workers, and what they share.
///
/// Cleanup lives in [`Drop`], so it runs however the data
/// plane dies — a reload, shutdown, or a panic unwinding
/// through [`State`] — not only on an explicit path. A
/// dropped-but-unstopped data plane would detach its still-
/// spinning workers and leave both interfaces' XDP programs
/// loaded.
struct DataPlane {
    running: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    wan: String,
    lan: String,
    /// WAN→LAN packets forwarded, one counter per queue.
    wan_counters: Vec<Arc<AtomicU64>>,
    /// LAN→WAN packets forwarded, one counter per queue.
    lan_counters: Vec<Arc<AtomicU64>>,
    zero_copy: bool,
    /// Held so it outlives every worker's sockets; its
    /// drop, last, unloads both interfaces' XDP
    /// programs.
    _umem: Umem,
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        // Signal, then join: each worker exits within one loop
        // iteration and drops its sockets. Once all are joined
        // the only umem reference left is `_umem`, whose drop
        // reverts both interfaces.
        self.running.store(false, Ordering::Relaxed);
        for handle in self.handles.drain(..) {
            // A panicked worker already reported itself; reap it
            // rather than double-panic out of drop.
            let _ = handle.join();
        }
    }
}

/// Per-interface counter snapshot.
pub struct InterfaceStatus {
    pub interface: String,
    /// Whether the kernel bound this interface zero-copy.
    pub zero_copy: bool,
    /// Packets forwarded, cumulative, one entry per queue.
    pub queues: Vec<u64>,
}

/// A host interface and what it can do, for the picker.
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub mtu: u32,
    pub up: bool,
    pub running: bool,
    /// Queue ids a socket with both rings can bind to.
    pub xdp_queues: u32,
    pub numa_node: Option<i32>,
    /// Driver module, e.g. `ice`, `veth`; `None` when the
    /// driver reports none.
    pub driver: Option<String>,
    /// Whether the running router uses it.
    pub attached: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("No cores are available for pinning.")]
    NoCores,
    #[error("WAN bound {wan} queues but LAN bound {lan}; they must match.")]
    QueueMismatch { wan: usize, lan: usize },
    #[error("Failed to query interfaces: {0}")]
    Nic(#[from] nic::Error),
    #[error(transparent)]
    Xdp(#[from] XdpError),
    #[error(transparent)]
    Fib(#[from] crate::net::FibError),
}
