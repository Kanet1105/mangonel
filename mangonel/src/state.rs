use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
};

use mangonel_libxdp::{Binding, Umem, XdpError, bind, clear_interface};
use mangonel_nic::nic::{self, Nic};

use crate::{config::Config, worker};

/// The daemon's interface attachments.
pub struct State {
    attachments: Mutex<HashMap<String, Attachment>>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            attachments: Mutex::new(HashMap::new()),
        }
    }

    /// Binds the interface and spawns one pinned worker per
    /// queue. The interface stops passing traffic to the
    /// kernel from here until detach.
    pub fn attach(&self, interface: &str) -> Result<(), StateError> {
        // The lock spans bind so a concurrent attach of the same
        // interface is a clean error, not a race; attach is
        // cold path.
        let mut attachments = self.lock();
        if attachments.contains_key(interface) {
            return Err(StateError::AlreadyAttached(interface.to_owned()));
        }

        let cores = worker::allowed_cores().ok_or(StateError::NoCores)?;
        let Binding {
            pairs,
            umem,
            zero_copy,
        } = bind(interface)?;

        let running = Arc::new(AtomicBool::new(true));
        let mut counters = Vec::with_capacity(pairs.len());
        let mut workers = Vec::with_capacity(pairs.len());
        for (index, (sender, receiver)) in pairs.into_iter().enumerate() {
            let counter = Arc::new(AtomicU64::new(0));
            let core = worker::assign_core(&cores, index);
            let handle = thread::spawn({
                let running = running.clone();
                let counter = counter.clone();
                move || {
                    // Pinned inside the thread: affinity is per-thread
                    // and cannot be set from outside.
                    assert!(
                        core_affinity::set_for_current(core),
                        "Failed to pin a worker to core {}. This is a bug.",
                        core.id
                    );
                    worker::run(sender, receiver, running, counter);
                }
            });
            counters.push(counter);
            workers.push(handle);
        }

        attachments.insert(
            interface.to_owned(),
            Attachment {
                running,
                counters,
                zero_copy,
                workers,
                _umem: umem,
            },
        );

        Ok(())
    }

    /// Stops the interface's workers, joins them, and
    /// releases the interface back to the kernel.
    pub fn detach(&self, interface: &str) -> Result<(), StateError> {
        let attachment = self
            .lock()
            .remove(interface)
            .ok_or_else(|| StateError::NotAttached(interface.to_owned()))?;
        // Dropped here, after the lock temporary is released:
        // Attachment::drop stops and joins the workers off the
        // lock, so status calls need not wait on the join.
        drop(attachment);

        Ok(())
    }

    /// Brings the router up from `config`: sets each data-
    /// plane interface to `workers` queues (`ethtool -L`),
    /// then attaches WAN and LAN. Re-appliable — it
    /// detaches them first, so `run` doubles as reload.
    ///
    /// The workers currently receive-count-drop, so this
    /// blackholes both interfaces; forwarding, and the
    /// shared umem it needs, come later.
    pub fn run(&self, config: &Config) -> Result<(), StateError> {
        let interfaces = [&config.data_plane.wan, &config.data_plane.lan];

        // Clean slate so run is a reload: ignore "not attached".
        for interface in interfaces {
            let _ = self.detach(interface);
        }

        // Queue count is a link-cycling ioctl and the socket
        // refuses to bind while it shrinks a queue, so set it
        // before attaching.
        for interface in interfaces {
            Nic::open(interface)?.set_queue_count(config.data_plane.workers)?;
        }

        for interface in interfaces {
            self.attach(interface)?;
        }

        Ok(())
    }

    /// Removes a leftover XDP program from an interface
    /// this daemon does not have attached — recovery
    /// after a crash left one dangling. Refuses an
    /// attached interface: detach it first, or this
    /// would tear the program out from under its
    /// running workers.
    pub fn clean(&self, interface: &str) -> Result<(), StateError> {
        if self.lock().contains_key(interface) {
            return Err(StateError::AttachedCannotClean(interface.to_owned()));
        }
        clear_interface(interface)?;

        Ok(())
    }

    /// Every interface the host has, with the properties
    /// that decide whether — and how well — it can be
    /// attached, and whether this daemon has it attached.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>, StateError> {
        let attached = self.lock();
        let mut interfaces = Vec::new();
        for name in Nic::list()? {
            let nic = Nic::open(&name)?;
            interfaces.push(InterfaceInfo {
                attached: attached.contains_key(&name),
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

    /// Detaches every interface; for shutdown.
    pub fn detach_all(&self) {
        // Emptied under the lock; the drained attachments drop
        // here, off the lock, each stopping and joining its
        // workers.
        let _attachments = std::mem::take(&mut *self.lock());
    }

    /// Cumulative per-queue packet counts, sorted by
    /// interface name.
    pub fn status(&self) -> Vec<InterfaceStatus> {
        let mut interfaces: Vec<InterfaceStatus> = self
            .lock()
            .iter()
            .map(|(interface, attachment)| InterfaceStatus {
                interface: interface.clone(),
                zero_copy: attachment.zero_copy,
                queues: attachment
                    .counters
                    .iter()
                    .map(|counter| counter.load(Ordering::Relaxed))
                    .collect(),
            })
            .collect();
        interfaces.sort_by(|a, b| a.interface.cmp(&b.interface));

        interfaces
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Attachment>> {
        // Recover a poisoned lock rather than propagating the
        // panic: a failed attach unwinds before it inserts, so
        // the map stays consistent, and one bad operation must
        // not brick the daemon's control plane.
        self.attachments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// One attached interface: its workers and what they share.
///
/// Cleanup lives in [`Drop`], so it runs however the
/// attachment dies — a detach, daemon shutdown, or a panic
/// unwinding through the owning [`State`] — not only on an
/// explicit path. A dropped-but-not-stopped attachment
/// would detach its still-spinning worker threads and leave
/// the XDP program loaded on the interface.
struct Attachment {
    running: Arc<AtomicBool>,
    /// Packets received, one counter per queue.
    counters: Vec<Arc<AtomicU64>>,
    /// Whether the kernel bound this interface zero-copy.
    zero_copy: bool,
    workers: Vec<JoinHandle<()>>,
    /// Held so it outlives every worker's socket halves;
    /// its drop, last, unloads the XDP program.
    _umem: Umem,
}

impl Drop for Attachment {
    fn drop(&mut self) {
        // Signal, then join: each worker exits within one loop
        // iteration and drops its socket halves. Once all are
        // joined the only umem reference left is `_umem`,
        // whose drop deletes it and reverts the interface.
        self.running.store(false, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            // A panicked worker already reported itself; reap it
            // rather than double-panic out of drop.
            let _ = worker.join();
        }
    }
}

/// Per-interface counter snapshot.
pub struct InterfaceStatus {
    pub interface: String,
    /// Whether the kernel bound this interface zero-copy.
    pub zero_copy: bool,
    /// Packets received, cumulative, one entry per queue.
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
    /// Whether this daemon currently has it attached.
    pub attached: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("The interface '{0}' is already attached.")]
    AlreadyAttached(String),
    #[error("The interface '{0}' is not attached.")]
    NotAttached(String),
    #[error("The interface '{0}' is attached; detach it before cleaning.")]
    AttachedCannotClean(String),
    #[error("No cores are available for pinning.")]
    NoCores,
    #[error("Failed to query interfaces: {0}")]
    Nic(#[from] nic::Error),
    #[error(transparent)]
    Xdp(#[from] XdpError),
}
