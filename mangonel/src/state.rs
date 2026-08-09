use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
};

use mangonel_libxdp::{Umem, XdpError, bind};

use crate::worker;

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
        let (pairs, umem) = bind(interface)?;

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
        // Joined outside the lock: workers exit within one loop
        // iteration, but status calls need not wait on it.
        attachment.stop();

        Ok(())
    }

    /// Detaches every interface; for shutdown.
    pub fn detach_all(&self) {
        let attachments = std::mem::take(&mut *self.lock());
        for attachment in attachments.into_values() {
            attachment.stop();
        }
    }

    /// Cumulative per-queue packet counts, sorted by
    /// interface name.
    pub fn status(&self) -> Vec<InterfaceStatus> {
        let mut interfaces: Vec<InterfaceStatus> = self
            .lock()
            .iter()
            .map(|(interface, attachment)| InterfaceStatus {
                interface: interface.clone(),
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
        self.attachments
            .lock()
            .expect("State mutex poisoned. This is a bug.")
    }
}

/// One attached interface: its workers and what they share.
struct Attachment {
    running: Arc<AtomicBool>,
    /// Packets received, one counter per queue.
    counters: Vec<Arc<AtomicU64>>,
    workers: Vec<JoinHandle<()>>,
    /// Held so it outlives every worker's socket halves.
    _umem: Umem,
}

impl Attachment {
    /// Stops and joins the workers, then drops: the pairs
    /// died with the workers, so dropping the umem unloads
    /// the XDP program and the interface reverts to the
    /// kernel.
    fn stop(self) {
        self.running.store(false, Ordering::Relaxed);
        for worker in self.workers {
            worker.join().expect("A worker panicked. This is a bug.");
        }
    }
}

/// Per-interface counter snapshot.
pub struct InterfaceStatus {
    pub interface: String,
    /// Packets received, cumulative, one entry per queue.
    pub queues: Vec<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("The interface '{0}' is already attached.")]
    AlreadyAttached(String),
    #[error("The interface '{0}' is not attached.")]
    NotAttached(String),
    #[error("No cores are available for pinning.")]
    NoCores,
    #[error(transparent)]
    Xdp(#[from] XdpError),
}
