use std::io;

use mangonel_libxdp::XdpError;
use mangonel_nic::nic;

/// Why the data plane could not start.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("No port to run on")]
    NoPorts,

    #[error("{0} has no queue to bind")]
    NoQueues(String),

    #[error("No core that this process may run on")]
    NoCores,

    #[error("Failed to read the allowed CPUs: {0}")]
    Affinity(io::Error),

    #[error("Failed to read {0}: {1}")]
    Sysfs(String, io::Error),

    #[error("Failed to set {0} to {1} queues: {2}")]
    QueueCount(String, u32, nic::Error),

    #[error("{name} has {rx} receive and {tx} transmit queues after being set to {wanted}")]
    QueueMismatch {
        name: String,
        rx: u32,
        tx: u32,
        wanted: u32,
    },

    #[error("The ports have too many queues for one umem to hold their frames")]
    TooManyFrames,

    #[error("Failed to spawn worker {0}: {1}")]
    Spawn(usize, io::Error),

    #[error("Failed to pin worker {0} to core {1}: {2}")]
    Pin(usize, usize, io::Error),

    #[error("Failed to bind {0} queue {1}: {2}")]
    Bind(String, u32, XdpError),

    #[error("Worker {0} exited during startup")]
    Startup(usize),
}
