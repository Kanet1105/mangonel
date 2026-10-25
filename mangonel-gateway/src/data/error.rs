use std::io;

use mangonel_libxdp::XdpError;
use mangonel_nic::nic;

/// Why the data plane could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No NIC to run on")]
    NoNics,

    #[error("{0} has no queue to bind")]
    NoQueues(String),

    #[error("The NICs sit on different NUMA nodes: {0} and {1}")]
    NumaMismatch(i32, i32),

    #[error("No core near the NICs that this process may run on")]
    NoCores,

    #[error("Failed to read {0}: {1}")]
    Sysfs(String, io::Error),

    #[error("Failed to set {0} to {1} queues: {2}")]
    QueueCount(String, u32, nic::Error),

    #[error("Failed to spawn worker {0}: {1}")]
    Spawn(usize, io::Error),

    #[error("Failed to pin worker {0} to core {1}")]
    Pin(usize, usize),

    #[error("Failed to bind {0} queue {1}: {2}")]
    Bind(String, u32, XdpError),

    #[error("Worker {0} exited during startup")]
    Startup(usize),
}
