use std::io;

use mangonel_libxdp::XdpError;
use mangonel_nic::nic;

/// Why the generator could not run.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Failed to install the signal handlers: {0}")]
    Signal(io::Error),

    #[error("Failed to open {0}: {1}")]
    Device(String, nic::Error),

    #[error(
        "{device} has {queues} queues to transmit on, fewer than the {threads} threads asked for"
    )]
    TooFewQueues {
        device: String,
        queues: u32,
        threads: u32,
    },

    #[error("A packet on {device} is {min} to {max} bytes, not {size}")]
    PacketSize {
        device: String,
        size: usize,
        min: usize,
        max: usize,
    },

    #[error("{count} ports from {first} up run past the last port there is")]
    PortRange { first: u16, count: u32 },

    #[error("Failed to lay the packet out: {0}")]
    Packet(mangonel_wire::Error),

    #[error("{0} threads need more frames than one umem holds")]
    TooManyFrames(u32),

    #[error("Failed to read the allowed CPUs: {0}")]
    Affinity(io::Error),

    #[error("Failed to bind {0} queue {1}: {2}")]
    Bind(String, u32, XdpError),

    #[error("Failed to spawn a transmit thread: {0}")]
    Spawn(io::Error),

    #[error("A transmit thread panicked")]
    Panicked,
}
