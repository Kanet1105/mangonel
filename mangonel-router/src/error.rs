//! One error type for every module, so `main` can `?`
//! across the whole daemon.

use std::io;

use mangonel_nic::nic;

use crate::{
    control,
    data,
};

/// Why the daemon could not start, or stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Control(#[from] control::Error),

    #[error(transparent)]
    Data(#[from] data::Error),

    #[error("Failed to start the control panel: {0}")]
    Panel(io::Error),

    #[error("Failed to install the signal handlers: {0}")]
    Signal(io::Error),

    #[error("No devices were given and there is no terminal to ask on; pass --wan and --lan")]
    NoTerminal,

    #[error("Failed to list the devices: {0}")]
    Devices(nic::Error),

    #[error("A router needs a WAN and a LAN device, and {0} can be offered")]
    TooFewDevices(usize),

    #[error("Failed to ask on the terminal: {0}")]
    Prompt(io::Error),

    /// The user backed out of the questions, and has been
    /// told so.
    #[error("Cancelled")]
    Cancelled,

    #[error("Failed to open {0}: {1}")]
    Device(String, nic::Error),

    #[error("{0} is given as more than one port")]
    DeviceTwice(String),

    #[error("{0} is the {1}th LAN port and has no default address; give it one")]
    NoDefaultAddress(String, usize),

    #[error("At most two resolvers can be handed out, not {0}")]
    TooManyResolvers(usize),

    #[error("A worker stopped on its own")]
    WorkerExited,
}

// Through control::Error, so a rejected port has one shape
// whichever way it arrives.
impl From<control::ConfigError> for Error {
    fn from(error: control::ConfigError) -> Self {
        Self::Control(error.into())
    }
}
