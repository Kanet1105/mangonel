//! Safe wrappers over libxdp's AF_XDP socket API.
//!
//! Environmental failures are `Result`s; violated
//! invariants are panics, checked once at the boundary
//! that establishes them.

#![warn(unreachable_pub)]

mod descriptor;
mod pool;
mod ring;
mod socket;
mod umem;
mod xdp;

pub use descriptor::XdpDescriptor;
pub use socket::{SocketConfig, SocketHalf, XdpReceiver, XdpSender};
pub use xdp::{XdpError, bind, bind_shared};
