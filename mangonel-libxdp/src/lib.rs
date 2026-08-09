//! Safe wrappers over libxdp's AF_XDP socket API.
//!
//! Environmental failures are `Result`s; violated
//! invariants are panics, checked once at the boundary
//! that establishes them.

mod descriptor;
mod ring;
mod socket;
mod umem;
mod xdp;

pub use descriptor::XdpDescriptor;
pub use socket::{FramePool, XdpSocket};
pub use umem::Umem;
pub use xdp::{Binding, XdpError, bind, bind_with_umem};
