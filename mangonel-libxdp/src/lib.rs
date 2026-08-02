//! Safe wrappers over libxdp's AF_XDP socket API.
//!
//! Error convention: environmental failures — syscalls,
//! libxdp calls, missing privileges — are `Result`s the
//! caller can act on. Violated invariants — a C
//! call reporting success while breaking its contract, or a
//! caller misusing a descriptor — are panics, checked once
//! at the boundary that establishes the invariant.

mod descriptor;
mod error;
mod ring;
mod socket;
mod umem;
mod util;

pub use descriptor::XdpDescriptor;
pub use error::XdpError;
pub use socket::{XdpReceiver, XdpSender, create_xdp_socket};
pub use umem::Umem;
