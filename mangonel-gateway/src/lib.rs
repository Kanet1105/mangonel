//! mangonel-gateway: the control plane that holds the
//! configuration, and the AF_XDP data plane that forwards
//! packets under it.

#![warn(unreachable_pub)]

pub mod control;
pub mod data;
mod error;

pub use error::Error;
