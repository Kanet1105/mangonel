//! The data plane: AF_XDP workers that forward packets
//! under the control plane's configuration.

mod error;
mod plane;
mod worker;

pub use error::Error;
pub use plane::DataPlane;
