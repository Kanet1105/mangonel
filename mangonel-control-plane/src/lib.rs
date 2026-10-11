//! mangonel-control-plane: configuration for the
//! AF_XDP data plane.
//!
//! The configuration lives in a [`left_right`] structure
//! whose single writer is a dedicated thread. Spawn it with
//! [`ControlPlane::spawn`], submit changes through a
//! [`ControlHandle`], and read the published [`State`]
//! through a [`Reader`].
//!
//! The state holds WAN and LAN ports ([`WanPort`],
//! [`LanPort`]), extended access lists ([`acl`]), and which
//! list filters each port in each direction ([`PortAcls`]).

#![warn(unreachable_pub)]

pub mod acl;
mod addr;
mod error;
mod plane;
mod port;
mod state;

pub use acl::{Acl, AclEntry};
pub use addr::{Cidr, IpFamily, MacAddr};
pub use error::ConfigError;
pub use left_right::ReadGuard;
pub use plane::{ControlHandle, ControlPlane, Error, Reader};
pub use port::{Addressing, Direction, Dns, LanIp, LanPort, PortAcls, Role, WanIp, WanPort};
pub use state::State;
