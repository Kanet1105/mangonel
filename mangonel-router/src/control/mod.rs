//! The control panel: configuration for the AF_XDP data
//! plane.
//!
//! The configuration lives in a [`left_right`] structure
//! whose single writer is a dedicated thread. Spawn it with
//! [`ControlPanel::spawn`], submit changes through its
//! methods, and read the published [`State`] through a
//! [`Reader`].
//!
//! The state holds WAN and LAN ports ([`WanPort`],
//! [`LanPort`]), extended access lists ([`acl`]), and which
//! list filters each port in each direction ([`PortAcls`]).

// The daemon sets its ports once at startup. The rest of the
// change API waits for a management interface to call it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the startup configuration is submitted so far"
    )
)]
#![cfg_attr(
    test,
    allow(
        dead_code,
        reason = "the tests reach most of the change API, not all of it"
    )
)]

pub(crate) mod acl;
mod addr;
mod error;
mod panel;
mod port;
mod state;

pub(crate) use acl::{
    Acl,
    AclEntry,
};
pub(crate) use addr::{
    Cidr,
    IpFamily,
    MacAddr,
};
pub(crate) use error::ConfigError;
pub(crate) use panel::{
    ControlPanel,
    Error,
    Reader,
};
pub(crate) use port::{
    Addressing,
    Direction,
    Dns,
    LanIp,
    LanPort,
    PortAcls,
    Role,
    WanIp,
    WanPort,
};
pub(crate) use state::State;
