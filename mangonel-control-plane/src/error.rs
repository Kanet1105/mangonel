//! Why the control plane rejects a change.

use std::net::IpAddr;

use thiserror::Error;

use crate::{MacAddr, Role};

/// Why a configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("{0} is not a unicast MAC address")]
    InvalidMac(MacAddr),
    #[error("{0} is already used by a {1} port")]
    MacInUse(MacAddr, Role),
    #[error("no {1} port with MAC {0}")]
    NotFound(MacAddr, Role),
    #[error("no port with MAC {0}")]
    PortNotFound(MacAddr),
    #[error("prefix /{prefix} is longer than /{max}")]
    PrefixTooLong { prefix: u8, max: u8 },
    #[error("{0} is not a host address in its subnet")]
    NotHostAddress(IpAddr),
    #[error("gateway {0} is not reachable from the port's subnet")]
    GatewayUnreachable(IpAddr),
    #[error("automatic DNS needs DHCP addressing")]
    AutoDnsWithoutDhcp,
    #[error("pool {0} - {1} is not a host range inside the subnet")]
    PoolOutsideSubnet(IpAddr, IpAddr),
    #[error("pool start {0} is after pool end {1}")]
    PoolReversed(IpAddr, IpAddr),
    #[error("port address {0} is inside its own DHCP pool")]
    AddressInPool(IpAddr),
    #[error("subnet {0} overlaps {1} on port {2}")]
    SubnetOverlap(String, String, MacAddr),

    #[error("{0:?} is not a valid ACL name")]
    InvalidAclName(String),
    #[error("no ACL named {0:?}")]
    AclNotFound(String),
    #[error("ACL {0:?} is attached to port {1}")]
    AclInUse(String, MacAddr),
    #[error("ACL {0:?} has no entry {1}")]
    AclEntryNotFound(String, u32),
    #[error("sequence number {0} is used more than once")]
    DuplicateSequence(u32),
    #[error("entry {0} mixes IPv4 and IPv6 addresses")]
    MixedFamilies(u32),
    #[error("prefix {0} has host bits set")]
    HostBitsSet(String),
    #[error("entry {0} has a port condition no port satisfies")]
    EmptyPortMatch(u32),
    #[error("entry {0} names an ICMP type without pinning IPv4 or IPv6")]
    AmbiguousIcmpType(u32),
    #[error("entry {0} names TCP, UDP or ICMP by number; use its own variant")]
    ReservedProtocol(u32),
}
