//! What the router is set up with, and what a typed value has to satisfy to be part of it.

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    time::Duration,
};

use mangonel_dhcp::{
    v4,
    v6,
};
use thiserror::Error;

/// Stands in for the lease time, which the DHCP servers check but the setup does not hold.
const LEASE: Duration = Duration::from_secs(3600);

/// The WAN and the LANs the router runs on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Setup {
    pub(crate) wan: Wan,
    pub(crate) lans: Vec<Lan>,
}

impl fmt::Display for Setup {
    /// A line per interface, each followed by an indented line per family.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Role::Wan, self.wan)?;
        for (n, lan) in self.lans.iter().enumerate() {
            write!(f, "\n{}: {lan}", Role::Lan(n))?;
        }

        Ok(())
    }
}

/// The WAN's device and how it gets its address in each family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wan {
    pub(crate) device: String,
    pub(crate) ipv4: Addressing,
    /// `None` if the WAN has no IPv6 address.
    pub(crate) ipv6: Option<Addressing>,
}

impl fmt::Display for Wan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.device)?;
        family_line(f, Family::V4, Some(self.ipv4))?;

        family_line(f, Family::V6, self.ipv6)
    }
}

/// A LAN's devices and the router's subnet on them in each family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lan {
    /// The devices bridged into the LAN, at least one.
    pub(crate) devices: Vec<String>,
    pub(crate) ipv4: Subnet,
    /// `None` if the LAN has no IPv6 address.
    pub(crate) ipv6: Option<Subnet>,
}

impl fmt::Display for Lan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.devices.join(", "))?;
        if self.devices.len() > 1 {
            f.write_str(" (bridged)")?;
        }
        family_line(f, Family::V4, Some(self.ipv4))?;

        family_line(f, Family::V6, self.ipv6)
    }
}

/// Writes the indented line of `family` under an interface, which says so if there is no `value`.
fn family_line(
    f: &mut fmt::Formatter<'_>,
    family: Family,
    value: Option<impl fmt::Display>,
) -> fmt::Result {
    match value {
        Some(value) => write!(f, "\n  {family}: {value}"),
        None => write!(f, "\n  {family}: none"),
    }
}

/// The router's address on a LAN in one family, and what it leases there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Subnet {
    pub(crate) cidr: Cidr,
    /// What the router leases as the DHCP server; `None` if it is not one.
    pub(crate) pool: Option<Pool>,
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pool {
            Some(pool) => write!(f, "{}, DHCP server {pool}", self.cidr),
            None => write!(f, "{}, no DHCP server", self.cidr),
        }
    }
}

/// The side of the router an interface faces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Wan,

    /// A LAN, numbered from zero in the order they are added.
    Lan(usize),
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Wan => f.write_str("WAN"),
            Role::Lan(0) => f.write_str("LAN"),
            Role::Lan(n) => write!(f, "LAN {}", n + 1),
        }
    }
}

/// An IP version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    V4,

    V6,
}

impl Family {
    /// The family `address` is of.
    pub(crate) fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        })
    }
}

/// How the WAN gets its address in one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Addressing {
    Static { cidr: Cidr, gateway: IpAddr },

    Dhcp,
}

impl fmt::Display for Addressing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addressing::Static { cidr, gateway } => {
                write!(f, "{} {cidr}, gateway {gateway}", Method::Static)
            }
            Addressing::Dhcp => Method::Dhcp.fmt(f),
        }
    }
}

/// The ways the WAN can get an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Static,

    Dhcp,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Method::Static => "Static",
            Method::Dhcp => "DHCP",
        })
    }
}

/// An address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cidr {
    pub(crate) address: IpAddr,
    /// Prefix length in bits.
    pub(crate) prefix: u8,
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// The first and last address a DHCP server leases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pool {
    pub(crate) start: IpAddr,
    pub(crate) end: IpAddr,
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} to {}", self.start, self.end)
    }
}

/// Why a typed value was refused.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(crate) enum Invalid {
    #[error("not an {0} address")]
    Address(Family),

    #[error("not in CIDR format (address/prefix)")]
    Cidr,

    #[error("not a prefix length from 1 to {0}")]
    Prefix(u8),

    #[error("the gateway cannot be the interface's own address")]
    OwnAddress,

    #[error("the pool cannot include the router's own address")]
    RouterInPool,

    #[error("not a host address inside the subnet")]
    OutsideSubnet,

    #[error("not inside the subnet, and not a link-local address")]
    OffLink,

    #[error("an interface cannot have its subnet's network or broadcast address")]
    NotHost,

    /// The subnet shares addresses with the one named, which an interface asked before has.
    #[error("overlaps {0} on {1}")]
    Overlap(Cidr, Role),

    /// Any other reason the DHCP server gives, in its words.
    #[error("{0}")]
    Pool(String),
}

/// Reads an address of `family`.
fn address(text: &str, family: Family) -> Result<IpAddr, Invalid> {
    match text.trim().parse() {
        Ok(address) if Family::of(address) == family => Ok(address),
        _ => Err(Invalid::Address(family)),
    }
}

/// Reads a prefix length that fits `family`.
fn prefix(text: &str, family: Family) -> Result<u8, Invalid> {
    let longest = match family {
        Family::V4 => 32,
        Family::V6 => 128,
    };

    match text.trim().parse() {
        Ok(prefix) if (1..=longest).contains(&prefix) => Ok(prefix),
        _ => Err(Invalid::Prefix(longest)),
    }
}

/// Reads, in CIDR format, an address of `family` an interface can have and its prefix length.
pub(crate) fn cidr(text: &str, family: Family) -> Result<Cidr, Invalid> {
    let (address, prefix) = text.split_once('/').ok_or(Invalid::Cidr)?;
    let address = self::address(address, family)?;
    let prefix = self::prefix(prefix, family)?;
    if network_or_broadcast(address, prefix) {
        return Err(Invalid::NotHost);
    }

    Ok(Cidr { address, prefix })
}

/// Reads the CIDR of a `family` subnet that shares no address with any of `taken`.
pub(crate) fn subnet(text: &str, family: Family, taken: &[(Role, Cidr)]) -> Result<Cidr, Invalid> {
    let cidr = self::cidr(text, family)?;

    match taken.iter().find(|(_, other)| overlap(cidr, *other)) {
        Some(&(role, other)) => Err(Invalid::Overlap(other, role)),
        None => Ok(cidr),
    }
}

/// Reads a gateway the interface at `cidr` reaches on its own link, other than itself.
pub(crate) fn gateway(text: &str, cidr: Cidr) -> Result<IpAddr, Invalid> {
    let family = Family::of(cidr.address);
    let gateway = address(text, family)?;
    if gateway == cidr.address {
        return Err(Invalid::OwnAddress);
    }
    if !on_link(cidr, gateway) {
        return Err(match family {
            Family::V4 => Invalid::OutsideSubnet,
            Family::V6 => Invalid::OffLink,
        });
    }

    Ok(gateway)
}

/// Whether a neighbour of the interface at `cidr` can have `address`.
fn on_link(cidr: Cidr, address: IpAddr) -> bool {
    match (cidr.address, address) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            in_subnet(cidr, address) && !network_or_broadcast(address, cidr.prefix)
        }
        // A link-local address is on every link, whatever the prefix.
        (IpAddr::V6(_), IpAddr::V6(v6)) => in_subnet(cidr, address) || v6.is_unicast_link_local(),
        _ => false,
    }
}

/// Whether `address` is the first or last of its subnet where those are the network's and the
/// broadcast's, which is IPv4 up to /30.
fn network_or_broadcast(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(address) if prefix <= 30 => {
            let hosts = hosts_v4(prefix);
            let host = u32::from(address) & hosts;

            host == 0 || host == hosts
        }
        IpAddr::V4(_) | IpAddr::V6(_) => false,
    }
}

/// Whether the subnets of `a` and `b` share an address.
fn overlap(a: Cidr, b: Cidr) -> bool {
    // They do when the one with the shorter prefix holds the other.
    let shorter = Cidr {
        address: a.address,
        prefix: a.prefix.min(b.prefix),
    };

    in_subnet(shorter, b.address)
}

/// Whether `address` is in the subnet of `cidr`, which an address of the other family never is.
fn in_subnet(cidr: Cidr, address: IpAddr) -> bool {
    match (cidr.address, address) {
        (IpAddr::V4(own), IpAddr::V4(address)) => {
            (u32::from(own) ^ u32::from(address)) & !hosts_v4(cidr.prefix) == 0
        }
        (IpAddr::V6(own), IpAddr::V6(address)) => {
            (u128::from(own) ^ u128::from(address)) & !hosts_v6(cidr.prefix) == 0
        }
        _ => false,
    }
}

/// The bits an IPv4 prefix leaves to the hosts; none at /32, where the shift overflows.
fn hosts_v4(prefix: u8) -> u32 {
    u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}

/// The bits an IPv6 prefix leaves to the hosts; none at /128, where the shift overflows.
fn hosts_v6(prefix: u8) -> u128 {
    u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0)
}

/// Reads the first address of a DHCP pool on the subnet of `cidr`.
pub(crate) fn pool_start(text: &str, cidr: Cidr) -> Result<IpAddr, Invalid> {
    let start = address(text, Family::of(cidr.address))?;
    check_pool(cidr, start, start)?;

    Ok(start)
}

/// Reads the last address of a DHCP pool on the subnet of `cidr` that begins at `start`.
pub(crate) fn pool_end(text: &str, cidr: Cidr, start: IpAddr) -> Result<IpAddr, Invalid> {
    let end = address(text, Family::of(cidr.address))?;
    check_pool(cidr, start, end)?;

    Ok(end)
}

/// Whether the DHCP server at `cidr` would lease `start` to `end`, by that server's own checks.
fn check_pool(cidr: Cidr, start: IpAddr, end: IpAddr) -> Result<(), Invalid> {
    let checked = match (cidr.address, start, end) {
        (IpAddr::V4(address), IpAddr::V4(pool_start), IpAddr::V4(pool_end)) => v4::server::Config {
            address,
            prefix: cidr.prefix,
            pool_start,
            pool_end,
            dns: Vec::new(),
            reservations: HashMap::new(),
            lease_time: LEASE,
        }
        .validate(),
        (IpAddr::V6(address), IpAddr::V6(pool_start), IpAddr::V6(pool_end)) => v6::server::Config {
            mac: [0; 6],
            prefix: address,
            prefix_len: cidr.prefix,
            pool_start,
            pool_end,
            dns: Vec::new(),
            reservations: HashMap::new(),
            preferred_lifetime: LEASE,
            valid_lifetime: LEASE,
            rapid_commit: false,
        }
        .validate(),
        _ => return Err(Invalid::Address(Family::of(cidr.address))),
    };
    // The DHCPv6 server is not told the router's address, so it cannot check this itself.
    if (start..=end).contains(&cidr.address) {
        return Err(Invalid::RouterInPool);
    }

    checked.map_err(|refused| match refused {
        // The other end of the pool already fits, so it is the typed address that does not.
        mangonel_dhcp::Error::PoolOutsideSubnet(..) => Invalid::OutsideSubnet,
        refused => Invalid::Pool(refused.to_string()),
    })
}
