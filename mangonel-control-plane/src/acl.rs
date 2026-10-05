//! Extended access control lists.
//!
//! Modelled on Cisco's extended ACLs: a named list of
//! entries, each matching on protocol, source and
//! destination address, and ports or ICMP type, and ordered
//! by sequence number. The first matching entry decides;
//! a packet that matches none is denied.
//!
//! One list serves both families. An entry whose addresses
//! are both [`AddrMatch::Any`] matches IPv4 and IPv6 alike;
//! naming a prefix pins the entry to that prefix's family.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Cidr, ConfigError, IpFamily};

/// Longest accepted [`Acl::name`].
pub const MAX_NAME_LEN: usize = 64;

const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// A named, ordered list of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    /// Non-empty, at most [`MAX_NAME_LEN`] bytes, no
    /// whitespace.
    pub name: String,
    /// Kept sorted by [`AclEntry::seq`] once accepted by
    /// the control plane.
    pub entries: Vec<AclEntry>,
}

impl Acl {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    pub fn entry(&self, seq: u32) -> Option<&AclEntry> {
        self.entries.iter().find(|entry| entry.seq == seq)
    }

    /// The first entry matching `packet`, if any.
    pub fn first_match(&self, packet: &Packet) -> Option<&AclEntry> {
        self.entries.iter().find(|entry| entry.matches(packet))
    }

    /// The verdict for `packet`, including the implicit
    /// deny at the end of every list.
    pub fn action(&self, packet: &Packet) -> Action {
        self.first_match(packet)
            .map_or(Action::Deny, |entry| entry.action)
    }

    /// Checks the name and every entry, and that sequence
    /// numbers are unique.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_name(&self.name)?;
        for (i, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if self.entries[..i].iter().any(|e| e.seq == entry.seq) {
                return Err(ConfigError::DuplicateSequence(entry.seq));
            }
        }
        Ok(())
    }

    /// Inserts `entry`, or replaces the one with the same
    /// sequence number, keeping the list sorted.
    pub(crate) fn upsert(&mut self, entry: AclEntry) {
        match self.entries.binary_search_by_key(&entry.seq, |e| e.seq) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    pub(crate) fn sort(&mut self) {
        self.entries.sort_by_key(|entry| entry.seq);
    }
}

/// One rule in an [`Acl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    /// Position in the list, lowest first. Unique within an
    /// ACL.
    pub seq: u32,
    pub action: Action,
    pub protocol: Protocol,
    pub source: AddrMatch,
    pub destination: AddrMatch,
    /// Whether the data plane should log packets that match
    /// this entry.
    pub log: bool,
}

impl AclEntry {
    pub fn matches(&self, packet: &Packet) -> bool {
        if !self.source.matches(packet.source) || !self.destination.matches(packet.destination) {
            return false;
        }
        match (self.protocol, packet.transport) {
            (Protocol::Ip, _) => true,
            (
                Protocol::Tcp {
                    source,
                    destination,
                    established,
                },
                Transport::Tcp {
                    source: sport,
                    destination: dport,
                    flags,
                },
            ) => {
                source.matches(sport)
                    && destination.matches(dport)
                    && (!established || flags & (TCP_ACK | TCP_RST) != 0)
            }
            (
                Protocol::Udp {
                    source,
                    destination,
                },
                Transport::Udp {
                    source: sport,
                    destination: dport,
                },
            ) => source.matches(sport) && destination.matches(dport),
            (Protocol::Icmp { kind }, Transport::Icmp { kind: k, code: c }) => {
                kind.is_none_or(|m| m.kind == k && m.code.is_none_or(|code| code == c))
            }
            (Protocol::Other(p), Transport::Other(q)) => p == q,
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.source.validate()?;
        self.destination.validate()?;

        let family = match (self.source.family(), self.destination.family()) {
            (Some(a), Some(b)) if a != b => return Err(ConfigError::MixedFamilies(self.seq)),
            (a, b) => a.or(b),
        };

        match self.protocol {
            Protocol::Tcp {
                source,
                destination,
                ..
            }
            | Protocol::Udp {
                source,
                destination,
            } => {
                source.validate(self.seq)?;
                destination.validate(self.seq)
            }
            Protocol::Icmp { kind: Some(_) } if family.is_none() => {
                Err(ConfigError::AmbiguousIcmpType(self.seq))
            }
            // These have their own variants, so a number
            // alias would never match: the data plane parses
            // them into Tcp, Udp or Icmp.
            Protocol::Other(6 | 17 | 1 | 58) => Err(ConfigError::ReservedProtocol(self.seq)),
            Protocol::Ip | Protocol::Icmp { .. } | Protocol::Other(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Deny,
}

/// What an entry matches above the IP layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Any IP packet.
    Ip,
    Tcp {
        source: PortMatch,
        destination: PortMatch,
        /// Match only packets of an established connection:
        /// those with ACK or RST set.
        established: bool,
    },
    Udp {
        source: PortMatch,
        destination: PortMatch,
    },
    /// ICMP on IPv4, ICMPv6 on IPv6.
    Icmp {
        /// Type numbers differ between the two, so an
        /// entry naming one must also pin its family with
        /// a source or destination prefix.
        kind: Option<IcmpMatch>,
    },
    /// Any other IP protocol, by number.
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpMatch {
    pub kind: u8,
    /// `None` matches every code of `kind`.
    pub code: Option<u8>,
}

/// An address an entry matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMatch {
    Any,
    /// A network prefix; host bits must be clear.
    V4(Cidr<Ipv4Addr>),
    V6(Cidr<Ipv6Addr>),
}

impl AddrMatch {
    /// Exactly one address.
    pub fn host(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Self::V4(Cidr::new(addr, 32)),
            IpAddr::V6(addr) => Self::V6(Cidr::new(addr, 128)),
        }
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (Self::Any, _) => true,
            (Self::V4(net), IpAddr::V4(addr)) => net.contains(addr),
            (Self::V6(net), IpAddr::V6(addr)) => net.contains(addr),
            _ => false,
        }
    }

    fn family(&self) -> Option<Family> {
        match self {
            Self::Any => None,
            Self::V4(_) => Some(Family::V4),
            Self::V6(_) => Some(Family::V6),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Any => Ok(()),
            Self::V4(net) => check_network(net),
            Self::V6(net) => check_network(net),
        }
    }
}

/// A TCP or UDP port condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMatch {
    Any,
    Eq(u16),
    Neq(u16),
    Lt(u16),
    Gt(u16),
    /// Inclusive on both ends.
    Range(u16, u16),
}

impl PortMatch {
    pub fn matches(&self, port: u16) -> bool {
        match *self {
            Self::Any => true,
            Self::Eq(p) => port == p,
            Self::Neq(p) => port != p,
            Self::Lt(p) => port < p,
            Self::Gt(p) => port > p,
            Self::Range(lo, hi) => (lo..=hi).contains(&port),
        }
    }

    /// Rejects conditions no port can satisfy.
    fn validate(&self, seq: u32) -> Result<(), ConfigError> {
        let empty = match *self {
            Self::Lt(p) => p == 0,
            Self::Gt(p) => p == u16::MAX,
            Self::Range(lo, hi) => lo > hi,
            Self::Any | Self::Eq(_) | Self::Neq(_) => false,
        };
        if empty {
            Err(ConfigError::EmptyPortMatch(seq))
        } else {
            Ok(())
        }
    }
}

/// The fields of a packet an ACL looks at, as the data
/// plane parsed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        source: u16,
        destination: u16,
        flags: u8,
    },
    Udp {
        source: u16,
        destination: u16,
    },
    /// ICMP on IPv4, ICMPv6 on IPv6.
    Icmp {
        kind: u8,
        code: u8,
    },
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

fn check_network<A: IpFamily>(net: &Cidr<A>) -> Result<(), ConfigError> {
    if net.prefix > A::BITS {
        return Err(ConfigError::PrefixTooLong {
            prefix: net.prefix,
            max: A::BITS,
        });
    }
    if !net.is_network() {
        return Err(ConfigError::HostBitsSet(net.to_string()));
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.chars().any(char::is_whitespace) {
        Err(ConfigError::InvalidAclName(name.to_owned()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn permit_web(seq: u32) -> AclEntry {
        AclEntry {
            seq,
            action: Action::Permit,
            protocol: Protocol::Tcp {
                source: PortMatch::Any,
                destination: PortMatch::Eq(443),
                established: false,
            },
            source: AddrMatch::V4(Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24)),
            destination: AddrMatch::Any,
            log: false,
        }
    }

    fn tcp(src: &str, dst: &str, dport: u16, flags: u8) -> Packet {
        Packet {
            source: src.parse().unwrap(),
            destination: dst.parse().unwrap(),
            transport: Transport::Tcp {
                source: 50000,
                destination: dport,
                flags,
            },
        }
    }

    #[test]
    fn first_match_wins_and_default_denies() {
        let mut acl = Acl::new("lan-out");
        acl.upsert(permit_web(20));
        acl.upsert(AclEntry {
            seq: 10,
            action: Action::Deny,
            protocol: Protocol::Ip,
            source: AddrMatch::host("192.168.1.66".parse().unwrap()),
            destination: AddrMatch::Any,
            log: true,
        });
        assert_eq!(acl.validate(), Ok(()));
        assert_eq!(acl.entries[0].seq, 10);

        let blocked = tcp("192.168.1.66", "1.1.1.1", 443, 0x02);
        assert_eq!(acl.action(&blocked), Action::Deny);
        assert_eq!(acl.first_match(&blocked).map(|e| e.seq), Some(10));

        assert_eq!(
            acl.action(&tcp("192.168.1.5", "1.1.1.1", 443, 0x02)),
            Action::Permit
        );
        assert_eq!(
            acl.action(&tcp("192.168.1.5", "1.1.1.1", 80, 0x02)),
            Action::Deny
        );
        assert_eq!(
            acl.action(&tcp("fd00::5", "2001:db8::1", 443, 0x02)),
            Action::Deny
        );
    }

    #[test]
    fn established_needs_ack_or_rst() {
        let entry = AclEntry {
            protocol: Protocol::Tcp {
                source: PortMatch::Any,
                destination: PortMatch::Any,
                established: true,
            },
            ..permit_web(10)
        };
        assert!(!entry.matches(&tcp("192.168.1.5", "1.1.1.1", 443, 0x02)));
        assert!(entry.matches(&tcp("192.168.1.5", "1.1.1.1", 443, 0x12)));
        assert!(entry.matches(&tcp("192.168.1.5", "1.1.1.1", 443, 0x04)));
    }

    #[test]
    fn any_address_matches_both_families() {
        let entry = AclEntry {
            seq: 10,
            action: Action::Permit,
            protocol: Protocol::Icmp { kind: None },
            source: AddrMatch::Any,
            destination: AddrMatch::Any,
            log: false,
        };
        for (src, dst) in [("10.0.0.1", "10.0.0.2"), ("fd00::1", "fd00::2")] {
            let packet = Packet {
                source: src.parse().unwrap(),
                destination: dst.parse().unwrap(),
                transport: Transport::Icmp { kind: 8, code: 0 },
            };
            assert!(entry.matches(&packet));
        }
    }

    #[test]
    fn port_matches() {
        assert!(PortMatch::Range(1000, 2000).matches(1000));
        assert!(PortMatch::Range(1000, 2000).matches(2000));
        assert!(!PortMatch::Lt(1024).matches(1024));
        assert!(PortMatch::Neq(22).matches(23));
    }

    #[test]
    fn validation() {
        let mut acl = Acl::new("bad name");
        assert!(matches!(
            acl.validate(),
            Err(ConfigError::InvalidAclName(_))
        ));

        acl.name = "ok".to_owned();
        acl.entries = vec![permit_web(10), permit_web(10)];
        assert_eq!(acl.validate(), Err(ConfigError::DuplicateSequence(10)));

        let entry = AclEntry {
            destination: AddrMatch::host("2001:db8::1".parse().unwrap()),
            ..permit_web(10)
        };
        assert_eq!(entry.validate(), Err(ConfigError::MixedFamilies(10)));

        let entry = AclEntry {
            source: AddrMatch::V4(Cidr::new(Ipv4Addr::new(192, 168, 1, 1), 24)),
            ..permit_web(10)
        };
        assert!(matches!(entry.validate(), Err(ConfigError::HostBitsSet(_))));

        let entry = AclEntry {
            protocol: Protocol::Udp {
                source: PortMatch::Range(9, 1),
                destination: PortMatch::Any,
            },
            ..permit_web(10)
        };
        assert_eq!(entry.validate(), Err(ConfigError::EmptyPortMatch(10)));

        let entry = AclEntry {
            protocol: Protocol::Icmp {
                kind: Some(IcmpMatch {
                    kind: 8,
                    code: None,
                }),
            },
            source: AddrMatch::Any,
            ..permit_web(10)
        };
        assert_eq!(entry.validate(), Err(ConfigError::AmbiguousIcmpType(10)));

        let entry = AclEntry {
            protocol: Protocol::Other(6),
            ..permit_web(10)
        };
        assert_eq!(entry.validate(), Err(ConfigError::ReservedProtocol(10)));
    }
}
