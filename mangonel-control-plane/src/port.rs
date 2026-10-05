//! WAN and LAN port configuration.
//!
//! Each port is dual stack: its IPv4 and IPv6 halves are
//! configured independently, and `None` leaves that family
//! disabled on the port. Either kind of port can have an
//! ACL attached in each direction.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Cidr, ConfigError, IpFamily, MacAddr};

/// An uplink towards an ISP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanPort {
    pub mac: MacAddr,
    pub ipv4: Option<WanIp<Ipv4Addr>>,
    pub ipv6: Option<WanIp<Ipv6Addr>>,
    pub acls: PortAcls,
}

impl WanPort {
    /// Checks the port on its own, without regard to other
    /// ports.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_mac(self.mac)?;
        if let Some(ip) = &self.ipv4 {
            ip.validate()?;
        }
        if let Some(ip) = &self.ipv6 {
            ip.validate()?;
        }
        Ok(())
    }
}

/// One address family's configuration on a [`WanPort`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanIp<A> {
    pub addressing: Addressing<A>,
    pub dns: Dns<A>,
}

impl<A: IpFamily> WanIp<A> {
    fn validate(&self) -> Result<(), ConfigError> {
        match &self.addressing {
            Addressing::Dhcp => Ok(()),
            Addressing::Static { cidr, gateway } => {
                if matches!(self.dns, Dns::Auto) {
                    return Err(ConfigError::AutoDnsWithoutDhcp);
                }
                cidr.check(A::BITS)?;
                let on_link = cidr.is_host(*gateway) && *gateway != cidr.address;
                if !on_link && !gateway.is_link_local() {
                    return Err(ConfigError::GatewayUnreachable(gateway.into_ip()));
                }
                Ok(())
            }
        }
    }
}

/// How a WAN port gets its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addressing<A> {
    /// Leased from the ISP: DHCP on IPv4, DHCPv6 on IPv6.
    Dhcp,
    Static {
        cidr: Cidr<A>,
        /// The default gateway. On IPv6 this may be a
        /// link-local address outside `cidr`.
        gateway: A,
    },
}

/// Where a WAN port's resolvers come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dns<A> {
    /// Whatever the ISP hands out with the lease. Only
    /// valid with [`Addressing::Dhcp`].
    Auto,
    Manual {
        primary: A,
        secondary: Option<A>,
    },
}

/// A downstream segment the gateway serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPort {
    pub mac: MacAddr,
    pub ipv4: Option<LanIp<Ipv4Addr>>,
    pub ipv6: Option<LanIp<Ipv6Addr>>,
    pub acls: PortAcls,
}

impl LanPort {
    /// Checks the port on its own, without regard to other
    /// ports.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_mac(self.mac)?;
        if let Some(ip) = &self.ipv4 {
            ip.validate()?;
        }
        if let Some(ip) = &self.ipv6 {
            ip.validate()?;
        }
        Ok(())
    }
}

/// One address family's configuration on a [`LanPort`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanIp<A> {
    /// The gateway's own address on the segment, and the
    /// segment's prefix.
    pub cidr: Cidr<A>,
    /// First address handed out to clients.
    pub pool_start: A,
    /// Last address handed out to clients, inclusive.
    pub pool_end: A,
    /// Whether to serve DHCP (DHCPv6 on IPv6) from the
    /// pool. The pool is validated either way so it can
    /// be turned on later without reconfiguring.
    pub dhcp: bool,
}

impl<A: IpFamily> LanIp<A> {
    fn validate(&self) -> Result<(), ConfigError> {
        // Room for the gateway and at least one client,
        // plus the network and broadcast addresses
        // on IPv4.
        self.cidr.check(A::BITS - 2)?;

        let (start, end) = (self.pool_start, self.pool_end);
        if !self.cidr.is_host(start) || !self.cidr.is_host(end) {
            return Err(ConfigError::PoolOutsideSubnet(
                start.into_ip(),
                end.into_ip(),
            ));
        }
        if start.as_u128() > end.as_u128() {
            return Err(ConfigError::PoolReversed(start.into_ip(), end.into_ip()));
        }
        let address = self.cidr.address.as_u128();
        if (start.as_u128()..=end.as_u128()).contains(&address) {
            return Err(ConfigError::AddressInPool(self.cidr.address.into_ip()));
        }
        Ok(())
    }
}

/// The ACLs filtering a port's traffic, by name.
///
/// Each list covers both families. A name must refer to an
/// ACL the control plane already holds, and that ACL cannot
/// be removed while attached.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortAcls {
    /// Applied to packets arriving on the port.
    pub inbound: Option<String>,
    /// Applied to packets leaving through the port.
    pub outbound: Option<String>,
}

impl PortAcls {
    pub fn get(&self, direction: Direction) -> Option<&str> {
        match direction {
            Direction::Inbound => self.inbound.as_deref(),
            Direction::Outbound => self.outbound.as_deref(),
        }
    }

    pub(crate) fn slot(&mut self, direction: Direction) -> &mut Option<String> {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.inbound
            .iter()
            .chain(&self.outbound)
            .map(String::as_str)
    }
}

/// Which way traffic crosses a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Which side of the gateway a port is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Wan,
    Lan,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wan => "WAN",
            Self::Lan => "LAN",
        })
    }
}

fn check_mac(mac: MacAddr) -> Result<(), ConfigError> {
    if mac.is_unicast() && !mac.is_zero() {
        Ok(())
    } else {
        Err(ConfigError::InvalidMac(mac))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const WAN_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
    pub(crate) const LAN_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x02]);

    pub(crate) fn lan(mac: MacAddr, v4: &str, v6: &str) -> LanPort {
        let v4: Ipv4Addr = v4.parse().unwrap();
        let [a, b, c, _] = v4.octets();
        let v6: Ipv6Addr = v6.parse().unwrap();
        let s = v6.segments();
        LanPort {
            mac,
            ipv4: Some(LanIp {
                cidr: Cidr::new(v4, 24),
                pool_start: Ipv4Addr::new(a, b, c, 100),
                pool_end: Ipv4Addr::new(a, b, c, 199),
                dhcp: true,
            }),
            ipv6: Some(LanIp {
                cidr: Cidr::new(v6, 64),
                pool_start: Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0x100),
                pool_end: Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0x1ff),
                dhcp: false,
            }),
            acls: PortAcls::default(),
        }
    }

    pub(crate) fn wan_static(mac: MacAddr, v4: &str, gw: &str) -> WanPort {
        WanPort {
            mac,
            ipv4: Some(WanIp {
                addressing: Addressing::Static {
                    cidr: Cidr::new(v4.parse().unwrap(), 24),
                    gateway: gw.parse().unwrap(),
                },
                dns: Dns::Manual {
                    primary: Ipv4Addr::new(1, 1, 1, 1),
                    secondary: Some(Ipv4Addr::new(8, 8, 8, 8)),
                },
            }),
            ipv6: Some(WanIp {
                addressing: Addressing::Dhcp,
                dns: Dns::Auto,
            }),
            acls: PortAcls::default(),
        }
    }

    #[test]
    fn valid_ports_pass() {
        assert_eq!(
            wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1").validate(),
            Ok(())
        );
        assert_eq!(lan(LAN_MAC, "192.168.1.1", "fd00:1::1").validate(), Ok(()));
    }

    #[test]
    fn multicast_mac_rejected() {
        let mac = MacAddr([0x01, 0, 0x5e, 0, 0, 1]);
        assert_eq!(
            lan(mac, "192.168.1.1", "fd00:1::1").validate(),
            Err(ConfigError::InvalidMac(mac))
        );
    }

    #[test]
    fn auto_dns_needs_dhcp() {
        let mut port = wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1");
        port.ipv4.as_mut().unwrap().dns = Dns::Auto;
        assert_eq!(port.validate(), Err(ConfigError::AutoDnsWithoutDhcp));
    }

    #[test]
    fn gateway_must_be_on_link() {
        let port = wan_static(WAN_MAC, "203.0.113.2", "198.51.100.1");
        assert!(matches!(
            port.validate(),
            Err(ConfigError::GatewayUnreachable(_))
        ));

        let port = wan_static(WAN_MAC, "203.0.113.2", "203.0.113.2");
        assert!(matches!(
            port.validate(),
            Err(ConfigError::GatewayUnreachable(_))
        ));
    }

    #[test]
    fn v6_link_local_gateway_allowed() {
        let mut port = wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1");
        port.ipv6 = Some(WanIp {
            addressing: Addressing::Static {
                cidr: Cidr::new("2001:db8::2".parse().unwrap(), 64),
                gateway: "fe80::1".parse().unwrap(),
            },
            dns: Dns::Manual {
                primary: "2606:4700:4700::1111".parse().unwrap(),
                secondary: None,
            },
        });
        assert_eq!(port.validate(), Ok(()));
    }

    #[test]
    fn pool_checks() {
        let mut port = lan(LAN_MAC, "192.168.1.1", "fd00:1::1");
        let ip = port.ipv4.as_mut().unwrap();
        ip.pool_end = Ipv4Addr::new(192, 168, 1, 255);
        assert!(matches!(
            port.validate(),
            Err(ConfigError::PoolOutsideSubnet(..))
        ));

        let mut port = lan(LAN_MAC, "192.168.1.1", "fd00:1::1");
        let ip = port.ipv4.as_mut().unwrap();
        (ip.pool_start, ip.pool_end) = (ip.pool_end, ip.pool_start);
        assert!(matches!(
            port.validate(),
            Err(ConfigError::PoolReversed(..))
        ));

        let port = lan(LAN_MAC, "192.168.1.150", "fd00:1::1");
        assert!(matches!(
            port.validate(),
            Err(ConfigError::AddressInPool(_))
        ));
    }

    #[test]
    fn lan_prefix_leaves_room_for_clients() {
        let mut port = lan(LAN_MAC, "192.168.1.1", "fd00:1::1");
        port.ipv4.as_mut().unwrap().cidr.prefix = 31;
        assert_eq!(
            port.validate(),
            Err(ConfigError::PrefixTooLong {
                prefix: 31,
                max: 30
            })
        );
    }
}
