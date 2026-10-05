//! Address types shared by the WAN and LAN configs.
//!
//! [`IpFamily`] lets one subnet implementation serve both
//! IPv4 and IPv6: every address is widened to a `u128` and
//! masked to the family's width.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::ConfigError;

/// An Ethernet hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl MacAddr {
    /// Whether the I/G bit is clear, i.e. the address names
    /// one interface rather than a group.
    pub fn is_unicast(self) -> bool {
        self.0[0] & 0x01 == 0
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }
}

/// An address family: implemented for [`Ipv4Addr`] and
/// [`Ipv6Addr`].
pub trait IpFamily: Copy + Eq + fmt::Debug + Send + Sync + 'static {
    /// Address width in bits.
    const BITS: u8;

    /// Whether the all-ones host part is reserved as a
    /// broadcast address. IPv6 has no broadcast.
    const HAS_BROADCAST: bool;

    /// The address zero-extended into the low bits.
    fn as_u128(self) -> u128;

    fn into_ip(self) -> IpAddr;

    /// Whether a gateway may sit outside the subnet because
    /// it is reached on-link regardless — true for IPv6
    /// link-local (`fe80::/10`), the usual router address
    /// learned from RAs.
    fn is_link_local(self) -> bool;
}

impl IpFamily for Ipv4Addr {
    const BITS: u8 = 32;
    const HAS_BROADCAST: bool = true;

    fn as_u128(self) -> u128 {
        u128::from(self.to_bits())
    }

    fn into_ip(self) -> IpAddr {
        IpAddr::V4(self)
    }

    fn is_link_local(self) -> bool {
        false
    }
}

impl IpFamily for Ipv6Addr {
    const BITS: u8 = 128;
    const HAS_BROADCAST: bool = false;

    fn as_u128(self) -> u128 {
        self.to_bits()
    }

    fn into_ip(self) -> IpAddr {
        IpAddr::V6(self)
    }

    fn is_link_local(self) -> bool {
        self.is_unicast_link_local()
    }
}

/// An interface address and the length of its subnet
/// prefix, e.g. `192.168.1.1/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr<A> {
    pub address: A,
    pub prefix: u8,
}

impl<A: IpFamily> fmt::Display for Cidr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address.into_ip(), self.prefix)
    }
}

impl<A: IpFamily> Cidr<A> {
    pub fn new(address: A, prefix: u8) -> Self {
        Self { address, prefix }
    }

    /// Whether `addr` falls inside this subnet.
    pub fn contains(&self, addr: A) -> bool {
        let mask = self.mask();
        addr.as_u128() & mask == self.address.as_u128() & mask
    }

    /// Whether `addr` is inside the subnet and assignable
    /// to a host: not the network address, nor the
    /// broadcast address on IPv4.
    ///
    /// Point-to-point prefixes (`/31`, `/32`, `/127`,
    /// `/128`) have no reserved addresses (RFC 3021).
    pub fn is_host(&self, addr: A) -> bool {
        if !self.contains(addr) {
            return false;
        }
        if self.prefix >= A::BITS - 1 {
            return true;
        }
        let host = addr.as_u128() & !self.mask() & full::<A>();
        host != 0 && !(A::HAS_BROADCAST && host == !self.mask() & full::<A>())
    }

    /// Whether the two subnets share any address.
    pub fn overlaps(&self, other: &Self) -> bool {
        let shorter = if self.prefix <= other.prefix {
            self
        } else {
            other
        };
        shorter.contains(self.address) && shorter.contains(other.address)
    }

    /// Rejects a prefix wider than the family or longer
    /// than `max`, and an address that is not a host
    /// address.
    pub(crate) fn check(&self, max: u8) -> Result<(), ConfigError> {
        let max = max.min(A::BITS);
        if self.prefix > max {
            return Err(ConfigError::PrefixTooLong {
                prefix: self.prefix,
                max,
            });
        }
        if !self.is_host(self.address) {
            return Err(ConfigError::NotHostAddress(self.address.into_ip()));
        }
        Ok(())
    }

    /// Whether `address` is the subnet's network address,
    /// i.e. has no host bits set.
    pub fn is_network(&self) -> bool {
        self.address.as_u128() & !self.mask() & full::<A>() == 0
    }

    fn mask(&self) -> u128 {
        match self.prefix.min(A::BITS) {
            0 => 0,
            prefix => (u128::MAX << (A::BITS - prefix)) & full::<A>(),
        }
    }
}

/// All `A::BITS` low bits set.
fn full<A: IpFamily>() -> u128 {
    u128::MAX >> (128 - u32::from(A::BITS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str, prefix: u8) -> Cidr<Ipv4Addr> {
        Cidr::new(s.parse().unwrap(), prefix)
    }

    fn v6(s: &str, prefix: u8) -> Cidr<Ipv6Addr> {
        Cidr::new(s.parse().unwrap(), prefix)
    }

    #[test]
    fn contains_respects_prefix() {
        let net = v4("192.168.1.1", 24);
        assert!(net.contains("192.168.1.254".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));
        assert!(v4("10.0.0.1", 0).contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn host_excludes_network_and_broadcast_on_v4_only() {
        let net = v4("192.168.1.1", 24);
        assert!(!net.is_host("192.168.1.0".parse().unwrap()));
        assert!(!net.is_host("192.168.1.255".parse().unwrap()));
        assert!(net.is_host("192.168.1.1".parse().unwrap()));

        let net = v6("2001:db8::1", 64);
        assert!(!net.is_host("2001:db8::".parse().unwrap()));
        assert!(net.is_host("2001:db8::ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn point_to_point_has_no_reserved_addresses() {
        let net = v4("10.0.0.0", 31);
        assert!(net.is_host("10.0.0.0".parse().unwrap()));
        assert!(net.is_host("10.0.0.1".parse().unwrap()));
        assert!(v6("2001:db8::1", 128).is_host("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn overlap_is_symmetric() {
        let wide = v4("10.0.0.1", 8);
        let narrow = v4("10.1.2.3", 24);
        assert!(wide.overlaps(&narrow));
        assert!(narrow.overlaps(&wide));
        assert!(!narrow.overlaps(&v4("10.1.3.1", 24)));
    }

    #[test]
    fn check_rejects_long_prefix() {
        assert_eq!(
            v4("10.0.0.1", 33).check(32),
            Err(ConfigError::PrefixTooLong {
                prefix: 33,
                max: 32
            })
        );
        assert!(v4("10.0.0.1", 30).check(30).is_ok());
    }

    #[test]
    fn mac_display() {
        let mac = MacAddr([0x02, 0, 0x5e, 0x10, 0xab, 0xff]);
        assert_eq!(mac.to_string(), "02:00:5e:10:ab:ff");
        assert!(mac.is_unicast());
        assert!(!MacAddr([0x01, 0, 0x5e, 0, 0, 1]).is_unicast());
    }
}
