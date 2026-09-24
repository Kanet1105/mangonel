//! IP prefixes shared by the filter and routing tables.

use std::net::IpAddr;

/// An IPv4 or IPv6 network; matches only its own family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// Host bits of `addr` are cleared.
    pub fn new(addr: impl Into<IpAddr>, len: u8) -> Result<Self, PrefixError> {
        let addr = match addr.into() {
            IpAddr::V4(addr) if len <= 32 => IpAddr::V4(mask4(addr.into(), len).into()),
            IpAddr::V6(addr) if len <= 128 => IpAddr::V6(mask6(addr.into(), len).into()),
            _ => return Err(PrefixError::Length(len)),
        };

        Ok(Self { addr, len })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn length(&self) -> u8 {
        self.len
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(prefix), IpAddr::V4(addr)) => {
                mask4(addr.into(), self.len) == u32::from(prefix)
            }
            (IpAddr::V6(prefix), IpAddr::V6(addr)) => {
                mask6(addr.into(), self.len) == u128::from(prefix)
            }
            _ => false,
        }
    }
}

fn mask4(addr: u32, len: u8) -> u32 {
    if len == 0 {
        return 0;
    }

    addr & (u32::MAX << (32 - len))
}

fn mask6(addr: u128, len: u8) -> u128 {
    if len == 0 {
        return 0;
    }

    addr & (u128::MAX << (128 - len))
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum PrefixError {
    #[error("The prefix length '{0}' exceeds the address width.")]
    Length(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_masks_and_contains() {
        let prefix = Prefix::new(ip("10.1.2.3"), 16).unwrap();
        assert_eq!(prefix.addr(), ip("10.1.0.0"));
        assert_eq!(prefix.length(), 16);
        assert!(prefix.contains(ip("10.1.255.255")));
        assert!(!prefix.contains(ip("10.2.0.0")));
        assert!(!prefix.contains(ip("::ffff:10.1.0.1")));
        assert!(
            Prefix::new(ip("0.0.0.0"), 0)
                .unwrap()
                .contains(ip("255.255.255.255"))
        );
        assert_eq!(
            Prefix::new(ip("10.0.0.0"), 33),
            Err(PrefixError::Length(33))
        );
    }

    #[test]
    fn v6_masks_and_contains() {
        let prefix = Prefix::new(ip("2001:db8:1:2:3::ffff"), 48).unwrap();
        assert_eq!(prefix.addr(), ip("2001:db8:1::"));
        assert!(prefix.contains(ip("2001:db8:1:ffff::1")));
        assert!(!prefix.contains(ip("2001:db8:2::1")));
        assert!(!prefix.contains(ip("10.1.0.1")));
        let host = Prefix::new(ip("2001:db8::1"), 128).unwrap();
        assert!(host.contains(ip("2001:db8::1")));
        assert!(!host.contains(ip("2001:db8::2")));
        assert!(Prefix::new(ip("::"), 0).unwrap().contains(ip("ff02::1")));
        assert_eq!(
            Prefix::new(ip("2001:db8::"), 129),
            Err(PrefixError::Length(129))
        );
    }
}
