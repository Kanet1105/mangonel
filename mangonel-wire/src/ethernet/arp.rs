//! ARP for IPv4 over Ethernet (RFC 826).

use std::net::Ipv4Addr;

use crate::{
    Error,
    field,
};

/// The message's length in bytes.
pub const LEN: usize = 28;

/// Which way the exchange goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Operation(pub u16);

impl Operation {
    pub const REQUEST: Self = Self(1);
    pub const REPLY: Self = Self(2);
}

/// A message viewed in place.
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
///
/// use mangonel_wire::{Arp, ethernet::arp::Operation};
///
/// let mut bytes = [0u8; 28];
/// let mut arp = Arp::init(&mut bytes[..])?;
/// arp.set_operation(Operation::REQUEST);
/// arp.set_sender_mac([2, 0, 0, 4, 0, 0]);
/// arp.set_sender_ip(Ipv4Addr::new(10, 0, 0, 2));
/// arp.set_target_ip(Ipv4Addr::new(10, 0, 0, 1));
/// let arp = Arp::parse(&bytes[..])?;
/// assert_eq!(arp.target_ip(), Ipv4Addr::new(10, 0, 0, 1));
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp<T>(T);

impl<T: AsRef<[u8]>> Arp<T> {
    /// Views `bytes` as a message; fails if it is cut short or
    /// is not IPv4 over Ethernet.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        let b = bytes.as_ref();
        field::need(b, LEN)?;
        if b[..6] != [0, 1, 0x08, 0x00, 6, 4] {
            return Err(Error::NotEthernetIpv4);
        }

        Ok(Self(bytes))
    }

    /// Zeroes `bytes` and writes the IPv4-over-Ethernet fixed
    /// fields, leaving the rest to the setters.
    pub fn init(mut bytes: T) -> Result<Self, Error>
    where
        T: AsMut<[u8]>,
    {
        field::need(bytes.as_ref(), LEN)?;
        let b = bytes.as_mut();
        b[..LEN].fill(0);
        b[..6].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn operation(&self) -> Operation {
        Operation(field::u16_at(self.0.as_ref(), 6))
    }

    pub fn sender_mac(&self) -> [u8; 6] {
        field::array_at(self.0.as_ref(), 8)
    }

    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(field::array_at::<4>(self.0.as_ref(), 14))
    }

    pub fn target_mac(&self) -> [u8; 6] {
        field::array_at(self.0.as_ref(), 18)
    }

    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(field::array_at::<4>(self.0.as_ref(), 24))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Arp<T> {
    pub fn set_operation(&mut self, operation: Operation) {
        field::set_u16_at(self.0.as_mut(), 6, operation.0);
    }

    pub fn set_sender_mac(&mut self, mac: [u8; 6]) {
        field::set_array_at(self.0.as_mut(), 8, mac);
    }

    pub fn set_sender_ip(&mut self, ip: Ipv4Addr) {
        field::set_array_at(self.0.as_mut(), 14, ip.octets());
    }

    pub fn set_target_mac(&mut self, mac: [u8; 6]) {
        field::set_array_at(self.0.as_mut(), 18, mac);
    }

    pub fn set_target_ip(&mut self, ip: Ipv4Addr) {
        field::set_array_at(self.0.as_mut(), 24, ip.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_becomes_reply_in_place() {
        let mut bytes = [0u8; 28];
        assert_eq!(Arp::parse(&bytes[..]), Err(Error::NotEthernetIpv4));
        let mut arp = Arp::init(&mut bytes[..]).unwrap();
        arp.set_operation(Operation::REQUEST);
        arp.set_sender_mac([2, 0, 0, 4, 0, 0]);
        arp.set_sender_ip(Ipv4Addr::new(10, 0, 0, 2));
        arp.set_target_ip(Ipv4Addr::new(10, 0, 0, 1));

        let mut arp = Arp::parse(&mut bytes[..]).unwrap();
        let (asker, asked) = (arp.sender_mac(), arp.sender_ip());
        arp.set_operation(Operation::REPLY);
        arp.set_target_mac(asker);
        arp.set_target_ip(asked);
        arp.set_sender_mac([2, 0, 0, 1, 0, 2]);
        arp.set_sender_ip(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            bytes,
            [
                0, 1, 8, 0, 6, 4, 0, 2, 2, 0, 0, 1, 0, 2, 10, 0, 0, 1, 2, 0, 0, 4, 0, 0, 10, 0, 0,
                2
            ]
        );
    }
}
