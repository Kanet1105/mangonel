//! ICMPv6 (RFC 4443); Neighbor Discovery messages are viewed
//! through [`crate::ipv6::nd`].

use std::net::Ipv6Addr;

use crate::{
    Error,
    checksum,
    field,
};

/// The IPv6 next-header number.
pub const PROTOCOL: u8 = 58;

/// The header's length in bytes, the type-specific word
/// included.
pub const HEADER_LEN: usize = 8;

/// The message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kind(pub u8);

impl Kind {
    pub const DESTINATION_UNREACHABLE: Self = Self(1);
    pub const PACKET_TOO_BIG: Self = Self(2);
    pub const TIME_EXCEEDED: Self = Self(3);
    pub const PARAMETER_PROBLEM: Self = Self(4);
    pub const ECHO_REQUEST: Self = Self(128);
    pub const ECHO_REPLY: Self = Self(129);
    pub const ROUTER_SOLICITATION: Self = Self(133);
    pub const ROUTER_ADVERTISEMENT: Self = Self(134);
    pub const NEIGHBOR_SOLICITATION: Self = Self(135);
    pub const NEIGHBOR_ADVERTISEMENT: Self = Self(136);
    pub const REDIRECT: Self = Self(137);
}

/// A message viewed in place, bounded by the bytes given.
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
///
/// use mangonel_wire::ipv6::{Icmp, icmp::Kind};
///
/// let (src, dst): (Ipv6Addr, Ipv6Addr) = ("fe80::2".parse()?, "fe80::1".parse()?);
/// let mut bytes = [0u8; 16];
/// let mut icmp = Icmp::parse(&mut bytes[..])?;
/// icmp.set_kind(Kind::ECHO_REQUEST);
/// icmp.set_identifier(0x1234);
/// icmp.fill_checksum(src, dst);
/// assert!(icmp.verify_checksum(src, dst));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp<T>(T);

impl<T: AsRef<[u8]>> Icmp<T> {
    /// Views `bytes` as a message; fails if the header is cut
    /// short.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        field::need(bytes.as_ref(), HEADER_LEN)?;

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn kind(&self) -> Kind {
        Kind(self.0.as_ref()[0])
    }

    pub fn code(&self) -> u8 {
        self.0.as_ref()[1]
    }

    pub fn checksum(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 2)
    }

    /// Whether the message sums to what its checksum says.
    pub fn verify_checksum(&self, src: Ipv6Addr, dst: Ipv6Addr) -> bool {
        let message = self.0.as_ref();
        let pseudo = checksum::pseudo_header(src.into(), dst.into(), PROTOCOL, message.len());

        checksum::finish(pseudo + checksum::sum(message)) == 0
    }

    /// The type-specific word after the checksum.
    pub fn rest_of_header(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 4)
    }

    /// The identifier of an echo.
    pub fn identifier(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 4)
    }

    /// The sequence number of an echo.
    pub fn sequence(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 6)
    }

    /// Everything after the header.
    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Icmp<T> {
    pub fn set_kind(&mut self, kind: Kind) {
        self.0.as_mut()[0] = kind.0;
    }

    pub fn set_code(&mut self, code: u8) {
        self.0.as_mut()[1] = code;
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        field::set_u16_at(self.0.as_mut(), 2, checksum);
    }

    /// Computes the checksum over the pseudo-header and the
    /// message and writes it.
    pub fn fill_checksum(&mut self, src: Ipv6Addr, dst: Ipv6Addr) {
        self.set_checksum(0);
        let message = self.0.as_ref();
        let pseudo = checksum::pseudo_header(src.into(), dst.into(), PROTOCOL, message.len());
        let sum = checksum::finish(pseudo + checksum::sum(message));
        self.set_checksum(sum);
    }

    pub fn set_rest_of_header(&mut self, word: u32) {
        field::set_u32_at(self.0.as_mut(), 4, word);
    }

    pub fn set_identifier(&mut self, id: u16) {
        field::set_u16_at(self.0.as_mut(), 4, id);
    }

    pub fn set_sequence(&mut self, sequence: u16) {
        field::set_u16_at(self.0.as_mut(), 6, sequence);
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0.as_mut()[HEADER_LEN..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_checksum_covers_the_pseudo_header() {
        let (src, dst): (Ipv6Addr, Ipv6Addr) =
            ("fe80::2".parse().unwrap(), "fe80::1".parse().unwrap());
        let mut bytes = [0u8; 12];
        let mut icmp = Icmp::parse(&mut bytes[..]).unwrap();
        icmp.set_kind(Kind::ECHO_REQUEST);
        icmp.set_identifier(1);
        icmp.set_sequence(2);
        icmp.payload_mut().copy_from_slice(b"ping");
        icmp.fill_checksum(src, dst);
        assert!(icmp.verify_checksum(src, dst));
        assert!(!icmp.verify_checksum(src, src));
        assert_eq!(icmp.rest_of_header(), 0x0001_0002);
        assert_eq!(icmp.payload(), b"ping");
    }
}
