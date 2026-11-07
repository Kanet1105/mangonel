//! IPv6 (RFC 8200), with the ICMP, Neighbor Discovery and
//! DHCP that ride on it.

pub mod dhcp;
pub mod icmp;
pub mod nd;

use std::net::Ipv6Addr;

pub use dhcp::Dhcp;
pub use icmp::Icmp;

use crate::{
    Error,
    Protocol,
    field,
};

/// The header's length in bytes.
pub const HEADER_LEN: usize = 40;

/// A packet viewed in place, bounded by its payload length.
///
/// # Examples
/// ```
/// use mangonel_wire::{Ipv6, Protocol};
///
/// let mut bytes = [0u8; 48];
/// let mut ip = Ipv6::init(&mut bytes[..])?;
/// ip.set_payload_length(8)?;
/// ip.set_next_header(Protocol::UDP);
/// ip.set_hop_limit(64);
/// ip.set_source("fe80::1".parse().unwrap());
/// ip.set_destination("ff02::1".parse().unwrap());
/// let (next, transport) = ip.upper_layer()?;
/// assert_eq!(next, Protocol::UDP);
/// assert_eq!(transport.len(), 8);
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6<T>(T);

impl<T: AsRef<[u8]>> Ipv6<T> {
    /// Views `bytes` as a packet; fails unless the version is 6
    /// and the payload length fits.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        let b = bytes.as_ref();
        field::need(b, HEADER_LEN)?;
        let version = b[0] >> 4;
        if version != 6 {
            return Err(Error::Version {
                found: version,
                expected: 6,
            });
        }
        field::need(b, HEADER_LEN + usize::from(field::u16_at(b, 4)))?;

        Ok(Self(bytes))
    }

    /// Zeroes the header and writes version 6 with an empty
    /// payload, leaving the rest to the setters.
    pub fn init(mut bytes: T) -> Result<Self, Error>
    where
        T: AsMut<[u8]>,
    {
        field::need(bytes.as_ref(), HEADER_LEN)?;
        let b = bytes.as_mut();
        b[..HEADER_LEN].fill(0);
        b[0] = 0x60;

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn traffic_class(&self) -> u8 {
        let b = self.0.as_ref();

        (b[0] << 4) | (b[1] >> 4)
    }

    /// The 20-bit flow label.
    pub fn flow_label(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 0) & 0x000F_FFFF
    }

    pub fn payload_length(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 4)
    }

    pub fn next_header(&self) -> Protocol {
        Protocol(self.0.as_ref()[6])
    }

    pub fn hop_limit(&self) -> u8 {
        self.0.as_ref()[7]
    }

    pub fn source(&self) -> Ipv6Addr {
        Ipv6Addr::from(field::array_at::<16>(self.0.as_ref(), 8))
    }

    pub fn destination(&self) -> Ipv6Addr {
        Ipv6Addr::from(field::array_at::<16>(self.0.as_ref(), 24))
    }

    /// What the payload length covers after the header,
    /// extension headers included; trailing padding is left out.
    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..HEADER_LEN + usize::from(self.payload_length())]
    }

    /// The protocol past the extension headers and the bytes
    /// from where it starts; a later fragment reports
    /// [`Protocol::FRAGMENT`] because its header is in the first.
    pub fn upper_layer(&self) -> Result<(Protocol, &[u8]), Error> {
        let payload = self.payload();
        let (protocol, at) = skip_extensions(self.next_header(), payload)?;

        Ok((protocol, &payload[at..]))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv6<T> {
    pub fn set_traffic_class(&mut self, class: u8) {
        let b = self.0.as_mut();
        b[0] = (b[0] & 0xF0) | (class >> 4);
        b[1] = (b[1] & 0x0F) | (class << 4);
    }

    /// Sets the flow label from the low 20 bits of `label`.
    pub fn set_flow_label(&mut self, label: u32) {
        let b = self.0.as_mut();
        let kept = field::u32_at(b, 0) & 0xFFF0_0000;
        field::set_u32_at(b, 0, kept | (label & 0x000F_FFFF));
    }

    /// Sets the payload length; fails if it would overrun the
    /// bytes.
    pub fn set_payload_length(&mut self, length: u16) -> Result<(), Error> {
        let len = usize::from(length);
        if HEADER_LEN + len > self.0.as_ref().len() {
            return Err(Error::Length(len));
        }
        field::set_u16_at(self.0.as_mut(), 4, length);

        Ok(())
    }

    pub fn set_next_header(&mut self, protocol: Protocol) {
        self.0.as_mut()[6] = protocol.0;
    }

    pub fn set_hop_limit(&mut self, limit: u8) {
        self.0.as_mut()[7] = limit;
    }

    /// Takes one off the hop limit, or returns false if it is
    /// already down to one or zero.
    pub fn decrement_hop_limit(&mut self) -> bool {
        let limit = self.hop_limit();
        if limit <= 1 {
            return false;
        }
        self.0.as_mut()[7] = limit - 1;

        true
    }

    pub fn set_source(&mut self, ip: Ipv6Addr) {
        field::set_array_at(self.0.as_mut(), 8, ip.octets());
    }

    pub fn set_destination(&mut self, ip: Ipv6Addr) {
        field::set_array_at(self.0.as_mut(), 24, ip.octets());
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let end = HEADER_LEN + usize::from(self.payload_length());

        &mut self.0.as_mut()[HEADER_LEN..end]
    }

    /// Exclusive [`Self::upper_layer`].
    pub fn upper_layer_mut(&mut self) -> Result<(Protocol, &mut [u8]), Error> {
        let next = self.next_header();
        let payload = self.payload_mut();
        let (protocol, at) = skip_extensions(next, payload)?;

        Ok((protocol, &mut payload[at..]))
    }
}

/// Walks the extension headers at the front of `payload` and
/// returns what follows them and where.
fn skip_extensions(mut next: Protocol, payload: &[u8]) -> Result<(Protocol, usize), Error> {
    let mut at = 0;
    loop {
        let len = match next {
            Protocol::HOP_BY_HOP | Protocol::ROUTING | Protocol::DESTINATION_OPTIONS => {
                field::need(&payload[at..], 2)?;
                (usize::from(payload[at + 1]) + 1) * 8
            }
            Protocol::AH => {
                field::need(&payload[at..], 2)?;
                (usize::from(payload[at + 1]) + 2) * 4
            }
            // RFC 8200 section 4.5: the offset is in bits 3..16 of the
            // third and fourth bytes; a later fragment has no transport header.
            Protocol::FRAGMENT => {
                field::need(&payload[at..], 8)?;
                if field::u16_at(payload, at + 2) & 0xFFF8 != 0 {
                    return Ok((Protocol::FRAGMENT, at));
                }

                8
            }
            _ => return Ok((next, at)),
        };
        field::need(&payload[at..], len)?;
        next = Protocol(payload[at]);
        at += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn fields_round_trip() {
        let mut bytes = [0u8; 50];
        let mut ip = Ipv6::init(&mut bytes[..]).unwrap();
        ip.set_traffic_class(0xB8);
        ip.set_flow_label(0xABCDE);
        ip.set_payload_length(10).unwrap();
        ip.set_next_header(Protocol::ICMPV6);
        ip.set_hop_limit(255);
        ip.set_source(addr("fe80::1"));
        ip.set_destination(addr("ff02::1"));
        assert_eq!(ip.set_payload_length(11), Err(Error::Length(11)));

        let ip = Ipv6::parse(&bytes[..]).unwrap();
        assert_eq!(ip.traffic_class(), 0xB8);
        assert_eq!(ip.flow_label(), 0xABCDE);
        assert_eq!(bytes[..4], [0x6B, 0x8A, 0xBC, 0xDE]);
        assert_eq!(ip.payload_length(), 10);
        assert_eq!(ip.next_header(), Protocol::ICMPV6);
        assert_eq!(ip.hop_limit(), 255);
        assert_eq!(ip.source(), addr("fe80::1"));
        assert_eq!(ip.destination(), addr("ff02::1"));
        assert_eq!(ip.payload().len(), 10);
        assert_eq!(
            Ipv6::parse(&bytes[..49]),
            Err(Error::Truncated {
                needed: 50,
                have: 49
            })
        );
        bytes[0] = 0x4B;
        assert_eq!(
            Ipv6::parse(&bytes[..]),
            Err(Error::Version {
                found: 4,
                expected: 6
            })
        );
    }

    #[test]
    fn extension_headers_are_skipped() {
        let mut bytes = [0u8; 40 + 8 + 8 + 8];
        let mut ip = Ipv6::init(&mut bytes[..]).unwrap();
        ip.set_payload_length(24).unwrap();
        ip.set_next_header(Protocol::HOP_BY_HOP);
        let payload = ip.payload_mut();
        payload[0] = Protocol::FRAGMENT.0;
        payload[1] = 0;
        payload[8] = Protocol::UDP.0;
        payload[16] = 0xAA;
        let (protocol, transport) = ip.upper_layer().unwrap();
        assert_eq!(protocol, Protocol::UDP);
        assert_eq!(transport, &[0xAA, 0, 0, 0, 0, 0, 0, 0]);
        let (_, transport) = ip.upper_layer_mut().unwrap();
        transport[1] = 0xBB;
        assert_eq!(bytes[57], 0xBB);

        let mut ip = Ipv6::parse(&mut bytes[..]).unwrap();
        ip.payload_mut()[1] = 3;
        assert_eq!(
            ip.upper_layer(),
            Err(Error::Truncated {
                needed: 32,
                have: 24
            })
        );
        ip.set_hop_limit(1);
        assert!(!ip.decrement_hop_limit());
        ip.set_hop_limit(2);
        assert!(ip.decrement_hop_limit());
        assert_eq!(ip.hop_limit(), 1);
    }

    #[test]
    fn upper_layer_stops_at_a_later_fragment() {
        let mut bytes = [0u8; 40 + 8 + 8];
        let mut ip = Ipv6::init(&mut bytes[..]).unwrap();
        ip.set_payload_length(16).unwrap();
        ip.set_next_header(Protocol::FRAGMENT);
        let payload = ip.payload_mut();
        payload[0] = Protocol::UDP.0;
        let (protocol, transport) = ip.upper_layer_mut().unwrap();
        assert_eq!(protocol, Protocol::UDP);
        transport[1] = 1;
        assert_eq!(bytes[48..50], [0, 1]);
        bytes[42..44].copy_from_slice(&[0x00, 0x08]);
        let ip = Ipv6::parse(&bytes[..]).unwrap();
        let (protocol, rest) = ip.upper_layer().unwrap();
        assert_eq!(protocol, Protocol::FRAGMENT);
        assert_eq!(rest.len(), 16);
    }
}
