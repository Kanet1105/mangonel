//! The IPv4 header (RFC 791).

use std::net::Ipv4Addr;

use crate::{
    Error,
    checksum,
    field,
};

/// What the payload carries, from the header's protocol field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(pub u8);

impl Protocol {
    pub const ICMP: Self = Self(1);
    pub const IPV4: Self = Self(4);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const IPV6: Self = Self(41);
    pub const ESP: Self = Self(50);
    pub const AH: Self = Self(51);
}

/// The fixed header's length in bytes; options extend it.
pub const HEADER_LEN: usize = 20;

/// A packet viewed in place, bounded by its total length.
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
///
/// use mangonel_wire::{Ipv4, network::ipv4::Protocol};
///
/// let mut bytes = [0u8; 40];
/// let mut ip = Ipv4::init(&mut bytes[..])?;
/// ip.set_total_length(28)?;
/// ip.set_ttl(64);
/// ip.set_protocol(Protocol::UDP);
/// ip.set_source(Ipv4Addr::new(10, 0, 0, 2));
/// ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
/// ip.fill_checksum();
/// assert!(ip.verify_checksum());
/// assert_eq!(ip.payload().len(), 8);
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<T>(T);

impl<T: AsRef<[u8]>> Ipv4<T> {
    /// Views `bytes` as a packet; fails unless the version is 4
    /// and the header and total lengths fit.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        let b = bytes.as_ref();
        field::need(b, HEADER_LEN)?;
        let version = b[0] >> 4;
        if version != 4 {
            return Err(Error::Version {
                found: version,
                expected: 4,
            });
        }
        let header_len = usize::from(b[0] & 0x0F) * 4;
        if header_len < HEADER_LEN {
            return Err(Error::HeaderLength(header_len));
        }
        field::need(b, header_len)?;
        let total_len = usize::from(field::u16_at(b, 2));
        if total_len < header_len {
            return Err(Error::Length(total_len));
        }
        field::need(b, total_len)?;

        Ok(Self(bytes))
    }

    /// Zeroes the fixed header and writes version 4 with no
    /// options and an empty payload, leaving the rest to the
    /// setters.
    pub fn init(mut bytes: T) -> Result<Self, Error>
    where
        T: AsMut<[u8]>,
    {
        field::need(bytes.as_ref(), HEADER_LEN)?;
        let b = bytes.as_mut();
        b[..HEADER_LEN].fill(0);
        b[0] = 0x45;
        field::set_u16_at(b, 2, 20);

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// The header's length including options.
    pub fn header_len(&self) -> usize {
        usize::from(self.0.as_ref()[0] & 0x0F) * 4
    }

    pub fn dscp(&self) -> u8 {
        self.0.as_ref()[1] >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.0.as_ref()[1] & 0x03
    }

    pub fn total_length(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 2)
    }

    pub fn identification(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 4)
    }

    pub fn dont_fragment(&self) -> bool {
        self.0.as_ref()[6] & 0x40 != 0
    }

    pub fn more_fragments(&self) -> bool {
        self.0.as_ref()[6] & 0x20 != 0
    }

    /// Where this fragment's payload sits in the original, in
    /// bytes.
    pub fn fragment_offset(&self) -> u16 {
        (field::u16_at(self.0.as_ref(), 6) & 0x1FFF) * 8
    }

    /// Whether the packet is one piece of a larger one.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.fragment_offset() != 0
    }

    pub fn ttl(&self) -> u8 {
        self.0.as_ref()[8]
    }

    pub fn protocol(&self) -> Protocol {
        Protocol(self.0.as_ref()[9])
    }

    pub fn checksum(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 10)
    }

    /// Whether the header sums to what its checksum field says.
    pub fn verify_checksum(&self) -> bool {
        checksum::finish(checksum::sum(self.header())) == 0
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::from(field::array_at::<4>(self.0.as_ref(), 12))
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::from(field::array_at::<4>(self.0.as_ref(), 16))
    }

    /// The header including options.
    pub fn header(&self) -> &[u8] {
        &self.0.as_ref()[..self.header_len()]
    }

    pub fn options(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..self.header_len()]
    }

    /// What the total length covers after the header; trailing
    /// padding is left out.
    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[self.header_len()..usize::from(self.total_length())]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ipv4<T> {
    pub fn set_dscp(&mut self, dscp: u8) {
        let bytes = self.0.as_mut();
        bytes[1] = (bytes[1] & 0x03) | (dscp << 2);
    }

    pub fn set_ecn(&mut self, ecn: u8) {
        let bytes = self.0.as_mut();
        bytes[1] = (bytes[1] & 0xFC) | (ecn & 0x03);
    }

    /// Sets the total length; fails if it would not cover the
    /// header or would overrun the bytes.
    pub fn set_total_length(&mut self, length: u16) -> Result<(), Error> {
        let len = usize::from(length);
        if len < self.header_len() || len > self.0.as_ref().len() {
            return Err(Error::Length(len));
        }
        field::set_u16_at(self.0.as_mut(), 2, length);

        Ok(())
    }

    pub fn set_identification(&mut self, id: u16) {
        field::set_u16_at(self.0.as_mut(), 4, id);
    }

    pub fn set_dont_fragment(&mut self, dont: bool) {
        field::set_bits(self.0.as_mut(), 6, 0x40, dont);
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.0.as_mut()[8] = ttl;
    }

    /// Takes one off the TTL and patches the checksum, or
    /// returns false if the TTL is already down to one or zero.
    pub fn decrement_ttl(&mut self) -> bool {
        let ttl = self.ttl();
        if ttl <= 1 {
            return false;
        }
        let bytes = self.0.as_mut();
        let patched = checksum::update(
            field::u16_at(bytes, 10),
            &[ttl, bytes[9]],
            &[ttl - 1, bytes[9]],
        );
        bytes[8] = ttl - 1;
        field::set_u16_at(bytes, 10, patched);

        true
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.0.as_mut()[9] = protocol.0;
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        field::set_u16_at(self.0.as_mut(), 10, checksum);
    }

    /// Computes the header checksum and writes it.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let sum = checksum::finish(checksum::sum(self.header()));
        self.set_checksum(sum);
    }

    pub fn set_source(&mut self, ip: Ipv4Addr) {
        field::set_array_at(self.0.as_mut(), 12, ip.octets());
    }

    pub fn set_destination(&mut self, ip: Ipv4Addr) {
        field::set_array_at(self.0.as_mut(), 16, ip.octets());
    }

    pub fn options_mut(&mut self) -> &mut [u8] {
        let end = self.header_len();

        &mut self.0.as_mut()[HEADER_LEN..end]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let (start, end) = (self.header_len(), usize::from(self.total_length()));

        &mut self.0.as_mut()[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header from Wikipedia's worked checksum example.
    const HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn known_header_parses_and_verifies() {
        let mut bytes = [0u8; 0x73];
        bytes[..20].copy_from_slice(&HEADER);
        let ip = Ipv4::parse(&bytes[..]).unwrap();
        assert_eq!(ip.header_len(), 20);
        assert_eq!(ip.total_length(), 0x73);
        assert!(ip.dont_fragment());
        assert!(!ip.is_fragment());
        assert_eq!(ip.ttl(), 64);
        assert_eq!(ip.protocol(), Protocol::UDP);
        assert_eq!(ip.source(), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ip.destination(), Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(ip.payload().len(), 0x73 - 20);
        assert!(ip.verify_checksum());

        let mut ip = Ipv4::parse(&mut bytes[..]).unwrap();
        ip.set_checksum(0);
        assert!(!ip.verify_checksum());
        ip.fill_checksum();
        assert_eq!(ip.checksum(), 0xb861);
    }

    #[test]
    fn ttl_decrements_with_the_checksum() {
        let mut bytes = [0u8; 0x73];
        bytes[..20].copy_from_slice(&HEADER);
        let mut ip = Ipv4::parse(&mut bytes[..]).unwrap();
        for ttl in (1..64).rev() {
            assert!(ip.decrement_ttl());
            assert_eq!(ip.ttl(), ttl);
            assert!(ip.verify_checksum());
        }
        assert!(!ip.decrement_ttl());
        assert_eq!(ip.ttl(), 1);
    }

    #[test]
    fn bad_headers_are_refused() {
        let mut bytes = [0u8; 0x73];
        bytes[..20].copy_from_slice(&HEADER);
        assert!(matches!(
            Ipv4::parse(&bytes[..0x72]),
            Err(Error::Truncated { needed: 0x73, .. })
        ));
        bytes[0] = 0x65;
        assert_eq!(
            Ipv4::parse(&bytes[..]),
            Err(Error::Version {
                found: 6,
                expected: 4
            })
        );
        bytes[0] = 0x44;
        assert_eq!(Ipv4::parse(&bytes[..]), Err(Error::HeaderLength(16)));
        bytes[0] = 0x46;
        bytes[3] = 0x17;
        assert_eq!(Ipv4::parse(&bytes[..]), Err(Error::Length(23)));
        bytes[3] = 0x18;
        let ip = Ipv4::parse(&bytes[..]).unwrap();
        assert_eq!(ip.options().len(), 4);
        assert!(ip.payload().is_empty());
    }

    #[test]
    fn init_then_grow() {
        let mut bytes = [0xFFu8; 30];
        let mut ip = Ipv4::init(&mut bytes[..]).unwrap();
        assert_eq!(ip.total_length(), 20);
        assert_eq!(ip.set_total_length(19), Err(Error::Length(19)));
        assert_eq!(ip.set_total_length(31), Err(Error::Length(31)));
        ip.set_total_length(30).unwrap();
        ip.set_dscp(0x2E);
        ip.set_ecn(1);
        assert_eq!((ip.dscp(), ip.ecn()), (0x2E, 1));
        assert_eq!(ip.payload_mut(), &[0xFF; 10]);
    }
}
