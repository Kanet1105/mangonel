//! TCP (RFC 9293).

use std::net::IpAddr;

use crate::{
    Error,
    checksum,
    field,
};

/// The IP protocol number, the same in both families.
pub const PROTOCOL: u8 = 6;

/// The fixed header's length in bytes; options extend it.
pub const HEADER_LEN: usize = 20;

/// The control bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flags(pub u8);

impl Flags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);

    /// Whether every bit of `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A segment viewed in place, bounded by the bytes given.
///
/// # Examples
/// ```
/// use mangonel_wire::{Tcp, tcp::Flags};
///
/// let mut bytes = [0u8; 20];
/// let mut tcp = Tcp::init(&mut bytes[..])?;
/// tcp.set_destination_port(443);
/// tcp.set_flags(Flags::SYN | Flags::ACK);
/// assert!(tcp.flags().contains(Flags::SYN));
/// assert!(!tcp.flags().contains(Flags::FIN));
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp<T>(T);

impl<T: AsRef<[u8]>> Tcp<T> {
    /// Views `bytes` as a segment; fails unless the data offset
    /// covers the fixed header and fits.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        let b = bytes.as_ref();
        field::need(b, HEADER_LEN)?;
        let header_len = usize::from(b[12] >> 4) * 4;
        if header_len < HEADER_LEN {
            return Err(Error::HeaderLength(header_len));
        }
        field::need(b, header_len)?;

        Ok(Self(bytes))
    }

    /// Zeroes the fixed header and writes a data offset with no
    /// options, leaving the rest to the setters.
    pub fn init(mut bytes: T) -> Result<Self, Error>
    where
        T: AsMut<[u8]>,
    {
        field::need(bytes.as_ref(), HEADER_LEN)?;
        let b = bytes.as_mut();
        b[..HEADER_LEN].fill(0);
        b[12] = 0x50;

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn source_port(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 0)
    }

    pub fn destination_port(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 2)
    }

    pub fn sequence(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 4)
    }

    pub fn acknowledgment(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 8)
    }

    /// The header's length including options.
    pub fn header_len(&self) -> usize {
        usize::from(self.0.as_ref()[12] >> 4) * 4
    }

    pub fn flags(&self) -> Flags {
        Flags(self.0.as_ref()[13])
    }

    pub fn window(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 14)
    }

    pub fn checksum(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 16)
    }

    /// Whether the segment sums to what its checksum says.
    pub fn verify_checksum(&self, src: IpAddr, dst: IpAddr) -> bool {
        let segment = self.0.as_ref();
        let pseudo = checksum::pseudo_header(src, dst, PROTOCOL, segment.len());

        checksum::finish(pseudo + checksum::sum(segment)) == 0
    }

    pub fn urgent_pointer(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 18)
    }

    pub fn options(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..self.header_len()]
    }

    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[self.header_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Tcp<T> {
    pub fn set_source_port(&mut self, port: u16) {
        field::set_u16_at(self.0.as_mut(), 0, port);
    }

    pub fn set_destination_port(&mut self, port: u16) {
        field::set_u16_at(self.0.as_mut(), 2, port);
    }

    pub fn set_sequence(&mut self, sequence: u32) {
        field::set_u32_at(self.0.as_mut(), 4, sequence);
    }

    pub fn set_acknowledgment(&mut self, ack: u32) {
        field::set_u32_at(self.0.as_mut(), 8, ack);
    }

    pub fn set_flags(&mut self, flags: Flags) {
        self.0.as_mut()[13] = flags.0;
    }

    pub fn set_window(&mut self, window: u16) {
        field::set_u16_at(self.0.as_mut(), 14, window);
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        field::set_u16_at(self.0.as_mut(), 16, checksum);
    }

    /// Computes the checksum over the pseudo-header and the
    /// segment and writes it.
    pub fn fill_checksum(&mut self, src: IpAddr, dst: IpAddr) {
        self.set_checksum(0);
        let segment = self.0.as_ref();
        let pseudo = checksum::pseudo_header(src, dst, PROTOCOL, segment.len());
        let sum = checksum::finish(pseudo + checksum::sum(segment));
        self.set_checksum(sum);
    }

    pub fn set_urgent_pointer(&mut self, pointer: u16) {
        field::set_u16_at(self.0.as_mut(), 18, pointer);
    }

    pub fn options_mut(&mut self) -> &mut [u8] {
        let end = self.header_len();

        &mut self.0.as_mut()[HEADER_LEN..end]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = self.header_len();

        &mut self.0.as_mut()[start..]
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn fields_and_checksum_round_trip() {
        let (src, dst) = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        );
        let mut bytes = [0u8; 30];
        let mut tcp = Tcp::init(&mut bytes[..]).unwrap();
        tcp.set_source_port(40000);
        tcp.set_destination_port(443);
        tcp.set_sequence(0xDEAD_BEEF);
        tcp.set_acknowledgment(1);
        tcp.set_flags(Flags::SYN | Flags::ECE);
        tcp.set_window(65535);
        tcp.set_urgent_pointer(7);
        tcp.payload_mut().copy_from_slice(b"0123456789");
        tcp.fill_checksum(src, dst);
        assert!(tcp.verify_checksum(src, dst));
        assert!(!tcp.verify_checksum(src, src));

        let tcp = Tcp::parse(&bytes[..]).unwrap();
        assert_eq!(tcp.source_port(), 40000);
        assert_eq!(tcp.destination_port(), 443);
        assert_eq!(tcp.sequence(), 0xDEAD_BEEF);
        assert_eq!(tcp.acknowledgment(), 1);
        assert_eq!(tcp.header_len(), 20);
        assert!(tcp.flags().contains(Flags::SYN));
        assert!(tcp.flags().contains(Flags::SYN | Flags::ECE));
        assert!(!tcp.flags().contains(Flags::ACK));
        assert_eq!(tcp.window(), 65535);
        assert_eq!(tcp.urgent_pointer(), 7);
        assert!(tcp.options().is_empty());
        assert_eq!(tcp.payload(), b"0123456789");
    }

    #[test]
    fn options_follow_the_data_offset() {
        let mut bytes = [0u8; 24];
        bytes[12] = 0x60;
        bytes[20..].copy_from_slice(&[2, 4, 0x05, 0xB4]);
        let tcp = Tcp::parse(&bytes[..]).unwrap();
        assert_eq!(tcp.options(), &[2, 4, 0x05, 0xB4]);
        assert!(tcp.payload().is_empty());
        bytes[12] = 0x40;
        assert_eq!(Tcp::parse(&bytes[..]), Err(Error::HeaderLength(16)));
        bytes[12] = 0x70;
        assert!(matches!(
            Tcp::parse(&bytes[..]),
            Err(Error::Truncated { needed: 28, .. })
        ));
    }
}
