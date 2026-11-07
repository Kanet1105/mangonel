//! UDP (RFC 768).

use std::net::IpAddr;

use crate::{
    Error,
    Protocol,
    checksum,
    field,
};

/// The header's length in bytes.
pub const HEADER_LEN: usize = 8;

/// A datagram viewed in place, bounded by its length field.
///
/// # Examples
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
///
/// use mangonel_wire::Udp;
///
/// let (src, dst) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
/// let mut bytes = [0u8; 12];
/// let mut udp = Udp::init(&mut bytes[..])?;
/// udp.set_length(12)?;
/// udp.set_source_port(68);
/// udp.set_destination_port(67);
/// udp.payload_mut().copy_from_slice(b"ping");
/// udp.fill_checksum(src, dst);
/// assert!(Udp::parse(&bytes[..])?.verify_checksum(src, dst));
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp<T>(T);

impl<T: AsRef<[u8]>> Udp<T> {
    /// Views `bytes` as a datagram; fails unless the length
    /// field covers the header and fits.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        let b = bytes.as_ref();
        field::need(b, HEADER_LEN)?;
        let len = usize::from(field::u16_at(b, 4));
        if len < HEADER_LEN {
            return Err(Error::Length(len));
        }
        field::need(b, len)?;

        Ok(Self(bytes))
    }

    /// Zeroes the header and writes an empty length, leaving the
    /// rest to the setters.
    pub fn init(mut bytes: T) -> Result<Self, Error>
    where
        T: AsMut<[u8]>,
    {
        field::need(bytes.as_ref(), HEADER_LEN)?;
        let b = bytes.as_mut();
        b[..HEADER_LEN].fill(0);
        b[5] = 8;

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

    /// The length of header and payload together.
    pub fn length(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 4)
    }

    pub fn checksum(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 6)
    }

    /// Whether the datagram sums to what its checksum says; an
    /// absent checksum passes over IPv4 and fails over IPv6.
    pub fn verify_checksum(&self, src: IpAddr, dst: IpAddr) -> bool {
        if self.checksum() == 0 {
            return src.is_ipv4();
        }
        let pseudo = checksum::pseudo_header(src, dst, Protocol::UDP, self.datagram().len());

        checksum::finish(pseudo + checksum::sum(self.datagram())) == 0
    }

    /// Header and payload together.
    pub fn datagram(&self) -> &[u8] {
        &self.0.as_ref()[..usize::from(self.length())]
    }

    pub fn payload(&self) -> &[u8] {
        &self.datagram()[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Udp<T> {
    pub fn set_source_port(&mut self, port: u16) {
        field::set_u16_at(self.0.as_mut(), 0, port);
    }

    pub fn set_destination_port(&mut self, port: u16) {
        field::set_u16_at(self.0.as_mut(), 2, port);
    }

    /// Sets the length; fails if it would not cover the header
    /// or would overrun the bytes.
    pub fn set_length(&mut self, length: u16) -> Result<(), Error> {
        let len = usize::from(length);
        if len < HEADER_LEN || len > self.0.as_ref().len() {
            return Err(Error::Length(len));
        }
        field::set_u16_at(self.0.as_mut(), 4, length);

        Ok(())
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        field::set_u16_at(self.0.as_mut(), 6, checksum);
    }

    /// Computes the checksum over the pseudo-header and the
    /// datagram and writes it, never as zero.
    pub fn fill_checksum(&mut self, src: IpAddr, dst: IpAddr) {
        self.set_checksum(0);
        let pseudo = checksum::pseudo_header(src, dst, Protocol::UDP, self.datagram().len());
        let sum = match checksum::finish(pseudo + checksum::sum(self.datagram())) {
            0 => 0xFFFF,
            sum => sum,
        };
        self.set_checksum(sum);
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let end = usize::from(self.length());

        &mut self.0.as_mut()[HEADER_LEN..end]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{
        Ipv4Addr,
        Ipv6Addr,
    };

    use super::*;

    #[test]
    fn checksum_over_both_families() {
        let v4 = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        let v6 = (
            IpAddr::V6("fe80::2".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
        );
        let mut bytes = [0u8; 16];
        let mut udp = Udp::init(&mut bytes[..]).unwrap();
        assert_eq!(udp.length(), 8);
        assert!(udp.verify_checksum(v4.0, v4.1));
        assert!(!udp.verify_checksum(v6.0, v6.1));
        udp.set_length(13).unwrap();
        udp.set_source_port(5000);
        udp.set_destination_port(53);
        udp.payload_mut().copy_from_slice(b"hello");
        for (src, dst) in [v4, v6] {
            udp.fill_checksum(src, dst);
            assert_ne!(udp.checksum(), 0);
            assert!(udp.verify_checksum(src, dst));
            assert!(!udp.verify_checksum(src, src));
        }
        let udp = Udp::parse(&bytes[..]).unwrap();
        assert_eq!(udp.payload(), b"hello");
        assert_eq!(udp.datagram().len(), 13);
        bytes[5] = 7;
        assert_eq!(Udp::parse(&bytes[..]), Err(Error::Length(7)));
        bytes[5] = 17;
        assert!(matches!(
            Udp::parse(&bytes[..]),
            Err(Error::Truncated { needed: 17, .. })
        ));
    }
}
