//! The Ethernet II header.

use crate::{
    Error,
    field,
};

/// The header's length in bytes.
pub const HEADER_LEN: usize = 14;

/// What a frame's payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const VLAN: Self = Self(0x8100);
    pub const IPV6: Self = Self(0x86DD);
}

/// A frame viewed in place.
///
/// # Examples
/// ```
/// use mangonel_wire::{Ethernet, ethernet::EtherType};
///
/// let mut frame = [0u8; 60];
/// let mut eth = Ethernet::parse(&mut frame[..])?;
/// eth.set_destination([0xff; 6]);
/// eth.set_ethertype(EtherType::ARP);
/// assert_eq!(eth.destination(), [0xff; 6]);
/// assert_eq!(eth.payload().len(), 46);
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ethernet<T>(T);

impl<T: AsRef<[u8]>> Ethernet<T> {
    /// Views `bytes` as a frame; fails if the header is cut short.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        field::need(bytes.as_ref(), HEADER_LEN)?;

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn destination(&self) -> [u8; 6] {
        field::array_at(self.0.as_ref(), 0)
    }

    pub fn source(&self) -> [u8; 6] {
        field::array_at(self.0.as_ref(), 6)
    }

    pub fn ethertype(&self) -> EtherType {
        EtherType(field::u16_at(self.0.as_ref(), 12))
    }

    /// Everything after the header.
    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Ethernet<T> {
    pub fn set_destination(&mut self, mac: [u8; 6]) {
        field::set_array_at(self.0.as_mut(), 0, mac);
    }

    pub fn set_source(&mut self, mac: [u8; 6]) {
        field::set_array_at(self.0.as_mut(), 6, mac);
    }

    pub fn set_ethertype(&mut self, ethertype: EtherType) {
        field::set_u16_at(self.0.as_mut(), 12, ethertype.0);
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0.as_mut()[HEADER_LEN..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip() {
        let mut bytes = [0u8; 20];
        assert_eq!(
            Ethernet::parse(&bytes[..13]),
            Err(Error::Truncated {
                needed: 14,
                have: 13
            })
        );
        let mut eth = Ethernet::parse(&mut bytes[..]).unwrap();
        eth.set_destination([1, 2, 3, 4, 5, 6]);
        eth.set_source([6, 5, 4, 3, 2, 1]);
        eth.set_ethertype(EtherType::IPV6);
        eth.payload_mut()[0] = 0x60;
        assert_eq!(eth.destination(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(eth.source(), [6, 5, 4, 3, 2, 1]);
        assert_eq!(eth.ethertype(), EtherType::IPV6);
        assert_eq!(eth.payload(), &[0x60, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[12..15], &[0x86, 0xDD, 0x60]);
    }
}
