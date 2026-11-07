//! The 802.1Q tag that follows an Ethernet header whose
//! ethertype is [`EtherType::VLAN`].

use super::EtherType;
use crate::{
    Error,
    field,
};

/// The tag's length in bytes.
pub const HEADER_LEN: usize = 4;

/// A tag viewed in place: priority, drop eligibility, VLAN id
/// and the ethertype of what follows.
///
/// # Examples
/// ```
/// use mangonel_wire::data_link::ethernet::{EtherType, Vlan};
///
/// let mut tag = [0u8; 4];
/// let mut vlan = Vlan::parse(&mut tag[..])?;
/// vlan.set_id(100);
/// vlan.set_priority(5);
/// vlan.set_ethertype(EtherType::IPV4);
/// assert_eq!((vlan.id(), vlan.priority()), (100, 5));
/// assert_eq!(tag, [0xa0, 0x64, 0x08, 0x00]);
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vlan<T>(T);

impl<T: AsRef<[u8]>> Vlan<T> {
    /// Views `bytes` as a tag; fails if it is cut short.
    pub fn parse(bytes: T) -> Result<Self, Error> {
        field::need(bytes.as_ref(), HEADER_LEN)?;

        Ok(Self(bytes))
    }

    /// The bytes the view was parsed from.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// The 3-bit priority code point.
    pub fn priority(&self) -> u8 {
        self.0.as_ref()[0] >> 5
    }

    pub fn drop_eligible(&self) -> bool {
        self.0.as_ref()[0] & 0x10 != 0
    }

    /// The 12-bit VLAN identifier.
    pub fn id(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 0) & 0x0FFF
    }

    pub fn ethertype(&self) -> EtherType {
        EtherType(field::u16_at(self.0.as_ref(), 2))
    }

    /// Everything after the tag.
    pub fn payload(&self) -> &[u8] {
        &self.0.as_ref()[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Vlan<T> {
    /// Sets the priority from the low 3 bits of `priority`.
    pub fn set_priority(&mut self, priority: u8) {
        let bytes = self.0.as_mut();
        bytes[0] = (bytes[0] & 0x1F) | (priority << 5);
    }

    pub fn set_drop_eligible(&mut self, eligible: bool) {
        field::set_bits(self.0.as_mut(), 0, 0x10, eligible);
    }

    /// Sets the identifier from the low 12 bits of `id`.
    pub fn set_id(&mut self, id: u16) {
        let bytes = self.0.as_mut();
        let [high, low] = id.to_be_bytes();
        bytes[0] = (bytes[0] & 0xF0) | (high & 0x0F);
        bytes[1] = low;
    }

    pub fn set_ethertype(&mut self, ethertype: EtherType) {
        field::set_u16_at(self.0.as_mut(), 2, ethertype.0);
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
        let mut bytes = [0xFFu8; 6];
        let mut vlan = Vlan::parse(&mut bytes[..]).unwrap();
        vlan.set_id(0x123);
        vlan.set_priority(2);
        vlan.set_drop_eligible(false);
        vlan.set_ethertype(EtherType::ARP);
        assert_eq!(vlan.id(), 0x123);
        assert_eq!(vlan.priority(), 2);
        assert!(!vlan.drop_eligible());
        assert_eq!(vlan.ethertype(), EtherType::ARP);
        assert_eq!(vlan.payload(), &[0xFF, 0xFF]);
        assert_eq!(bytes[..4], [0x41, 0x23, 0x08, 0x06]);
    }
}
