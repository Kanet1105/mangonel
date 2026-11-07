//! ICMPv4 (RFC 792).

use crate::{
    Error,
    checksum,
    field,
};

/// The header's length in bytes, the type-specific word
/// included.
pub const HEADER_LEN: usize = 8;

/// The message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kind(pub u8);

impl Kind {
    pub const ECHO_REPLY: Self = Self(0);
    pub const DESTINATION_UNREACHABLE: Self = Self(3);
    pub const ECHO_REQUEST: Self = Self(8);
    pub const TIME_EXCEEDED: Self = Self(11);
    pub const PARAMETER_PROBLEM: Self = Self(12);
}

/// A message viewed in place, bounded by the bytes given.
///
/// # Examples
/// ```
/// use mangonel_wire::ipv4::{Icmp, icmp::Kind};
///
/// let mut bytes = [0u8; 16];
/// let mut icmp = Icmp::parse(&mut bytes[..])?;
/// icmp.set_kind(Kind::ECHO_REQUEST);
/// icmp.set_identifier(0x1234);
/// icmp.set_sequence(1);
/// icmp.fill_checksum();
/// assert!(icmp.verify_checksum());
/// # Ok::<(), mangonel_wire::Error>(())
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
    pub fn verify_checksum(&self) -> bool {
        checksum::finish(checksum::sum(self.0.as_ref())) == 0
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

    /// Everything after the header: echo data, or the offending
    /// packet's header in an error.
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

    /// Computes the checksum over the message and writes it.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let sum = checksum::finish(checksum::sum(self.0.as_ref()));
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
    fn echo_request_becomes_reply() {
        let mut bytes = [0u8; 12];
        let mut icmp = Icmp::parse(&mut bytes[..]).unwrap();
        icmp.set_kind(Kind::ECHO_REQUEST);
        icmp.set_identifier(0xABCD);
        icmp.set_sequence(9);
        icmp.payload_mut().copy_from_slice(b"data");
        icmp.fill_checksum();
        assert!(icmp.verify_checksum());
        let request = icmp.checksum();

        icmp.set_kind(Kind::ECHO_REPLY);
        assert!(!icmp.verify_checksum());
        let patched = checksum::update(request, &[8, 0], &[0, 0]);
        icmp.set_checksum(patched);
        assert!(icmp.verify_checksum());
        assert_eq!(icmp.rest_of_header(), 0xABCD_0009);
        assert_eq!(
            Icmp::parse(&bytes[..7]).unwrap_err(),
            Error::Truncated { needed: 8, have: 7 }
        );
    }
}
