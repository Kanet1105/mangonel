//! Big-endian field access shared by every view.

use crate::Error;

/// Fails unless `bytes` holds at least `needed`.
pub(crate) fn need(bytes: &[u8], needed: usize) -> Result<(), Error> {
    if bytes.len() < needed {
        return Err(Error::Truncated {
            needed,
            have: bytes.len(),
        });
    }

    Ok(())
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

pub(crate) fn set_u16_at(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn set_u32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn array_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[at..at + N]);

    out
}

pub(crate) fn set_array_at<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
    bytes[at..at + N].copy_from_slice(&value);
}

/// Sets or clears `mask` in the byte at `at`.
pub(crate) fn set_bits(bytes: &mut [u8], at: usize, mask: u8, on: bool) {
    if on {
        bytes[at] |= mask;
    } else {
        bytes[at] &= !mask;
    }
}
