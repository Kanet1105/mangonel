//! The Internet checksum (RFC 1071) and its incremental
//! update (RFC 1624).

use std::net::IpAddr;

/// The 16-bit big-endian words of `data`, the odd byte padded.
fn words(data: &[u8]) -> impl Iterator<Item = u16> {
    let chunks = data.chunks_exact(2);
    let last = chunks.remainder().first().map(|byte| u16::from(*byte) << 8);

    chunks
        .map(|word| u16::from_be_bytes([word[0], word[1]]))
        .chain(last)
}

/// The unfolded sum of `data`, for at most 128 KiB.
pub fn sum(data: &[u8]) -> u32 {
    words(data).map(u32::from).sum()
}

/// Folds a sum and complements it into a checksum field.
pub fn finish(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let folded = u16::try_from(sum).expect("a folded sum fits in 16 bits. This is a bug.");

    !folded
}

/// The sum a transport checksum starts from.
pub fn pseudo_header(src: IpAddr, dst: IpAddr, protocol: u8, length: usize) -> u32 {
    let length = u32::try_from(length).expect("a packet is shorter than 4 GiB. This is a bug.");
    let addresses = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => sum(&src.octets()) + sum(&dst.octets()),
        (IpAddr::V6(src), IpAddr::V6(dst)) => sum(&src.octets()) + sum(&dst.octets()),
        _ => panic!("a pseudo-header mixes address families. This is a bug."),
    };

    addresses + (length >> 16) + (length & 0xFFFF) + u32::from(protocol)
}

/// `checksum` after the bytes `old` became `new`.
pub fn update(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let unchanged = u32::from(!checksum);
    let removed: u32 = words(old).map(|word| u32::from(!word)).sum();

    finish(unchanged + removed + sum(new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(sum(&data), 0x2ddf0);
        assert_eq!(finish(sum(&data)), 0x220d);
        // A message carrying its own checksum sums to all ones.
        let mut carried = data.to_vec();
        carried.extend_from_slice(&0x220du16.to_be_bytes());
        assert_eq!(finish(sum(&carried)), 0);
    }

    #[test]
    fn odd_lengths_pad_with_zero() {
        assert_eq!(sum(&[0xAB]), 0xAB00);
        assert_eq!(sum(&[0xAB, 0xCD, 0xEF]), 0xABCD + 0xEF00);
    }

    #[test]
    fn update_matches_recomputing() {
        let mut data = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0, 0,
        ];
        let before = finish(sum(&data));
        let old = [data[8], data[9]];
        data[8] = 63;
        let new = [data[8], data[9]];
        assert_eq!(update(before, &old, &new), finish(sum(&data)));
        assert_eq!(update(before, &old[..1], &[63]), update(before, &old, &new));
    }
}
