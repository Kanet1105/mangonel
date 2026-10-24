//! Toeplitz hashing of flow tuples, bit-compatible with NIC
//! RSS.

use std::{
    array,
    net::{SocketAddrV4, SocketAddrV6},
};

/// A Toeplitz hasher for one RSS key.
#[derive(Clone)]
pub struct Toeplitz {
    key: [u8; Self::KEY_LEN],

    /// `table[i][b]` is the hash of byte `b` at input
    /// offset `i`.
    table: Box<[[u32; 256]]>,
}

impl Default for Toeplitz {
    fn default() -> Self {
        Self::new()
    }
}

impl Toeplitz {
    pub const KEY_LEN: usize = 40;

    /// Longest input: an IPv6 address pair and port pair.
    const INPUT_LEN: usize = Self::KEY_LEN - 4;

    /// Panics if the OS cannot supply a random key.
    pub fn new() -> Self {
        let mut key = [0; Self::KEY_LEN];
        getrandom::fill(&mut key).expect("OS randomness for the Toeplitz key");

        Self::new_with_key(&key)
    }

    pub fn new_with_key(key: &[u8; Self::KEY_LEN]) -> Self {
        let table = (0..Self::INPUT_LEN)
            .map(|offset| {
                array::from_fn(|byte| {
                    (0..8)
                        .filter(|bit| byte & (0x80 >> bit) != 0)
                        .fold(0, |hash, bit| hash ^ window(key, offset * 8 + bit))
                })
            })
            .collect();

        Self { key: *key, table }
    }

    pub fn key(&self) -> &[u8; Self::KEY_LEN] {
        &self.key
    }

    /// Panics if `input` is longer than 36 bytes.
    pub fn hash(&self, input: &[u8]) -> u32 {
        assert!(input.len() <= Self::INPUT_LEN, "Toeplitz input too long");

        input
            .iter()
            .zip(&self.table)
            .fold(0, |hash, (&byte, row)| hash ^ row[usize::from(byte)])
    }

    /// Hashes the RSS 4-tuple; zero ports give the address
    /// pair hash.
    pub fn hash_v4(&self, src: SocketAddrV4, dst: SocketAddrV4) -> u32 {
        let mut input = [0; 12];
        input[..4].copy_from_slice(&src.ip().octets());
        input[4..8].copy_from_slice(&dst.ip().octets());
        input[8..10].copy_from_slice(&src.port().to_be_bytes());
        input[10..].copy_from_slice(&dst.port().to_be_bytes());

        self.hash(&input)
    }

    /// Hashes the RSS 4-tuple; zero ports give the address
    /// pair hash.
    pub fn hash_v6(&self, src: SocketAddrV6, dst: SocketAddrV6) -> u32 {
        let mut input = [0; 36];
        input[..16].copy_from_slice(&src.ip().octets());
        input[16..32].copy_from_slice(&dst.ip().octets());
        input[32..34].copy_from_slice(&src.port().to_be_bytes());
        input[34..].copy_from_slice(&dst.port().to_be_bytes());

        self.hash(&input)
    }
}

/// The 32 key bits starting at bit `start`, MSB first.
fn window(key: &[u8; Toeplitz::KEY_LEN], start: usize) -> u32 {
    let byte = start / 8;
    let shift = start % 8;
    let word = u32::from_be_bytes([key[byte], key[byte + 1], key[byte + 2], key[byte + 3]]);

    word << shift | u32::from(key[byte + 4]) >> (8 - shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key from Microsoft's RSS verification suite.
    const KEY: [u8; Toeplitz::KEY_LEN] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    /// `(src, dst, address pair hash, 4-tuple hash)`.
    const V4: [(&str, &str, u32, u32); 5] = [
        (
            "66.9.149.187:2794",
            "161.142.100.80:1766",
            0x323e8fc2,
            0x51ccc178,
        ),
        (
            "199.92.111.2:14230",
            "65.69.140.83:4739",
            0xd718262a,
            0xc626b0ea,
        ),
        (
            "24.19.198.95:12898",
            "12.22.207.184:38024",
            0xd2d0a5de,
            0x5c2b394a,
        ),
        (
            "38.27.205.30:48228",
            "209.142.163.6:2217",
            0x82989176,
            0xafc7327f,
        ),
        (
            "153.39.163.191:44251",
            "202.188.127.2:1303",
            0x5d1809c5,
            0x10e828a2,
        ),
    ];

    const V6: [(&str, &str, u32, u32); 3] = [
        (
            "[3ffe:2501:200:1fff::7]:2794",
            "[3ffe:2501:200:3::1]:1766",
            0x2cc18cd5,
            0x40207d3d,
        ),
        (
            "[3ffe:501:8::260:97ff:fe40:efab]:14230",
            "[ff02::1]:4739",
            0x0f0c461c,
            0xdde51bbf,
        ),
        (
            "[3ffe:1900:4545:3:200:f8ff:fe21:67cf]:44251",
            "[fe80::200:f8ff:fe21:67cf]:38024",
            0x4b61e985,
            0x02d1feef,
        ),
    ];

    #[test]
    fn matches_microsoft_v4_vectors() {
        let toeplitz = Toeplitz::new_with_key(&KEY);
        for (src, dst, pair, tuple) in V4 {
            let mut src: SocketAddrV4 = src.parse().unwrap();
            let mut dst: SocketAddrV4 = dst.parse().unwrap();
            assert_eq!(toeplitz.hash_v4(src, dst), tuple);

            src.set_port(0);
            dst.set_port(0);
            assert_eq!(toeplitz.hash_v4(src, dst), pair);
        }
    }

    #[test]
    fn matches_microsoft_v6_vectors() {
        let toeplitz = Toeplitz::new_with_key(&KEY);
        for (src, dst, pair, tuple) in V6 {
            let mut src: SocketAddrV6 = src.parse().unwrap();
            let mut dst: SocketAddrV6 = dst.parse().unwrap();
            assert_eq!(toeplitz.hash_v6(src, dst), tuple);

            src.set_port(0);
            dst.set_port(0);
            assert_eq!(toeplitz.hash_v6(src, dst), pair);
        }
    }

    #[test]
    fn random_key_rebuilds_same_hasher() {
        let random = Toeplitz::new();
        let rebuilt = Toeplitz::new_with_key(random.key());
        let (src, dst, ..) = V4[0];
        let (src, dst) = (src.parse().unwrap(), dst.parse().unwrap());
        assert_eq!(random.hash_v4(src, dst), rebuilt.hash_v4(src, dst));
    }

    #[test]
    #[should_panic = "too long"]
    fn rejects_input_past_key() {
        Toeplitz::new_with_key(&KEY).hash(&[0; 37]);
    }
}
