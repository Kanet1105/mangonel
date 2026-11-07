/// Why bytes could not be viewed as a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{needed} bytes needed but {have} given")]
    Truncated { needed: usize, have: usize },

    #[error("IP version {found} where {expected} was expected")]
    Version { found: u8, expected: u8 },

    #[error("ICMP type {found} where {expected} was expected")]
    Kind { found: u8, expected: u8 },

    #[error("header length {0} is shorter than the fixed header")]
    HeaderLength(usize),

    #[error("length field {0} does not fit the header or the bytes given")]
    Length(usize),

    #[error("ARP for something other than IPv4 over Ethernet")]
    NotEthernetIpv4,
}
