//! What an IP packet carries.

use crate::{
    Icmpv4,
    Icmpv6,
    Protocol,
    Tcp,
    Udp,
};

/// A transport header viewed in place, chosen by the IP
/// protocol number.
#[derive(Debug, PartialEq, Eq)]
pub enum Transport<T> {
    Udp(Udp<T>),

    Tcp(Tcp<T>),

    Icmpv4(Icmpv4<T>),

    Icmpv6(Icmpv6<T>),

    /// Something the crate has no view for, or a later
    /// fragment whose transport header is in the first.
    Other {
        protocol: Protocol,
        payload: T,
    },
}

impl<T: AsRef<[u8]>> Transport<T> {
    /// Views `bytes` by `protocol`; fails as the chosen view's
    /// `parse` does.
    pub fn parse(protocol: Protocol, bytes: T) -> Result<Self, crate::Error> {
        Ok(match protocol {
            Protocol::UDP => Self::Udp(Udp::parse(bytes)?),
            Protocol::TCP => Self::Tcp(Tcp::parse(bytes)?),
            Protocol::ICMP => Self::Icmpv4(Icmpv4::parse(bytes)?),
            Protocol::ICMPV6 => Self::Icmpv6(Icmpv6::parse(bytes)?),
            protocol => Self::Other {
                protocol,
                payload: bytes,
            },
        })
    }
}
