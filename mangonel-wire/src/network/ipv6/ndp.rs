//! Neighbor Discovery (RFC 4861): the four ICMPv6 messages a
//! router sends and answers, each viewed over the whole
//! ICMPv6 message so the checksum stays in reach.

use std::net::Ipv6Addr;

use crate::{
    Error,
    field,
    network::ipv6::icmp::Kind,
};

/// An option's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OptionKind(pub u8);

impl OptionKind {
    pub const SOURCE_LINK_LAYER: Self = Self(1);
    pub const TARGET_LINK_LAYER: Self = Self(2);
    pub const PREFIX_INFORMATION: Self = Self(3);
    pub const REDIRECTED_HEADER: Self = Self(4);
    pub const MTU: Self = Self(5);
}

/// The options at the end of a message, yielded as type and
/// body; iteration stops at the first malformed one.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a>(&'a [u8]);

impl<'a> Options<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The link-layer address the first option of `kind`
    /// carries, if any.
    pub fn link_layer(mut self, kind: OptionKind) -> Option<[u8; 6]> {
        self.find(|(k, body)| *k == kind && body.len() >= 6)
            .map(|(_, body)| field::array_at(body, 0))
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (OptionKind, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let len = usize::from(*self.0.get(1)?) * 8;
        if len == 0 || self.0.len() < len {
            self.0 = &[];

            return None;
        }
        let (option, rest) = self.0.split_at(len);
        self.0 = rest;

        Some((OptionKind(option[0]), &option[2..]))
    }
}

/// A link-layer address option, ready to append to a message.
pub fn link_layer_option(kind: OptionKind, mac: [u8; 6]) -> [u8; 8] {
    let mut option = [kind.0, 1, 0, 0, 0, 0, 0, 0];
    option[2..].copy_from_slice(&mac);

    option
}

/// Fails unless `bytes` is a message of `kind` at least `len`
/// long.
fn check(bytes: &[u8], kind: Kind, len: usize) -> Result<(), Error> {
    field::need(bytes, len)?;
    if bytes[0] != kind.0 {
        return Err(Error::Kind {
            found: bytes[0],
            expected: kind.0,
        });
    }

    Ok(())
}

/// Zeroes `len` bytes and writes the type, leaving the rest to
/// the setters.
fn start(bytes: &mut [u8], kind: Kind, len: usize) -> Result<(), Error> {
    field::need(bytes, len)?;
    bytes[..len].fill(0);
    bytes[0] = kind.0;

    Ok(())
}

macro_rules! message {
    ($(#[$doc:meta])* $name:ident, $kind:expr, $len:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<T>(T);

        impl<T: AsRef<[u8]>> $name<T> {
            /// The fixed part's length in bytes; options follow.
            pub const HEADER_LEN: usize = $len;

            /// Views `bytes` as this message; fails on another
            /// type or a short header.
            pub fn parse(bytes: T) -> Result<Self, Error> {
                check(bytes.as_ref(), $kind, $len)?;

                Ok(Self(bytes))
            }

            /// Zeroes the fixed part and writes the type, leaving
            /// the rest to the setters.
            pub fn init(mut bytes: T) -> Result<Self, Error>
            where
                T: AsMut<[u8]>,
            {
                start(bytes.as_mut(), $kind, $len)?;

                Ok(Self(bytes))
            }

            /// The bytes the view was parsed from, the whole ICMPv6
            /// message.
            pub fn into_inner(self) -> T {
                self.0
            }

            pub fn options(&self) -> Options<'_> {
                Options(&self.0.as_ref()[$len..])
            }
        }

        impl<T: AsRef<[u8]> + AsMut<[u8]>> $name<T> {
            /// The bytes after the fixed part, for writing options.
            pub fn options_mut(&mut self) -> &mut [u8] {
                &mut self.0.as_mut()[$len..]
            }
        }
    };
}

message! {
    /// A host asking for routers, with at most a source
    /// link-layer option.
    RouterSolicitation, Kind::ROUTER_SOLICITATION, 8
}

message! {
    /// A router announcing itself and the link's parameters.
    RouterAdvertisement, Kind::ROUTER_ADVERTISEMENT, 16
}

impl<T: AsRef<[u8]>> RouterAdvertisement<T> {
    /// The hop limit hosts should use, or zero for no opinion.
    pub fn current_hop_limit(&self) -> u8 {
        self.0.as_ref()[4]
    }

    /// Whether addresses come from DHCPv6.
    pub fn managed(&self) -> bool {
        self.0.as_ref()[5] & 0x80 != 0
    }

    /// Whether other configuration comes from DHCPv6.
    pub fn other_configuration(&self) -> bool {
        self.0.as_ref()[5] & 0x40 != 0
    }

    /// How long the sender serves as a default router, in
    /// seconds; zero for not at all.
    pub fn router_lifetime(&self) -> u16 {
        field::u16_at(self.0.as_ref(), 6)
    }

    /// Milliseconds a neighbor stays reachable after
    /// confirmation; zero for no opinion.
    pub fn reachable_time(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 8)
    }

    /// Milliseconds between retransmitted solicitations; zero
    /// for no opinion.
    pub fn retransmit_timer(&self) -> u32 {
        field::u32_at(self.0.as_ref(), 12)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RouterAdvertisement<T> {
    pub fn set_current_hop_limit(&mut self, limit: u8) {
        self.0.as_mut()[4] = limit;
    }

    pub fn set_managed(&mut self, managed: bool) {
        field::set_bits(self.0.as_mut(), 5, 0x80, managed);
    }

    pub fn set_other_configuration(&mut self, other: bool) {
        field::set_bits(self.0.as_mut(), 5, 0x40, other);
    }

    pub fn set_router_lifetime(&mut self, seconds: u16) {
        field::set_u16_at(self.0.as_mut(), 6, seconds);
    }

    pub fn set_reachable_time(&mut self, millis: u32) {
        field::set_u32_at(self.0.as_mut(), 8, millis);
    }

    pub fn set_retransmit_timer(&mut self, millis: u32) {
        field::set_u32_at(self.0.as_mut(), 12, millis);
    }
}

message! {
    /// A node asking who holds the target address.
    ///
    /// # Examples
    /// ```
    /// use std::net::Ipv6Addr;
    ///
    /// use mangonel_wire::network::ipv6::ndp::{NeighborSolicitation, OptionKind, link_layer_option};
    ///
    /// let mut bytes = [0u8; 32];
    /// let mut ns = NeighborSolicitation::init(&mut bytes[..])?;
    /// ns.set_target("fe80::1".parse()?);
    /// ns.options_mut().copy_from_slice(&link_layer_option(
    ///     OptionKind::SOURCE_LINK_LAYER,
    ///     [2, 0, 0, 4, 0, 0],
    /// ));
    /// let ns = NeighborSolicitation::parse(&bytes[..])?;
    /// assert_eq!(
    ///     ns.options().link_layer(OptionKind::SOURCE_LINK_LAYER),
    ///     Some([2, 0, 0, 4, 0, 0])
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    NeighborSolicitation, Kind::NEIGHBOR_SOLICITATION, 24
}

impl<T: AsRef<[u8]>> NeighborSolicitation<T> {
    pub fn target(&self) -> Ipv6Addr {
        Ipv6Addr::from(field::array_at::<16>(self.0.as_ref(), 8))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighborSolicitation<T> {
    pub fn set_target(&mut self, target: Ipv6Addr) {
        field::set_array_at(self.0.as_mut(), 8, target.octets());
    }
}

message! {
    /// A node answering for, or announcing, the target address.
    NeighborAdvertisement, Kind::NEIGHBOR_ADVERTISEMENT, 24
}

impl<T: AsRef<[u8]>> NeighborAdvertisement<T> {
    /// Whether the sender is a router.
    pub fn router(&self) -> bool {
        self.0.as_ref()[4] & 0x80 != 0
    }

    /// Whether this answers a solicitation.
    pub fn solicited(&self) -> bool {
        self.0.as_ref()[4] & 0x40 != 0
    }

    /// Whether the link-layer option should replace a cached one.
    pub fn override_cache(&self) -> bool {
        self.0.as_ref()[4] & 0x20 != 0
    }

    pub fn target(&self) -> Ipv6Addr {
        Ipv6Addr::from(field::array_at::<16>(self.0.as_ref(), 8))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NeighborAdvertisement<T> {
    pub fn set_router(&mut self, router: bool) {
        field::set_bits(self.0.as_mut(), 4, 0x80, router);
    }

    pub fn set_solicited(&mut self, solicited: bool) {
        field::set_bits(self.0.as_mut(), 4, 0x40, solicited);
    }

    pub fn set_override_cache(&mut self, over: bool) {
        field::set_bits(self.0.as_mut(), 4, 0x20, over);
    }

    pub fn set_target(&mut self, target: Ipv6Addr) {
        field::set_array_at(self.0.as_mut(), 8, target.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ipv6::Icmp;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn solicitation_is_answered_in_place() {
        let (asker, router) = (addr("fe80::2"), addr("fe80::1"));
        let mut bytes = [0u8; 32];
        let mut ns = NeighborSolicitation::init(&mut bytes[..]).unwrap();
        ns.set_target(router);
        ns.options_mut().copy_from_slice(&link_layer_option(
            OptionKind::SOURCE_LINK_LAYER,
            [2, 0, 0, 4, 0, 0],
        ));
        Icmp::parse(&mut bytes[..])
            .unwrap()
            .fill_checksum(asker, addr("ff02::1:ff00:1"));

        let ns = NeighborSolicitation::parse(&bytes[..]).unwrap();
        assert_eq!(ns.target(), router);
        let asker_mac = ns
            .options()
            .link_layer(OptionKind::SOURCE_LINK_LAYER)
            .unwrap();
        assert_eq!(asker_mac, [2, 0, 0, 4, 0, 0]);
        assert_eq!(
            NeighborAdvertisement::parse(&bytes[..]),
            Err(Error::Kind {
                found: 135,
                expected: 136
            })
        );

        let mut na = NeighborAdvertisement::init(&mut bytes[..]).unwrap();
        na.set_router(true);
        na.set_solicited(true);
        na.set_override_cache(true);
        na.set_target(router);
        na.options_mut().copy_from_slice(&link_layer_option(
            OptionKind::TARGET_LINK_LAYER,
            [2, 0, 0, 1, 0, 2],
        ));
        let mut icmp = Icmp::parse(&mut bytes[..]).unwrap();
        icmp.fill_checksum(router, asker);
        assert_eq!(icmp.kind(), Kind::NEIGHBOR_ADVERTISEMENT);
        assert!(icmp.verify_checksum(router, asker));
        let na = NeighborAdvertisement::parse(&bytes[..]).unwrap();
        assert!(na.router() && na.solicited() && na.override_cache());
        assert_eq!(bytes[4], 0xE0);
        assert_eq!(
            na.options().collect::<Vec<_>>(),
            vec![(OptionKind::TARGET_LINK_LAYER, &[2, 0, 0, 1, 0, 2][..])]
        );
    }

    #[test]
    fn router_advertisement_fields() {
        let mut bytes = [0u8; 24];
        let mut ra = RouterAdvertisement::init(&mut bytes[..]).unwrap();
        ra.set_current_hop_limit(64);
        ra.set_managed(true);
        ra.set_other_configuration(true);
        ra.set_router_lifetime(1800);
        ra.set_reachable_time(30_000);
        ra.set_retransmit_timer(1000);
        ra.options_mut().copy_from_slice(&link_layer_option(
            OptionKind::SOURCE_LINK_LAYER,
            [2, 0, 0, 1, 0, 2],
        ));
        let ra = RouterAdvertisement::parse(&bytes[..]).unwrap();
        assert_eq!(ra.current_hop_limit(), 64);
        assert!(ra.managed() && ra.other_configuration());
        assert_eq!(ra.router_lifetime(), 1800);
        assert_eq!(ra.reachable_time(), 30_000);
        assert_eq!(ra.retransmit_timer(), 1000);
        assert_eq!(ra.options().link_layer(OptionKind::TARGET_LINK_LAYER), None);
        assert!(RouterSolicitation::parse(&bytes[..]).is_err());
    }

    #[test]
    fn malformed_options_end_iteration() {
        let zero_length = [1, 0, 2, 0, 0, 4, 0, 0];
        assert_eq!(Options::new(&zero_length).count(), 0);
        let truncated = [1, 2, 2, 0, 0, 4, 0, 0];
        assert_eq!(Options::new(&truncated).count(), 0);
        let two = [5, 1, 0, 0, 0, 0, 5, 0xDC, 1, 1, 2, 0, 0, 4, 0, 0, 7];
        let options: Vec<_> = Options::new(&two).collect();
        assert_eq!(options[0], (OptionKind::MTU, &[0, 0, 0, 0, 5, 0xDC][..]));
        assert_eq!(options[1].0, OptionKind::SOURCE_LINK_LAYER);
        assert_eq!(options.len(), 2);
    }
}
