//! DHCPv4 (RFC 2131): a [`server`] for one subnet's pool
//! and a [`client`] for one interface.

pub mod client;
pub mod server;

use std::{
    net::Ipv4Addr,
    time::Duration,
};

pub use dhcproto::v4::{
    CLIENT_PORT,
    SERVER_PORT,
};
use dhcproto::v4::{
    DhcpOption,
    HType,
    Message,
    OptionCode,
};

/// Addresses a pool scan examines before giving up.
pub(crate) const SCAN_LIMIT: u32 = 1 << 16;

/// The Ethernet address a message carries, if it carries one.
pub(crate) fn mac_of(msg: &Message) -> Option<[u8; 6]> {
    if msg.htype() != HType::Eth || msg.hlen() != 6 {
        return None;
    }

    msg.chaddr().get(..6)?.try_into().ok()
}

/// The client identifier option, or the one RFC 2132 derives from the MAC.
pub(crate) fn client_id_of(msg: &Message, mac: [u8; 6]) -> Vec<u8> {
    match msg.opts().get(OptionCode::ClientIdentifier) {
        Some(DhcpOption::ClientIdentifier(id)) if !id.is_empty() => id.clone(),
        _ => default_client_id(mac),
    }
}

/// Hardware type 1 followed by the MAC, as RFC 2132 section 9.14 lays out.
pub(crate) fn default_client_id(mac: [u8; 6]) -> Vec<u8> {
    let mut id = Vec::with_capacity(7);
    id.push(1);
    id.extend_from_slice(&mac);

    id
}

pub(crate) fn requested_ip_of(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    }
}

pub(crate) fn server_id_of(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

pub(crate) fn hostname_of(msg: &Message) -> Option<String> {
    match msg.opts().get(OptionCode::Hostname) {
        Some(DhcpOption::Hostname(name)) => Some(name.clone()),
        _ => None,
    }
}

/// The subnet mask of a prefix length.
pub(crate) fn mask(prefix: u8) -> Ipv4Addr {
    match prefix {
        0 => Ipv4Addr::UNSPECIFIED,
        32.. => Ipv4Addr::BROADCAST,
        n => Ipv4Addr::from(u32::MAX << (32 - u32::from(n))),
    }
}

/// The prefix length of a contiguous mask.
pub(crate) fn prefix_of(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let prefix = u8::try_from(bits.leading_ones()).ok()?;
    (self::mask(prefix) == mask).then_some(prefix)
}

pub(crate) fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    (u32::from(a) ^ u32::from(b)) & u32::from(mask(prefix)) == 0
}

/// Whole seconds, saturating at what the wire can carry.
pub(crate) fn seconds(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_round_trip() {
        for prefix in 0..=32 {
            assert_eq!(prefix_of(mask(prefix)), Some(prefix));
        }
        assert_eq!(mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_of(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn subnet_membership() {
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        assert!(same_subnet(gw, Ipv4Addr::new(10, 0, 0, 200), 24));
        assert!(!same_subnet(gw, Ipv4Addr::new(10, 0, 1, 1), 24));
        assert!(same_subnet(gw, Ipv4Addr::new(10, 0, 1, 1), 16));
    }
}
