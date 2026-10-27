//! DHCPv6 (RFC 8415): a stateful [`server`] for one link's
//! pool and a [`client`] for one interface.

pub mod client;
pub mod server;

use std::{
    net::Ipv6Addr,
    time::Duration,
};

pub use dhcproto::v6::{
    CLIENT_PORT,
    SERVER_PORT,
};
use dhcproto::v6::{
    DhcpOption,
    IAAddr,
    IANA,
    Message,
    OptionCode,
    Status,
};

/// All_DHCP_Relay_Agents_and_Servers, where clients send.
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Addresses a pool scan examines before giving up.
pub(crate) const SCAN_LIMIT: u128 = 1 << 16;

/// DUID-LL (RFC 8415 section 11.4) over an Ethernet address.
pub(crate) fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut duid = vec![0, 3, 0, 1];
    duid.extend_from_slice(&mac);

    duid
}

pub(crate) fn client_id_of(msg: &Message) -> Option<&[u8]> {
    match msg.opts().get(OptionCode::ClientId) {
        Some(DhcpOption::ClientId(id)) if !id.is_empty() => Some(id),
        _ => None,
    }
}

pub(crate) fn server_id_of(msg: &Message) -> Option<&[u8]> {
    match msg.opts().get(OptionCode::ServerId) {
        Some(DhcpOption::ServerId(id)) if !id.is_empty() => Some(id),
        _ => None,
    }
}

/// Every IA_NA the message carries.
pub(crate) fn ianas(msg: &Message) -> impl Iterator<Item = &IANA> {
    msg.opts()
        .get_all(OptionCode::IANA)
        .unwrap_or(&[])
        .iter()
        .filter_map(|opt| match opt {
            DhcpOption::IANA(ia) => Some(ia),
            _ => None,
        })
}

/// Every address inside an IA_NA.
pub(crate) fn addresses(ia: &IANA) -> impl Iterator<Item = &IAAddr> {
    ia.opts
        .get_all(OptionCode::IAAddr)
        .unwrap_or(&[])
        .iter()
        .filter_map(|opt| match opt {
            DhcpOption::IAAddr(addr) => Some(addr),
            _ => None,
        })
}

/// The status an IA_NA carries, success when it carries none.
pub(crate) fn status_of(ia: &IANA) -> Status {
    match ia.opts.get(OptionCode::StatusCode) {
        Some(DhcpOption::StatusCode(code)) => code.status,
        _ => Status::Success,
    }
}

pub(crate) fn dns_of(msg: &Message) -> Vec<Ipv6Addr> {
    match msg.opts().get(OptionCode::DomainNameServers) {
        Some(DhcpOption::DomainNameServers(servers)) => servers.clone(),
        _ => Vec::new(),
    }
}

pub(crate) fn in_prefix(address: Ipv6Addr, prefix: Ipv6Addr, len: u8) -> bool {
    let mask = match len {
        0 => 0,
        128.. => u128::MAX,
        n => u128::MAX << (128 - u32::from(n)),
    };

    (u128::from(address) ^ u128::from(prefix)) & mask == 0
}

/// Whole seconds, saturating at what the wire can carry.
pub(crate) fn seconds(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duid_and_prefix() {
        assert_eq!(
            duid_ll([1, 2, 3, 4, 5, 6]),
            vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6]
        );
        let prefix: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        assert!(in_prefix("2001:db8:1::10".parse().unwrap(), prefix, 64));
        assert!(!in_prefix("2001:db8:2::10".parse().unwrap(), prefix, 64));
    }
}
