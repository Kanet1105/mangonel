//! Picking DHCPv6 out of a packet, with what `mangonel-dhcp`'s
//! `v6` handlers take alongside the message.

use std::net::Ipv6Addr;

use crate::{
    Udp,
    network::ipv6::{
        Ipv6,
        Protocol,
    },
    transport::udp,
};

pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;

/// A DHCPv6 message told apart by its destination port,
/// carrying what the matching handler takes besides the clock.
///
/// # Examples
/// ```
/// use mangonel_wire::{Packet, network::ipv6::Dhcp};
///
/// # let mut data = [0u8; 300];
/// # data[12..14].copy_from_slice(&[0x86, 0xDD]);
/// # let mut ip = mangonel_wire::Ipv6::init(&mut data[14..])?;
/// # ip.set_payload_length(246)?;
/// # ip.set_next_header(mangonel_wire::network::ipv6::Protocol::UDP);
/// # let mut udp = mangonel_wire::Udp::init(ip.payload_mut())?;
/// # udp.set_length(246)?;
/// # udp.set_destination_port(547);
/// let frame = mangonel_wire::parse(&mut data[..])?;
/// if let Packet::Ipv6(ip) = frame.packet() {
///     match ip.dhcp(frame.source()) {
///         Some(Dhcp::Server { payload, from, mac }) => {
///             /* server.handle(payload, from, mac, now) */
///             assert_eq!(payload.len(), 238);
///         }
///         Some(Dhcp::Client { payload }) => { /* client.handle(payload, now) */ }
///         None => { /* forward it */ }
///     }
/// }
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp<'a> {
    /// For `v6::server::Server::handle`, which also needs where
    /// the message came from.
    Server {
        payload: &'a [u8],
        from: Ipv6Addr,
        mac: [u8; 6],
    },

    /// For `v6::client::Client::handle`.
    Client { payload: &'a [u8] },
}

impl<T: AsRef<[u8]>> Ipv6<T> {
    /// The DHCP message the packet carries, if it carries one
    /// whole: UDP past the extension headers, bound for a DHCP
    /// port; `mac` is the frame's source, for the server.
    pub fn dhcp(&self, mac: [u8; 6]) -> Option<Dhcp<'_>> {
        let (protocol, bytes) = self.upper_layer().ok()?;
        if protocol != Protocol::UDP {
            return None;
        }
        let udp = Udp::parse(bytes).ok()?;
        let port = udp.destination_port();
        let payload = udp::payload_of(udp);

        match port {
            SERVER_PORT => Some(Dhcp::Server {
                payload,
                from: self.source(),
                mac,
            }),
            CLIENT_PORT => Some(Dhcp::Client { payload }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];

    fn packet(port: u16) -> [u8; 60] {
        let mut data = [0u8; 60];
        let mut ip = Ipv6::init(&mut data[..]).unwrap();
        ip.set_payload_length(20).unwrap();
        ip.set_next_header(Protocol::UDP);
        ip.set_source("fe80::2".parse().unwrap());
        let mut udp = Udp::init(ip.payload_mut()).unwrap();
        udp.set_length(20).unwrap();
        udp.set_destination_port(port);

        data
    }

    #[test]
    fn each_port_names_its_handler() {
        let data = packet(547);
        assert_eq!(
            Ipv6::parse(&data[..]).unwrap().dhcp(MAC),
            Some(Dhcp::Server {
                payload: &[0; 12],
                from: "fe80::2".parse().unwrap(),
                mac: MAC,
            })
        );
        let data = packet(546);
        assert!(matches!(
            Ipv6::parse(&data[..]).unwrap().dhcp(MAC),
            Some(Dhcp::Client { payload }) if payload.len() == 12
        ));
    }

    #[test]
    fn anything_else_is_none() {
        let data = packet(67);
        assert_eq!(Ipv6::parse(&data[..]).unwrap().dhcp(MAC), None);
        let mut data = packet(547);
        data[6] = Protocol::TCP.0;
        assert_eq!(Ipv6::parse(&data[..]).unwrap().dhcp(MAC), None);
        let mut data = packet(547);
        data[40 + 5] = 7;
        assert_eq!(Ipv6::parse(&data[..]).unwrap().dhcp(MAC), None);
    }
}
