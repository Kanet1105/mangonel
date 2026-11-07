//! Picking DHCP out of a frame, with what `mangonel-dhcp`'s
//! handlers take alongside the message.

use std::net::Ipv6Addr;

use crate::{
    Frame,
    Packet,
    Transport,
    Udp,
    udp,
};

pub const V4_SERVER_PORT: u16 = 67;
pub const V4_CLIENT_PORT: u16 = 68;
pub const V6_CLIENT_PORT: u16 = 546;
pub const V6_SERVER_PORT: u16 = 547;

/// A DHCP message told apart by its destination port, carrying
/// what the matching `mangonel-dhcp` handler takes besides the
/// clock.
///
/// # Examples
/// ```
/// use mangonel_wire::Dhcp;
///
/// # let mut data = [0u8; 300];
/// # data[12..14].copy_from_slice(&[0x08, 0x00]);
/// # let mut ip = mangonel_wire::Ipv4::init(&mut data[14..])?;
/// # ip.set_total_length(286)?;
/// # ip.set_protocol(mangonel_wire::Protocol::UDP);
/// # let mut udp = mangonel_wire::Udp::init(ip.payload_mut())?;
/// # udp.set_length(266)?;
/// # udp.set_destination_port(67);
/// let frame = mangonel_wire::parse(&mut data[..])?;
/// match frame.dhcp() {
///     Some(Dhcp::V4Server { payload }) => assert_eq!(payload.len(), 258),
///     Some(Dhcp::V6Server { payload, from, mac }) => { /* server.handle(payload, from, mac, now) */ }
///     Some(Dhcp::V4Client { .. } | Dhcp::V6Client { .. }) => { /* client.handle(payload, now) */ }
///     None => { /* forward it */ }
/// }
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp<'a> {
    /// For `v4::server::Server::handle`.
    V4Server { payload: &'a [u8] },

    /// For `v4::client::Client::handle`.
    V4Client { payload: &'a [u8] },

    /// For `v6::server::Server::handle`, which also needs where
    /// the message came from.
    V6Server {
        payload: &'a [u8],
        from: Ipv6Addr,
        mac: [u8; 6],
    },

    /// For `v6::client::Client::handle`.
    V6Client { payload: &'a [u8] },
}

impl Frame<'_> {
    /// The DHCP message the frame carries, if it carries one
    /// the crate can hand over whole.
    pub fn dhcp(&self) -> Option<Dhcp<'_>> {
        match self.packet() {
            Packet::Ipv4(ip) => {
                let Transport::Udp(udp) = ip.transport().ok()? else {
                    return None;
                };

                match udp.destination_port() {
                    V4_SERVER_PORT => Some(Dhcp::V4Server {
                        payload: payload_of(udp),
                    }),
                    V4_CLIENT_PORT => Some(Dhcp::V4Client {
                        payload: payload_of(udp),
                    }),
                    _ => None,
                }
            }
            Packet::Ipv6(ip) => {
                let Transport::Udp(udp) = ip.transport().ok()? else {
                    return None;
                };

                match udp.destination_port() {
                    V6_SERVER_PORT => Some(Dhcp::V6Server {
                        payload: payload_of(udp),
                        from: ip.source(),
                        mac: self.source(),
                    }),
                    V6_CLIENT_PORT => Some(Dhcp::V6Client {
                        payload: payload_of(udp),
                    }),
                    _ => None,
                }
            }
            Packet::Arp(_) | Packet::Other { .. } => None,
        }
    }
}

/// The payload with the lifetime of the bytes rather than of
/// the view.
fn payload_of(udp: Udp<&[u8]>) -> &[u8] {
    let end = usize::from(udp.length());

    &udp.into_inner()[udp::HEADER_LEN..end]
}

impl<T: AsRef<[u8]>> Udp<T> {
    /// Whether the datagram is bound for any DHCP port.
    pub fn is_dhcp(&self) -> bool {
        matches!(
            self.destination_port(),
            V4_SERVER_PORT | V4_CLIENT_PORT | V6_CLIENT_PORT | V6_SERVER_PORT
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Ipv4,
        Ipv6,
        Protocol,
        parse,
    };

    fn v4_frame(port: u16) -> [u8; 60] {
        let mut data = [0u8; 60];
        data[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut ip = Ipv4::init(&mut data[14..]).unwrap();
        ip.set_total_length(40).unwrap();
        ip.set_protocol(Protocol::UDP);
        let mut udp = Udp::init(ip.payload_mut()).unwrap();
        udp.set_length(20).unwrap();
        udp.set_destination_port(port);
        udp.payload_mut().fill(0xAB);

        data
    }

    fn v6_frame(port: u16) -> [u8; 80] {
        let mut data = [0u8; 80];
        data[6..12].copy_from_slice(&[2, 0, 0, 4, 0, 0]);
        data[12..14].copy_from_slice(&[0x86, 0xDD]);
        let mut ip = Ipv6::init(&mut data[14..]).unwrap();
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
        let mut data = v4_frame(67);
        let frame = parse(&mut data[..]).unwrap();
        assert_eq!(
            frame.dhcp(),
            Some(Dhcp::V4Server {
                payload: &[0xAB; 12]
            })
        );
        let mut data = v4_frame(68);
        assert!(matches!(
            parse(&mut data[..]).unwrap().dhcp(),
            Some(Dhcp::V4Client { payload }) if payload.len() == 12
        ));
        let mut data = v6_frame(547);
        let frame = parse(&mut data[..]).unwrap();
        assert_eq!(
            frame.dhcp(),
            Some(Dhcp::V6Server {
                payload: &[0; 12],
                from: "fe80::2".parse().unwrap(),
                mac: [2, 0, 0, 4, 0, 0],
            })
        );
        let mut data = v6_frame(546);
        assert!(matches!(
            parse(&mut data[..]).unwrap().dhcp(),
            Some(Dhcp::V6Client { .. })
        ));
    }

    #[test]
    fn anything_else_is_none() {
        let mut data = v4_frame(547);
        assert_eq!(parse(&mut data[..]).unwrap().dhcp(), None);
        let mut data = v6_frame(67);
        assert_eq!(parse(&mut data[..]).unwrap().dhcp(), None);
        let mut data = v4_frame(67);
        data[14 + 9] = Protocol::TCP.0;
        assert_eq!(parse(&mut data[..]).unwrap().dhcp(), None);
        let mut data = v4_frame(67);
        data[14 + 20 + 5] = 7;
        assert_eq!(parse(&mut data[..]).unwrap().dhcp(), None);
        let mut data = [0u8; 60];
        data[12..14].copy_from_slice(&[0x08, 0x06]);
        crate::Arp::init(&mut data[14..]).unwrap();
        assert_eq!(parse(&mut data[..]).unwrap().dhcp(), None);
        let dns = v4_frame(53);
        assert!(!Udp::parse(&dns[34..]).unwrap().is_dhcp());
    }
}
