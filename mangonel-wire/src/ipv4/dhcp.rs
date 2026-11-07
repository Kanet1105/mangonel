//! Picking DHCPv4 out of a packet, with what `mangonel-dhcp`'s
//! `v4` handlers take alongside the message.

use crate::{
    Udp,
    ipv4::{
        Ipv4,
        Protocol,
    },
    udp,
};

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

/// A DHCPv4 message told apart by its destination port,
/// carrying what the matching handler takes besides the clock.
///
/// # Examples
/// ```
/// use mangonel_wire::{Packet, ipv4::Dhcp};
///
/// # let mut data = [0u8; 300];
/// # data[12..14].copy_from_slice(&[0x08, 0x00]);
/// # let mut ip = mangonel_wire::Ipv4::init(&mut data[14..])?;
/// # ip.set_total_length(286)?;
/// # ip.set_protocol(mangonel_wire::ipv4::Protocol::UDP);
/// # let mut udp = mangonel_wire::Udp::init(ip.payload_mut())?;
/// # udp.set_length(266)?;
/// # udp.set_destination_port(67);
/// let frame = mangonel_wire::parse(&mut data[..])?;
/// if let Packet::Ipv4(ip) = frame.packet() {
///     match ip.dhcp() {
///         Some(Dhcp::Server { payload }) => assert_eq!(payload.len(), 258),
///         Some(Dhcp::Client { payload }) => { /* client.handle(payload, now) */ }
///         None => { /* forward it */ }
///     }
/// }
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcp<'a> {
    /// For `v4::server::Server::handle`.
    Server { payload: &'a [u8] },

    /// For `v4::client::Client::handle`.
    Client { payload: &'a [u8] },
}

impl<T: AsRef<[u8]>> Ipv4<T> {
    /// The DHCP message the packet carries, if it carries one
    /// whole: UDP, not a fragment, bound for a DHCP port.
    pub fn dhcp(&self) -> Option<Dhcp<'_>> {
        if self.protocol() != Protocol::UDP || self.is_fragment() {
            return None;
        }
        let udp = Udp::parse(self.payload()).ok()?;
        let port = udp.destination_port();
        let payload = udp::payload_of(udp);

        match port {
            SERVER_PORT => Some(Dhcp::Server { payload }),
            CLIENT_PORT => Some(Dhcp::Client { payload }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(port: u16) -> [u8; 46] {
        let mut data = [0u8; 46];
        let mut ip = Ipv4::init(&mut data[..]).unwrap();
        ip.set_total_length(40).unwrap();
        ip.set_protocol(Protocol::UDP);
        let mut udp = Udp::init(ip.payload_mut()).unwrap();
        udp.set_length(20).unwrap();
        udp.set_destination_port(port);
        udp.payload_mut().fill(0xAB);

        data
    }

    #[test]
    fn each_port_names_its_handler() {
        let data = packet(67);
        assert_eq!(
            Ipv4::parse(&data[..]).unwrap().dhcp(),
            Some(Dhcp::Server {
                payload: &[0xAB; 12]
            })
        );
        let data = packet(68);
        assert_eq!(
            Ipv4::parse(&data[..]).unwrap().dhcp(),
            Some(Dhcp::Client {
                payload: &[0xAB; 12]
            })
        );
    }

    #[test]
    fn anything_else_is_none() {
        let data = packet(547);
        assert_eq!(Ipv4::parse(&data[..]).unwrap().dhcp(), None);
        let mut data = packet(67);
        data[9] = Protocol::TCP.0;
        assert_eq!(Ipv4::parse(&data[..]).unwrap().dhcp(), None);
        let mut data = packet(67);
        data[20 + 5] = 7;
        assert_eq!(Ipv4::parse(&data[..]).unwrap().dhcp(), None);
        let mut data = packet(67);
        data[7] = 1;
        assert_eq!(Ipv4::parse(&data[..]).unwrap().dhcp(), None);
    }
}
