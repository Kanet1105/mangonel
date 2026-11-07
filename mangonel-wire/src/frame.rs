//! One entry point that takes a frame apart.

use crate::{
    Arp,
    Error,
    Ethernet,
    Ipv4,
    Ipv6,
    Vlan,
    ethernet,
    ethernet::EtherType,
    vlan,
};

/// What a frame carries, viewed in place.
#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Arp(Arp<&'a mut [u8]>),

    Ipv4(Ipv4<&'a mut [u8]>),

    Ipv6(Ipv6<&'a mut [u8]>),

    /// Something the crate has no view for.
    Other {
        ethertype: EtherType,
        payload: &'a mut [u8],
    },
}

/// A frame taken apart: the Ethernet header, a VLAN tag if
/// there is one, and the packet after them, each viewed in
/// place and all writable at once.
///
/// # Examples
/// ```
/// use mangonel_wire::{Packet, arp::Operation};
///
/// # let mut data = [0u8; 60];
/// # data[12..14].copy_from_slice(&[0x08, 0x06]);
/// # mangonel_wire::Arp::init(&mut data[14..])?;
/// let mut frame = mangonel_wire::parse(&mut data[..])?;
/// if let Packet::Arp(arp) = frame.packet_mut() {
///     arp.set_operation(Operation::REPLY);
/// }
/// let (dst, src) = (frame.destination(), frame.source());
/// frame.set_destination(src);
/// frame.set_source(dst);
/// # Ok::<(), mangonel_wire::Error>(())
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    ethernet: Ethernet<&'a mut [u8]>,
    vlan: Option<Vlan<&'a mut [u8]>>,
    packet: Packet<'a>,
}

/// Takes `bytes` apart as a frame; fails if any header the
/// crate knows is cut short or malformed.
pub fn parse(bytes: &mut [u8]) -> Result<Frame<'_>, Error> {
    Ethernet::parse(&bytes[..])?;
    let (header, mut rest) = bytes.split_at_mut(ethernet::HEADER_LEN);
    let ethernet = Ethernet::parse(header)?;
    let mut ethertype = ethernet.ethertype();
    let mut vlan = None;
    if ethertype == EtherType::VLAN {
        Vlan::parse(&rest[..])?;
        let (tag, after) = rest.split_at_mut(vlan::HEADER_LEN);
        let tag = Vlan::parse(tag)?;
        ethertype = tag.ethertype();
        vlan = Some(tag);
        rest = after;
    }
    let packet = match ethertype {
        EtherType::ARP => Packet::Arp(Arp::parse(rest)?),
        EtherType::IPV4 => Packet::Ipv4(Ipv4::parse(rest)?),
        EtherType::IPV6 => Packet::Ipv6(Ipv6::parse(rest)?),
        ethertype => Packet::Other {
            ethertype,
            payload: rest,
        },
    };

    Ok(Frame {
        ethernet,
        vlan,
        packet,
    })
}

impl<'a> Frame<'a> {
    pub fn destination(&self) -> [u8; 6] {
        self.ethernet.destination()
    }

    pub fn source(&self) -> [u8; 6] {
        self.ethernet.source()
    }

    /// What the packet is, past any VLAN tag.
    pub fn ethertype(&self) -> EtherType {
        self.vlan
            .as_ref()
            .map_or_else(|| self.ethernet.ethertype(), Vlan::ethertype)
    }

    pub fn set_destination(&mut self, mac: [u8; 6]) {
        self.ethernet.set_destination(mac);
    }

    pub fn set_source(&mut self, mac: [u8; 6]) {
        self.ethernet.set_source(mac);
    }

    pub fn vlan(&self) -> Option<&Vlan<&'a mut [u8]>> {
        self.vlan.as_ref()
    }

    pub fn vlan_mut(&mut self) -> Option<&mut Vlan<&'a mut [u8]>> {
        self.vlan.as_mut()
    }

    pub fn packet(&self) -> &Packet<'a> {
        &self.packet
    }

    pub fn packet_mut(&mut self) -> &mut Packet<'a> {
        &mut self.packet
    }

    /// Gives up the header views and keeps the packet.
    pub fn into_packet(self) -> Packet<'a> {
        self.packet
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::arp::Operation;

    #[test]
    fn arp_request_is_answered_through_the_frame() {
        let mut data = [0u8; 60];
        data[0..6].copy_from_slice(&[0xFF; 6]);
        data[6..12].copy_from_slice(&[2, 0, 0, 4, 0, 0]);
        data[12..14].copy_from_slice(&[0x08, 0x06]);
        let mut arp = Arp::init(&mut data[14..]).unwrap();
        arp.set_operation(Operation::REQUEST);
        arp.set_sender_mac([2, 0, 0, 4, 0, 0]);
        arp.set_sender_ip(Ipv4Addr::new(10, 0, 0, 2));
        arp.set_target_ip(Ipv4Addr::new(10, 0, 0, 1));

        let mut frame = parse(&mut data[..]).unwrap();
        assert_eq!(frame.ethertype(), EtherType::ARP);
        assert!(frame.vlan().is_none());
        let asker = frame.source();
        match frame.packet_mut() {
            Packet::Arp(arp) => {
                assert_eq!(arp.target_ip(), Ipv4Addr::new(10, 0, 0, 1));
                arp.set_operation(Operation::REPLY);
                arp.set_target_mac(asker);
                arp.set_target_ip(arp.sender_ip());
                arp.set_sender_mac([2, 0, 0, 1, 0, 2]);
                arp.set_sender_ip(Ipv4Addr::new(10, 0, 0, 1));
            }
            other => panic!("not ARP: {other:?}"),
        }
        frame.set_destination(asker);
        frame.set_source([2, 0, 0, 1, 0, 2]);
        assert_eq!(&data[..14], &[2, 0, 0, 4, 0, 0, 2, 0, 0, 1, 0, 2, 8, 6]);
        assert_eq!(&data[20..22], &[0, 2]);
        assert_eq!(&data[32..38], &[2, 0, 0, 4, 0, 0]);
    }

    #[test]
    fn vlan_tag_is_stepped_over() {
        let mut data = [0u8; 18 + 20];
        data[12..18].copy_from_slice(&[0x81, 0x00, 0x00, 0x64, 0x08, 0x00]);
        Ipv4::init(&mut data[18..]).unwrap();
        let mut frame = parse(&mut data[..]).unwrap();
        assert_eq!(frame.ethertype(), EtherType::IPV4);
        assert_eq!(frame.vlan().unwrap().id(), 100);
        frame.vlan_mut().unwrap().set_id(200);
        assert!(matches!(frame.packet(), Packet::Ipv4(ip) if ip.ttl() == 0));
        if let Packet::Ipv4(ip) = frame.packet_mut() {
            ip.set_ttl(64);
        }
        assert_eq!(data[15], 200);
        assert_eq!(data[18 + 8], 64);
    }

    #[test]
    fn unknown_and_broken_payloads() {
        let mut data = [0u8; 20];
        data[12..14].copy_from_slice(&[0x88, 0xCC]);
        let frame = parse(&mut data[..]).unwrap();
        assert!(matches!(
            frame.into_packet(),
            Packet::Other {
                ethertype: EtherType(0x88CC),
                payload
            } if payload.len() == 6
        ));
        data[12..14].copy_from_slice(&[0x86, 0xDD]);
        assert!(matches!(
            parse(&mut data[..]),
            Err(Error::Truncated { needed: 40, .. })
        ));
        assert!(matches!(
            parse(&mut data[..10]),
            Err(Error::Truncated { needed: 14, .. })
        ));
    }
}
