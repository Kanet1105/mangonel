//! Wire layouts: parsing and in-place rewriting of Ethernet
//! frames carrying IPv4, with incremental checksum updates.

use std::net::Ipv4Addr;

use crate::control::{
    MacAddr,
    acl::{
        self,
        Packet,
    },
};

const ETHERTYPE_IPV4: u16 = 0x0800;
/// 802.1Q, 802.1ad, and the pre-standard QinQ TPID.
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88a8, 0x9100];
const VLAN_TAG_LEN: usize = 4;
/// Tags walked before giving up on a frame.
const MAX_VLAN_TAGS: usize = 2;
pub(crate) const ICMP: u8 = 1;
pub(crate) const TCP: u8 = 6;
pub(crate) const UDP: u8 = 17;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Tcp,

    Udp,

    /// Identifier stands in for both ports.
    IcmpEcho,

    /// Filterable, not translatable.
    Other,
}

/// The Ethernet header and its VLAN tags.
struct EthernetFrame {
    /// Where the payload starts.
    l3: usize,
    ethertype: u16,
    /// The outermost tag's ID.
    vlan: Option<u16>,
}

impl EthernetFrame {
    /// Walks the VLAN tag stack to the payload ethertype.
    fn parse(frame: &[u8]) -> Option<Self> {
        let mut at = 12;
        let mut vlan = None;
        for _ in 0..=MAX_VLAN_TAGS {
            if frame.len() < at + 2 {
                return None;
            }
            let ethertype = be16(frame, at);
            if !ETHERTYPE_VLAN.contains(&ethertype) {
                return Some(Self {
                    l3: at + 2,
                    ethertype,
                    vlan,
                });
            }
            if frame.len() < at + VLAN_TAG_LEN {
                return None;
            }
            // Twelve ID bits under the priority and DEI bits.
            vlan.get_or_insert(be16(frame, at + 2) & 0x0fff);
            at += VLAN_TAG_LEN;
        }

        None
    }
}

/// Offsets and fields of a parsed IPv4 packet, measured
/// from the start of its frame.
#[derive(Debug)]
pub(crate) struct Ipv4Packet {
    /// Past the Ethernet header and any VLAN tags.
    pub(crate) l3: usize,
    pub(crate) l4: usize,
    /// Past the packet; Ethernet padding may follow.
    pub(crate) end: usize,
    /// The outermost tag's ID, as the port sees it.
    pub(crate) vlan: Option<u16>,
    pub(crate) transport: Transport,
    pub(crate) protocol: u8,
    pub(crate) ttl: u8,
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: Ipv4Addr,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
}

impl Ipv4Packet {
    /// `None` for anything but a well-formed, unfragmented
    /// IPv4 frame with its transport header present.
    pub(crate) fn parse(frame: &[u8]) -> Option<Self> {
        let EthernetFrame {
            l3,
            ethertype,
            vlan,
        } = EthernetFrame::parse(frame)?;
        if frame.len() < l3 + 20 || ethertype != ETHERTYPE_IPV4 || frame[l3] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(frame[l3] & 0x0f) * 4;
        let total_len = usize::from(be16(frame, l3 + 2));
        if header_len < 20 || total_len < header_len || l3 + total_len > frame.len() {
            return None;
        }
        // Later fragments carry no transport header.
        if be16(frame, l3 + 6) & 0x1fff != 0 {
            return None;
        }
        let l4 = l3 + header_len;
        let end = l3 + total_len;
        let protocol = frame[l3 + 9];
        let (transport, source_port, destination_port) = transport(frame, l4, end, protocol)?;

        Some(Self {
            l3,
            l4,
            end,
            vlan,
            transport,
            protocol,
            ttl: frame[l3 + 8],
            source: Ipv4Addr::from(be32(frame, l3 + 12)),
            destination: Ipv4Addr::from(be32(frame, l3 + 16)),
            source_port,
            destination_port,
        })
    }

    /// The fields an ACL matches on.
    pub(crate) fn acl(&self, frame: &[u8]) -> Packet {
        let transport = match self.transport {
            Transport::Tcp => acl::Transport::Tcp {
                source: self.source_port,
                destination: self.destination_port,
                flags: frame[self.l4 + 13],
            },
            Transport::Udp => acl::Transport::Udp {
                source: self.source_port,
                destination: self.destination_port,
            },
            _ if self.protocol == ICMP && self.end >= self.l4 + 2 => acl::Transport::Icmp {
                kind: frame[self.l4],
                code: frame[self.l4 + 1],
            },
            _ => acl::Transport::Other(self.protocol),
        };

        Packet {
            source: self.source.into(),
            destination: self.destination.into(),
            transport,
        }
    }

    pub(crate) fn rewrite_source(&self, frame: &mut [u8], addr: Ipv4Addr, port: u16) {
        self.rewrite(
            frame,
            self.l3 + 12,
            source_port_at(self.transport, self.l4),
            addr,
            port,
        );
    }

    pub(crate) fn rewrite_destination(&self, frame: &mut [u8], addr: Ipv4Addr, port: u16) {
        self.rewrite(
            frame,
            self.l3 + 16,
            destination_port_at(self.transport, self.l4),
            addr,
            port,
        );
    }

    /// Patches one address and one port, and every checksum
    /// that covers them, incrementally.
    fn rewrite(&self, frame: &mut [u8], addr_at: usize, port_at: usize, addr: Ipv4Addr, port: u16) {
        let old_addr: [u8; 4] = frame[addr_at..addr_at + 4]
            .try_into()
            .expect("Address offset came from parse. This is a bug.");
        let old_port = [frame[port_at], frame[port_at + 1]];
        let new_addr = addr.octets();
        let new_port = port.to_be_bytes();
        update_checksum(frame, self.l3 + 10, &old_addr, &new_addr);
        match self.transport {
            Transport::Tcp => {
                update_checksum(frame, self.l4 + 16, &old_addr, &new_addr);
                update_checksum(frame, self.l4 + 16, &old_port, &new_port);
            }
            // Zero means no checksum; a computed zero is sent
            // as all ones.
            Transport::Udp if be16(frame, self.l4 + 6) != 0 => {
                update_checksum(frame, self.l4 + 6, &old_addr, &new_addr);
                update_checksum(frame, self.l4 + 6, &old_port, &new_port);
                if be16(frame, self.l4 + 6) == 0 {
                    frame[self.l4 + 6..self.l4 + 8].copy_from_slice(&[0xff, 0xff]);
                }
            }
            Transport::Udp => {}
            // No pseudo-header: only the identifier changes.
            Transport::IcmpEcho => update_checksum(frame, self.l4 + 2, &old_port, &new_port),
            Transport::Other => unreachable!("Other is dropped before translation."),
        }
        frame[addr_at..addr_at + 4].copy_from_slice(&new_addr);
        frame[port_at..port_at + 2].copy_from_slice(&new_port);
    }

    pub(crate) fn decrement_ttl(&self, frame: &mut [u8]) {
        let at = self.l3 + 8;
        let old = [frame[at], frame[at + 1]];
        let new = [frame[at] - 1, frame[at + 1]];
        update_checksum(frame, self.l3 + 10, &old, &new);
        frame[at] = new[0];
    }
}

/// The MAC fields sit ahead of any VLAN tag; panics on a
/// frame shorter than its header.
pub(crate) fn destination_mac(frame: &[u8]) -> MacAddr {
    MacAddr(
        frame[..6]
            .try_into()
            .expect("A frame is at least an Ethernet header long."),
    )
}

/// The forwarding rewrite: from us, to the next hop.
pub(crate) fn rewrite_macs(frame: &mut [u8], source: MacAddr, destination: MacAddr) {
    frame[..6].copy_from_slice(&destination.0);
    frame[6..12].copy_from_slice(&source.0);
}

/// Classifies the transport at `l4`, ending at `end`;
/// `None` when a known header is truncated.
fn transport(frame: &[u8], l4: usize, end: usize, protocol: u8) -> Option<(Transport, u16, u16)> {
    let echo = |kind: u8| matches!(kind, ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY);

    Some(match protocol {
        TCP if end >= l4 + 20 => (Transport::Tcp, be16(frame, l4), be16(frame, l4 + 2)),
        UDP if end >= l4 + 8 => (Transport::Udp, be16(frame, l4), be16(frame, l4 + 2)),
        ICMP if end >= l4 + 8 && echo(frame[l4]) => {
            let id = be16(frame, l4 + 4);
            (Transport::IcmpEcho, id, id)
        }
        TCP | UDP => return None,
        _ => (Transport::Other, 0, 0),
    })
}

fn source_port_at(transport: Transport, l4: usize) -> usize {
    match transport {
        Transport::IcmpEcho => l4 + 4,
        _ => l4,
    }
}

fn destination_port_at(transport: Transport, l4: usize) -> usize {
    match transport {
        Transport::IcmpEcho => l4 + 4,
        _ => l4 + 2,
    }
}

fn be16(frame: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([frame[at], frame[at + 1]])
}

fn be32(frame: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]])
}

/// RFC 1624: `HC' = ~(~HC + ~m + m')`, over the 16-bit
/// words of `old` and `new`, which must be the same even
/// length.
fn update_checksum(frame: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    let mut acc = u32::from(!be16(frame, at));
    for (old, new) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        acc += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        acc += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let folded = u16::try_from(acc).expect("Folded below 2^16. This is a bug.");
    frame[at..at + 2].copy_from_slice(&(!folded).to_be_bytes());
}

/// Frame builders and checksum oracles for tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Ones' complement sum; zero over data that includes a
    /// correct checksum.
    pub(crate) fn checksum(data: &[u8]) -> u16 {
        let mut acc: u32 = 0;
        for chunk in data.chunks(2) {
            acc += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }

        !u16::try_from(acc).unwrap()
    }

    fn pseudo4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, len: usize) -> Vec<u8> {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());

        pseudo
    }

    /// An IPv4 frame with correct checksums; `l4` is the
    /// transport header and payload with its checksum field
    /// zeroed, `checksum_at` that field's offset within it.
    pub(crate) fn frame4(
        (src_mac, dst_mac): (MacAddr, MacAddr),
        (source, destination): (Ipv4Addr, Ipv4Addr),
        protocol: u8,
        l4: &[u8],
        checksum_at: Option<usize>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac.0);
        frame.extend_from_slice(&src_mac.0);
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let total = u16::try_from(20 + l4.len()).unwrap();
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&destination.octets());
        let ip_sum = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_sum.to_be_bytes());
        frame.extend_from_slice(l4);
        if let Some(at) = checksum_at {
            let sum = if protocol == ICMP {
                checksum(l4)
            } else {
                let mut covered = pseudo4(source, destination, protocol, l4.len());
                covered.extend_from_slice(l4);
                checksum(&covered)
            };
            frame[34 + at..36 + at].copy_from_slice(&sum.to_be_bytes());
        }

        frame
    }

    /// Pushes a tag onto the frame's stack, outermost.
    pub(crate) fn tag(frame: &mut Vec<u8>, tpid: u16, id: u16) {
        let mut tag = tpid.to_be_bytes().to_vec();
        tag.extend_from_slice(&id.to_be_bytes());
        frame.splice(12..12, tag);
    }

    pub(crate) fn tcp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut l4 = Vec::new();
        l4.extend_from_slice(&source_port.to_be_bytes());
        l4.extend_from_slice(&destination_port.to_be_bytes());
        l4.extend_from_slice(&[0; 16]);
        l4[12] = 0x50;
        l4[13] = 0x02;
        l4.extend_from_slice(b"payload");

        l4
    }

    pub(crate) fn udp(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut l4 = Vec::new();
        l4.extend_from_slice(&source_port.to_be_bytes());
        l4.extend_from_slice(&destination_port.to_be_bytes());
        l4.extend_from_slice(&15u16.to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
        l4.extend_from_slice(b"payload");

        l4
    }

    pub(crate) fn icmp(kind: u8, id: u16) -> Vec<u8> {
        let mut l4 = vec![kind, 0, 0, 0];
        l4.extend_from_slice(&id.to_be_bytes());
        l4.extend_from_slice(&1u16.to_be_bytes());
        l4.extend_from_slice(b"ping");

        l4
    }

    pub(crate) fn assert_checksums4(frame: &[u8]) {
        let packet = Ipv4Packet::parse(frame).unwrap();
        assert_eq!(checksum(&frame[packet.l3..packet.l4]), 0, "ip checksum");
        let l4 = &frame[packet.l4..];
        match packet.protocol {
            ICMP => assert_eq!(checksum(l4), 0, "icmp checksum"),
            UDP if be16(frame, packet.l4 + 6) == 0 => {}
            protocol => {
                let mut covered = pseudo4(packet.source, packet.destination, protocol, l4.len());
                covered.extend_from_slice(l4);
                assert_eq!(checksum(&covered), 0, "transport checksum");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        testing::*,
        *,
    };

    const A_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0a]);
    const B_MAC: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x0b]);
    const V4_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const V4_B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const V4_NEW: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);

    #[test]
    fn parses_v4_fields() {
        let frame = frame4(
            (A_MAC, B_MAC),
            (V4_A, V4_B),
            TCP,
            &tcp(51000, 443),
            Some(16),
        );
        let packet = Ipv4Packet::parse(&frame).unwrap();
        assert_eq!(packet.l3, 14);
        assert_eq!(packet.l4, 34);
        assert_eq!(packet.end, frame.len());
        assert_eq!(packet.transport, Transport::Tcp);
        assert_eq!(packet.ttl, 64);
        assert_eq!((packet.source, packet.source_port), (V4_A, 51000));
        assert_eq!((packet.destination, packet.destination_port), (V4_B, 443));
    }

    #[test]
    fn rejects_malformed_v4() {
        let good = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        let mut fragment = good.clone();
        fragment[20..22].copy_from_slice(&[0x20, 0x01]);
        assert!(Ipv4Packet::parse(&fragment).is_none());
        let mut truncated = good.clone();
        truncated.truncate(14 + 20 + 10);
        assert!(Ipv4Packet::parse(&truncated).is_none());
        let mut short_header = good.clone();
        short_header[14] = 0x44;
        assert!(Ipv4Packet::parse(&short_header).is_none());
        let mut wrong_version = good.clone();
        wrong_version[14] = 0x65;
        assert!(Ipv4Packet::parse(&wrong_version).is_none());
        let gre = frame4((A_MAC, B_MAC), (V4_A, V4_B), 47, &[0; 8], None);
        assert_eq!(Ipv4Packet::parse(&gre).unwrap().transport, Transport::Other);
        assert!(Ipv4Packet::parse(&good[..10]).is_none());
    }

    #[test]
    fn rewrites_v4_with_valid_checksums() {
        for (protocol, l4, at) in [
            (TCP, tcp(51000, 443), Some(16)),
            (UDP, udp(5000, 53), Some(6)),
            (UDP, udp(5000, 53), None),
            (ICMP, icmp(ICMP_ECHO_REQUEST, 0x1234), Some(2)),
        ] {
            let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), protocol, &l4, at);
            let packet = Ipv4Packet::parse(&frame).unwrap();
            packet.rewrite_source(&mut frame, V4_NEW, 40000);
            packet.decrement_ttl(&mut frame);
            let packet = Ipv4Packet::parse(&frame).unwrap();
            assert_eq!((packet.source, packet.source_port), (V4_NEW, 40000));
            assert_eq!(packet.ttl, 63);
            assert_checksums4(&frame);
            packet.rewrite_destination(&mut frame, V4_A, 7);
            let packet = Ipv4Packet::parse(&frame).unwrap();
            assert_eq!((packet.destination, packet.destination_port), (V4_A, 7));
            assert_checksums4(&frame);
        }
    }

    #[test]
    fn builds_the_acl_view() {
        let frame = frame4(
            (A_MAC, B_MAC),
            (V4_A, V4_B),
            TCP,
            &tcp(51000, 443),
            Some(16),
        );
        let packet = Ipv4Packet::parse(&frame).unwrap().acl(&frame);
        assert_eq!(packet.source, V4_A);
        assert_eq!(packet.destination, V4_B);
        assert_eq!(
            packet.transport,
            acl::Transport::Tcp {
                source: 51000,
                destination: 443,
                flags: 0x02,
            }
        );

        // Any ICMP type is matchable, not just echo.
        let unreachable = frame4((A_MAC, B_MAC), (V4_A, V4_B), ICMP, &icmp(3, 0), Some(2));
        let packet = Ipv4Packet::parse(&unreachable).unwrap();
        assert_eq!(packet.transport, Transport::Other);
        assert_eq!(
            packet.acl(&unreachable).transport,
            acl::Transport::Icmp { kind: 3, code: 0 }
        );
    }

    #[test]
    fn walks_the_vlan_tag_stack() {
        let mut frame = frame4(
            (A_MAC, B_MAC),
            (V4_A, V4_B),
            TCP,
            &tcp(51000, 443),
            Some(16),
        );
        assert_eq!(Ipv4Packet::parse(&frame).unwrap().vlan, None);
        // Priority and DEI bits are not part of the ID.
        tag(&mut frame, 0x8100, 0xe000 | 100);
        let packet = Ipv4Packet::parse(&frame).unwrap();
        assert_eq!(packet.l3, 18);
        assert_eq!(packet.vlan, Some(100));
        assert_eq!((packet.source, packet.source_port), (V4_A, 51000));
        tag(&mut frame, 0x88a8, 7);
        let packet = Ipv4Packet::parse(&frame).unwrap();
        assert_eq!(packet.l3, 22);
        assert_eq!(packet.vlan, Some(7));
        assert_checksums4(&frame);
        tag(&mut frame, 0x9100, 9);
        assert!(Ipv4Packet::parse(&frame).is_none());
    }

    #[test]
    fn rejects_truncated_tags() {
        let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        tag(&mut frame, 0x8100, 1);
        frame.truncate(15);
        assert!(Ipv4Packet::parse(&frame).is_none());
        frame.truncate(13);
        assert!(Ipv4Packet::parse(&frame).is_none());
    }

    #[test]
    fn mac_rewrites_survive_tags() {
        let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        tag(&mut frame, 0x8100, 5);
        assert_eq!(destination_mac(&frame), B_MAC);
        let ours = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
        let next_hop = MacAddr([0x02, 0, 0, 0, 0, 0xfe]);
        rewrite_macs(&mut frame, ours, next_hop);
        assert_eq!(destination_mac(&frame), next_hop);
        assert_eq!(frame[6..12], ours.0);
        let packet = Ipv4Packet::parse(&frame).unwrap();
        assert_eq!((packet.vlan, packet.source), (Some(5), V4_A));
        assert_checksums4(&frame);
    }

    #[test]
    fn checksum_update_matches_recompute() {
        let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        let old = frame[26..30].to_vec();
        let new = V4_NEW.octets();
        update_checksum(&mut frame, 24, &old, &new);
        frame[26..30].copy_from_slice(&new);
        assert_eq!(checksum(&frame[14..34]), 0);
    }
}
