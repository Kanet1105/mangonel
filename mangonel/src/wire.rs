//! Wire layouts: parsing and in-place rewriting of Ethernet
//! frames and the IPv4 and IPv6 packets they carry, with
//! incremental checksum updates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Mac = [u8; 6];

pub const ETHERNET_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// 802.1Q, 802.1ad, and the pre-standard QinQ TPID.
pub const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88a8, 0x9100];
const VLAN_TAG_LEN: usize = 4;
/// Tags walked before giving up on a frame.
const MAX_VLAN_TAGS: usize = 2;
pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMPV6: u8 = 58;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// The fields a packet is filtered and tracked on. Ports
/// are zero for protocols without them; `protocol` is the
/// IPv4 protocol or the IPv6 next header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// Identifier stands in for both ports.
    IcmpEcho,
    /// Filterable, not translatable.
    Other,
}

/// Either family, by ethertype.
pub enum Frame {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

impl Frame {
    pub fn parse(frame: &[u8]) -> Option<Self> {
        let ethernet = EthernetFrame::parse(frame)?;
        match ethernet.ethertype {
            ETHERTYPE_IPV4 => Ipv4Packet::parse(frame, ethernet).map(Self::V4),
            ETHERTYPE_IPV6 => Ipv6Packet::parse(frame, ethernet).map(Self::V6),
            _ => None,
        }
    }

    pub fn tuple(&self) -> Tuple {
        match self {
            Self::V4(frame) => frame.tuple(),
            Self::V6(frame) => frame.tuple(),
        }
    }
}

/// The Ethernet header and its VLAN tags, parsed once and
/// handed to the family parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetFrame {
    /// Where the payload starts.
    pub l3: usize,
    pub ethertype: u16,
    /// The outermost tag's ID.
    pub vlan: Option<u16>,
}

impl EthernetFrame {
    /// Walks the VLAN tag stack to the payload ethertype.
    pub fn parse(frame: &[u8]) -> Option<Self> {
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
pub struct Ipv4Packet {
    /// Past the Ethernet header and any VLAN tags.
    pub l3: usize,
    pub l4: usize,
    /// The outermost tag's ID, as the port sees it.
    pub vlan: Option<u16>,
    pub transport: Transport,
    pub protocol: u8,
    pub ttl: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

impl Ipv4Packet {
    /// `None` for anything but a well-formed, unfragmented
    /// IPv4 frame with its transport header present.
    /// `ethernet` is `frame`'s own parsed header.
    pub fn parse(frame: &[u8], ethernet: EthernetFrame) -> Option<Self> {
        let EthernetFrame {
            l3,
            ethertype,
            vlan,
        } = ethernet;
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
        let echo = |kind: u8| matches!(kind, ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY);
        let (transport, source_port, destination_port) =
            transport(frame, l4, end, protocol, ICMP, echo)?;

        Some(Self {
            l3,
            l4,
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

    pub fn tuple(&self) -> Tuple {
        Tuple {
            source: self.source.into(),
            destination: self.destination.into(),
            protocol: self.protocol,
            source_port: self.source_port,
            destination_port: self.destination_port,
        }
    }

    pub fn rewrite_source(&self, frame: &mut [u8], addr: Ipv4Addr, port: u16) {
        self.rewrite(
            frame,
            self.l3 + 12,
            source_port_at(self.transport, self.l4),
            addr,
            port,
        );
    }

    pub fn rewrite_destination(&self, frame: &mut [u8], addr: Ipv4Addr, port: u16) {
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

    pub fn decrement_ttl(&self, frame: &mut [u8]) {
        let at = self.l3 + 8;
        let old = [frame[at], frame[at + 1]];
        let new = [frame[at] - 1, frame[at + 1]];
        update_checksum(frame, self.l3 + 10, &old, &new);
        frame[at] = new[0];
    }
}

/// Offsets and fields of a parsed IPv6 packet, measured
/// from the start of its frame.
#[derive(Debug)]
pub struct Ipv6Packet {
    /// Past the Ethernet header and any VLAN tags.
    pub l3: usize,
    pub l4: usize,
    /// The outermost tag's ID, as the port sees it.
    pub vlan: Option<u16>,
    pub transport: Transport,
    /// The next header; extension headers count as `Other`.
    pub protocol: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

impl Ipv6Packet {
    /// `None` for anything but a well-formed IPv6 frame
    /// whose transport header, if any, follows the fixed
    /// header directly. `ethernet` is `frame`'s own parsed
    /// header.
    pub fn parse(frame: &[u8], ethernet: EthernetFrame) -> Option<Self> {
        let EthernetFrame {
            l3,
            ethertype,
            vlan,
        } = ethernet;
        if frame.len() < l3 + 40 || ethertype != ETHERTYPE_IPV6 || frame[l3] >> 4 != 6 {
            return None;
        }
        let l4 = l3 + 40;
        let end = l4 + usize::from(be16(frame, l3 + 4));
        if end > frame.len() {
            return None;
        }
        let protocol = frame[l3 + 6];
        let echo = |kind: u8| matches!(kind, ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY);
        let (transport, source_port, destination_port) =
            transport(frame, l4, end, protocol, ICMPV6, echo)?;

        Some(Self {
            l3,
            l4,
            vlan,
            transport,
            protocol,
            hop_limit: frame[l3 + 7],
            source: Ipv6Addr::from(be128(frame, l3 + 8)),
            destination: Ipv6Addr::from(be128(frame, l3 + 24)),
            source_port,
            destination_port,
        })
    }

    pub fn tuple(&self) -> Tuple {
        Tuple {
            source: self.source.into(),
            destination: self.destination.into(),
            protocol: self.protocol,
            source_port: self.source_port,
            destination_port: self.destination_port,
        }
    }

    pub fn rewrite_source(&self, frame: &mut [u8], addr: Ipv6Addr, port: u16) {
        self.rewrite(
            frame,
            self.l3 + 8,
            source_port_at(self.transport, self.l4),
            addr,
            port,
        );
    }

    pub fn rewrite_destination(&self, frame: &mut [u8], addr: Ipv6Addr, port: u16) {
        self.rewrite(
            frame,
            self.l3 + 24,
            destination_port_at(self.transport, self.l4),
            addr,
            port,
        );
    }

    /// As [`Ipv4Packet::rewrite`]; no header checksum, and
    /// every transport checksum covers the pseudo-header.
    fn rewrite(&self, frame: &mut [u8], addr_at: usize, port_at: usize, addr: Ipv6Addr, port: u16) {
        let old_addr: [u8; 16] = frame[addr_at..addr_at + 16]
            .try_into()
            .expect("Address offset came from parse. This is a bug.");
        let old_port = [frame[port_at], frame[port_at + 1]];
        let new_addr = addr.octets();
        let new_port = port.to_be_bytes();
        let checksum_at = match self.transport {
            Transport::Tcp => self.l4 + 16,
            Transport::Udp => self.l4 + 6,
            Transport::IcmpEcho => self.l4 + 2,
            Transport::Other => unreachable!("Other is dropped before translation."),
        };
        update_checksum(frame, checksum_at, &old_addr, &new_addr);
        update_checksum(frame, checksum_at, &old_port, &new_port);
        // UDP over IPv6 must carry a checksum.
        if self.transport == Transport::Udp && be16(frame, checksum_at) == 0 {
            frame[checksum_at..checksum_at + 2].copy_from_slice(&[0xff, 0xff]);
        }
        frame[addr_at..addr_at + 16].copy_from_slice(&new_addr);
        frame[port_at..port_at + 2].copy_from_slice(&new_port);
    }

    pub fn decrement_hop_limit(&self, frame: &mut [u8]) {
        frame[self.l3 + 7] -= 1;
    }
}

/// The MAC fields sit ahead of any VLAN tag, so these
/// apply to every Ethernet frame. Each panics on a frame
/// shorter than its header.
pub fn destination_mac(frame: &[u8]) -> Mac {
    frame[..6]
        .try_into()
        .expect("A frame is at least an Ethernet header long.")
}

pub fn source_mac(frame: &[u8]) -> Mac {
    frame[6..12]
        .try_into()
        .expect("A frame is at least an Ethernet header long.")
}

pub fn rewrite_destination_mac(frame: &mut [u8], mac: Mac) {
    frame[..6].copy_from_slice(&mac);
}

pub fn rewrite_source_mac(frame: &mut [u8], mac: Mac) {
    frame[6..12].copy_from_slice(&mac);
}

/// The forwarding rewrite: from us, to the next hop.
pub fn rewrite_macs(frame: &mut [u8], source: Mac, destination: Mac) {
    rewrite_source_mac(frame, source);
    rewrite_destination_mac(frame, destination);
}

/// Classifies the transport at `l4`, ending at `end`;
/// `None` when a known header is truncated.
fn transport(
    frame: &[u8],
    l4: usize,
    end: usize,
    protocol: u8,
    icmp: u8,
    echo: impl Fn(u8) -> bool,
) -> Option<(Transport, u16, u16)> {
    Some(match protocol {
        TCP if end >= l4 + 20 => (Transport::Tcp, be16(frame, l4), be16(frame, l4 + 2)),
        UDP if end >= l4 + 8 => (Transport::Udp, be16(frame, l4), be16(frame, l4 + 2)),
        _ if protocol == icmp && end >= l4 + 8 && echo(frame[l4]) => {
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

pub fn be16(frame: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([frame[at], frame[at + 1]])
}

pub fn be32(frame: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]])
}

fn be128(frame: &[u8], at: usize) -> u128 {
    u128::from_be_bytes(
        frame[at..at + 16]
            .try_into()
            .expect("Caller bounds the slice. This is a bug."),
    )
}

/// RFC 1624: `HC' = ~(~HC + ~m + m')`, over the 16-bit words
/// of `old` and `new`, which must be the same even length.
pub fn update_checksum(frame: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
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

    fn pseudo6(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, len: usize) -> Vec<u8> {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);

        pseudo
    }

    fn ethernet((src_mac, dst_mac): (Mac, Mac), ethertype: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&src_mac);
        frame.extend_from_slice(&ethertype.to_be_bytes());

        frame
    }

    /// An IPv4 frame with correct checksums; `l4` is the
    /// transport header and payload with its checksum field
    /// zeroed, `checksum_at` that field's offset within it.
    pub(crate) fn frame4(
        macs: (Mac, Mac),
        (source, destination): (Ipv4Addr, Ipv4Addr),
        protocol: u8,
        l4: &[u8],
        checksum_at: Option<usize>,
    ) -> Vec<u8> {
        let mut frame = ethernet(macs, ETHERTYPE_IPV4);
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

    /// As [`frame4`] for IPv6; every transport checksum
    /// covers the pseudo-header.
    pub(crate) fn frame6(
        macs: (Mac, Mac),
        (source, destination): (Ipv6Addr, Ipv6Addr),
        protocol: u8,
        l4: &[u8],
        checksum_at: Option<usize>,
    ) -> Vec<u8> {
        let mut frame = ethernet(macs, ETHERTYPE_IPV6);
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&u16::try_from(l4.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&[protocol, 64]);
        frame.extend_from_slice(&source.octets());
        frame.extend_from_slice(&destination.octets());
        frame.extend_from_slice(l4);
        if let Some(at) = checksum_at {
            let mut covered = pseudo6(source, destination, protocol, l4.len());
            covered.extend_from_slice(l4);
            let sum = checksum(&covered);
            frame[54 + at..56 + at].copy_from_slice(&sum.to_be_bytes());
        }

        frame
    }

    pub(crate) fn parse4(frame: &[u8]) -> Option<Ipv4Packet> {
        match Frame::parse(frame)? {
            Frame::V4(packet) => Some(packet),
            Frame::V6(_) => None,
        }
    }

    pub(crate) fn parse6(frame: &[u8]) -> Option<Ipv6Packet> {
        match Frame::parse(frame)? {
            Frame::V6(packet) => Some(packet),
            Frame::V4(_) => None,
        }
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
        let packet = parse4(frame).unwrap();
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

    pub(crate) fn assert_checksums6(frame: &[u8]) {
        let packet = parse6(frame).unwrap();
        let l4 = &frame[packet.l4..];
        let mut covered = pseudo6(packet.source, packet.destination, packet.protocol, l4.len());
        covered.extend_from_slice(l4);
        assert_eq!(checksum(&covered), 0, "transport checksum");
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::*, *};

    const A_MAC: Mac = [0x02, 0, 0, 0, 0, 0x0a];
    const B_MAC: Mac = [0x02, 0, 0, 0, 0, 0x0b];
    const V4_A: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const V4_B: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const V4_NEW: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);
    const V6_A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x10);
    const V6_B: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
    const V6_NEW: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 5);

    #[test]
    fn parses_v4_fields() {
        let frame = frame4(
            (A_MAC, B_MAC),
            (V4_A, V4_B),
            TCP,
            &tcp(51000, 443),
            Some(16),
        );
        let packet = parse4(&frame).unwrap();
        assert_eq!(packet.l3, 14);
        assert_eq!(packet.l4, 34);
        assert_eq!(packet.transport, Transport::Tcp);
        assert_eq!(packet.ttl, 64);
        assert_eq!((packet.source, packet.source_port), (V4_A, 51000));
        assert_eq!((packet.destination, packet.destination_port), (V4_B, 443));
        assert!(matches!(Frame::parse(&frame), Some(Frame::V4(_))));
    }

    #[test]
    fn rejects_malformed_v4() {
        let good = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        let mut fragment = good.clone();
        fragment[20..22].copy_from_slice(&[0x20, 0x01]);
        assert!(parse4(&fragment).is_none());
        let mut truncated = good.clone();
        truncated.truncate(14 + 20 + 10);
        assert!(parse4(&truncated).is_none());
        let mut short_header = good.clone();
        short_header[14] = 0x44;
        assert!(parse4(&short_header).is_none());
        let mut wrong_version = good.clone();
        wrong_version[14] = 0x65;
        assert!(parse4(&wrong_version).is_none());
        let gre = frame4((A_MAC, B_MAC), (V4_A, V4_B), 47, &[0; 8], None);
        assert_eq!(parse4(&gre).unwrap().transport, Transport::Other);
        assert!(Frame::parse(&good[..10]).is_none());
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
            let packet = parse4(&frame).unwrap();
            packet.rewrite_source(&mut frame, V4_NEW, 40000);
            packet.decrement_ttl(&mut frame);
            let packet = parse4(&frame).unwrap();
            assert_eq!((packet.source, packet.source_port), (V4_NEW, 40000));
            assert_eq!(packet.ttl, 63);
            assert_checksums4(&frame);
            packet.rewrite_destination(&mut frame, V4_A, 7);
            let packet = parse4(&frame).unwrap();
            assert_eq!((packet.destination, packet.destination_port), (V4_A, 7));
            assert_checksums4(&frame);
        }
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
        assert_eq!(parse4(&frame).unwrap().vlan, None);
        // Priority and DEI bits are not part of the ID.
        tag(&mut frame, 0x8100, 0xe000 | 100);
        let packet = parse4(&frame).unwrap();
        assert_eq!(packet.l3, 18);
        assert_eq!(packet.vlan, Some(100));
        assert_eq!((packet.source, packet.source_port), (V4_A, 51000));
        assert!(matches!(Frame::parse(&frame), Some(Frame::V4(_))));
        tag(&mut frame, 0x88a8, 7);
        let packet = parse4(&frame).unwrap();
        assert_eq!(packet.l3, 22);
        assert_eq!(packet.vlan, Some(7));
        assert_checksums4(&frame);
        tag(&mut frame, 0x9100, 9);
        assert!(parse4(&frame).is_none());
        assert!(Frame::parse(&frame).is_none());
    }

    #[test]
    fn rewrites_tagged_frames() {
        let mut frame = frame6((A_MAC, B_MAC), (V6_A, V6_B), UDP, &udp(5000, 53), Some(6));
        tag(&mut frame, 0x8100, 42);
        let packet = parse6(&frame).unwrap();
        assert_eq!((packet.l3, packet.l4, packet.vlan), (18, 58, Some(42)));
        packet.rewrite_source(&mut frame, V6_NEW, 40000);
        let packet = parse6(&frame).unwrap();
        assert_eq!((packet.source, packet.source_port), (V6_NEW, 40000));
        assert_eq!(packet.vlan, Some(42));
        assert_checksums6(&frame);
    }

    #[test]
    fn rejects_truncated_tags() {
        let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        tag(&mut frame, 0x8100, 1);
        frame.truncate(15);
        assert!(Frame::parse(&frame).is_none());
        frame.truncate(13);
        assert!(Frame::parse(&frame).is_none());
    }

    #[test]
    fn parses_v6_fields() {
        let frame = frame6((A_MAC, B_MAC), (V6_A, V6_B), UDP, &udp(5000, 53), Some(6));
        let packet = parse6(&frame).unwrap();
        assert_eq!(packet.l3, 14);
        assert_eq!(packet.l4, 54);
        assert_eq!(packet.transport, Transport::Udp);
        assert_eq!(packet.hop_limit, 64);
        assert_eq!((packet.source, packet.source_port), (V6_A, 5000));
        assert_eq!((packet.destination, packet.destination_port), (V6_B, 53));
        assert_eq!(packet.tuple().protocol, UDP);
        assert!(matches!(Frame::parse(&frame), Some(Frame::V6(_))));
    }

    #[test]
    fn rejects_malformed_v6() {
        let good = frame6((A_MAC, B_MAC), (V6_A, V6_B), TCP, &tcp(1, 2), Some(16));
        let mut truncated = good.clone();
        truncated.truncate(14 + 40 + 10);
        assert!(parse6(&truncated).is_none());
        let mut wrong_version = good.clone();
        wrong_version[14] = 0x45;
        assert!(parse6(&wrong_version).is_none());
        // A fragment header is an extension header.
        let fragment = frame6((A_MAC, B_MAC), (V6_A, V6_B), 44, &[0; 8], None);
        assert_eq!(parse6(&fragment).unwrap().transport, Transport::Other);
    }

    #[test]
    fn rewrites_v6_with_valid_checksums() {
        for (protocol, l4) in [
            (TCP, tcp(51000, 443)),
            (UDP, udp(5000, 53)),
            (ICMPV6, icmp(ICMPV6_ECHO_REQUEST, 0x1234)),
        ] {
            let at = Some(match protocol {
                TCP => 16,
                UDP => 6,
                _ => 2,
            });
            let mut frame = frame6((A_MAC, B_MAC), (V6_A, V6_B), protocol, &l4, at);
            let packet = parse6(&frame).unwrap();
            packet.rewrite_source(&mut frame, V6_NEW, 40000);
            packet.decrement_hop_limit(&mut frame);
            let packet = parse6(&frame).unwrap();
            assert_eq!((packet.source, packet.source_port), (V6_NEW, 40000));
            assert_eq!(packet.hop_limit, 63);
            assert_checksums6(&frame);
            packet.rewrite_destination(&mut frame, V6_A, 7);
            let packet = parse6(&frame).unwrap();
            assert_eq!((packet.destination, packet.destination_port), (V6_A, 7));
            assert_checksums6(&frame);
        }
    }

    #[test]
    fn mac_rewrites_survive_tags() {
        let mut frame = frame4((A_MAC, B_MAC), (V4_A, V4_B), TCP, &tcp(1, 2), Some(16));
        tag(&mut frame, 0x8100, 5);
        assert_eq!(source_mac(&frame), A_MAC);
        assert_eq!(destination_mac(&frame), B_MAC);
        let ours: Mac = [0x02, 0, 0, 0, 0, 0x01];
        let next_hop: Mac = [0x02, 0, 0, 0, 0, 0xfe];
        rewrite_macs(&mut frame, ours, next_hop);
        assert_eq!(source_mac(&frame), ours);
        assert_eq!(destination_mac(&frame), next_hop);
        let packet = parse4(&frame).unwrap();
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
