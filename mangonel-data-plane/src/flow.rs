//! Flow hashing for dispatch: every frame of a flow, in
//! either direction, hashes alike.
//!
//! Parses Ethernet (with one VLAN tag), then IPv4 or IPv6,
//! then TCP, UDP or SCTP ports. The two endpoints are put
//! in a fixed order before hashing, so replies land in the
//! same bucket as requests. Fragments hash on addresses
//! alone: only the first one carries ports, and all of them
//! must reach the same worker. Anything else hashes to 0.

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_SCTP: u8 = 132;

/// IPv4 more-fragments flag and fragment offset.
const IPV4_FRAGMENT: u16 = 0x3fff;

/// The frame's flow hash, from its Ethernet header onwards.
pub fn flow_hash(frame: &[u8]) -> u32 {
    let Some((ethertype, l3)) = ethertype(frame) else {
        return 0;
    };
    match ethertype {
        ETHERTYPE_IPV4 => ipv4(&frame[l3..]).unwrap_or(0),
        ETHERTYPE_IPV6 => ipv6(&frame[l3..]).unwrap_or(0),
        _ => 0,
    }
}

/// The network-layer ethertype and where its header starts.
fn ethertype(frame: &[u8]) -> Option<(u16, usize)> {
    let ethertype = be16(frame, 12)?;
    if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        return Some((be16(frame, 16)?, 18));
    }

    Some((ethertype, 14))
}

fn ipv4(packet: &[u8]) -> Option<u32> {
    let header_length = usize::from(packet.first()? & 0x0f) * 4;
    if header_length < 20 {
        return None;
    }
    let protocol = *packet.get(9)?;
    let source = u128::from(be32(packet, 12)?);
    let destination = u128::from(be32(packet, 16)?);
    let fragmented = be16(packet, 6)? & IPV4_FRAGMENT != 0;
    let ports = if fragmented {
        None
    } else {
        ports(protocol, packet.get(header_length..)?)
    };

    Some(endpoints(protocol, (source, destination), ports))
}

fn ipv6(packet: &[u8]) -> Option<u32> {
    // Extension headers are not walked: a packet with any
    // hashes on addresses alone, which is coarser but still
    // keeps the flow together.
    let next_header = *packet.get(6)?;
    let source = be128(packet, 8)?;
    let destination = be128(packet, 24)?;
    let ports = ports(next_header, packet.get(40..)?);

    Some(endpoints(next_header, (source, destination), ports))
}

fn ports(protocol: u8, segment: &[u8]) -> Option<(u16, u16)> {
    match protocol {
        PROTOCOL_TCP | PROTOCOL_UDP | PROTOCOL_SCTP => Some((be16(segment, 0)?, be16(segment, 2)?)),
        _ => None,
    }
}

/// Hashes the protocol and both endpoints, lower endpoint
/// first, so the result is the same in both directions.
// The casts split each address into its two 64-bit halves.
#[expect(clippy::cast_possible_truncation)]
fn endpoints(protocol: u8, addresses: (u128, u128), ports: Option<(u16, u16)>) -> u32 {
    let (source_port, destination_port) = ports.unwrap_or((0, 0));
    let a = (addresses.0, source_port);
    let b = (addresses.1, destination_port);
    let (low, high) = if a <= b { (a, b) } else { (b, a) };

    let mut hash = u64::from(protocol);
    for word in [
        (low.0 >> 64) as u64,
        low.0 as u64,
        u64::from(low.1),
        (high.0 >> 64) as u64,
        high.0 as u64,
        u64::from(high.1),
    ] {
        hash = mix(hash ^ word);
    }

    fold(hash)
}

/// The splitmix64 finalizer: every input bit reaches every
/// output bit.
fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Both halves feed the low bits buckets are picked from.
#[expect(clippy::cast_possible_truncation)]
fn fold(hash: u64) -> u32 {
    (hash ^ (hash >> 32)) as u32
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn be128(bytes: &[u8], at: usize) -> Option<u128> {
    Some(u128::from_be_bytes(
        bytes.get(at..at + 16)?.try_into().ok()?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An Ethernet + IPv4 frame with a 4-byte port header.
    pub(crate) fn ipv4_frame(
        protocol: u8,
        source: [u8; 4],
        destination: [u8; 4],
        ports: (u16, u16),
        fragment: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0; 20];
        ip[0] = 0x45;
        ip[6..8].copy_from_slice(&fragment.to_be_bytes());
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&source);
        ip[16..20].copy_from_slice(&destination);
        frame.extend(ip);
        frame.extend(ports.0.to_be_bytes());
        frame.extend(ports.1.to_be_bytes());
        frame
    }

    fn ipv6_frame(source: u128, destination: u128, ports: (u16, u16)) -> Vec<u8> {
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let mut ip = vec![0; 40];
        ip[6] = PROTOCOL_UDP;
        ip[8..24].copy_from_slice(&source.to_be_bytes());
        ip[24..40].copy_from_slice(&destination.to_be_bytes());
        frame.extend(ip);
        frame.extend(ports.0.to_be_bytes());
        frame.extend(ports.1.to_be_bytes());
        frame
    }

    const A: [u8; 4] = [192, 168, 1, 10];
    const B: [u8; 4] = [1, 1, 1, 1];

    #[test]
    fn both_directions_hash_alike() {
        let out = flow_hash(&ipv4_frame(PROTOCOL_TCP, A, B, (50000, 443), 0));
        let back = flow_hash(&ipv4_frame(PROTOCOL_TCP, B, A, (443, 50000), 0));
        assert_eq!(out, back);
        assert_ne!(out, 0);

        let out = flow_hash(&ipv6_frame(1, 2, (5353, 53)));
        assert_eq!(out, flow_hash(&ipv6_frame(2, 1, (53, 5353))));
    }

    #[test]
    fn ports_and_protocol_distinguish_flows() {
        let base = flow_hash(&ipv4_frame(PROTOCOL_TCP, A, B, (50000, 443), 0));
        assert_ne!(
            base,
            flow_hash(&ipv4_frame(PROTOCOL_TCP, A, B, (50001, 443), 0))
        );
        assert_ne!(
            base,
            flow_hash(&ipv4_frame(PROTOCOL_UDP, A, B, (50000, 443), 0))
        );
    }

    #[test]
    fn fragments_ignore_ports() {
        let first = flow_hash(&ipv4_frame(PROTOCOL_UDP, A, B, (1, 2), 0x2000));
        let later = flow_hash(&ipv4_frame(PROTOCOL_UDP, A, B, (9, 9), 0x0010));
        assert_eq!(first, later);
    }

    #[test]
    fn a_vlan_tag_is_skipped() {
        let plain = ipv4_frame(PROTOCOL_TCP, A, B, (50000, 443), 0);
        let mut tagged = plain[..12].to_vec();
        tagged.extend(ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend([0x00, 0x2a]);
        tagged.extend(&plain[12..]);
        assert_eq!(flow_hash(&plain), flow_hash(&tagged));
    }

    #[test]
    fn non_ip_and_runts_hash_to_zero() {
        let mut arp = vec![0; 42];
        arp[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert_eq!(flow_hash(&arp), 0);
        assert_eq!(flow_hash(&[0; 10]), 0);
        let truncated = ipv4_frame(PROTOCOL_TCP, A, B, (1, 2), 0);
        assert_eq!(flow_hash(&truncated[..20]), 0);
    }
}
