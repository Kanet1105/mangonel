//! L3 forwarding: zero-copy header views, a two-route FIB,
//! and a MAC-learning neighbor table.
//!
//! Everything here overlays the frame bytes in place — no
//! packet is ever copied into an owned struct. The router
//! parses just enough to decide an egress and rewrite the
//! Ethernet and IPv4 headers.

use std::{collections::HashMap, net::Ipv4Addr};

const ETH_LEN: usize = 14;
const ETHERTYPE_OFFSET: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

// IPv4 field offsets, from the start of the IP header.
const IPV4_MIN_LEN: usize = 20;
const IPV4_TTL: usize = 8;
const IPV4_CHECKSUM: usize = 10;
const IPV4_SRC: usize = 12;
const IPV4_DST: usize = 16;

// ARP field offsets, from the start of the ARP header. Only
// the IPv4-over-Ethernet layout is read.
const ARP_MIN_LEN: usize = 28;
const ARP_SENDER_MAC: usize = 8;
const ARP_SENDER_IP: usize = 14;

/// A hardware address.
pub type Mac = [u8; 6];

/// Which interface a frame arrived on or leaves by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Wan,
    Lan,
}

/// The two-route table for a WAN/LAN edge router: the LAN
/// prefix is directly connected, everything else goes to
/// the WAN gateway.
pub struct Fib {
    lan_network: u32,
    lan_mask: u32,
    wan_gateway: Ipv4Addr,
}

impl Fib {
    pub fn parse(lan_prefix: &str, wan_gateway: &str) -> Result<Self, FibError> {
        let (address, length) = lan_prefix
            .split_once('/')
            .ok_or_else(|| FibError::Prefix(lan_prefix.to_owned()))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| FibError::Prefix(lan_prefix.to_owned()))?;
        let length: u32 = length
            .parse()
            .ok()
            .filter(|&length| length <= 32)
            .ok_or_else(|| FibError::Prefix(lan_prefix.to_owned()))?;
        // A /0 mask is all zeros; the shift below is undefined for
        // 32.
        let mask = if length == 0 {
            0
        } else {
            u32::MAX << (32 - length)
        };
        let wan_gateway: Ipv4Addr = wan_gateway
            .parse()
            .map_err(|_| FibError::Gateway(wan_gateway.to_owned()))?;

        Ok(Self {
            lan_network: u32::from(address) & mask,
            lan_mask: mask,
            wan_gateway,
        })
    }

    /// The egress and next-hop IP for a destination.
    fn route(&self, destination: Ipv4Addr) -> (Side, Ipv4Addr) {
        if u32::from(destination) & self.lan_mask == self.lan_network {
            // On the LAN segment: the destination is the next hop.
            (Side::Lan, destination)
        } else {
            (Side::Wan, self.wan_gateway)
        }
    }

    /// Whether `address` is directly connected on `side` —
    /// the only addresses whose MAC it is correct to
    /// learn, since forwarded traffic carries a far
    /// source IP behind the last hop's MAC.
    fn directly_connected(&self, side: Side, address: Ipv4Addr) -> bool {
        match side {
            Side::Lan => u32::from(address) & self.lan_mask == self.lan_network,
            Side::Wan => address == self.wan_gateway,
        }
    }
}

/// IP-to-MAC bindings learned from passing traffic. One per
/// worker — no lock, since a worker is single-threaded — so
/// learning is per-queue.
#[derive(Default)]
pub struct Neighbors {
    table: HashMap<Ipv4Addr, Mac>,
}

impl Neighbors {
    fn learn(&mut self, address: Ipv4Addr, mac: Mac) {
        self.table.insert(address, mac);
    }

    fn get(&self, address: Ipv4Addr) -> Option<Mac> {
        self.table.get(&address).copied()
    }
}

/// The routing state a worker forwards with: the FIB and
/// each interface's own MAC (the source MAC for rewritten
/// frames).
pub struct Router {
    fib: Fib,
    wan_mac: Mac,
    lan_mac: Mac,
}

impl Router {
    pub fn new(fib: Fib, wan_mac: Mac, lan_mac: Mac) -> Self {
        Self {
            fib,
            wan_mac,
            lan_mac,
        }
    }

    fn mac(&self, side: Side) -> Mac {
        match side {
            Side::Wan => self.wan_mac,
            Side::Lan => self.lan_mac,
        }
    }

    /// Processes a frame received on `ingress` whose egress
    /// is `egress`: learns its source, then rewrites
    /// the headers in place and returns `true` to
    /// forward, or `false` to drop.
    ///
    /// Drops anything that is not IPv4 destined out
    /// `egress` with a resolvable next hop and live TTL
    /// — including ARP, which a router does not forward
    /// but does snoop for learning.
    pub fn forward(
        &self,
        frame: &mut [u8],
        ingress: Side,
        egress: Side,
        neighbors: &mut Neighbors,
    ) -> bool {
        let Some(ethertype) = read_u16(frame, ETHERTYPE_OFFSET) else {
            return false;
        };
        let source_mac = eth_source(frame);

        match ethertype {
            ETHERTYPE_ARP => {
                self.snoop_arp(frame, ingress, neighbors);

                false
            }
            ETHERTYPE_IPV4 => self.route_ipv4(frame, ingress, egress, source_mac, neighbors),
            _ => false,
        }
    }

    /// Learns the sender of a directly-connected ARP.
    fn snoop_arp(&self, frame: &[u8], ingress: Side, neighbors: &mut Neighbors) {
        let arp = &frame[ETH_LEN..];
        if arp.len() < ARP_MIN_LEN {
            return;
        }
        let mac: Mac = arp[ARP_SENDER_MAC..ARP_SENDER_MAC + 6].try_into().unwrap();
        let ip = Ipv4Addr::from(read_u32(arp, ARP_SENDER_IP));
        if self.fib.directly_connected(ingress, ip) {
            neighbors.learn(ip, mac);
        }
    }

    fn route_ipv4(
        &self,
        frame: &mut [u8],
        ingress: Side,
        egress: Side,
        source_mac: Option<Mac>,
        neighbors: &mut Neighbors,
    ) -> bool {
        if frame.len() < ETH_LEN + IPV4_MIN_LEN {
            return false;
        }
        let source = Ipv4Addr::from(read_u32(&frame[ETH_LEN..], IPV4_SRC));
        // Learn the source only if it is directly connected; a
        // forwarded packet's source is far behind the last hop.
        if let Some(mac) = source_mac
            && self.fib.directly_connected(ingress, source)
        {
            neighbors.learn(source, mac);
        }

        let destination = Ipv4Addr::from(read_u32(&frame[ETH_LEN..], IPV4_DST));
        let (route_egress, next_hop) = self.fib.route(destination);
        // Wrong direction for this receive path (a hairpin, or
        // transit not for us): drop.
        if route_egress != egress {
            return false;
        }
        // Would expire in transit: drop (no ICMP yet).
        if frame[ETH_LEN + IPV4_TTL] <= 1 {
            return false;
        }
        let Some(destination_mac) = neighbors.get(next_hop) else {
            return false;
        };

        decrement_ttl(&mut frame[ETH_LEN..]);
        frame[0..6].copy_from_slice(&destination_mac);
        frame[6..12].copy_from_slice(&self.mac(egress));

        true
    }
}

fn eth_source(frame: &[u8]) -> Option<Mac> {
    frame.get(6..12).map(|mac| mac.try_into().unwrap())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_be_bytes(slice.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Decrements the IPv4 TTL and repairs the header checksum
/// by full recomputation over the header (IHL words).
fn decrement_ttl(ip: &mut [u8]) {
    ip[IPV4_TTL] -= 1;

    let header_len = usize::from(ip[0] & 0x0f) * 4;
    ip[IPV4_CHECKSUM] = 0;
    ip[IPV4_CHECKSUM + 1] = 0;
    let mut sum: u32 = 0;
    let mut offset = 0;
    while offset + 1 < header_len {
        sum += u32::from(u16::from_be_bytes([ip[offset], ip[offset + 1]]));
        offset += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = u16::try_from(sum).expect("checksum sum folded to 16 bits above");
    let checksum = !folded;
    ip[IPV4_CHECKSUM..IPV4_CHECKSUM + 2].copy_from_slice(&checksum.to_be_bytes());
}

#[derive(Debug, thiserror::Error)]
pub enum FibError {
    #[error("Invalid LAN prefix '{0}'; expected e.g. 192.168.1.0/24.")]
    Prefix(String),
    #[error("Invalid WAN gateway address '{0}'.")]
    Gateway(String),
}

#[cfg(test)]
mod test {
    use super::*;

    const HOST: Mac = [0x02, 0, 0, 0, 0, 0x10];
    const GATEWAY: Mac = [0x02, 0, 0, 0, 0, 0x01];
    const WAN_MAC: Mac = [0x02, 0, 0, 0, 0xaa, 0];
    const LAN_MAC: Mac = [0x02, 0, 0, 0, 0xbb, 0];

    fn fib() -> Fib {
        Fib::parse("192.168.1.0/24", "203.0.113.1").unwrap()
    }

    fn router() -> Router {
        Router::new(fib(), WAN_MAC, LAN_MAC)
    }

    /// An IPv4-over-Ethernet frame with a valid header
    /// checksum.
    fn frame(src_mac: Mac, src: &str, dst: &str, ttl: u8) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_LEN + IPV4_MIN_LEN];
        frame[6..12].copy_from_slice(&src_mac);
        frame[ETHERTYPE_OFFSET..ETHERTYPE_OFFSET + 2]
            .copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = &mut frame[ETH_LEN..];
        ip[0] = 0x45; // IPv4, IHL 5
        ip[IPV4_TTL] = ttl + 1; // decrement_ttl brings it to ttl with a valid checksum
        ip[9] = 17; // UDP, arbitrary
        ip[IPV4_SRC..IPV4_SRC + 4].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        ip[IPV4_DST..IPV4_DST + 4].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        decrement_ttl(ip);

        frame
    }

    /// The one's-complement sum over the header is all ones
    /// exactly when the checksum is valid.
    fn checksum_valid(ip: &[u8]) -> bool {
        let header_len = usize::from(ip[0] & 0x0f) * 4;
        let mut sum: u32 = 0;
        let mut offset = 0;
        while offset + 1 < header_len {
            sum += u32::from(u16::from_be_bytes([ip[offset], ip[offset + 1]]));
            offset += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        sum == 0xffff
    }

    #[test]
    fn routes_lan_prefix_to_lan_else_to_gateway() {
        let fib = fib();
        assert_eq!(
            fib.route("192.168.1.50".parse().unwrap()),
            (Side::Lan, "192.168.1.50".parse().unwrap())
        );
        assert_eq!(
            fib.route("8.8.8.8".parse().unwrap()),
            (Side::Wan, "203.0.113.1".parse().unwrap())
        );
    }

    #[test]
    fn rejects_bad_prefix_and_gateway() {
        assert!(Fib::parse("192.168.1.0", "203.0.113.1").is_err());
        assert!(Fib::parse("192.168.1.0/33", "203.0.113.1").is_err());
        assert!(Fib::parse("192.168.1.0/24", "not-an-ip").is_err());
    }

    #[test]
    fn decrement_ttl_keeps_the_checksum_valid() {
        let mut frame = frame(HOST, "192.168.1.50", "8.8.8.8", 64);
        assert!(checksum_valid(&frame[ETH_LEN..]));
        decrement_ttl(&mut frame[ETH_LEN..]);
        assert_eq!(frame[ETH_LEN + IPV4_TTL], 63);
        assert!(checksum_valid(&frame[ETH_LEN..]));
    }

    #[test]
    fn forwards_lan_to_wan_after_learning_the_gateway() {
        let router = router();
        let mut neighbors = Neighbors::default();
        // The gateway's MAC is learned from a packet it sources.
        let gateway_frame = frame(GATEWAY, "203.0.113.1", "192.168.1.50", 64);
        assert!(!router.forward(
            &mut gateway_frame.clone(),
            Side::Wan,
            Side::Lan,
            &mut neighbors
        ));

        let mut frame = frame(HOST, "192.168.1.50", "8.8.8.8", 64);
        assert!(router.forward(&mut frame, Side::Lan, Side::Wan, &mut neighbors));
        // dst MAC = gateway, src MAC = egress (WAN) interface, TTL
        // down.
        assert_eq!(&frame[0..6], &GATEWAY);
        assert_eq!(&frame[6..12], &WAN_MAC);
        assert_eq!(frame[ETH_LEN + IPV4_TTL], 63);
        assert!(checksum_valid(&frame[ETH_LEN..]));
    }

    #[test]
    fn drops_when_next_hop_is_unresolved() {
        let router = router();
        let mut neighbors = Neighbors::default();
        // Nothing learned yet, so the gateway MAC is unknown.
        let mut frame = frame(HOST, "192.168.1.50", "8.8.8.8", 64);
        assert!(!router.forward(&mut frame, Side::Lan, Side::Wan, &mut neighbors));
    }

    #[test]
    fn drops_hairpin_within_the_lan() {
        let router = router();
        let mut neighbors = Neighbors::default();
        // LAN ingress, LAN destination: egress would be LAN, not
        // the WAN this receive path serves.
        let mut frame = frame(HOST, "192.168.1.50", "192.168.1.99", 64);
        assert!(!router.forward(&mut frame, Side::Lan, Side::Wan, &mut neighbors));
    }

    #[test]
    fn drops_expiring_ttl() {
        let router = router();
        let mut neighbors = Neighbors::default();
        neighbors.learn("203.0.113.1".parse().unwrap(), GATEWAY);
        let mut frame = frame(HOST, "192.168.1.50", "8.8.8.8", 1);
        assert!(!router.forward(&mut frame, Side::Lan, Side::Wan, &mut neighbors));
    }
}
