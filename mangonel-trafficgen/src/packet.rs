//! The packet every frame carries, built once and copied.

use std::net::SocketAddrV4;

use mangonel_wire::{
    Ethernet,
    Ipv4,
    Udp,
    checksum,
    data_link::ethernet::{
        self,
        EtherType,
    },
    network::ipv4::{
        self,
        Protocol,
    },
    transport::udp,
};

/// The Ethernet, IPv4 and UDP headers ahead of the payload.
const HEADERS: usize = ethernet::HEADER_LEN + ipv4::HEADER_LEN + udp::HEADER_LEN;
/// Where the UDP destination port sits in a frame.
const PORT_AT: usize = ethernet::HEADER_LEN + ipv4::HEADER_LEN + 2;
/// Where the UDP checksum sits in a frame.
const CHECKSUM_AT: usize = ethernet::HEADER_LEN + ipv4::HEADER_LEN + 6;
/// The check sequence the interface appends to a frame,
/// which a packet's size on the wire counts.
const CHECK_SEQUENCE: usize = 4;
/// The smallest packet Ethernet carries, on the wire.
pub(crate) const MIN_SIZE: usize = 64;

/// Who the packets are from and for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Addresses {
    pub(crate) source_mac: [u8; 6],
    pub(crate) destination_mac: [u8; 6],
    pub(crate) source: SocketAddrV4,
    /// With the first of the destination ports.
    pub(crate) destination: SocketAddrV4,
    pub(crate) hop_limit: u8,
}

/// One UDP packet as a frame, and what varying its
/// destination port takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    frame: Vec<u8>,
    /// The destination port the frame carries.
    port: u16,
    /// The UDP checksum the frame carries.
    checksum: u16,
}

impl Template {
    /// A packet of `size` bytes on the wire, which counts
    /// the check sequence that follows the frame. The
    /// payload is zeroes.
    pub(crate) fn new(addresses: &Addresses, size: usize) -> Result<Self, mangonel_wire::Error> {
        // What does not even hold the headers is caught by
        // the views below.
        let mut frame = vec![0u8; size.saturating_sub(CHECK_SEQUENCE)];
        let too_long = |_| mangonel_wire::Error::Length(frame.len());
        let packet = frame.len().saturating_sub(ethernet::HEADER_LEN);
        let datagram = u16::try_from(packet.saturating_sub(ipv4::HEADER_LEN)).map_err(too_long)?;
        let packet = u16::try_from(packet).map_err(too_long)?;
        let (from, to) = (*addresses.source.ip(), *addresses.destination.ip());

        let mut ethernet = Ethernet::parse(&mut frame[..])?;
        ethernet.set_destination(addresses.destination_mac);
        ethernet.set_source(addresses.source_mac);
        ethernet.set_ethertype(EtherType::IPV4);
        let mut ip = Ipv4::init(ethernet.payload_mut())?;
        ip.set_total_length(packet)?;
        // Never fragmented, so the identification can stay
        // zero.
        ip.set_dont_fragment(true);
        ip.set_ttl(addresses.hop_limit);
        ip.set_protocol(Protocol::UDP);
        ip.set_source(from);
        ip.set_destination(to);
        ip.fill_checksum();
        let mut udp = Udp::init(ip.payload_mut())?;
        udp.set_source_port(addresses.source.port());
        udp.set_destination_port(addresses.destination.port());
        udp.set_length(datagram)?;
        udp.fill_checksum(from.into(), to.into());
        let checksum = udp.checksum();

        Ok(Self {
            frame,
            port: addresses.destination.port(),
            checksum,
        })
    }

    /// The frame's length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.frame.len()
    }

    /// Writes the packet into `frame`, which is exactly
    /// [`Self::len`] bytes, bound for `port`.
    pub(crate) fn write(&self, frame: &mut [u8], port: u16) {
        frame.copy_from_slice(&self.frame);
        if port == self.port {
            return;
        }

        // Only the port differs, so the checksum is patched
        // for it rather than summed over the payload. A
        // computed zero goes out as all ones: zero means no
        // checksum was sent.
        let port = port.to_be_bytes();
        let patched = match checksum::update(self.checksum, &self.port.to_be_bytes(), &port) {
            0 => 0xFFFF,
            patched => patched,
        };
        frame[PORT_AT..PORT_AT + 2].copy_from_slice(&port);
        frame[CHECKSUM_AT..CHECKSUM_AT + 2].copy_from_slice(&patched.to_be_bytes());
    }
}

/// The largest packet, on the wire, an interface with this
/// MTU carries.
pub(crate) fn max_size(mtu: u32) -> usize {
    usize::try_from(mtu)
        .unwrap_or(usize::MAX)
        .saturating_add(ethernet::HEADER_LEN + CHECK_SEQUENCE)
}

/// Whether `size` bytes on the wire hold the headers of a
/// UDP packet at all.
pub(crate) fn holds_headers(size: usize) -> bool {
    size >= HEADERS + CHECK_SEQUENCE
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn addresses() -> Addresses {
        Addresses {
            source_mac: [2, 0, 0, 4, 0, 0],
            destination_mac: [2, 0, 0, 1, 0, 2],
            source: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 50), 4000),
            destination: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 9000),
            hop_limit: 64,
        }
    }

    /// Checks a frame through and returns its ports and
    /// payload length.
    fn checked(frame: &[u8]) -> (u16, u16, usize) {
        let addresses = addresses();
        let ethernet = Ethernet::parse(frame).unwrap();
        assert_eq!(ethernet.destination(), addresses.destination_mac);
        assert_eq!(ethernet.source(), addresses.source_mac);
        assert_eq!(ethernet.ethertype(), EtherType::IPV4);
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.ttl(), addresses.hop_limit);
        assert_eq!(ip.protocol(), Protocol::UDP);
        assert_eq!(ip.source(), *addresses.source.ip());
        assert_eq!(ip.destination(), *addresses.destination.ip());
        // The packet fills the frame: nothing is padding.
        assert_eq!(
            usize::from(ip.total_length()),
            frame.len() - ethernet::HEADER_LEN
        );
        let udp = Udp::parse(ip.payload()).unwrap();
        assert!(udp.verify_checksum(ip.source().into(), ip.destination().into()));
        assert_ne!(udp.checksum(), 0);

        (
            udp.source_port(),
            udp.destination_port(),
            udp.payload().len(),
        )
    }

    #[test]
    fn the_smallest_packet_is_a_sound_udp_datagram() {
        let template = Template::new(&addresses(), MIN_SIZE).unwrap();
        assert_eq!(template.len(), 60);
        let mut frame = vec![0xA5; template.len()];
        template.write(&mut frame, 9000);
        assert_eq!(checked(&frame), (4000, 9000, 60 - HEADERS));
    }

    #[test]
    fn a_full_size_packet_fills_the_mtu() {
        let size = max_size(1500);
        assert_eq!(size, 1518);
        let template = Template::new(&addresses(), size).unwrap();
        let mut frame = vec![0xA5; template.len()];
        template.write(&mut frame, 9000);
        assert_eq!(checked(&frame), (4000, 9000, 1500 - 28));
    }

    #[test]
    fn every_destination_port_carries_a_sound_checksum() {
        let template = Template::new(&addresses(), 100).unwrap();
        let mut frame = vec![0; template.len()];
        for port in 0..=u16::MAX {
            template.write(&mut frame, port);
            assert_eq!(checked(&frame).1, port);
        }
    }

    #[test]
    fn a_size_without_room_for_the_headers_is_refused() {
        assert!(holds_headers(HEADERS + CHECK_SEQUENCE));
        assert!(!holds_headers(HEADERS + CHECK_SEQUENCE - 1));
        assert!(Template::new(&addresses(), HEADERS + CHECK_SEQUENCE - 1).is_err());
        assert!(Template::new(&addresses(), 0).is_err());
    }
}
