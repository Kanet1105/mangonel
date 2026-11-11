//! Frames the gateway originates, written from the Ethernet
//! header up.

use std::net::{
    Ipv4Addr,
    SocketAddrV4,
};

use mangonel_wire::{
    Arp,
    Ethernet,
    Ipv4,
    Udp,
    data_link::ethernet::{
        self,
        EtherType,
        arp::{
            self,
            Operation,
        },
    },
    network::ipv4::{
        self,
        Protocol,
    },
    transport::udp,
};

use crate::data::frame::Frame;

/// The address every station on a segment listens to.
pub(crate) const BROADCAST: [u8; 6] = [0xFF; 6];
/// The shortest frame Ethernet carries, without its check
/// sequence. Shorter packets are padded up to it.
const MIN_FRAME: usize = 60;
/// The hop limit of packets the gateway originates.
pub(crate) const TTL: u8 = 64;

/// A UDP datagram the gateway sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Datagram {
    pub(crate) source: SocketAddrV4,
    pub(crate) destination: SocketAddrV4,
    pub(crate) payload: Vec<u8>,
}

/// Makes `frame` an ARP request from `mac` at `address` for
/// whoever holds `target`. False if the frame cannot hold
/// one.
pub(crate) fn arp_request<F: Frame>(
    frame: &mut F,
    mac: [u8; 6],
    address: Ipv4Addr,
    target: Ipv4Addr,
) -> bool {
    if !resize(frame, ethernet::HEADER_LEN + arp::LEN) {
        return false;
    }

    write_arp_request(frame.data_mut(), mac, address, target).is_ok()
}

fn write_arp_request(
    data: &mut [u8],
    mac: [u8; 6],
    address: Ipv4Addr,
    target: Ipv4Addr,
) -> Result<(), mangonel_wire::Error> {
    let mut ethernet = Ethernet::parse(data)?;
    ethernet.set_destination(BROADCAST);
    ethernet.set_source(mac);
    ethernet.set_ethertype(EtherType::ARP);
    let mut arp = Arp::init(ethernet.payload_mut())?;
    arp.set_operation(Operation::REQUEST);
    arp.set_sender_mac(mac);
    arp.set_sender_ip(address);
    arp.set_target_ip(target);

    Ok(())
}

/// Makes `frame` carry `datagram` from `source` to
/// `destination`. False if the frame cannot hold it.
pub(crate) fn udp<F: Frame>(
    frame: &mut F,
    source: [u8; 6],
    destination: [u8; 6],
    datagram: &Datagram,
) -> bool {
    let length = ethernet::HEADER_LEN + ipv4::HEADER_LEN + udp::HEADER_LEN + datagram.payload.len();
    if !resize(frame, length) {
        return false;
    }

    write_udp(frame.data_mut(), source, destination, datagram).is_ok()
}

fn write_udp(
    data: &mut [u8],
    source: [u8; 6],
    destination: [u8; 6],
    datagram: &Datagram,
) -> Result<(), mangonel_wire::Error> {
    let length = udp::HEADER_LEN + datagram.payload.len();
    let truncated = |length: usize| mangonel_wire::Error::Length(length);
    let udp_length = u16::try_from(length).map_err(|_| truncated(length))?;
    let total_length = u16::try_from(ipv4::HEADER_LEN + length).map_err(|_| truncated(length))?;
    let (from, to) = (*datagram.source.ip(), *datagram.destination.ip());

    let mut ethernet = Ethernet::parse(data)?;
    ethernet.set_destination(destination);
    ethernet.set_source(source);
    ethernet.set_ethertype(EtherType::IPV4);
    let mut ip = Ipv4::init(ethernet.payload_mut())?;
    ip.set_total_length(total_length)?;
    // Never fragmented, so the identification can stay zero.
    ip.set_dont_fragment(true);
    ip.set_ttl(TTL);
    ip.set_protocol(Protocol::UDP);
    ip.set_source(from);
    ip.set_destination(to);
    ip.fill_checksum();
    let mut udp = Udp::init(ip.payload_mut())?;
    udp.set_source_port(datagram.source.port());
    udp.set_destination_port(datagram.destination.port());
    udp.set_length(udp_length)?;
    udp.payload_mut().copy_from_slice(&datagram.payload);
    udp.fill_checksum(from.into(), to.into());

    Ok(())
}

/// Makes `frame` hold a packet of `length` bytes, zero
/// padded up to the shortest frame. False if it cannot.
fn resize<F: Frame>(frame: &mut F, length: usize) -> bool {
    let padded = length.max(MIN_FRAME);
    if padded > frame.capacity() {
        return false;
    }
    frame.set_length(padded);
    frame.data_mut()[length..].fill(0);

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::frame::tests::Buffer;

    const MAC: [u8; 6] = [2, 0, 0, 1, 0, 2];

    #[test]
    fn arp_request_asks_everyone_for_the_target() {
        let mut frame = Buffer(Vec::new());
        assert!(arp_request(
            &mut frame,
            MAC,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 7),
        ));

        assert_eq!(frame.0.len(), MIN_FRAME);
        let ethernet = Ethernet::parse(&frame.0[..]).unwrap();
        assert_eq!(ethernet.destination(), BROADCAST);
        assert_eq!(ethernet.source(), MAC);
        assert_eq!(ethernet.ethertype(), EtherType::ARP);
        let arp = Arp::parse(ethernet.payload()).unwrap();
        assert_eq!(arp.operation(), Operation::REQUEST);
        assert_eq!(arp.sender_mac(), MAC);
        assert_eq!(arp.sender_ip(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(arp.target_mac(), [0; 6]);
        assert_eq!(arp.target_ip(), Ipv4Addr::new(10, 0, 0, 7));
        // Nothing of the buffer's junk goes out as padding.
        assert!(
            frame.0[ethernet::HEADER_LEN + arp::LEN..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn udp_frame_checks_out() {
        let datagram = Datagram {
            source: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 67),
            destination: SocketAddrV4::new(Ipv4Addr::BROADCAST, 68),
            payload: vec![7; 300],
        };
        let mut frame = Buffer(vec![1; 90]);
        assert!(udp(&mut frame, MAC, BROADCAST, &datagram));

        assert_eq!(frame.0.len(), 14 + 20 + 8 + 300);
        let ethernet = Ethernet::parse(&frame.0[..]).unwrap();
        assert_eq!(ethernet.destination(), BROADCAST);
        assert_eq!(ethernet.source(), MAC);
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.ttl(), TTL);
        assert_eq!(ip.source(), *datagram.source.ip());
        assert_eq!(ip.destination(), Ipv4Addr::BROADCAST);
        let udp = Udp::parse(ip.payload()).unwrap();
        assert!(udp.verify_checksum(ip.source().into(), ip.destination().into()));
        assert_eq!((udp.source_port(), udp.destination_port()), (67, 68));
        assert_eq!(udp.payload(), &datagram.payload[..]);
    }

    #[test]
    fn a_datagram_too_long_for_the_frame_is_refused() {
        let datagram = Datagram {
            source: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 67),
            destination: SocketAddrV4::new(Ipv4Addr::BROADCAST, 68),
            payload: vec![0; 4000],
        };
        let mut frame = Buffer(vec![1; 90]);
        assert!(!udp(&mut frame, MAC, BROADCAST, &datagram));
        assert_eq!(frame.0, vec![1; 90]);
    }
}
