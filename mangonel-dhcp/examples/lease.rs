//! Leases an IPv4 address on an interface with the crate's
//! own client and prints what it was given, configuring
//! nothing.
//!
//! `cargo run -p mangonel-dhcp --example lease -- <ifname> [seconds]`
//!
//! The interface has no address to bind a UDP socket to
//! yet, so whole Ethernet frames go through a packet
//! socket, which needs CAP_NET_RAW. On success it prints one
//! line, `address=10.0.0.2/24 router=10.0.0.1 dns=10.0.0.1
//! server=10.0.0.1`, and exits 0; with no lease within the
//! given seconds, 10 by default, it exits 1.

use std::{
    error::Error,
    ffi::CString,
    fs,
    io,
    mem,
    net::Ipv4Addr,
    os::fd::{
        AsRawFd,
        FromRawFd,
        OwnedFd,
    },
    process::ExitCode,
    time::{
        Duration,
        Instant,
    },
};

use mangonel_dhcp::v4::{
    CLIENT_PORT,
    SERVER_PORT,
    client::{
        Client,
        Config,
        Event,
        Lease,
        Transmit,
    },
};
use mangonel_wire::{
    Ethernet,
    Ipv4,
    Udp,
    data_link::ethernet::EtherType,
    network::ipv4::{
        Dhcp,
        Protocol,
    },
};

const BROADCAST: [u8; 6] = [0xFF; 6];
/// Ethernet, IPv4 and UDP headers ahead of the message.
const HEADERS: usize = 14 + 20 + 8;

fn main() -> ExitCode {
    match run() {
        Ok(lease) => {
            println!("{lease}");

            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("lease: {error}");

            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let name = args.next().ok_or("usage: lease <ifname> [seconds]")?;
    let patience = match args.next() {
        Some(seconds) => Duration::from_secs(seconds.parse()?),
        None => Duration::from_secs(10),
    };

    let mac = mac_of(&name)?;
    let socket = PacketSocket::open(&name)?;
    let mut client = Client::new(Config::new(mac));
    let deadline = Instant::now() + patience;
    let mut buffer = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!("no lease on {name} within {patience:?}").into());
        }
        if let Some(transmit) = client.poll(now).transmit {
            socket.send(&frame(mac, &transmit)?)?;
        }

        // Until the client's next timer, or the deadline.
        let wake = client
            .next_wake()
            .map_or(deadline, |wake| wake.min(deadline));
        let wait = wake.saturating_duration_since(Instant::now());
        let Some(length) = socket.receive(&mut buffer, wait)? else {
            continue;
        };
        let Some(ip) = ipv4_of(&buffer[..length]) else {
            continue;
        };
        // Our own requests come back up the socket too; only
        // what is bound for the client port is an answer.
        let Some(Dhcp::Client { payload }) = ip.dhcp() else {
            continue;
        };
        // A message that is not ours or does not decode is
        // someone else's.
        let Ok(output) = client.handle(payload, Instant::now()) else {
            continue;
        };
        if let Some(transmit) = output.transmit {
            socket.send(&frame(mac, &transmit)?)?;
        }
        if let Some(Event::Bound(lease)) = output.event {
            return Ok(describe(&lease));
        }
    }
}

/// One line of `key=value` pairs a script can pick apart.
fn describe(lease: &Lease) -> String {
    let router = lease
        .router
        .map_or_else(|| "none".to_owned(), |router| router.to_string());
    let dns: Vec<String> = lease.dns.iter().map(Ipv4Addr::to_string).collect();
    let dns = if dns.is_empty() {
        "none".to_owned()
    } else {
        dns.join(",")
    };

    format!(
        "address={}/{} router={router} dns={dns} server={}",
        lease.address, lease.prefix, lease.server
    )
}

/// The interface's hardware address, from sysfs.
fn mac_of(name: &str) -> Result<[u8; 6], Box<dyn Error>> {
    let text = fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
    let mut mac = [0u8; 6];
    let mut octets = text.trim().split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(octets.next().ok_or("the MAC is too short")?, 16)?;
    }

    Ok(mac)
}

/// The client's message as a frame for everyone on the
/// segment: until the lease is granted, the client asks by
/// broadcast.
fn frame(mac: [u8; 6], transmit: &Transmit) -> Result<Vec<u8>, mangonel_wire::Error> {
    let length = u16::try_from(8 + transmit.packet.len())
        .map_err(|_| mangonel_wire::Error::Length(transmit.packet.len()))?;
    let mut data = vec![0u8; HEADERS + transmit.packet.len()];
    let mut ethernet = Ethernet::parse(&mut data[..])?;
    ethernet.set_destination(BROADCAST);
    ethernet.set_source(mac);
    ethernet.set_ethertype(EtherType::IPV4);
    let mut ip = Ipv4::init(ethernet.payload_mut())?;
    ip.set_total_length(20 + length)?;
    ip.set_ttl(64);
    ip.set_protocol(Protocol::UDP);
    ip.set_source(transmit.source);
    ip.set_destination(transmit.destination);
    ip.fill_checksum();
    let mut udp = Udp::init(ip.payload_mut())?;
    udp.set_source_port(CLIENT_PORT);
    udp.set_destination_port(SERVER_PORT);
    udp.set_length(length)?;
    udp.payload_mut().copy_from_slice(&transmit.packet);
    udp.fill_checksum(transmit.source.into(), transmit.destination.into());

    Ok(data)
}

/// The IPv4 packet in `frame`, if it carries a sound one.
fn ipv4_of(frame: &[u8]) -> Option<Ipv4<&[u8]>> {
    let ethernet = Ethernet::parse(frame).ok()?;
    if ethernet.ethertype() != EtherType::IPV4 {
        return None;
    }
    let ip = Ipv4::parse(&frame[14..]).ok()?;

    ip.verify_checksum().then_some(ip)
}

/// A packet socket carrying one interface's IPv4 frames.
struct PacketSocket(OwnedFd);

impl PacketSocket {
    fn open(name: &str) -> Result<Self, Box<dyn Error>> {
        let cname = CString::new(name)?;
        // SAFETY: The name is a nul-terminated string that
        // outlives the call.
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            return Err(format!("no interface named {name}").into());
        }

        let protocol = u16::try_from(libc::ETH_P_IP)?.to_be();
        // SAFETY: A plain syscall; the result is checked
        // before it is used as a descriptor.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(protocol)) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: The descriptor was just opened and nothing
        // else owns it.
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });

        // SAFETY: All zeroes is a valid link-layer address
        // to fill in.
        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
        address.sll_family = u16::try_from(libc::AF_PACKET)?;
        address.sll_protocol = protocol;
        address.sll_ifindex = i32::try_from(index)?;
        // SAFETY: The address is initialized and the length
        // passed is its own.
        let bound = unsafe {
            libc::bind(
                socket.0.as_raw_fd(),
                (&raw const address).cast(),
                libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>())?,
            )
        };
        if bound != 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(socket)
    }

    fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: The pointer and length describe `frame`,
        // which outlives the call.
        let sent = unsafe { libc::send(self.0.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// The length of the next frame, read into `buffer`, or
    /// `None` if none arrives within `timeout`.
    fn receive(&self, buffer: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let mut poll_fd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Rounded up, so a timer due in under a millisecond
        // does not spin.
        let milliseconds = i32::try_from(timeout.as_millis().saturating_add(1)).unwrap_or(i32::MAX);
        // SAFETY: One initialized pollfd is passed, as the
        // count says.
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, milliseconds) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(None);
        }

        // SAFETY: The pointer and length describe `buffer`,
        // which outlives the call.
        let received = unsafe {
            libc::recv(
                self.0.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };

        usize::try_from(received)
            .map(Some)
            .map_err(|_| io::Error::last_os_error())
    }
}
