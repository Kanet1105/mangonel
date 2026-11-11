//! The command line, after xdp-trafficgen's.

use std::{
    fmt,
    net::Ipv4Addr,
    num::{
        NonZeroU32,
        NonZeroU64,
    },
    str::FromStr,
};

use clap::{
    Args,
    Parser,
    Subcommand,
};

/// Generates traffic to load whatever an interface leads to.
#[derive(Debug, Parser)]
#[command(version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Send UDP over IPv4 through AF_XDP sockets, as fast as
    /// the interface takes it.
    Udp(Udp),
}

/// What the `udp` command sends, where and for how long.
#[derive(Debug, Args)]
pub(crate) struct Udp {
    /// The device to transmit on.
    pub(crate) ifname: String,

    /// Destination MAC address of the packets: the next
    /// hop's.
    #[arg(
        short = 'm',
        long,
        value_name = "MAC",
        default_value = "00:00:00:00:00:00"
    )]
    pub(crate) dst_mac: Mac,

    /// Source MAC address of the packets. Defaults to the
    /// device's own.
    #[arg(short = 'M', long, value_name = "MAC")]
    pub(crate) src_mac: Option<Mac>,

    /// Destination IPv4 address of the packets.
    #[arg(
        short = 'a',
        long,
        value_name = "ADDRESS",
        default_value = "198.18.0.2"
    )]
    pub(crate) dst_addr: Ipv4Addr,

    /// Source IPv4 address of the packets.
    #[arg(
        short = 'A',
        long,
        value_name = "ADDRESS",
        default_value = "198.18.0.1"
    )]
    pub(crate) src_addr: Ipv4Addr,

    /// Destination port, or the first of them with
    /// --dyn-ports.
    #[arg(short = 'p', long, value_name = "PORT", default_value_t = 1)]
    pub(crate) dst_port: u16,

    /// Source port of the packets.
    #[arg(short = 'P', long, value_name = "PORT", default_value_t = 1)]
    pub(crate) src_port: u16,

    /// Vary the destination port over this many ports, each
    /// a flow of its own.
    #[arg(short = 'd', long, value_name = "COUNT", default_value_t = NonZeroU32::MIN)]
    pub(crate) dyn_ports: NonZeroU32,

    /// Stop after this many packets. Without it or
    /// --duration, send until interrupted.
    #[arg(short = 'n', long, value_name = "COUNT")]
    pub(crate) num_packets: Option<NonZeroU64>,

    /// Stop after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    pub(crate) duration: Option<NonZeroU64>,

    /// Size of each packet on the wire, counting the Ethernet
    /// header and the four-byte checksum that follows the
    /// frame.
    #[arg(short = 's', long, value_name = "BYTES", default_value_t = 64)]
    pub(crate) pkt_size: usize,

    /// Threads to transmit from, each on a queue and a core
    /// of its own.
    #[arg(short = 't', long, value_name = "COUNT", default_value_t = NonZeroU32::MIN)]
    pub(crate) threads: NonZeroU32,

    /// Seconds between lines of statistics.
    #[arg(short = 'I', long, value_name = "SECONDS", default_value_t = NonZeroU64::MIN)]
    pub(crate) interval: NonZeroU64,

    /// Hops the packets may travel. One, the default, lets no
    /// router pass them on.
    #[arg(short = 'l', long, value_name = "HOPS", default_value_t = 1)]
    pub(crate) hop_limit: u8,

    /// Packets handed to the interface at a time.
    #[arg(short = 'b', long, value_name = "COUNT", default_value_t = NonZeroU32::new(64).unwrap())]
    pub(crate) batch_size: NonZeroU32,
}

/// An Ethernet address as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mac(pub(crate) [u8; 6]);

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;

        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl FromStr for Mac {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let malformed = || format!("{text:?} is not a MAC address like 02:00:00:01:00:02");
        let mut mac = [0u8; 6];
        let mut octets = text.split(':');
        for byte in &mut mac {
            let octet = octets.next().filter(|octet| octet.len() == 2);
            *byte =
                u8::from_str_radix(octet.ok_or_else(malformed)?, 16).map_err(|_| malformed())?;
        }
        if octets.next().is_some() {
            return Err(malformed());
        }

        Ok(Self(mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp(args: &[&str]) -> Result<Udp, clap::Error> {
        let args = ["mangonel-trafficgen", "udp"].iter().chain(args).copied();
        let Command::Udp(udp) = Cli::try_parse_from(args)?.command;

        Ok(udp)
    }

    #[test]
    fn a_device_alone_sends_what_cannot_be_routed() {
        let udp = udp(&["eth0"]).unwrap();
        assert_eq!(udp.ifname, "eth0");
        assert_eq!(udp.dst_mac, Mac([0; 6]));
        assert_eq!(udp.src_mac, None);
        // The benchmarking range of RFC 2544.
        assert_eq!(udp.src_addr, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(udp.dst_addr, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!((udp.src_port, udp.dst_port, udp.dyn_ports.get()), (1, 1, 1));
        assert_eq!((udp.pkt_size, udp.hop_limit), (64, 1));
        assert_eq!((udp.threads.get(), udp.batch_size.get()), (1, 64));
        assert_eq!(udp.interval.get(), 1);
        assert!(udp.num_packets.is_none() && udp.duration.is_none());
    }

    #[test]
    fn the_short_options_are_xdp_trafficgens() {
        let udp = udp(&[
            "-m",
            "02:00:00:01:00:02",
            "-M",
            "02:00:00:04:00:00",
            "-a",
            "203.0.113.1",
            "-A",
            "10.0.0.50",
            "-p",
            "9000",
            "-P",
            "4000",
            "-d",
            "1024",
            "-n",
            "1000000",
            "-s",
            "1518",
            "-t",
            "2",
            "-I",
            "5",
            "-l",
            "64",
            "eth0",
        ])
        .unwrap();
        assert_eq!(udp.dst_mac, Mac([2, 0, 0, 1, 0, 2]));
        assert_eq!(udp.src_mac, Some(Mac([2, 0, 0, 4, 0, 0])));
        assert_eq!(udp.dst_addr, Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(udp.src_addr, Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(
            (udp.dst_port, udp.src_port, udp.dyn_ports.get()),
            (9000, 4000, 1024)
        );
        assert_eq!(udp.num_packets.map(NonZeroU64::get), Some(1_000_000));
        assert_eq!(
            (udp.pkt_size, udp.threads.get(), udp.interval.get()),
            (1518, 2, 5)
        );
        assert_eq!(udp.hop_limit, 64);
    }

    #[test]
    fn malformed_arguments_are_refused() {
        assert!(udp(&[]).is_err());
        for mac in [
            "",
            "02:00:00:01:00",
            "02:00:00:01:00:02:03",
            "02:00:00:01:00:zz",
            "2:0:0:1:0:2",
        ] {
            assert!(udp(&["-m", mac, "eth0"]).is_err(), "{mac:?}");
        }
        assert!(udp(&["-a", "fe80::2", "eth0"]).is_err());
        assert!(udp(&["-t", "0", "eth0"]).is_err());
        assert!(udp(&["-d", "0", "eth0"]).is_err());
    }

    #[test]
    fn a_mac_reads_back_as_it_prints() {
        let text = "02:00:5e:10:ab:ff";
        assert_eq!(text.parse::<Mac>().unwrap().to_string(), text);
    }
}
