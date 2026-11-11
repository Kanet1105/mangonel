//! The command line: the devices to route between, or none
//! of them for a terminal user to be asked.

use std::{
    fmt,
    net::Ipv4Addr,
    num::NonZeroU32,
    str::FromStr,
};

use clap::Parser;

use crate::{
    control::{
        Addressing,
        Cidr,
        Dns,
        LanIp,
        LanPort,
        MacAddr,
        PortAcls,
        WanIp,
        WanPort,
    },
    error::Error,
};

/// Routes between one WAN device and the LAN devices behind
/// it. Started without --wan and --lan, it asks for them.
#[derive(Debug, Parser)]
#[command(version, about)]
pub(crate) struct Cli {
    /// The uplink. It leases its address over DHCP unless
    /// one is given, with the router the rest of the world
    /// is reached through.
    #[arg(long, requires = "lan", value_name = "DEVICE[=ADDRESS/PREFIX,GATEWAY]")]
    pub(crate) wan: Option<Wan>,

    /// A downstream segment; repeat for each. Without an
    /// address the Nth one given takes 10.0.N.1/24, counting
    /// from 0. The segment's other addresses are leased to
    /// its hosts, unless ",static" says they are set by
    /// hand.
    #[arg(
        long,
        requires = "wan",
        value_name = "DEVICE[=ADDRESS/PREFIX][,static]"
    )]
    pub(crate) lan: Vec<Lan>,

    /// A resolver to hand to LAN hosts; repeat for a second.
    /// Defaults to those of the WAN lease, or to the gateway
    /// of a WAN address given here.
    #[arg(long, value_name = "ADDRESS")]
    pub(crate) dns: Vec<Ipv4Addr>,

    /// The most workers to run. By default there is one per
    /// queue of the device with the fewest, as far as the
    /// cores go.
    #[arg(long, value_name = "COUNT")]
    pub(crate) workers: Option<NonZeroU32>,
}

/// The WAN device and, unless it leases one, its address
/// and gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wan {
    pub(crate) device: String,
    pub(crate) address: Option<(Cidr<Ipv4Addr>, Ipv4Addr)>,
}

/// As [`FromStr`] reads it.
impl fmt::Display for Wan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.device)?;
        match self.address {
            Some((cidr, gateway)) => write!(f, "={cidr},{gateway}"),
            None => Ok(()),
        }
    }
}

impl FromStr for Wan {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let Some((name, address)) = spec.split_once('=') else {
            return Ok(Self {
                device: device(spec)?,
                address: None,
            });
        };
        let (address, gateway) = address
            .split_once(',')
            .ok_or("an address needs its gateway: ADDRESS/PREFIX,GATEWAY")?;
        let gateway = gateway
            .parse()
            .map_err(|_| format!("{gateway:?} is not an IPv4 address"))?;

        Ok(Self {
            device: device(name)?,
            address: Some((cidr(address)?, gateway)),
        })
    }
}

impl Wan {
    /// The WAN port as the control panel takes it, for the
    /// device's `mac`. LAN hosts are handed `resolvers`, or
    /// when there are none, what the port's addressing
    /// suggests.
    pub(crate) fn port(&self, mac: [u8; 6], resolvers: &[Ipv4Addr]) -> Result<WanPort, Error> {
        if resolvers.len() > 2 {
            return Err(Error::TooManyResolvers(resolvers.len()));
        }
        let given = resolvers.first().map(|&primary| Dns::Manual {
            primary,
            secondary: resolvers.get(1).copied(),
        });
        let (addressing, dns) = match self.address {
            // An upstream router usually resolves for its
            // segment too.
            Some((cidr, gateway)) => (
                Addressing::Static { cidr, gateway },
                given.unwrap_or(Dns::Manual {
                    primary: gateway,
                    secondary: None,
                }),
            ),
            None => (Addressing::Dhcp, given.unwrap_or(Dns::Auto)),
        };

        Ok(WanPort {
            mac: MacAddr(mac),
            ipv4: Some(WanIp { addressing, dns }),
            ipv6: None,
            acls: PortAcls::default(),
        })
    }
}

/// A LAN device, its address unless it takes the default,
/// and whether its hosts are leased theirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lan {
    pub(crate) device: String,
    pub(crate) cidr: Option<Cidr<Ipv4Addr>>,
    /// Whether the gateway serves DHCP on the segment.
    pub(crate) dhcp: bool,
}

/// As [`FromStr`] reads it.
impl fmt::Display for Lan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.device)?;
        if let Some(cidr) = self.cidr {
            write!(f, "={cidr}")?;
        }
        if !self.dhcp {
            f.write_str(STATIC)?;
        }

        Ok(())
    }
}

impl FromStr for Lan {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (spec, dhcp) = match spec.strip_suffix(STATIC) {
            Some(spec) => (spec, false),
            None => (spec, true),
        };
        let (name, address) = match spec.split_once('=') {
            Some((name, address)) => (name, Some(cidr(address)?)),
            None => (spec, None),
        };

        Ok(Self {
            device: device(name)?,
            cidr: address,
            dhcp,
        })
    }
}

impl Lan {
    /// The address the `index`th LAN port takes when it is
    /// given none; only the first 256 have one.
    pub(crate) fn default_cidr(index: usize) -> Option<Cidr<Ipv4Addr>> {
        let subnet = u8::try_from(index).ok()?;

        Some(Cidr::new(Ipv4Addr::new(10, 0, subnet, 1), 24))
    }

    /// The `index`th LAN port as the control panel takes it,
    /// for the device's `mac`.
    pub(crate) fn port(&self, index: usize, mac: [u8; 6]) -> Result<LanPort, Error> {
        let cidr = self
            .cidr
            .or_else(|| Self::default_cidr(index))
            .ok_or_else(|| Error::NoDefaultAddress(self.device.clone(), index))?;
        let (pool_start, pool_end) = pool(cidr);

        Ok(LanPort {
            mac: MacAddr(mac),
            ipv4: Some(LanIp {
                cidr,
                pool_start,
                pool_end,
                dhcp: self.dhcp,
            }),
            ipv6: None,
            acls: PortAcls::default(),
        })
    }
}

/// What follows a LAN device whose hosts are not leased
/// their addresses.
const STATIC: &str = ",static";

/// A device name the kernel could have given.
fn device(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(format!(
            "a device name is 1 to {} bytes, not {name:?}",
            libc::IFNAMSIZ - 1
        ));
    }

    Ok(name.to_owned())
}

/// An address with its prefix length, as `ADDRESS/PREFIX`.
pub(crate) fn cidr(text: &str) -> Result<Cidr<Ipv4Addr>, String> {
    let malformed = || format!("{text:?} is not an IPv4 ADDRESS/PREFIX");
    let (address, prefix) = text.split_once('/').ok_or_else(malformed)?;
    let address = address.parse().map_err(|_| malformed())?;
    let prefix = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(malformed)?;

    Ok(Cidr::new(address, prefix))
}

/// The addresses a LAN port leases by default: every host
/// address on the longer side of its own. A subnet too
/// small to have any is left for the control panel to
/// reject.
fn pool(cidr: Cidr<Ipv4Addr>) -> (Ipv4Addr, Ipv4Addr) {
    let address = u32::from(cidr.address);
    let hosts = u32::MAX.checked_shr(u32::from(cidr.prefix)).unwrap_or(0);
    let first = (address & !hosts).saturating_add(1);
    let last = (address | hosts).saturating_sub(1);
    let (start, end) = if address.saturating_sub(first) > last.saturating_sub(address) {
        (first, address.saturating_sub(1))
    } else {
        (address.saturating_add(1), last)
    };

    (Ipv4Addr::from(start), Ipv4Addr::from(end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 1, 0, 1];

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("mangonel-router").chain(args.iter().copied()))
    }

    #[test]
    fn devices_alone_are_enough() {
        let cli = parse(&["--wan", "wan", "--lan", "lan-0", "--lan", "lan-1"]).unwrap();
        let wan = cli.wan.unwrap();
        assert_eq!(wan.device, "wan");
        assert_eq!(cli.workers, None);

        // The WAN leases, and hands on what the lease names.
        let port = wan.port(MAC, &cli.dns).unwrap();
        assert_eq!(port.validate(), Ok(()));
        assert_eq!(
            port.ipv4,
            Some(WanIp {
                addressing: Addressing::Dhcp,
                dns: Dns::Auto,
            })
        );

        // Each LAN takes the next subnet and leases the rest
        // of it.
        for (index, subnet) in [0, 1].into_iter().enumerate() {
            let port = cli.lan[index].port(index, MAC).unwrap();
            assert_eq!(port.validate(), Ok(()));
            assert_eq!(
                port.ipv4,
                Some(LanIp {
                    cidr: Cidr::new(Ipv4Addr::new(10, 0, subnet, 1), 24),
                    pool_start: Ipv4Addr::new(10, 0, subnet, 2),
                    pool_end: Ipv4Addr::new(10, 0, subnet, 254),
                    dhcp: true,
                })
            );
        }
    }

    #[test]
    fn no_devices_means_asking() {
        let cli = parse(&["--workers", "2"]).unwrap();
        assert!(cli.wan.is_none() && cli.lan.is_empty());

        // One without the other is neither.
        assert!(parse(&["--wan", "wan"]).is_err());
        assert!(parse(&["--lan", "lan"]).is_err());
    }

    #[test]
    fn addresses_can_be_given() {
        let cli = parse(&[
            "--wan",
            "wan=203.0.113.2/24,203.0.113.1",
            "--lan=lan-0=192.168.7.254/23",
            "--workers",
            "2",
        ])
        .unwrap();
        assert_eq!(cli.workers.map(NonZeroU32::get), Some(2));

        let port = cli.wan.unwrap().port(MAC, &cli.dns).unwrap();
        assert_eq!(port.validate(), Ok(()));
        let gateway = Ipv4Addr::new(203, 0, 113, 1);
        assert_eq!(
            port.ipv4,
            Some(WanIp {
                addressing: Addressing::Static {
                    cidr: Cidr::new(Ipv4Addr::new(203, 0, 113, 2), 24),
                    gateway,
                },
                dns: Dns::Manual {
                    primary: gateway,
                    secondary: None,
                },
            })
        );

        let port = cli.lan[0].port(0, MAC).unwrap();
        assert_eq!(port.validate(), Ok(()));
        let ip = port.ipv4.unwrap();
        assert_eq!(ip.cidr, Cidr::new(Ipv4Addr::new(192, 168, 7, 254), 23));
        assert_eq!(
            (ip.pool_start, ip.pool_end),
            (
                Ipv4Addr::new(192, 168, 6, 1),
                Ipv4Addr::new(192, 168, 7, 253)
            )
        );
    }

    #[test]
    fn a_lan_can_leave_its_hosts_to_set_their_own_addresses() {
        for (spec, address) in [
            ("lan,static", None),
            ("lan=10.9.0.1/24,static", Some("10.9.0.1/24")),
        ] {
            let lan: Lan = spec.parse().unwrap();
            assert_eq!(lan.device, "lan");
            assert_eq!(lan.cidr, address.map(|address| cidr(address).unwrap()));
            assert!(!lan.dhcp);

            let port = lan.port(0, MAC).unwrap();
            assert_eq!(port.validate(), Ok(()));
            assert!(!port.ipv4.unwrap().dhcp);
        }
    }

    #[test]
    fn a_port_reads_back_as_it_prints() {
        for spec in ["wan", "wan=203.0.113.2/24,203.0.113.1"] {
            assert_eq!(spec.parse::<Wan>().unwrap().to_string(), spec);
        }
        for spec in [
            "lan",
            "lan,static",
            "lan=10.9.0.1/24",
            "lan=10.9.0.1/24,static",
        ] {
            assert_eq!(spec.parse::<Lan>().unwrap().to_string(), spec);
        }
    }

    #[test]
    fn resolvers_given_replace_the_defaults() {
        let resolvers = [
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
        ];
        let leasing: Wan = "wan".parse().unwrap();
        let fixed: Wan = "wan=203.0.113.2/24,203.0.113.1".parse().unwrap();

        assert_eq!(
            leasing
                .port(MAC, &resolvers[..1])
                .unwrap()
                .ipv4
                .unwrap()
                .dns,
            Dns::Manual {
                primary: resolvers[0],
                secondary: None,
            }
        );
        assert_eq!(
            fixed.port(MAC, &resolvers[..2]).unwrap().ipv4.unwrap().dns,
            Dns::Manual {
                primary: resolvers[0],
                secondary: Some(resolvers[1]),
            }
        );
        assert!(matches!(
            leasing.port(MAC, &resolvers),
            Err(Error::TooManyResolvers(3))
        ));

        let cli = parse(&["--wan", "wan", "--lan", "lan", "--dns", "9.9.9.9"]).unwrap();
        assert_eq!(cli.dns, resolvers[..1]);
    }

    #[test]
    fn malformed_arguments_are_refused() {
        assert!(parse(&["--wan", "wan", "--wan", "wan-1", "--lan", "lan"]).is_err());
        for wan in [
            "",
            "a-name-of-16-byt",
            "wan=203.0.113.2/24",
            "wan=203.0.113.2,203.0.113.1",
            "wan=203.0.113.2/33,203.0.113.1",
            "wan=203.0.113.2/24,upstream",
        ] {
            assert!(parse(&["--wan", wan, "--lan", "lan"]).is_err(), "{wan:?}");
        }
        for lan in [
            "",
            "lan=10.0.0.1",
            "lan=10.0.0/24",
            "lan=10.0.0.1/x",
            ",static",
        ] {
            assert!(parse(&["--wan", "wan", "--lan", lan]).is_err(), "{lan:?}");
        }
        assert!(parse(&["--wan", "wan", "--lan", "lan", "--workers", "0"]).is_err());
    }

    #[test]
    fn a_subnet_too_small_to_lease_from_is_left_to_the_control_panel() {
        let port = |spec: &str| spec.parse::<Lan>().unwrap().port(0, MAC).unwrap();
        assert!(port("lan=10.0.0.1/31").validate().is_err());
        assert!(port("lan=10.0.0.0/24").validate().is_err());

        // The smallest that works has one address to lease.
        let lan = port("lan=10.0.0.2/30");
        assert_eq!(lan.validate(), Ok(()));
        let ip = lan.ipv4.unwrap();
        assert_eq!(ip.pool_start, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.pool_end, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn only_the_first_256_lans_have_a_default_address() {
        let lan: Lan = "lan".parse().unwrap();
        assert!(lan.port(255, MAC).is_ok());
        assert!(matches!(
            lan.port(256, MAC),
            Err(Error::NoDefaultAddress(device, 256)) if device == "lan"
        ));
    }
}
