//! Interface facts an AF_XDP program needs before it can
//! bind.
//!
//! Gathered from three sources, because no single one
//! covers everything:
//!
//! - `if_nametoindex` for the index `bind` wants.
//! - `ioctl` on an `AF_INET` socket for the MAC, MTU and
//!   flags, plus `SIOCETHTOOL` for driver and channel info.
//! - `sysfs` for the per-queue directories and the NUMA
//!   node, which have no ioctl equivalent, and
//!   `/proc/net/route` for the default route.

use std::{
    ffi::CString,
    fs, io,
    mem::zeroed,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use libc::{c_char, c_int};
use thiserror::Error;

const ETHTOOL_GDRVINFO: u32 = 0x0000_0003;
const ETHTOOL_GCHANNELS: u32 = 0x0000_003c;
const ETHTOOL_SCHANNELS: u32 = 0x0000_003d;

/// Everything a bind decision depends on for one interface.
///
/// A snapshot, not a live view: MTU, link state and channel
/// counts can all change under you. Call [`Nic::open`]
/// again to refresh.
#[derive(Debug, Clone)]
pub struct Nic {
    name: String,
    index: u32,
    mac: [u8; 6],
    mtu: u32,
    flags: c_int,
    rx_queues: u32,
    tx_queues: u32,
    numa_node: Option<i32>,
    driver: Option<Driver>,
    channels: Option<Channels>,
}

/// Identity reported by the driver via `ETHTOOL_GDRVINFO`.
#[derive(Debug, Clone)]
pub struct Driver {
    /// Module name, e.g. `ice`, `mlx5_core`, `veth`.
    /// Determines whether `XDP_ZEROCOPY` is available
    /// at all.
    pub name: String,
    pub version: String,
    pub firmware: String,
    /// PCI address, e.g. `0000:af:00.0`. Empty for virtual
    /// devices.
    pub bus_info: String,
}

/// Queue counts as `ETHTOOL_GCHANNELS` reports them.
///
/// Distinct from [`Nic::rx_queues`]: these are the driver's
/// configurable channel counts, where `combined` channels
/// serve both RX and TX. Many virtual drivers do not
/// implement this at all.
#[derive(Debug, Clone, Copy)]
pub struct Channels {
    pub rx: u32,
    pub tx: u32,
    pub other: u32,
    pub combined: u32,
    pub max_rx: u32,
    pub max_tx: u32,
    pub max_other: u32,
    pub max_combined: u32,
}

impl Nic {
    /// Queries every field for the interface named `name`.
    pub fn open(name: &str) -> Result<Self, Error> {
        let cname = CString::new(name)
            .ok()
            .filter(|_| !name.is_empty() && name.len() < libc::IFNAMSIZ)
            .ok_or_else(|| Error::InvalidName(name.to_owned()))?;

        let index = match unsafe { libc::if_nametoindex(cname.as_ptr()) } {
            0 => return Err(Error::NotFound(name.to_owned())),
            index => index,
        };

        let sock = control_socket(name)?;

        let mac = hwaddr(&sock, name)?;
        let mtu = mtu(&sock, name)?;
        let flags = flags(&sock, name)?;
        let (rx_queues, tx_queues) = queue_counts(name)?;

        Ok(Self {
            name: name.to_owned(),
            index,
            mac,
            mtu,
            flags,
            rx_queues,
            tx_queues,
            numa_node: numa_node(name),
            // Both are unsupported on plenty of drivers; absence is not an error.
            driver: drvinfo(&sock, name).ok(),
            channels: channels(&sock, name).ok(),
        })
    }

    /// Names of every interface the kernel knows, including
    /// those that are down.
    pub fn list() -> Result<Vec<String>, Error> {
        let dir = "/sys/class/net";
        let entries = fs::read_dir(dir).map_err(|e| Error::Sysfs(dir.to_owned(), e))?;
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        Ok(names)
    }

    /// The interface carrying the IPv4 default route — the
    /// one a packet leaves by when nothing more
    /// specific matches.
    ///
    /// Note this is often *not* a NIC worth binding AF_XDP
    /// to: on a host running containers or bridges the
    /// default route can point at `docker0`, a
    /// `br-*` bridge or a `veth`, none of which support
    /// `XDP_ZEROCOPY`. Check [`Nic::driver`] before
    /// committing to it.
    ///
    /// Only IPv4 is considered; the v6 table has a
    /// different format and lives in `/proc/net/
    /// ipv6_route`.
    pub fn default_interface() -> Result<Self, Error> {
        const ROUTES: &str = "/proc/net/route";
        let table = fs::read_to_string(ROUTES).map_err(|e| Error::Sysfs(ROUTES.to_owned(), e))?;
        match default_iface_from_route_table(&table) {
            Some(name) => Self::open(&name),
            None => Err(Error::NoDefaultRoute(ROUTES)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// `sxdp_ifindex` for `bind`.
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Largest payload the interface will carry, excluding
    /// the Ethernet header.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Raw `IFF_*` bits.
    pub fn flags(&self) -> c_int {
        self.flags
    }

    /// Whether the interface is administratively up. `bind`
    /// fails otherwise.
    pub fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP != 0
    }

    /// Whether carrier is present. An interface can be up
    /// with no link.
    pub fn is_running(&self) -> bool {
        self.flags & libc::IFF_RUNNING != 0
    }

    /// `real_num_rx_queues`, counted from the per-queue
    /// sysfs directories.
    pub fn rx_queues(&self) -> u32 {
        self.rx_queues
    }

    /// `real_num_tx_queues`, counted from the per-queue
    /// sysfs directories.
    pub fn tx_queues(&self) -> u32 {
        self.tx_queues
    }

    /// Number of queue ids a socket with both RX and TX
    /// rings can bind to.
    ///
    /// `bind` rejects a queue id at or above the
    /// interface's RX count for a socket with an RX
    /// ring, and likewise for TX, so a socket carrying both
    /// is limited by the smaller of the two. Valid ids are
    /// `0..xdp_queues()`.
    pub fn xdp_queues(&self) -> u32 {
        self.rx_queues.min(self.tx_queues)
    }

    /// NUMA node the device is attached to, for pinning the
    /// UMEM and the polling thread nearby. `None` for
    /// virtual devices, or `-1` when the kernel reports
    /// no affinity.
    pub fn numa_node(&self) -> Option<i32> {
        self.numa_node
    }

    /// `None` when the driver does not implement
    /// `ETHTOOL_GDRVINFO`.
    pub fn driver(&self) -> Option<&Driver> {
        self.driver.as_ref()
    }

    /// `None` when the driver does not implement
    /// `ETHTOOL_GCHANNELS`, which is common for virtual
    /// interfaces.
    pub fn channels(&self) -> Option<&Channels> {
        self.channels.as_ref()
    }

    /// Sets the interface to `count` RX and TX queues, so
    /// an AF_XDP socket can bind queues `0..count` and
    /// RSS spreads flows across them.
    ///
    /// Equivalent to `ethtool -L <if> combined N`, or `rx N
    /// tx N` on drivers that count RX and TX channels
    /// separately. See `queue_counts` for why the two forms
    /// are not interchangeable.
    ///
    /// Requires `CAP_NET_ADMIN`. The driver reallocates its
    /// rings to service the request, which momentarily
    /// drops the link and discards whatever was
    /// in flight, so this is a setup-time operation, not
    /// something to call on a live capture.
    ///
    /// Call it *before* binding: `ethtool_set_channels`
    /// refuses to remove a queue that a zero-copy
    /// AF_XDP socket still owns a UMEM pool on, so
    /// shrinking an interface out from under a bound socket
    /// fails with `EINVAL` rather than tearing the
    /// socket down.
    ///
    /// Fails with `EOPNOTSUPP` on the many virtual drivers
    /// implementing neither half of the channels API —
    /// the same ones [`Nic::channels`] reports as
    /// `None`. It is a no-op, reported as success, when the
    /// interface already has the requested counts: the
    /// kernel compares against the current counts and
    /// returns early before touching the driver.
    ///
    /// Refreshes `self` on success, since the queue counts
    /// and channel configuration this snapshot holds
    /// are exactly what the call changed.
    pub fn set_queue_count(&mut self, count: u32) -> Result<(), Error> {
        let sock = control_socket(&self.name)?;
        let current = channels(&sock, &self.name)?;
        let (rx_count, tx_count, combined_count) = channel_counts(&current, count);

        let mut req = EthtoolChannels {
            cmd: ETHTOOL_SCHANNELS,
            // The kernel validates against the driver's own maxima and ignores
            // whatever is passed here, so there is nothing to fill in.
            max_rx: 0,
            max_tx: 0,
            max_other: 0,
            max_combined: 0,
            rx_count,
            tx_count,
            // Left as-is: several drivers park control queues here, and zeroing
            // it is not part of "one RX and one TX queue".
            other_count: current.other,
            combined_count,
        };
        ethtool(&sock, "SIOCETHTOOL(SCHANNELS)", &self.name, &mut req)?;

        let refreshed = Self::open(&self.name)?;
        *self = refreshed;
        Ok(())
    }
}

/// The `(rx_count, tx_count, combined_count)` leaving
/// `count` RX and TX queues, given what the driver reports
/// now.
///
/// Drivers fall into two camps and reject the other camp's
/// request. One that serves both directions from `combined`
/// channels has `max_rx`/`max_tx` of zero, so asking for
/// `rx N tx N` is `EINVAL`; one with dedicated rings has
/// `max_combined` of zero and rejects `combined N` the same
/// way. The current counts say which camp this interface is
/// in.
///
/// A zero `combined_count` on a driver that supports both
/// is still answered with dedicated queues — it is already
/// configured that way, and the point here is the queue
/// count, not migrating it to another channel layout.
fn channel_counts(current: &Channels, count: u32) -> (u32, u32, u32) {
    if current.combined > 0 {
        (0, 0, count)
    } else {
        (count, count, 0)
    }
}

/// A socket to hang the interface ioctls off. Any family
/// works; AF_INET SOCK_DGRAM needs no capabilities of its
/// own — the privileged calls check `CAP_NET_ADMIN` per
/// request, not at open time.
fn control_socket(name: &str) -> Result<OwnedFd, Error> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::Ioctl(
            "socket(AF_INET)",
            name.to_owned(),
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(sock) })
}

/// A zeroed [`libc::ifreq`] naming `iface`.
///
/// The union member the ioctl reads is left zeroed; each
/// caller writes or reads the one its request number
/// selects.
// c_char's signedness is platform-dependent (i8 here, u8 on aarch64), and an
// interface name is raw bytes where the sign carries no meaning — `as` is the
// portable reinterpretation.
#[allow(clippy::cast_possible_wrap)]
fn ifreq(iface: &str) -> libc::ifreq {
    let mut req: libc::ifreq = unsafe { zeroed() };
    // Length is checked against IFNAMSIZ in Nic::open, so this
    // cannot overrun.
    for (dst, byte) in req.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = *byte as c_char;
    }
    req
}

fn ioctl_ifreq(
    sock: &OwnedFd,
    what: &'static str,
    request: libc::c_ulong,
    name: &str,
    req: &mut libc::ifreq,
) -> Result<(), Error> {
    if unsafe { libc::ioctl(sock.as_raw_fd(), request, req as *mut libc::ifreq) } < 0 {
        return Err(Error::Ioctl(
            what,
            name.to_owned(),
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

// The MAC arrives as c_char, whose signedness is
// platform-dependent; `as u8` is the portable byte
// reinterpretation.
#[allow(clippy::cast_sign_loss)]
fn hwaddr(sock: &OwnedFd, name: &str) -> Result<[u8; 6], Error> {
    let mut req = ifreq(name);
    ioctl_ifreq(sock, "SIOCGIFHWADDR", libc::SIOCGIFHWADDR, name, &mut req)?;
    // sa_data holds the link-layer address; only the first 6
    // bytes matter for Ethernet, and non-Ethernet links
    // simply report a shorter address here.
    let data = unsafe { req.ifr_ifru.ifru_hwaddr.sa_data };
    let mut mac = [0u8; 6];
    for (dst, src) in mac.iter_mut().zip(data) {
        *dst = src as u8;
    }
    Ok(mac)
}

fn mtu(sock: &OwnedFd, name: &str) -> Result<u32, Error> {
    let mut req = ifreq(name);
    ioctl_ifreq(sock, "SIOCGIFMTU", libc::SIOCGIFMTU, name, &mut req)?;
    // ifru_mtu is a c_int; a plain `as u32` would turn a
    // negative value into a huge MTU instead of surfacing
    // the kernel nonsense it would be.
    Ok(u32::try_from(unsafe { req.ifr_ifru.ifru_mtu }).expect("kernel reported a negative MTU"))
}

fn flags(sock: &OwnedFd, name: &str) -> Result<c_int, Error> {
    let mut req = ifreq(name);
    ioctl_ifreq(sock, "SIOCGIFFLAGS", libc::SIOCGIFFLAGS, name, &mut req)?;
    // ifr_flags is a short, so widen rather than reading a
    // wider member.
    Ok(c_int::from(unsafe { req.ifr_ifru.ifru_flags }))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EthtoolDrvinfo {
    cmd: u32,
    driver: [c_char; 32],
    version: [c_char; 32],
    fw_version: [c_char; 32],
    bus_info: [c_char; 32],
    erom_version: [c_char; 32],
    reserved2: [c_char; 12],
    n_priv_flags: u32,
    n_stats: u32,
    testinfo_len: u32,
    eedump_len: u32,
    regdump_len: u32,
}

/// Runs a `SIOCETHTOOL` command, whose payload is passed by
/// pointer through `ifr_data` rather than inline in the
/// `ifreq`.
fn ethtool<T>(
    sock: &OwnedFd,
    what: &'static str,
    name: &str,
    payload: &mut T,
) -> Result<(), Error> {
    let mut req = ifreq(name);
    req.ifr_ifru.ifru_data = (payload as *mut T).cast::<c_char>();
    ioctl_ifreq(sock, what, libc::SIOCETHTOOL, name, &mut req)
}

fn drvinfo(sock: &OwnedFd, name: &str) -> Result<Driver, Error> {
    let mut info = EthtoolDrvinfo {
        cmd: ETHTOOL_GDRVINFO,
        driver: [0; 32],
        version: [0; 32],
        fw_version: [0; 32],
        bus_info: [0; 32],
        erom_version: [0; 32],
        reserved2: [0; 12],
        n_priv_flags: 0,
        n_stats: 0,
        testinfo_len: 0,
        eedump_len: 0,
        regdump_len: 0,
    };
    ethtool(sock, "SIOCETHTOOL(GDRVINFO)", name, &mut info)?;
    Ok(Driver {
        name: fixed_str(&info.driver),
        version: fixed_str(&info.version),
        firmware: fixed_str(&info.fw_version),
        bus_info: fixed_str(&info.bus_info),
    })
}

fn channels(sock: &OwnedFd, name: &str) -> Result<Channels, Error> {
    let mut ch = EthtoolChannels {
        cmd: ETHTOOL_GCHANNELS,
        max_rx: 0,
        max_tx: 0,
        max_other: 0,
        max_combined: 0,
        rx_count: 0,
        tx_count: 0,
        other_count: 0,
        combined_count: 0,
    };
    ethtool(sock, "SIOCETHTOOL(GCHANNELS)", name, &mut ch)?;
    Ok(Channels {
        rx: ch.rx_count,
        tx: ch.tx_count,
        other: ch.other_count,
        combined: ch.combined_count,
        max_rx: ch.max_rx,
        max_tx: ch.max_tx,
        max_other: ch.max_other,
        max_combined: ch.max_combined,
    })
}

/// Reads a nul-padded fixed-size C string field, tolerating
/// a missing nul.
// String bytes arrive as c_char, whose signedness is platform-dependent;
// `as u8` is the portable byte reinterpretation.
#[allow(clippy::cast_sign_loss)]
fn fixed_str(field: &[c_char]) -> String {
    let bytes: Vec<u8> = field.iter().map(|&b| b as u8).collect();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Counts the `rx-*` and `tx-*` directories under the
/// interface's sysfs `queues/`, which is exactly
/// `real_num_rx_queues` / `real_num_tx_queues` — the values
/// `bind` range-checks a queue id against.
/// `ETHTOOL_GCHANNELS` is not a substitute: it reports
/// configurable channels, and many drivers do not implement
/// it.
fn queue_counts(name: &str) -> Result<(u32, u32), Error> {
    let dir = format!("/sys/class/net/{name}/queues");
    let entries = fs::read_dir(&dir).map_err(|e| Error::Sysfs(dir.clone(), e))?;
    let (mut rx, mut tx) = (0, 0);
    for entry in entries.flatten() {
        match entry.file_name().to_str() {
            Some(n) if n.starts_with("rx-") => rx += 1,
            Some(n) if n.starts_with("tx-") => tx += 1,
            _ => {}
        }
    }
    Ok((rx, tx))
}

/// Picks the default-route interface out of a
/// `/proc/net/route` dump.
///
/// Columns are `Iface Destination Gateway Flags RefCnt Use
/// Metric Mask ...`, with addresses as native-endian hex. A
/// default route is the one matching everything: zero
/// destination *and* zero mask. Checking the mask matters —
/// a `0.0.0.0/8` route would share the destination but is
/// not a default.
///
/// Lowest metric wins, which is how the kernel itself
/// breaks ties when more than one default route exists.
fn default_iface_from_route_table(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let destination = fields.next()?;
            let metric = fields.nth(4)?.parse::<u32>().ok()?; // skip gateway/flags/refcnt/use
            let mask = fields.next()?;
            let is_default = destination.trim_start_matches('0').is_empty()
                && mask.trim_start_matches('0').is_empty();
            is_default.then(|| (metric, iface.to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, iface)| iface)
}

/// `None` when the file is absent, which is the normal case
/// for virtual devices.
fn numa_node(name: &str) -> Option<i32> {
    let path = format!("/sys/class/net/{name}/device/numa_node");
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("interface name {0:?} must be 1 to 15 bytes with no nul")]
    InvalidName(String),

    #[error("interface {0:?} not found")]
    NotFound(String),

    #[error("{0} on {1:?} failed: {2}")]
    Ioctl(&'static str, String, io::Error),

    #[error("reading {0} failed: {1}")]
    Sysfs(String, io::Error),

    #[error("no IPv4 default route in {0}")]
    NoDefaultRoute(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethtool_structs_match_the_kernel_layout() {
        assert_eq!(size_of::<EthtoolChannels>(), 36);
        assert_eq!(size_of::<EthtoolDrvinfo>(), 196);
    }

    #[test]
    fn rejects_unusable_and_unknown_names() {
        assert!(matches!(Nic::open(""), Err(Error::InvalidName(_))));
        assert!(matches!(
            Nic::open("an-interface-name-far-too-long"),
            Err(Error::InvalidName(_))
        ));
        assert!(matches!(Nic::open("eth\0z"), Err(Error::InvalidName(_))));
        assert!(matches!(Nic::open("no-such-nic"), Err(Error::NotFound(_))));
    }

    /// Loopback stands in for a real device: it is always
    /// present, and it implements neither half of the
    /// channels API, so the ioctl path can be exercised
    /// without reconfiguring a NIC out from under the
    /// host.
    #[test]
    fn reads_loopback_and_reports_unsupported_ioctls() {
        let mut lo = Nic::open("lo").expect("loopback should always exist");
        assert_eq!(lo.name(), "lo");
        assert!(lo.index() > 0);
        assert!(lo.is_up());
        assert!(lo.mtu() > 0);
        // Loopback has no hardware address.
        assert_eq!(lo.mac(), [0; 6]);
        assert!(lo.rx_queues() >= 1);
        assert!(lo.tx_queues() >= 1);
        assert!(Nic::list().unwrap().iter().any(|n| n == "lo"));

        match lo.set_queue_count(1) {
            Err(Error::Ioctl("SIOCETHTOOL(GCHANNELS)", name, e)) => {
                assert_eq!(name, "lo");
                assert_eq!(e.raw_os_error(), Some(libc::EOPNOTSUPP));
            }
            other => panic!("expected EOPNOTSUPP from loopback, got {other:?}"),
        }
    }

    #[test]
    fn channel_counts_follow_the_driver_style() {
        fn channels_with(rx: u32, tx: u32, combined: u32) -> Channels {
            Channels {
                rx,
                tx,
                other: 0,
                combined,
                max_rx: 0,
                max_tx: 0,
                max_other: 0,
                max_combined: 0,
            }
        }

        // mlx5-style: everything through combined channels.
        assert_eq!(channel_counts(&channels_with(0, 0, 8), 4), (0, 0, 4));
        // Dedicated rx/tx channels get N of each.
        assert_eq!(channel_counts(&channels_with(4, 4, 0), 2), (2, 2, 0));
        // Matching the current counts is what makes the ioctl a
        // no-op.
        assert_eq!(channel_counts(&channels_with(0, 0, 1), 1), (0, 0, 1));
        assert_eq!(channel_counts(&channels_with(1, 1, 0), 1), (1, 1, 0));
    }

    #[test]
    fn finds_the_default_route_in_the_route_table() {
        // Real `/proc/net/route` output: one default route plus a
        // container bridge route and an on-link route, neither of
        // which is a default.
        const TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert_eq!(
            default_iface_from_route_table(TABLE).as_deref(),
            Some("enp5s0")
        );

        // Among several defaults, the lowest metric wins.
        const MULTIPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask
wwan0\t00000000\t0101A8C0\t0003\t0\t0\t700\t00000000
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000
wlan0\t00000000\t0103A8C0\t0003\t0\t0\t600\t00000000
";
        assert_eq!(
            default_iface_from_route_table(MULTIPLE).as_deref(),
            Some("eth0")
        );

        // 0.0.0.0/8 shares the destination but has a non-zero mask,
        // so it is not a default route.
        const MASKED: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask
eth0\t00000000\t00000000\t0001\t0\t0\t0\t000000FF
";
        assert_eq!(default_iface_from_route_table(MASKED), None);

        // Empty and malformed tables yield no answer rather than
        // panicking.
        assert_eq!(default_iface_from_route_table(""), None);
        assert_eq!(default_iface_from_route_table("Iface\tDestination\n"), None);
        assert_eq!(default_iface_from_route_table("header\neth0\t000\n"), None);
    }

    /// Dumps everything [`Nic`] can see about the
    /// default-route interface.
    ///
    /// A diagnostic rather than a check — `cargo test`
    /// swallows stdout unless you ask for it:
    ///
    /// ```text
    /// cargo test -p mangonel-nic default_nic_report -- --nocapture
    /// ```
    #[test]
    fn default_nic_report() {
        let nic = match Nic::default_interface() {
            Ok(nic) => nic,
            Err(e) => {
                println!("no default interface: {e}");
                return;
            }
        };

        let mac = nic
            .mac()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        println!("default interface: {} (index {})", nic.name(), nic.index());
        println!("  mac          {mac}");
        println!("  mtu          {}", nic.mtu());
        println!(
            "  flags        {:#06x} ({}{})",
            nic.flags(),
            if nic.is_up() { "up" } else { "down" },
            if nic.is_running() { ", running" } else { "" },
        );
        println!(
            "  queues       rx {} / tx {}",
            nic.rx_queues(),
            nic.tx_queues()
        );
        println!(
            "  xdp bindable queue ids 0..{} ({} socket{})",
            nic.xdp_queues(),
            nic.xdp_queues(),
            if nic.xdp_queues() == 1 { "" } else { "s" },
        );
        match nic.numa_node() {
            Some(node) => println!("  numa node    {node}"),
            None => println!("  numa node    unknown (virtual device)"),
        }
        match nic.driver() {
            Some(d) => {
                println!("  driver       {} {}", d.name, d.version);
                println!(
                    "  firmware     {}",
                    if d.firmware.is_empty() {
                        "-"
                    } else {
                        d.firmware.trim()
                    }
                );
                println!(
                    "  bus          {}",
                    if d.bus_info.is_empty() {
                        "- (not a PCI device)"
                    } else {
                        &d.bus_info
                    }
                );
            }
            None => println!("  driver       unavailable (no ETHTOOL_GDRVINFO)"),
        }
        match nic.channels() {
            Some(c) => println!(
                "  channels     combined {}/{}, rx {}/{}, tx {}/{}",
                c.combined, c.max_combined, c.rx, c.max_rx, c.tx, c.max_tx
            ),
            None => println!("  channels     unavailable (no ETHTOOL_GCHANNELS)"),
        }

        // Cheap sanity so the report is not the only thing
        // exercised.
        assert!(!nic.name().is_empty());
        assert!(nic.index() > 0);
    }
}
