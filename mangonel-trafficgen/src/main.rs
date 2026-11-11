//! mangonel-trafficgen: a traffic generator on AF_XDP
//! sockets, after xdp-trafficgen.
//!
//! It fills a device's transmit queues with one UDP packet,
//! varied by destination port, to load whatever the device
//! leads to, and reports the rate it sent at.

#![warn(unreachable_pub)]

mod affinity;
mod cli;
mod error;
mod generate;
mod packet;
mod signal;

use std::{
    net::SocketAddrV4,
    process::ExitCode,
    sync::atomic::{
        AtomicBool,
        AtomicU64,
        Ordering,
    },
    thread,
    time::{
        Duration,
        Instant,
    },
};

use clap::Parser;
use mangonel_libxdp::{
    XdpConfig,
    bind,
};
use mangonel_nic::nic::Nic;

use crate::{
    cli::{
        Cli,
        Command,
        Udp,
    },
    error::Error,
    generate::{
        Job,
        Ports,
    },
    packet::{
        Addresses,
        Template,
    },
};

/// How often the main thread looks at the clock and the
/// transmit threads.
const WATCH: Duration = Duration::from_millis(10);

fn main() -> ExitCode {
    let Command::Udp(udp) = Cli::parse().command;
    match run(&udp) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mangonel-trafficgen: {error}");

            ExitCode::FAILURE
        }
    }
}

/// Sends as `udp` asks, reporting the rate as it goes and
/// the total at the end.
fn run(udp: &Udp) -> Result<(), Error> {
    let stop = signal::install().map_err(Error::Signal)?;
    let device = &udp.ifname;
    let nic = Nic::open(device).map_err(|error| Error::Device(device.clone(), error))?;

    let threads = udp.threads.get();
    if threads > nic.xdp_queues() {
        return Err(Error::TooFewQueues {
            device: device.clone(),
            queues: nic.xdp_queues(),
            threads,
        });
    }
    let (min, max) = (packet::MIN_SIZE, packet::max_size(nic.mtu()));
    if !(min..=max).contains(&udp.pkt_size) || !packet::holds_headers(udp.pkt_size) {
        return Err(Error::PacketSize {
            device: device.clone(),
            size: udp.pkt_size,
            min,
            max,
        });
    }
    let port_count = udp.dyn_ports.get();
    let last_port = u32::from(udp.dst_port).saturating_add(port_count - 1);
    if last_port > u32::from(u16::MAX) {
        return Err(Error::PortRange {
            first: udp.dst_port,
            count: port_count,
        });
    }
    let addresses = Addresses {
        source_mac: udp.src_mac.map_or(nic.mac(), |mac| mac.0),
        destination_mac: udp.dst_mac.0,
        source: SocketAddrV4::new(udp.src_addr, udp.src_port),
        destination: SocketAddrV4::new(udp.dst_addr, udp.dst_port),
        hop_limit: udp.hop_limit,
    };
    let template = Template::new(&addresses, udp.pkt_size).map_err(Error::Packet)?;

    // One socket per thread, each on a queue of its own.
    let defaults = XdpConfig::default();
    let config = XdpConfig {
        frame_count: defaults
            .frames_for(threads)
            .ok_or(Error::TooManyFrames(threads))?,
        ..defaults
    };
    let mut sockets = Vec::new();
    for queue in 0..threads {
        let socket = bind(device, queue, config)
            .map_err(|error| Error::Bind(device.clone(), queue, error))?;
        sockets.push(socket);
    }
    let cpus = affinity::from_the_top().map_err(Error::Affinity)?;

    println!(
        "mangonel-trafficgen: {} byte packets from {} to {} ports {}-{last_port}, out of {device} \
         on {threads} thread{}",
        udp.pkt_size,
        addresses.source,
        addresses.destination.ip(),
        udp.dst_port,
        if threads == 1 { "" } else { "s" },
    );
    let sent: Vec<AtomicU64> = (0..threads).map(|_| AtomicU64::new(0)).collect();
    let total = || {
        sent.iter()
            .map(|sent| sent.load(Ordering::Relaxed))
            .sum::<u64>()
    };
    let interval = Duration::from_secs(udp.interval.get());
    let started = Instant::now();
    let deadline = udp
        .duration
        .map(|seconds| started + Duration::from_secs(seconds.get()));

    let elapsed = thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, (socket, sent)) in (0..threads).zip(sockets.into_iter().zip(&sent)) {
            let job = Job {
                socket,
                template: &template,
                ports: Ports::new(udp.dst_port, port_count, index, threads),
                batch: udp.batch_size.get() as usize,
                quota: udp
                    .num_packets
                    .map(|packets| share(packets.get(), index, threads)),
                sent,
                stop,
            };
            let cpu = cpus.get(index as usize % cpus.len().max(1)).copied();
            let spawned = thread::Builder::new()
                .name(format!("transmit-{index}"))
                .spawn_scoped(scope, move || {
                    // A thread that cannot be pinned still
                    // sends, only less steadily.
                    if let Some(Err(error)) = cpu.map(affinity::pin) {
                        eprintln!("mangonel-trafficgen: thread {index} is not pinned: {error}");
                    }

                    generate::transmit(job)
                });
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    // The scope waits for the threads already
                    // started, so they are told to stop.
                    stop.store(true, Ordering::Relaxed);

                    return Err(Error::Spawn(error));
                }
            }
        }

        report(&handles, &total, udp.pkt_size, interval, deadline, stop);

        // The longest any thread sent for is how long the
        // run lasted.
        let mut elapsed = Duration::ZERO;
        for handle in handles {
            elapsed = elapsed.max(handle.join().map_err(|_| Error::Panicked)?);
        }

        Ok(elapsed)
    })?;

    let total = total();
    let packets = rate(total, elapsed);
    println!(
        "mangonel-trafficgen: sent {total} packets in {:.2} s, {packets} pkt/s, {} Gbit/s",
        elapsed.as_secs_f64(),
        gigabits(packets, udp.pkt_size),
    );

    Ok(())
}

/// Prints the rate once an interval until every thread is
/// done, and ends the run when its time is up.
fn report(
    handles: &[thread::ScopedJoinHandle<'_, Duration>],
    total: &impl Fn() -> u64,
    size: usize,
    interval: Duration,
    deadline: Option<Instant>,
    stop: &AtomicBool,
) {
    let mut last = (Instant::now(), 0);
    while !handles.iter().all(thread::ScopedJoinHandle::is_finished) {
        thread::sleep(WATCH);
        let now = Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            stop.store(true, Ordering::Relaxed);
        }
        let since = now.duration_since(last.0);
        if since >= interval {
            let total = total();
            let packets = rate(total - last.1, since);
            println!(
                "mangonel-trafficgen: {packets} pkt/s {} Gbit/s",
                gigabits(packets, size)
            );
            last = (now, total);
        }
    }
}

/// Packets per second, for `packets` sent over `elapsed`.
fn rate(packets: u64, elapsed: Duration) -> u64 {
    let per_second = u128::from(packets) * 1_000_000 / elapsed.as_micros().max(1);

    u64::try_from(per_second).unwrap_or(u64::MAX)
}

/// The throughput of `packets` a second of `size` bytes each
/// on the wire, in gigabits a second to two places. Like
/// the size, it counts the frame and its check sequence,
/// not the preamble or the gap between frames.
fn gigabits(packets: u64, size: usize) -> String {
    let bits = u128::from(packets) * u128::try_from(size).unwrap_or(u128::MAX) * 8;
    // Hundredths of a gigabit, rounded to the nearest.
    let hundredths = (bits + 5_000_000) / 10_000_000;

    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// Thread `index`'s part of `packets` split over `threads`,
/// the remainder going to the first of them.
fn share(packets: u64, index: u32, threads: u32) -> u64 {
    let (index, threads) = (u64::from(index), u64::from(threads));

    packets / threads + u64::from(index < packets % threads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_budget_is_split_without_losing_any() {
        for (packets, threads) in [(10, 3), (2, 4), (1_000_000, 7), (0, 2)] {
            let shares: Vec<u64> = (0..threads)
                .map(|index| share(packets, index, threads))
                .collect();
            assert_eq!(shares.iter().sum::<u64>(), packets);
            assert!(shares.windows(2).all(|pair| pair[0] >= pair[1]));
        }
        assert_eq!(share(10, 0, 3), 4);
    }

    #[test]
    fn throughput_is_in_gigabits_to_two_places() {
        // A million of the smallest packets a second.
        assert_eq!(gigabits(1_000_000, 64), "0.51");
        // 10 Gbit/s of full-size frames, less the preamble
        // and gap a real link also spends.
        assert_eq!(gigabits(812_744, 1518), "9.87");
        assert_eq!(gigabits(0, 64), "0.00");
        assert_eq!(gigabits(1, 64), "0.00");
        assert_eq!(gigabits(9_766, 64), "0.01");
        assert_eq!(gigabits(100_000_000, 1518), "1214.40");
    }

    #[test]
    fn a_rate_is_packets_over_seconds() {
        assert_eq!(rate(1_000, Duration::from_secs(2)), 500);
        assert_eq!(rate(3, Duration::from_millis(1)), 3_000);
        assert_eq!(rate(0, Duration::ZERO), 0);
    }
}
