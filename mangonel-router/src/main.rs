//! mangonel-router: the gateway daemon.
//!
//! Started with one WAN device and the LAN devices behind
//! it, it hands their configuration to the control panel,
//! sets every device to the same number of queues, and
//! forwards with one worker per queue until it is told to
//! stop.

#![warn(unreachable_pub)]

mod cli;
mod control;
mod data;
mod error;
mod prompt;
mod signal;

use std::{num::NonZeroU32, process::ExitCode, sync::atomic::Ordering, thread, time::Duration};

use clap::Parser;
use mangonel_nic::nic::Nic;

use crate::{
    cli::{Cli, Lan, Wan},
    control::{Addressing, ControlPanel, LanPort, WanPort},
    data::DataPlane,
    error::Error,
};

/// How often the main thread looks for a signal or a dead
/// worker.
const WATCH: Duration = Duration::from_millis(100);

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        // The questionnaire has said so itself.
        Err(Error::Cancelled) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("mangonel-router: {error}");

            ExitCode::FAILURE
        }
    }
}

/// Runs the gateway until a signal stops it.
fn run(cli: &Cli) -> Result<(), Error> {
    signal::install().map_err(Error::Signal)?;

    // Before any question, so that Ctrl-C at a prompt
    // cancels it rather than kills the process mid-draw.
    let (wan, lans): (Wan, Vec<Lan>) = match &cli.wan {
        Some(wan) => (wan.clone(), cli.lan.clone()),
        None => prompt::ask()?,
    };

    // The WAN first, then the LANs as given.
    let devices = std::iter::once(&wan.device).chain(lans.iter().map(|lan| &lan.device));
    let mut nics: Vec<Nic> = Vec::new();
    for device in devices {
        let nic = Nic::open(device).map_err(|error| Error::Device(device.clone(), error))?;
        // The control panel tells ports apart by MAC.
        if nics
            .iter()
            .any(|other| other.name() == nic.name() || other.mac() == nic.mac())
        {
            return Err(Error::DeviceTwice(device.clone()));
        }
        nics.push(nic);
    }

    let panel = ControlPanel::spawn().map_err(Error::Panel)?;
    let port = wan.port(nics[0].mac(), &cli.dns)?;
    println!("mangonel-router: {}", describe_wan(&nics[0], &port));
    panel.set_wan(port)?;
    for (index, (lan, nic)) in lans.iter().zip(&nics[1..]).enumerate() {
        let port = lan.port(index, nic.mac())?;
        println!("mangonel-router: {}", describe_lan(nic, &port));
        panel.set_lan(port)?;
    }

    let limit = cli.workers.map(NonZeroU32::get);
    let plane = DataPlane::new(nics, &panel.reader(), limit)?;
    let cores: Vec<String> = plane.cores().iter().map(usize::to_string).collect();
    println!(
        "mangonel-router: {} workers on cores {}",
        cores.len(),
        cores.join(" ")
    );
    println!("mangonel-router: ready");

    while !signal::requested() {
        if !plane.is_running() {
            return Err(Error::WorkerExited);
        }
        thread::sleep(WATCH);
    }

    for (index, counters) in plane.counters().iter().enumerate() {
        println!(
            "mangonel-router: worker {index} received {} sent {} dropped {}",
            counters.received.load(Ordering::Relaxed),
            counters.sent.load(Ordering::Relaxed),
            counters.dropped.load(Ordering::Relaxed),
        );
    }
    // The workers go before the control panel they read.
    drop(plane);
    drop(panel);

    Ok(())
}

fn describe_wan(nic: &Nic, port: &WanPort) -> String {
    let addressing = match port.ipv4.as_ref().map(|ip| &ip.addressing) {
        Some(Addressing::Static { cidr, gateway }) => format!("{cidr} via {gateway}"),
        Some(Addressing::Dhcp) => "leasing its address".to_owned(),
        None => "no IPv4".to_owned(),
    };

    format!("wan {} {}: {addressing}", nic.name(), port.mac)
}

fn describe_lan(nic: &Nic, port: &LanPort) -> String {
    let addressing = match &port.ipv4 {
        Some(ip) if ip.dhcp => {
            format!("{}, leasing {} to {}", ip.cidr, ip.pool_start, ip.pool_end)
        }
        Some(ip) => format!("{}, leasing nothing", ip.cidr),
        None => "no IPv4".to_owned(),
    };

    format!("lan {} {}: {addressing}", nic.name(), port.mac)
}
