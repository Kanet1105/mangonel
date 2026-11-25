//! mangonel-gateway: the WAN/LAN gateway.

#![warn(unreachable_pub)]

mod cli;
mod config;

use std::{
    io::{
        self,
        IsTerminal,
    },
    process::ExitCode,
};

use thiserror::Error;

use crate::cli::{
    device,
    terminal::Terminal,
    wizard,
};

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Nic(#[from] mangonel_nic::nic::Error),

    #[error("need a network device each for the WAN and a LAN, found {0} besides loopback")]
    TooFewDevices(usize),

    #[error(transparent)]
    Wizard(#[from] wizard::Error),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mangonel-gateway: {e}");

            ExitCode::FAILURE
        }
    }
}

/// Asks the setup questions and shows what was chosen.
fn run() -> Result<(), Error> {
    // inquire draws its prompts on stderr.
    if !io::stderr().is_terminal() {
        return Err(wizard::Error::NotATerminal.into());
    }

    let devices = device::discover()?;
    if devices.len() < 2 {
        return Err(Error::TooFewDevices(devices.len()));
    }

    let setup = wizard::run(&devices, &mut Terminal::new())?;
    println!("\n{setup}");

    Ok(())
}
