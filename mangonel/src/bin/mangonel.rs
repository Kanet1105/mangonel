//! The mangonel CLI: drives the daemon over its control
//! socket. Speaks HTTP/1.1 by hand — one request per
//! invocation, `Connection: close` — so it needs no async
//! runtime or HTTP client.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use mangonel::api;

#[derive(Parser)]
#[command(
    name = "mangonel",
    version,
    about = "Control the mangonel router daemon"
)]
struct Cli {
    /// Path to the daemon's control socket.
    #[arg(long, default_value = api::DEFAULT_SOCKET_PATH)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the daemon version, uptime, and attachments.
    Status,
    /// Show per-queue packet counters.
    Stats,
    /// List the host's interfaces and their properties.
    Interfaces,
    /// Bring the router up from the daemon's config file
    /// (also reloads).
    Run,
    /// Stop the daemon.
    Shutdown,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mangonel: {error}");

            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Status => {
            let status: api::StatusResponse = get(&cli.socket, "/api/v1/status")?;
            println!(
                "mangonel {} — up {}s",
                status.version, status.uptime_seconds
            );
            if status.interfaces.is_empty() {
                println!("no interfaces attached");
            } else {
                println!("attached:");
                for interface in &status.interfaces {
                    println!("  {interface}");
                }
            }
        }
        Command::Stats => {
            let stats: api::StatsResponse = get(&cli.socket, "/api/v1/stats")?;
            if stats.interfaces.is_empty() {
                println!("no interfaces attached");
            }
            for interface in &stats.interfaces {
                let total: u64 = interface.queues.iter().sum();
                let mode = if interface.zero_copy {
                    "zero-copy"
                } else {
                    "copy"
                };
                println!("{} ({mode}) — {total} packets", interface.interface);
                for (queue, count) in interface.queues.iter().enumerate() {
                    println!("  queue {queue}: {count}");
                }
            }
        }
        Command::Interfaces => {
            let response: api::InterfacesResponse = get(&cli.socket, "/api/v1/interfaces")?;
            for interface in &response.interfaces {
                let state = if interface.attached {
                    "attached"
                } else if interface.up {
                    "up"
                } else {
                    "down"
                };
                let driver = interface.driver.as_deref().unwrap_or("?");
                println!(
                    "{} [{state}] {driver} — {} xdp queues, mtu {}, mac {}",
                    interface.name, interface.xdp_queues, interface.mtu, interface.mac
                );
            }
        }
        Command::Run => {
            post(&cli.socket, "/api/v1/run")?;
            println!("router running");
        }
        Command::Shutdown => {
            post(&cli.socket, "/api/v1/shutdown")?;
            println!("daemon stopping");
        }
    }

    Ok(())
}

/// A GET whose body is deserialized into `T`.
fn get<T: serde::de::DeserializeOwned>(socket: &str, path: &str) -> Result<T, CliError> {
    let (code, body) = request(socket, "GET", path)?;
    check(code, &body)?;

    Ok(serde_json::from_str(&body)?)
}

/// A POST that expects an empty success body.
fn post(socket: &str, path: &str) -> Result<(), CliError> {
    let (code, body) = request(socket, "POST", path)?;

    check(code, &body)
}

/// Turns a non-2xx status into an error, preferring the
/// daemon's JSON message.
fn check(code: u16, body: &str) -> Result<(), CliError> {
    if (200..300).contains(&code) {
        return Ok(());
    }
    let message = serde_json::from_str::<api::ErrorResponse>(body)
        .map(|error| error.error)
        .unwrap_or_else(|_| format!("HTTP {code}"));

    Err(CliError::Daemon(message))
}

/// One HTTP/1.1 request over the control socket; returns
/// the status code and body. `Connection: close` lets the
/// server's EOF delimit the body, so no length parsing.
fn request(socket: &str, method: &str, path: &str) -> Result<(u16, String), CliError> {
    let mut stream = UnixStream::connect(socket).map_err(|source| CliError::Connect {
        socket: socket.to_owned(),
        source,
    })?;
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(CliError::BadResponse)?;
    let head = std::str::from_utf8(&response[..separator]).map_err(|_| CliError::BadResponse)?;
    let body =
        String::from_utf8(response[separator + 4..].to_vec()).map_err(|_| CliError::BadResponse)?;
    let code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(CliError::BadResponse)?;

    Ok((code, body))
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("cannot reach the daemon at {socket}: {source} (is mangoneld running?)")]
    Connect { socket: String, source: io::Error },
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("the daemon sent a malformed response")]
    BadResponse,
    #[error("{0}")]
    Daemon(String),
    #[error("could not parse the daemon's response: {0}")]
    Json(#[from] serde_json::Error),
}
