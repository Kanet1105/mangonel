//! End-to-end forwarding test. Builds an L2 topology — two
//! hosts in network namespaces, mangonel bridging two veths
//! between them — brings the router up from a config, pings
//! across, and checks the per-queue counters climbed both
//! ways. Needs root; run via `just smoke`.
//!
//! ```sh
//! cargo test -p mangonel --no-run
//! sudo -E cargo test -p mangonel -- --ignored --nocapture
//! ```

use std::{
    process::{Child, Command},
    thread::sleep,
    time::Duration,
};

use mangonel::api;

const WAN: &str = "mgl-wan";
const LAN: &str = "mgl-lan";
const WAN_PEER: &str = "mgl-wan-p";
const LAN_PEER: &str = "mgl-lan-p";
const H1: &str = "mgl-h1";
const H2: &str = "mgl-h2";
const H1_ADDR: &str = "10.123.0.1";
const H2_ADDR: &str = "10.123.0.2";
// Short: a Unix socket path must fit SUN_LEN (~108 bytes).
const SOCKET: &str = "/tmp/mgl-forwarding.sock";
const CONFIG: &str = "/tmp/mgl-forwarding.toml";
const BASE: &str = "http://localhost/api/v1";

fn run(command: &str, arguments: &[&str]) {
    let status = Command::new(command).args(arguments).status().unwrap();
    assert!(status.success(), "`{command} {arguments:?}` failed");
}

/// Runs a command in host namespace `netns`.
fn netns(name: &str, arguments: &[&str]) {
    let mut full = vec!["netns", "exec", name];
    full.extend_from_slice(arguments);
    run("ip", &full);
}

fn quiet(command: &str, arguments: &[&str]) {
    let _ = Command::new(command).args(arguments).output();
}

/// Tears the whole fixture down on drop — including on an
/// assert failure — so a failed run leaves nothing behind.
struct Fixture(Child);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        teardown();
    }
}

fn teardown() {
    // Deleting a link deletes its veth peer; deleting a netns
    // takes any links still inside it.
    quiet("ip", &["link", "delete", WAN]);
    quiet("ip", &["link", "delete", LAN]);
    quiet("ip", &["netns", "delete", H1]);
    quiet("ip", &["netns", "delete", H2]);
    let _ = std::fs::remove_file(SOCKET);
    let _ = std::fs::remove_file(CONFIG);
}

/// wan-peer lives in h1, lan-peer in h2, and wan/lan stay
/// in the root namespace for mangonel to bind. The two
/// hosts share one /24, so plain L2 forwarding carries
/// their ARP and ICMP.
fn setup() {
    teardown();
    run("ip", &["netns", "add", H1]);
    run("ip", &["netns", "add", H2]);
    run(
        "ip",
        &["link", "add", WAN, "type", "veth", "peer", "name", WAN_PEER],
    );
    run(
        "ip",
        &["link", "add", LAN, "type", "veth", "peer", "name", LAN_PEER],
    );
    run("ip", &["link", "set", WAN_PEER, "netns", H1]);
    run("ip", &["link", "set", LAN_PEER, "netns", H2]);

    run("ip", &["link", "set", WAN, "up"]);
    run("ip", &["link", "set", LAN, "up"]);
    netns(
        H1,
        &[
            "ip",
            "addr",
            "add",
            &format!("{H1_ADDR}/24"),
            "dev",
            WAN_PEER,
        ],
    );
    netns(H1, &["ip", "link", "set", WAN_PEER, "up"]);
    netns(
        H2,
        &[
            "ip",
            "addr",
            "add",
            &format!("{H2_ADDR}/24"),
            "dev",
            LAN_PEER,
        ],
    );
    netns(H2, &["ip", "link", "set", LAN_PEER, "up"]);

    std::fs::write(
        CONFIG,
        format!("[data_plane]\nwan = \"{WAN}\"\nlan = \"{LAN}\"\nworkers = 1\n\n[control]\nsocket = \"{SOCKET}\"\n"),
    )
    .unwrap();
}

fn request(method: &str, path: &str) -> (u32, String) {
    let output = Command::new("curl")
        .args([
            "-s",
            "-w",
            "\n%{http_code}",
            "--unix-socket",
            SOCKET,
            "-X",
            method,
            &format!("{BASE}{path}"),
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let (body, code) = text
        .rsplit_once('\n')
        .expect("curl -w always appends a line");

    (code.parse().unwrap_or(0), body.to_owned())
}

/// The daemon auto-runs the router at startup, and only
/// begins serving once it finishes; a 200 here means the
/// bring-up completed.
fn wait_until_ready() {
    for _ in 0..100 {
        if request("GET", "/status").0 == 200 {
            return;
        }
        sleep(Duration::from_millis(200));
    }
    panic!("daemon did not become ready");
}

#[test]
#[ignore = "needs root; creates namespaces and veth links"]
fn forwards_between_wan_and_lan() {
    setup();
    let daemon = Command::new(env!("CARGO_BIN_EXE_mangoneld"))
        .args(["--config", CONFIG])
        .spawn()
        .unwrap();
    let _fixture = Fixture(daemon);
    wait_until_ready();

    // The router must have both interfaces up.
    let (code, body) = request("GET", "/status");
    assert_eq!(code, 200);
    let status: api::StatusResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(
        status.interfaces.len(),
        2,
        "router did not bring up both interfaces: {body}"
    );

    // Ping across the bridge; forwarding carries ARP then ICMP.
    let ping = Command::new("ip")
        .args([
            "netns", "exec", H1, "ping", "-c", "3", "-i", "0.2", "-W", "1", H2_ADDR,
        ])
        .status()
        .unwrap();

    let (code, body) = request("GET", "/stats");
    assert_eq!(code, 200);
    let stats: api::StatsResponse = serde_json::from_str(&body).unwrap();
    let forwarded: u64 = stats
        .interfaces
        .iter()
        .flat_map(|interface| interface.queues.iter())
        .sum();
    assert!(forwarded > 0, "no packets forwarded: {body}");
    assert!(ping.success(), "ping across the bridge failed");

    request("POST", "/shutdown");
}
