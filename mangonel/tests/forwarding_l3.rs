//! End-to-end L3 routing test. With a `[routing]` config
//! the router routes between two *different* subnets: a LAN
//! host and a WAN "gateway" host, each in its own
//! namespace, reach each other only if mangonel parses,
//! rewrites, and forwards their IPv4 packets.
//!
//! Two things work around this increment's limits. The
//! router does not answer ARP for its own gateway
//! addresses, so each host gets a static ARP entry for its
//! gateway. And next-hop MACs are learned only from
//! directly-connected sources, so both hosts must source
//! traffic — the test pings from both directions to
//! bootstrap learning before it asserts.
//!
//! Needs root; run via `just smoke`:
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
const WAN_PEER: &str = "mgl-wp";
const LAN_PEER: &str = "mgl-lp";
const WAN_NS: &str = "mgl-w";
const LAN_NS: &str = "mgl-l";

// Two /24s. The hosts are the far ends; the router's own
// gateway addresses (.1) have no stack — they exist only as
// the hosts' static ARP targets.
const WAN_HOST: &str = "10.123.1.2"; // the wan_gateway
const WAN_ROUTER: &str = "10.123.1.1";
const LAN_HOST: &str = "10.123.2.2";
const LAN_ROUTER: &str = "10.123.2.1";
const WAN_PREFIX: &str = "10.123.1.0/24";
const LAN_PREFIX: &str = "10.123.2.0/24";

const SOCKET: &str = "/tmp/mgl-l3.sock";
const CONFIG: &str = "/tmp/mgl-l3.toml";
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

/// The interface's MAC, read from sysfs — the source MAC
/// the router rewrites onto egress frames, and the hosts'
/// static ARP target.
fn mac(interface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{interface}/address"))
        .unwrap()
        .trim()
        .to_owned()
}

/// Owns the daemon and the background ping, killed and
/// cleaned up on drop so a panicking test leaves nothing
/// behind.
struct Fixture(Vec<Child>);

impl Drop for Fixture {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
        teardown();
    }
}

fn teardown() {
    quiet("ip", &["link", "delete", WAN]);
    quiet("ip", &["link", "delete", LAN]);
    quiet("ip", &["netns", "delete", WAN_NS]);
    quiet("ip", &["netns", "delete", LAN_NS]);
    let _ = std::fs::remove_file(SOCKET);
    let _ = std::fs::remove_file(CONFIG);
}

fn setup() {
    teardown();
    run("ip", &["netns", "add", WAN_NS]);
    run("ip", &["netns", "add", LAN_NS]);
    run(
        "ip",
        &["link", "add", WAN, "type", "veth", "peer", "name", WAN_PEER],
    );
    run(
        "ip",
        &["link", "add", LAN, "type", "veth", "peer", "name", LAN_PEER],
    );
    run("ip", &["link", "set", WAN_PEER, "netns", WAN_NS]);
    run("ip", &["link", "set", LAN_PEER, "netns", LAN_NS]);
    run("ip", &["link", "set", WAN, "up"]);
    run("ip", &["link", "set", LAN, "up"]);

    let wan_mac = mac(WAN);
    let lan_mac = mac(LAN);

    // WAN host: its address, its route to the LAN subnet via
    // the router, and a static ARP for the router (which
    // answers no ARP of its own).
    netns(
        WAN_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{WAN_HOST}/24"),
            "dev",
            WAN_PEER,
        ],
    );
    netns(WAN_NS, &["ip", "link", "set", WAN_PEER, "up"]);
    netns(
        WAN_NS,
        &["ip", "route", "add", LAN_PREFIX, "via", WAN_ROUTER],
    );
    netns(
        WAN_NS,
        &[
            "ip",
            "neigh",
            "add",
            WAN_ROUTER,
            "lladdr",
            &wan_mac,
            "dev",
            WAN_PEER,
            "nud",
            "permanent",
        ],
    );

    // LAN host: symmetric.
    netns(
        LAN_NS,
        &[
            "ip",
            "addr",
            "add",
            &format!("{LAN_HOST}/24"),
            "dev",
            LAN_PEER,
        ],
    );
    netns(LAN_NS, &["ip", "link", "set", LAN_PEER, "up"]);
    netns(
        LAN_NS,
        &["ip", "route", "add", WAN_PREFIX, "via", LAN_ROUTER],
    );
    netns(
        LAN_NS,
        &[
            "ip",
            "neigh",
            "add",
            LAN_ROUTER,
            "lladdr",
            &lan_mac,
            "dev",
            LAN_PEER,
            "nud",
            "permanent",
        ],
    );

    std::fs::write(
        CONFIG,
        format!(
            "[data_plane]\nwan = \"{WAN}\"\nlan = \"{LAN}\"\nworkers = 1\n\n\
             [control]\nsocket = \"{SOCKET}\"\n\n\
             [routing]\nlan_prefix = \"{LAN_PREFIX}\"\nwan_gateway = \"{WAN_HOST}\"\n"
        ),
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

fn wait_until_ready() {
    for _ in 0..100 {
        if request("GET", "/status").0 == 200 {
            return;
        }
        sleep(Duration::from_millis(200));
    }
    panic!("daemon did not become ready");
}

/// A ping from within a namespace.
fn ping(namespace: &str, target: &str, count: &str, background: bool) -> Option<Child> {
    let mut command = Command::new("ip");
    command.args([
        "netns", "exec", namespace, "ping", "-c", count, "-i", "0.3", "-W", "1", target,
    ]);
    if background {
        Some(command.spawn().unwrap())
    } else {
        let success = command.status().unwrap().success();
        assert!(success, "ping {namespace} -> {target} got no replies");
        None
    }
}

#[test]
#[ignore = "needs root; creates namespaces and veth links"]
fn routes_between_subnets() {
    setup();
    let daemon = Command::new(env!("CARGO_BIN_EXE_mangoneld"))
        .args(["--config", CONFIG])
        .spawn()
        .unwrap();
    let mut fixture = Fixture(vec![daemon]);
    wait_until_ready();

    let status: api::StatusResponse = serde_json::from_str(&request("GET", "/status").1).unwrap();
    assert_eq!(
        status.interfaces.len(),
        2,
        "router did not bring up both interfaces"
    );

    // The WAN gateway only forwards; it must source traffic for
    // its MAC to be learned, so ping it in the background
    // throughout. That, plus the foreground LAN->WAN ping,
    // seeds learning in both directions.
    let gateway_ping = ping(WAN_NS, LAN_HOST, "30", true);
    fixture.0.extend(gateway_ping);
    sleep(Duration::from_secs(1));

    // Now LAN -> WAN must complete: the first packets may drop
    // while the gateway MAC is still unlearned, but -c 8
    // outlasts the bootstrap.
    ping(LAN_NS, WAN_HOST, "8", false);

    let stats: api::StatsResponse = serde_json::from_str(&request("GET", "/stats").1).unwrap();
    let forwarded: u64 = stats
        .interfaces
        .iter()
        .flat_map(|interface| interface.queues.iter())
        .sum();
    assert!(forwarded > 0, "no packets routed");

    request("POST", "/shutdown");
}
