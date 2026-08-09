//! End-to-end daemon test: start mangoneld, attach a veth
//! over the control socket, watch stats climb, detach.
//! Needs root and creates veth links; run via `just smoke`.

use std::{
    process::{Child, Command},
    thread::sleep,
    time::Duration,
};

use mangonel::api;

const LINK: &str = "veth-mgld0";
const PEER: &str = "veth-mgld1";
// Short: a Unix socket path must fit SUN_LEN (~108 bytes).
const SOCKET: &str = "/tmp/mangoneld-test.sock";
const BASE: &str = "http://localhost/api/v1";

fn ip(arguments: &[&str]) {
    let status = Command::new("ip").args(arguments).status().unwrap();
    assert!(status.success(), "`ip {arguments:?}` failed");
}

/// Deletes the pair, capturing output so the "Cannot find
/// device" from deleting a non-existent link stays quiet.
fn delete_link() {
    let _ = Command::new("ip").args(["link", "delete", LINK]).output();
}

/// A `(status_code, body)` from a control-socket request.
/// Connection failures — a daemon not yet listening —
/// surface as code 0.
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

/// Owns the daemon child and the fixtures: killed and
/// cleaned up on drop, so a panicking test leaves nothing
/// behind. Deleting the link also unloads whatever XDP
/// program is attached to it.
struct Fixture(Child);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        delete_link();
        let _ = std::fs::remove_file(SOCKET);
    }
}

/// Polls the status endpoint until the daemon answers.
fn wait_until_ready() {
    for _ in 0..100 {
        if request("GET", "/status").0 == 200 {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("daemon did not become ready");
}

#[test]
#[ignore = "needs root, creates veth links, spawns the daemon"]
fn attach_over_control_socket() {
    // Clear leftovers from an earlier failed run.
    delete_link();
    let _ = std::fs::remove_file(SOCKET);
    ip(&["link", "add", LINK, "type", "veth", "peer", "name", PEER]);
    ip(&["link", "set", LINK, "up"]);
    ip(&["link", "set", PEER, "up"]);

    let daemon = Command::new(env!("CARGO_BIN_EXE_mangoneld"))
        .args(["--socket", SOCKET])
        .spawn()
        .unwrap();
    let _fixture = Fixture(daemon);
    wait_until_ready();

    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/attach")).0,
        204
    );
    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/attach")).0,
        409,
        "double attach must conflict"
    );

    // Traffic in through the peer; link-up multicast reaches
    // the attached interface's XDP hook.
    let _ = Command::new("ping")
        .args(["-c", "3", "-i", "0.2", &format!("ff02::1%{PEER}")])
        .status();
    sleep(Duration::from_secs(2));

    let (code, body) = request("GET", "/stats");
    assert_eq!(code, 200);
    let stats: api::StatsResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(stats.interfaces.len(), 1);
    assert_eq!(stats.interfaces[0].interface, LINK);
    let received: u64 = stats.interfaces[0].queues.iter().sum();
    assert!(received > 0, "no packets counted on {LINK}");

    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/detach")).0,
        204
    );
    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/detach")).0,
        404,
        "double detach must be not-found"
    );

    // Detach released the interface: it binds again.
    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/attach")).0,
        204
    );
    assert_eq!(
        request("POST", &format!("/interfaces/{LINK}/detach")).0,
        204
    );

    assert_eq!(request("POST", "/shutdown").0, 204);
}
