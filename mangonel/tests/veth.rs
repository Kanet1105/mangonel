//! Smoke test over a veth pair. Needs root to create links
//! and bind AF_XDP; built first as the invoking user so the
//! compiler cache is not left root-owned:
//!
//! ```sh
//! cargo test -p mangonel --no-run
//! sudo -E cargo test -p mangonel -- --ignored --nocapture
//! ```

use std::{process::Command, thread::sleep, time::Duration};

use mangonel::state::State;

const LINK: &str = "veth-mgl0";
const PEER: &str = "veth-mgl1";

fn ip(arguments: &[&str]) {
    let status = Command::new("ip").args(arguments).status().unwrap();
    assert!(status.success(), "`ip {arguments:?}` failed");
}

/// Deletes the pair, capturing output so the "Cannot find
/// device" from deleting a non-existent link stays quiet.
fn delete_link() {
    let _ = Command::new("ip").args(["link", "delete", LINK]).output();
}

/// Deletes the pair on drop — including on assert failure —
/// so a failed run does not leave links behind.
struct Links;

impl Drop for Links {
    fn drop(&mut self) {
        delete_link();
    }
}

#[test]
#[ignore = "needs root and creates veth links"]
fn attach_detach_veth() {
    // Delete a leftover pair from an earlier failed run, then
    // create fresh; deleting one end deletes both.
    delete_link();
    let _links = Links;
    ip(&["link", "add", LINK, "type", "veth", "peer", "name", PEER]);
    ip(&["link", "set", LINK, "up"]);
    ip(&["link", "set", PEER, "up"]);

    let state = State::new();
    state.attach(LINK).unwrap();
    assert!(state.attach(LINK).is_err(), "double attach must error");

    // Traffic in through the peer. The kernel's own IPv6
    // neighbour discovery on link-up would eventually
    // suffice; the pings make it prompt and deterministic.
    let _ = Command::new("ping")
        .args(["-c", "3", "-i", "0.2", &format!("ff02::1%{PEER}")])
        .status();
    sleep(Duration::from_secs(2));

    let status = state.status();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].interface, LINK);
    let received: u64 = status[0].queues.iter().sum();
    assert!(received > 0, "no packets counted on {LINK}");

    state.detach(LINK).unwrap();
    assert!(state.detach(LINK).is_err(), "double detach must error");

    // Detach released the interface: a second cycle binds it
    // again.
    state.attach(LINK).unwrap();
    state.detach(LINK).unwrap();
}
