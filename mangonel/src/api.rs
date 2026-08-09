//! The control API contract: the shapes the daemon and its
//! clients — the CLI, and later a frontend — exchange over
//! `/api/v1`.

use serde::{Deserialize, Serialize};

/// Default control socket, overridable with `--socket`.
/// The parent is the systemd `RuntimeDirectory`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/mangonel/mangonel.sock";

/// `GET /api/v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub interfaces: Vec<String>,
}

/// `GET /api/v1/stats`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub interfaces: Vec<InterfaceStats>,
}

/// Per-interface counters, one `queues` entry per queue.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub interface: String,
    pub zero_copy: bool,
    pub queues: Vec<u64>,
}

/// `GET /api/v1/interfaces`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterfacesResponse {
    pub interfaces: Vec<Interface>,
}

/// A host interface and what decides whether it can be
/// attached.
#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    pub mtu: u32,
    pub up: bool,
    pub running: bool,
    pub xdp_queues: u32,
    pub numa_node: Option<i32>,
    pub driver: Option<String>,
    pub attached: bool,
}

/// The body of any non-2xx response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
