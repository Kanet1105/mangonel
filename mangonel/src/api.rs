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
    pub queues: Vec<u64>,
}

/// The body of any non-2xx response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
