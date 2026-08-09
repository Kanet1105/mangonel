//! The daemon's TOML configuration.
//!
//! The daemon owns the file: it reads the path on startup
//! and re-reads it on `run`. Control transports are read
//! once at startup; the data plane is what `run` applies.

use std::path::Path;

use serde::Deserialize;

/// Default config path, overridable with `--config`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mangonel/config.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub data_plane: DataPlane,
    #[serde(default)]
    pub control: Control,
    /// Absent means L2 transparent forwarding; present
    /// turns on L3 routing.
    pub routing: Option<Routing>,
}

/// The L3 routing table, as strings parsed when the router
/// comes up.
#[derive(Debug, Clone, Deserialize)]
pub struct Routing {
    /// The directly-connected LAN prefix, e.g.
    /// `192.168.1.0/24`.
    pub lan_prefix: String,
    /// The next hop for everything else, e.g.
    /// `203.0.113.1`.
    pub wan_gateway: String,
}

/// The interfaces the router runs on and how many workers
/// each gets.
#[derive(Debug, Clone, Deserialize)]
pub struct DataPlane {
    pub wan: String,
    pub lan: String,
    /// Queues to set on each interface (`ethtool -L`) and,
    /// with one worker per queue, the worker count.
    #[serde(default = "default_workers")]
    pub workers: u32,
}

/// Where the control API listens. The UDS is always on; the
/// TCP listener is optional and must stay off the data
/// plane — loopback, or a management NIC — since AF_XDP
/// takes every packet on an attached interface.
#[derive(Debug, Clone, Deserialize)]
pub struct Control {
    #[serde(default = "default_socket")]
    pub socket: String,
    pub tcp: Option<String>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            tcp: None,
        }
    }
}

fn default_workers() -> u32 {
    1
}

fn default_socket() -> String {
    crate::api::DEFAULT_SOCKET_PATH.to_owned()
}

impl Config {
    /// Reads and parses the config at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Read(path.display().to_string(), source))?;

        toml::from_str(&text)
            .map_err(|source| ConfigError::Parse(path.display().to_string(), source))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read the config at {0}: {1}")]
    Read(String, std::io::Error),
    #[error("Failed to parse the config at {0}: {1}")]
    Parse(String, toml::de::Error),
}
