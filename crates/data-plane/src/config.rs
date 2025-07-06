use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub nic: String,
    pub worker_count: usize,
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        toml::from_str(&content).map_err(ConfigError::Parse)
    }
}

pub enum ConfigError {
    ReadFile(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadFile(error) => write!(f, "Failed to read configuration file: {}", error),
            Self::Parse(error) => write!(f, "Failed to parse configuration file: {}", error),
        }
    }
}

impl std::error::Error for ConfigError {}
