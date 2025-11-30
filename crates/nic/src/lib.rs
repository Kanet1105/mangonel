use default_net::mac::MacAddr;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    process::Command,
};

#[derive(Clone)]
pub struct NetworkInterface {
    name: String,
    index: u32,
    mac: MacAddr,
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

impl std::fmt::Debug for NetworkInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Network Interface: {}", self.name)?;
        writeln!(f, "Index: {}", self.index)?;
        writeln!(f, "Mac: {}", self.mac)?;
        writeln!(f, "IP Addresses:")?;
        for ipv4 in &self.ipv4 {
            writeln!(f, "\tIPv4: {ipv4}")?;
        }
        for ipv6 in &self.ipv6 {
            writeln!(f, "\tIPv6: {ipv6}")?;
        }
        Ok(())
    }
}

impl NetworkInterface {
    /// Get the default network interface
    pub fn get_default() -> Result<Self, Error> {
        let default_iface =
            default_net::get_default_interface().map_err(Error::DefaultInterface)?;
        let iface = NetworkInterface {
            name: default_iface.name,
            index: default_iface.index,
            mac: default_iface
                .mac_addr
                .ok_or(Error::DefaultInterface("No MAC address".to_string()))?,
            ipv4: default_iface.ipv4.iter().map(|ipv4| ipv4.addr).collect(),
            ipv6: default_iface.ipv6.iter().map(|ipv6| ipv6.addr).collect(),
        };
        Ok(iface)
    }

    /// Set the number of combined TX/RX queues for this interface
    ///
    /// This uses ethtool to change the combined channel count.
    /// Requires appropriate permissions (typically root/sudo).
    ///
    /// # Arguments
    /// * `queue_count` - The number of combined queues to set
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(Error)` if the operation fails
    pub fn set_queue_count(&self, queue_count: u32) -> Result<(), Error> {
        let output = Command::new("ethtool")
            .arg("-L")
            .arg(&self.name)
            .arg("combined")
            .arg(queue_count.to_string())
            .output()
            .map_err(|error| Error::Ethtool(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Ethtool(stderr.to_string()));
        }
        Ok(())
    }

    /// Get the current number of combined TX/RX queues for this interface
    ///
    /// This uses ethtool to query the combined channel count.
    ///
    /// # Returns
    /// * `Ok(u32)` with the number of combined queues
    /// * `Err(Error)` if the operation fails
    pub fn get_queue_count(&self) -> Result<u32, Error> {
        let output = Command::new("ethtool")
            .arg("-l")
            .arg(&self.name)
            .output()
            .map_err(|error| Error::Ethtool(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Ethtool(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the output to find "Combined:" line in the "Current hardware settings:" section
        let mut in_current_section = false;
        for line in stdout.lines() {
            if line.contains("Current hardware settings:") {
                in_current_section = true;
                continue;
            }

            if in_current_section && line.contains("Combined:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let count_str = parts[1].trim();
                    return count_str.parse::<u32>().map_err(Error::ParseError);
                }
            }
        }
        Err(Error::Ethtool(
            "Could not find Combined queue count in ethtool output".to_owned(),
        ))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    pub fn ipv4(&self) -> &[Ipv4Addr] {
        &self.ipv4
    }

    pub fn ipv6(&self) -> &[Ipv6Addr] {
        &self.ipv6
    }
}

/// Error types for network interface operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to get default network interface: {0}")]
    DefaultInterface(String),
    #[error("Ethtool error: {0}")]
    Ethtool(String),
    #[error("Failed to parse value: {0}")]
    ParseError(#[from] ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default() {
        let iface = NetworkInterface::get_default();
        match iface {
            Ok(iface) => {
                println!("Default interface: {:?}", iface);
                assert!(!iface.name.is_empty());
            }
            Err(e) => {
                println!("Could not get default interface: {}", e);
            }
        }
    }

    #[test]
    fn test_get_queue_count() {
        if let Ok(iface) = NetworkInterface::get_default() {
            match iface.get_queue_count() {
                Ok(count) => {
                    println!("Queue count: {}", count);
                    assert!(count > 0);
                }
                Err(e) => {
                    println!("Could not get queue count: {}", e);
                }
            }
        }
    }
}
