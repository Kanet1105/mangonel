use pnet::datalink::{self, NetworkInterface};

pub fn get_network_interface(name: &str) -> Result<NetworkInterface, NetworkInterfaceError> {
    let nic = datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or(NetworkInterfaceError::NotFound(name.to_owned()))?;

    if !nic.is_up() {
        return Err(NetworkInterfaceError::InterfaceDown(nic.name.to_owned()));
    }
    Ok(nic)
}

pub enum NetworkInterfaceError {
    NotFound(String),
    InterfaceDown(String),
}

impl std::fmt::Debug for NetworkInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for NetworkInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkInterfaceError::NotFound(name) => {
                write!(f, "Network interface '{}' not found", name)
            }
            NetworkInterfaceError::InterfaceDown(name) => {
                write!(f, "Network interface '{}' is down", name)
            }
        }
    }
}

impl std::error::Error for NetworkInterfaceError {}
