//! The network devices the wizard offers.

use mangonel_nic::nic::{
    Error,
    Nic,
};

/// A network device as the wizard lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Device {
    pub(crate) name: String,
    /// What tells this device from the others in a list.
    pub(crate) detail: String,
    /// Whether the IPv4 default route leaves by this device.
    pub(crate) default_route: bool,
}

/// Every interface but loopback, in name order.
pub(crate) fn discover() -> Result<Vec<Device>, Error> {
    let default_route = Nic::default_interface().ok();
    let mut devices = Vec::new();

    for name in Nic::list()? {
        let nic = match Nic::open(&name) {
            Ok(nic) => nic,
            // Not an interface, or gone since it was listed.
            Err(Error::InvalidName(_) | Error::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        if nic.is_loopback() {
            continue;
        }

        let default_route = default_route
            .as_ref()
            .is_some_and(|default| default.name() == name);
        let driver = nic.driver().map(|driver| driver.name.as_str());
        let mut detail = describe(nic.mac(), nic.is_up(), nic.is_running(), driver);
        if default_route {
            detail.push_str("  default route");
        }

        devices.push(Device {
            name,
            detail,
            default_route,
        });
    }

    Ok(devices)
}

/// MAC, link state and driver in columns that line up down a list.
fn describe(mac: [u8; 6], up: bool, running: bool, driver: Option<&str>) -> String {
    let mac = mac.map(|byte| format!("{byte:02x}")).join(":");
    let link = match (up, running) {
        (false, _) => "down",
        (true, false) => "no link",
        (true, true) => "link up",
    };

    format!("{mac}  {link:<7}  {}", driver.unwrap_or("-"))
}
