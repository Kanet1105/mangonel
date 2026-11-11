//! The questions a terminal user is taken through when the
//! command line named no devices.

use std::{
    io::{
        self,
        IsTerminal,
    },
    net::Ipv4Addr,
};

use mangonel_nic::nic::Nic;

use crate::{
    cli::{
        self,
        Lan,
        Wan,
    },
    control::{
        Cidr,
        MacAddr,
    },
    error::Error,
};

/// A MAC for a port that is built only to be validated.
const ANY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

/// How a port's addresses come about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Dhcp,
    Static,
}

/// A device on offer, with what tells it from the others.
struct Device {
    name: String,
    hint: String,
}

/// Asks which device is the WAN and which are LANs, and how
/// each is addressed.
pub(crate) fn ask() -> Result<(Wan, Vec<Lan>), Error> {
    if !io::stdin().is_terminal() {
        return Err(Error::NoTerminal);
    }
    let devices = devices()?;
    if devices.len() < 2 {
        return Err(Error::TooFewDevices(devices.len()));
    }

    questions(devices).map_err(|error| {
        if error.kind() == io::ErrorKind::Interrupted {
            // Escape or Ctrl-C, which the prompt has already
            // acknowledged. The terminal may be gone too, so
            // the farewell is best effort.
            let _ = cliclack::outro_cancel("Nothing was started");

            Error::Cancelled
        } else {
            Error::Prompt(error)
        }
    })
}

/// Every device a port could be: all but the loopback.
fn devices() -> Result<Vec<Device>, Error> {
    let names = Nic::list().map_err(Error::Devices)?;

    Ok(names
        .iter()
        // One that vanished since it was listed is not on
        // offer.
        .filter_map(|name| Nic::open(name).ok())
        .filter(|nic| nic.flags() & libc::IFF_LOOPBACK == 0)
        .map(|nic| Device {
            hint: describe(&nic),
            name: nic.name().to_owned(),
        })
        .collect())
}

/// What tells a device from the others at a glance.
fn describe(nic: &Nic) -> String {
    let driver = nic
        .driver()
        .map_or("unknown driver", |driver| driver.name.as_str());
    let queues = match nic.xdp_queues() {
        1 => "1 queue".to_owned(),
        queues => format!("{queues} queues"),
    };
    let link = if nic.is_running() { "up" } else { "down" };

    format!("{}, {driver}, {queues}, {link}", MacAddr(nic.mac()))
}

/// The questionnaire itself. A cancelled prompt comes back
/// as an interrupted read.
fn questions(mut devices: Vec<Device>) -> io::Result<(Wan, Vec<Lan>)> {
    cliclack::intro("mangonel-router")?;

    let device = choose("Choose the WAN device", &mut devices)?;
    let mode = choose_mode(
        &device,
        "lease its address from the upstream",
        "enter its address and gateway",
    )?;
    let address = match mode {
        Mode::Dhcp => None,
        Mode::Static => Some(ask_wan_address(&device)?),
    };
    let wan = Wan { device, address };

    let mut lans: Vec<Lan> = Vec::new();
    loop {
        let device = choose("Choose a LAN device", &mut devices)?;
        let mode = choose_mode(
            &device,
            "lease addresses to the hosts on it",
            "leave the hosts on it to set their own",
        )?;
        let cidr = ask_lan_address(&device, &wan, &lans)?;
        lans.push(Lan {
            device,
            cidr: Some(cidr),
            dhcp: mode == Mode::Dhcp,
        });

        let more = !devices.is_empty()
            && cliclack::confirm("Add additional lan device?")
                .initial_value(false)
                .interact()?;
        if !more {
            break;
        }
    }

    cliclack::note(
        "To start this way without the questions",
        command(&wan, &lans),
    )?;
    cliclack::outro("Starting the router")?;

    Ok((wan, lans))
}

/// Has the user pick one of `devices`, which is then no
/// longer on offer.
fn choose(prompt: &str, devices: &mut Vec<Device>) -> io::Result<String> {
    let mut select = cliclack::select(prompt);
    for (index, device) in devices.iter().enumerate() {
        select = select.item(index, &device.name, &device.hint);
    }
    let index = select.interact()?;

    Ok(devices.remove(index).name)
}

/// Has the user pick how `device` is addressed, each mode
/// explained by what it does on this kind of port.
fn choose_mode(device: &str, dhcp: &str, fixed: &str) -> io::Result<Mode> {
    cliclack::select(format!("Choose a mode for {device}"))
        .item(Mode::Dhcp, "DHCP", dhcp)
        .item(Mode::Static, "Static", fixed)
        .interact()
}

/// Asks for a static WAN address and the gateway behind it.
fn ask_wan_address(device: &str) -> io::Result<(Cidr<Ipv4Addr>, Ipv4Addr)> {
    let typed: String = cliclack::input(format!("Address of {device}, with its prefix length"))
        .placeholder("203.0.113.2/24")
        .validate(|typed: &String| wan_cidr(typed).map(drop))
        .interact()?;
    let cidr = wan_cidr(&typed).map_err(io::Error::other)?;

    let typed: String = cliclack::input(format!("Gateway {device} reaches the rest through"))
        .placeholder("203.0.113.1")
        .validate(move |typed: &String| wan_gateway(cidr, typed).map(drop))
        .interact()?;
    let gateway = wan_gateway(cidr, &typed).map_err(io::Error::other)?;

    Ok((cidr, gateway))
}

/// Asks for the gateway's own address on a LAN device,
/// offering the one it would take by default.
fn ask_lan_address(device: &str, wan: &Wan, lans: &[Lan]) -> io::Result<Cidr<Ipv4Addr>> {
    let taken = taken(wan, lans);
    let mut input = cliclack::input(format!(
        "Address of the gateway on {device}, with its prefix length"
    ));
    // Unless an earlier answer already took that subnet.
    if let Some(default) = Lan::default_cidr(lans.len()).filter(|cidr| lan_free(*cidr, &taken)) {
        input = input.default_input(&default.to_string());
    }
    let validated = taken.clone();
    let typed: String = input
        .validate(move |typed: &String| lan_cidr(typed, &validated).map(drop))
        .interact()?;

    lan_cidr(&typed, &taken).map_err(io::Error::other)
}

/// The subnets the answers so far occupy, each with the
/// device it is on.
fn taken(wan: &Wan, lans: &[Lan]) -> Vec<(String, Cidr<Ipv4Addr>)> {
    let wan = wan.address.map(|(cidr, _)| (wan.device.clone(), cidr));
    let lans = lans
        .iter()
        .filter_map(|lan| Some((lan.device.clone(), lan.cidr?)));

    wan.into_iter().chain(lans).collect()
}

/// A WAN address as typed, if the control panel would take
/// it.
fn wan_cidr(typed: &str) -> Result<Cidr<Ipv4Addr>, String> {
    let cidr = cli::cidr(typed.trim())?;
    cidr.check(32).map_err(|error| error.to_string())?;

    Ok(cidr)
}

/// A WAN gateway as typed, if the control panel would take
/// it with the address `cidr`.
fn wan_gateway(cidr: Cidr<Ipv4Addr>, typed: &str) -> Result<Ipv4Addr, String> {
    let typed = typed.trim();
    let gateway: Ipv4Addr = typed
        .parse()
        .map_err(|_| format!("{typed:?} is not an IPv4 address"))?;
    let wan = Wan {
        device: "wan".to_owned(),
        address: Some((cidr, gateway)),
    };
    wan.port(ANY_MAC, &[])
        .map_err(|error| error.to_string())?
        .validate()
        .map_err(|error| error.to_string())?;

    Ok(gateway)
}

/// A LAN address as typed, if the control panel would take
/// it beside the subnets already `taken`.
fn lan_cidr(typed: &str, taken: &[(String, Cidr<Ipv4Addr>)]) -> Result<Cidr<Ipv4Addr>, String> {
    let cidr = cli::cidr(typed.trim())?;
    let lan = Lan {
        device: "lan".to_owned(),
        cidr: Some(cidr),
        dhcp: true,
    };
    lan.port(0, ANY_MAC)
        .map_err(|error| error.to_string())?
        .validate()
        .map_err(|error| error.to_string())?;
    if let Some((device, other)) = taken.iter().find(|(_, other)| cidr.overlaps(other)) {
        return Err(format!("{cidr} overlaps {other} on {device}"));
    }

    Ok(cidr)
}

/// Whether `cidr` overlaps none of the subnets `taken`.
fn lan_free(cidr: Cidr<Ipv4Addr>, taken: &[(String, Cidr<Ipv4Addr>)]) -> bool {
    !taken.iter().any(|(_, other)| cidr.overlaps(other))
}

/// The command line that starts the router with these
/// answers, an argument to a line so none is wrapped apart.
fn command(wan: &Wan, lans: &[Lan]) -> String {
    let lans: String = lans
        .iter()
        .map(|lan| format!(" \\\n    --lan {lan}"))
        .collect();

    format!("mangonel-router \\\n    --wan {wan}{lans}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr<Ipv4Addr> {
        cli::cidr(text).unwrap()
    }

    #[test]
    fn a_wan_address_has_to_be_a_host_in_its_subnet() {
        assert_eq!(wan_cidr(" 203.0.113.2/24 "), Ok(cidr("203.0.113.2/24")));
        assert!(wan_cidr("203.0.113.2").is_err());
        assert!(wan_cidr("203.0.113.0/24").is_err());
        assert!(wan_cidr("203.0.113.255/24").is_err());
        assert!(wan_cidr("wan").is_err());
    }

    #[test]
    fn a_wan_gateway_has_to_be_another_host_on_the_segment() {
        let address = cidr("203.0.113.2/24");
        assert_eq!(
            wan_gateway(address, "203.0.113.1"),
            Ok(Ipv4Addr::new(203, 0, 113, 1))
        );
        assert!(wan_gateway(address, "203.0.113.2").is_err());
        assert!(wan_gateway(address, "198.51.100.1").is_err());
        assert!(wan_gateway(address, "upstream").is_err());
    }

    #[test]
    fn a_lan_address_needs_room_for_hosts_and_a_subnet_of_its_own() {
        let taken = vec![
            ("wan".to_owned(), cidr("203.0.113.2/24")),
            ("lan-0".to_owned(), cidr("10.0.0.1/24")),
        ];
        assert_eq!(lan_cidr("10.0.1.1/24", &taken), Ok(cidr("10.0.1.1/24")));
        assert!(lan_cidr("10.0.1.1/31", &taken).is_err());
        assert!(lan_cidr("10.0.1.0/24", &taken).is_err());

        let overlap = lan_cidr("10.0.0.129/25", &taken).unwrap_err();
        assert!(overlap.contains("lan-0"), "{overlap}");
        let overlap = lan_cidr("203.0.0.1/8", &taken).unwrap_err();
        assert!(overlap.contains("wan"), "{overlap}");
    }

    #[test]
    fn the_default_lan_address_is_offered_only_while_it_is_free() {
        let wan: Wan = "wan=10.0.1.2/24,10.0.1.1".parse().unwrap();
        let taken = taken(&wan, &["lan-0=10.0.0.1/24".parse().unwrap()]);
        assert!(lan_free(cidr("10.0.2.1/24"), &taken));
        // The second LAN's default sits on the WAN's subnet.
        assert!(!lan_free(Lan::default_cidr(1).unwrap(), &taken));
    }

    #[test]
    fn the_answers_read_back_as_a_command_line() {
        let wan: Wan = "wan=203.0.113.2/24,203.0.113.1".parse().unwrap();
        let lans: Vec<Lan> = vec![
            "lan-0=10.0.0.1/24".parse().unwrap(),
            "lan-1=10.0.1.1/24,static".parse().unwrap(),
        ];
        assert_eq!(
            command(&wan, &lans),
            [
                "mangonel-router \\",
                "    --wan wan=203.0.113.2/24,203.0.113.1 \\",
                "    --lan lan-0=10.0.0.1/24 \\",
                "    --lan lan-1=10.0.1.1/24,static",
            ]
            .join("\n")
        );
    }

    #[test]
    fn the_loopback_is_not_on_offer() {
        let devices = devices().unwrap();
        assert!(devices.iter().all(|device| device.name != "lo"));
    }
}
