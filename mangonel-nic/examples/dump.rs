//! Prints what `Nic` can see, for every interface or the
//! ones named as args.
//!
//! `cargo run -p mangonel-nic --example dump [ifname ...]`

use mangonel_nic::nic::Nic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut names: Vec<String> = std::env::args().skip(1).collect();
    if names.is_empty() {
        names = Nic::list()?;
    }

    for name in names {
        let nic = match Nic::open(&name) {
            Ok(nic) => nic,
            Err(e) => {
                println!("{name}: {e}");
                continue;
            }
        };

        let mac = nic
            .mac()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");

        println!("{}  (index {})", nic.name(), nic.index());
        println!("  mac          {mac}");
        println!("  mtu          {}", nic.mtu());
        println!(
            "  state        {}{}",
            if nic.is_up() { "up" } else { "down" },
            if nic.is_running() { ", running" } else { "" }
        );
        println!(
            "  queues       rx {} / tx {}  -> xdp queue ids 0..{}",
            nic.rx_queues(),
            nic.tx_queues(),
            nic.xdp_queues()
        );
        match nic.numa_node() {
            Some(node) => println!("  numa node    {node}"),
            None => println!("  numa node    -"),
        }
        match nic.driver() {
            Some(d) => println!(
                "  driver       {} {} (fw {}, bus {})",
                d.name,
                d.version,
                if d.firmware.is_empty() {
                    "-"
                } else {
                    &d.firmware
                },
                if d.bus_info.is_empty() {
                    "-"
                } else {
                    &d.bus_info
                },
            ),
            None => println!("  driver       - (ETHTOOL_GDRVINFO unsupported)"),
        }
        match nic.channels() {
            Some(c) => println!(
                "  channels     combined {}/{}, rx {}/{}, tx {}/{}",
                c.combined, c.max_combined, c.rx, c.max_rx, c.tx, c.max_tx
            ),
            None => println!("  channels     - (ETHTOOL_GCHANNELS unsupported)"),
        }
        println!();
    }
    Ok(())
}
