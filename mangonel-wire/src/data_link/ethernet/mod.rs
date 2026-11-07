//! Ethernet II, with the 802.1Q tag and the ARP that ride on
//! it.

pub mod arp;
pub mod header;
pub mod vlan;

pub use arp::Arp;
pub use header::{
    EtherType,
    Ethernet,
    HEADER_LEN,
};
pub use vlan::Vlan;
