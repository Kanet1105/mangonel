//! Layer 2: what carries the IP packets.

pub mod ethernet;

pub use ethernet::{
    Arp,
    EtherType,
    Ethernet,
    Vlan,
};
