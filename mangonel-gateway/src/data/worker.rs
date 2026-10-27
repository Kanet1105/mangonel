//! A worker: one queue index on every NIC, each frame run
//! to completion through filtering, NAT and routing.
//!
//! The order is Cisco's. The inbound ACL sees the addresses
//! a packet arrived with and the outbound ACL the
//! translated ones. Leaving through the WAN, a packet is
//! routed before its source is translated; arriving on it,
//! its destination is translated before it is routed.

use std::{
    collections::HashMap,
    mem,
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    time::{
        Duration,
        Instant,
    },
};

use mangonel_libxdp::{
    XdpConfig,
    XdpDescriptor,
    XdpSocket,
    bind,
};
use mangonel_ring::Ring;

use crate::{
    control::{
        Acl,
        Addressing,
        Cidr,
        Direction,
        MacAddr,
        Reader,
        State,
        WanIp,
        acl::{
            Action,
            Packet,
        },
    },
    data::{
        Error,
        nat::{
            Flow,
            Nat,
        },
        wire::{
            self,
            Ipv4Packet,
            Transport,
        },
    },
};

/// Frames taken per receive and per handoff read.
const BURST: usize = 64;
/// Frames in flight from one worker to another.
pub(crate) const HANDOFF_DEPTH: usize = 1024;
/// How often idle NAT sessions are swept.
const EXPIRE_EVERY: Duration = Duration::from_secs(1);

/// A frame bound for the worker that owns its NAT session,
/// with the index of the NIC it arrived on.
pub(crate) type Handoff = (usize, XdpDescriptor);

/// A worker's rings to the others: one in from each, and
/// one out to each by worker index, its own unused.
pub(crate) struct Handoffs {
    pub(crate) inbox: Vec<Ring<Handoff>>,
    pub(crate) outbox: Vec<Ring<Handoff>>,
}

/// Drives one queue index on every NIC.
pub(crate) struct Worker {
    /// In the data plane's NIC order.
    ports: Vec<Port>,
    pipeline: Pipeline,
    reader: Reader,
    handoffs: Handoffs,
    stop: Arc<AtomicBool>,
}

impl Worker {
    /// Binds queue `index` on each of `nics`, given by name
    /// and MAC.
    pub(crate) fn bind(
        index: usize,
        nics: &[(String, MacAddr)],
        config: XdpConfig,
        reader: Reader,
        handoffs: Handoffs,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        let queue = u32::try_from(index).expect("A queue index fits a u32. This is a bug.");
        let ports = nics
            .iter()
            .map(|(name, mac)| {
                let socket = bind(name, queue, config)
                    .map_err(|error| Error::Bind(name.clone(), queue, error))?;

                Ok(Port {
                    mac: *mac,
                    socket,
                    tx: Vec::new(),
                })
            })
            .collect::<Result<_, Error>>()?;
        let workers = handoffs.outbox.len();

        Ok(Self {
            ports,
            pipeline: Pipeline {
                nat: Nat::new(index, workers),
                neighbors: HashMap::new(),
            },
            reader,
            handoffs,
            stop,
        })
    }

    /// Forwards until stopped or the control plane is gone.
    pub(crate) fn run(mut self) {
        let mut rx: Vec<XdpDescriptor> = (0..BURST).map(|_| XdpDescriptor::default()).collect();
        let mut handoffs: Vec<Vec<Handoff>> =
            self.handoffs.outbox.iter().map(|_| Vec::new()).collect();
        let mut drops = Vec::new();
        let mut expired = Instant::now();
        while !self.stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now.duration_since(expired) >= EXPIRE_EVERY {
                self.pipeline.nat.expire(now);
                expired = now;
            }

            let Some(state) = self.reader.enter() else {
                break;
            };
            let views: Vec<View<'_>> = self
                .ports
                .iter()
                .map(|port| View::new(&state, port.mac))
                .collect();
            for ingress in 0..self.ports.len() {
                let received = self.ports[ingress].socket.receive(&mut rx);
                for slot in &mut rx[..received as usize] {
                    let mut descriptor = mem::take(slot);
                    match self
                        .pipeline
                        .forward(&views, ingress, descriptor.data_mut(), now)
                    {
                        Verdict::Forward(egress) => self.ports[egress].tx.push(descriptor),
                        Verdict::Handoff(owner) => handoffs[owner].push((ingress, descriptor)),
                        Verdict::Drop => drops.push(descriptor),
                    }
                }
            }
            for inbox in &self.handoffs.inbox {
                let Ok(mut grant) = inbox.bulk_read(BURST) else {
                    continue;
                };
                while let Some((ingress, mut descriptor)) = grant.read() {
                    // This worker owns the port, so the frame
                    // is not handed on again.
                    match self
                        .pipeline
                        .forward(&views, ingress, descriptor.data_mut(), now)
                    {
                        Verdict::Forward(egress) => self.ports[egress].tx.push(descriptor),
                        Verdict::Handoff(_) | Verdict::Drop => drops.push(descriptor),
                    }
                }
            }
            // Released before any send, so a publish waits on
            // no syscall.
            drop(views);
            drop(state);

            for (owner, frames) in handoffs.iter_mut().enumerate() {
                if frames.is_empty() {
                    continue;
                }
                if let Ok(mut grant) = self.handoffs.outbox[owner].bulk_write(frames.len()) {
                    for handoff in frames.drain(..grant.size()) {
                        grant
                            .write(handoff)
                            .expect("Wrote past the grant. This is a bug.");
                    }
                }
                // What a full ring cannot take is dropped.
                drops.extend(frames.drain(..).map(|(_, descriptor)| descriptor));
            }
            for port in &mut self.ports {
                if port.tx.is_empty() {
                    continue;
                }
                let sent = port.socket.send(&mut port.tx);
                port.tx.drain(..sent as usize);
                // Dropped rather than held, so a stalled port
                // cannot hoard frames.
                drops.append(&mut port.tx);
            }
            if !drops.is_empty() {
                self.ports[0].socket.drop(&mut drops);
                drops.clear();
            }
        }
    }
}

/// One NIC as a worker drives it.
struct Port {
    mac: MacAddr,
    socket: XdpSocket,
    /// Frames to leave through this port.
    tx: Vec<XdpDescriptor>,
}

/// What forwarding needs of a port's IPv4 configuration.
#[derive(Clone, Copy, Debug)]
enum Side {
    /// Not a configured port, or one without a static
    /// address.
    Off,

    Wan {
        address: Ipv4Addr,
        gateway: Ipv4Addr,
    },

    Lan(Cidr<Ipv4Addr>),
}

/// A port's configuration as of one pass.
struct View<'a> {
    mac: MacAddr,
    side: Side,
    inbound: Option<&'a Acl>,
    outbound: Option<&'a Acl>,
}

impl<'a> View<'a> {
    fn new(state: &'a State, mac: MacAddr) -> Self {
        let side = if let Some(port) = state.wan(mac) {
            // TODO: addresses leased over DHCP.
            match &port.ipv4 {
                Some(WanIp {
                    addressing: Addressing::Static { cidr, gateway },
                    ..
                }) => Side::Wan {
                    address: cidr.address,
                    gateway: *gateway,
                },
                _ => Side::Off,
            }
        } else {
            state
                .lan(mac)
                .and_then(|port| port.ipv4.as_ref())
                .map_or(Side::Off, |ip| Side::Lan(ip.cidr))
        };

        Self {
            mac,
            side,
            inbound: state.port_acl(mac, Direction::Inbound),
            outbound: state.port_acl(mac, Direction::Outbound),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Out through the port at this index, rewritten.
    Forward(usize),

    /// To the worker at this index, untouched.
    Handoff(usize),

    Drop,
}

/// A worker's forwarding state.
struct Pipeline {
    nat: Nat,
    // TODO: fill through ARP; nothing resolves until then.
    /// Next-hop MACs by address.
    neighbors: HashMap<Ipv4Addr, MacAddr>,
}

impl Pipeline {
    /// Decides a frame that arrived on port `ingress`,
    /// rewriting it in place when it is forwarded.
    fn forward(
        &mut self,
        views: &[View<'_>],
        ingress: usize,
        frame: &mut [u8],
        now: Instant,
    ) -> Verdict {
        let view = &views[ingress];
        // TODO: ARP, DHCP, IPv6, expired TTLs and traffic
        // for the gateway itself go to a host path; until
        // there is one they are dropped.
        let Some(packet) = Ipv4Packet::parse(frame) else {
            return Verdict::Drop;
        };
        if wire::destination_mac(frame) != view.mac
            || packet.vlan.is_some()
            || packet.ttl <= 1
            || !permits(view.inbound, &packet.acl(frame))
        {
            return Verdict::Drop;
        }

        let (egress, next_hop) = match view.side {
            Side::Off => return Verdict::Drop,
            Side::Lan(subnet) => {
                // On-link traffic is not ours to route.
                if subnet.contains(packet.destination) {
                    return Verdict::Drop;
                }

                if let Some(egress) = lan_for(views, packet.destination) {
                    // Between LANs: routed, not translated.
                    (egress, packet.destination)
                } else {
                    let Some((egress, address, gateway)) = wan(views) else {
                        return Verdict::Drop;
                    };
                    if packet.transport == Transport::Other {
                        return Verdict::Drop;
                    }
                    let flow = Flow {
                        protocol: packet.protocol,
                        inside: SocketAddrV4::new(packet.source, packet.source_port),
                        remote: SocketAddrV4::new(packet.destination, packet.destination_port),
                    };
                    let Some(port) = self.nat.outbound(flow, now) else {
                        return Verdict::Drop;
                    };
                    packet.rewrite_source(frame, address, port);

                    (egress, gateway)
                }
            }
            Side::Wan { address, .. } => {
                if packet.destination != address || packet.transport == Transport::Other {
                    return Verdict::Drop;
                }
                match self.nat.owner(packet.destination_port) {
                    Some(owner) if owner != self.nat.worker() => return Verdict::Handoff(owner),
                    Some(_) => {}
                    None => return Verdict::Drop,
                }

                let remote = SocketAddrV4::new(packet.source, packet.source_port);
                let Some(inside) =
                    self.nat
                        .inbound(packet.protocol, packet.destination_port, remote, now)
                else {
                    return Verdict::Drop;
                };
                let Some(egress) = lan_for(views, *inside.ip()) else {
                    return Verdict::Drop;
                };
                packet.rewrite_destination(frame, *inside.ip(), inside.port());

                (egress, *inside.ip())
            }
        };

        let packet =
            Ipv4Packet::parse(frame).expect("A rewritten frame still parses. This is a bug.");
        if !permits(views[egress].outbound, &packet.acl(frame)) {
            return Verdict::Drop;
        }
        let Some(&mac) = self.neighbors.get(&next_hop) else {
            return Verdict::Drop;
        };
        packet.decrement_ttl(frame);
        wire::rewrite_macs(frame, views[egress].mac, mac);

        Verdict::Forward(egress)
    }
}

/// Whether `acl`, when one is attached, lets `packet`
/// through.
fn permits(acl: Option<&Acl>, packet: &Packet) -> bool {
    acl.is_none_or(|acl| acl.action(packet) == Action::Permit)
}

/// The LAN port whose subnet holds `address`.
fn lan_for(views: &[View<'_>], address: Ipv4Addr) -> Option<usize> {
    views
        .iter()
        .position(|view| matches!(view.side, Side::Lan(subnet) if subnet.contains(address)))
}

/// The first addressed WAN port: its index, address and
/// gateway.
fn wan(views: &[View<'_>]) -> Option<(usize, Ipv4Addr, Ipv4Addr)> {
    views
        .iter()
        .enumerate()
        .find_map(|(index, view)| match view.side {
            Side::Wan { address, gateway } => Some((index, address, gateway)),
            _ => None,
        })
}
