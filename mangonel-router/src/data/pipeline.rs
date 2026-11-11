//! One worker's forwarding: each frame run to completion
//! through filtering, the gateway's own services, routing
//! and NAT.
//!
//! The order is Cisco's. The inbound ACL sees the addresses
//! a packet arrived with and the outbound ACL the
//! translated ones. Leaving through the WAN, a packet is
//! routed before its source is translated; arriving on it,
//! its destination is translated before it is routed.
//!
//! Nothing here touches a socket. A frame comes in as bytes
//! and leaves on an [`Output`], so the pipeline runs the
//! same on umem frames and on test buffers.

use std::{
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    sync::Arc,
    time::{
        Duration,
        Instant,
    },
};

use mangonel_dhcp::v4::{
    client::Transmit,
    server::Destination,
};
use mangonel_wire::{
    Arp,
    Ethernet,
    Ipv4,
    Packet,
    Tcp,
    Udp,
    checksum,
    data_link::ethernet::arp::Operation,
    network::ipv4::{
        Dhcp as DhcpMessage,
        Icmp,
        Protocol,
        dhcp::{
            CLIENT_PORT,
            SERVER_PORT,
        },
        icmp::Kind,
    },
    transport::tcp::Flags,
};

use crate::{
    control::{
        Acl,
        Addressing,
        Cidr,
        Direction,
        Dns,
        LanIp,
        MacAddr,
        Reader,
        State,
        WanIp,
        acl,
    },
    data::{
        build::{
            self,
            BROADCAST,
            Datagram,
        },
        dhcp::Dhcp,
        frame::{
            Frame,
            Output,
        },
        nat::{
            Flow,
            Nat,
            Segment,
        },
        neighbor::{
            Neighbors,
            Table,
        },
    },
};

/// Frames held for one neighbour while it is resolved.
const PARKED_PER_NEIGHBOR: usize = 8;
/// Neighbours one worker resolves at a time.
const RESOLVING_LIMIT: usize = 64;
/// How long an ARP request waits for its reply.
const ARP_RETRY: Duration = Duration::from_secs(1);
/// Requests sent before the frames waiting are given up.
const ARP_TRIES: u8 = 3;
/// How often the timers run.
const TICK: Duration = Duration::from_secs(1);

/// What the workers share, because a flow's packets do not
/// all arrive on one worker's queues.
pub(crate) struct Shared {
    neighbors: Neighbors,
    nat: Nat,
    dhcp: Dhcp,
}

impl Shared {
    /// Empty tables for `ports` ports.
    pub(crate) fn new(ports: usize) -> Self {
        Self {
            neighbors: Neighbors::new(),
            nat: Nat::new(),
            dhcp: Dhcp::new(ports),
        }
    }
}

/// A port's IPv4 configuration as the control panel last
/// published it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Side {
    /// Not a configured port, or one without IPv4.
    Off,
    Wan(WanIp<Ipv4Addr>),
    Lan(LanIp<Ipv4Addr>),
}

/// One port as the pipeline forwards with it.
struct Port {
    mac: [u8; 6],
    side: Side,
    /// The port's address and subnet. A WAN port leasing
    /// its address has none until the lease is granted.
    cidr: Option<Cidr<Ipv4Addr>>,
    /// The default router, on a WAN port that has one.
    gateway: Option<Ipv4Addr>,
    inbound: Option<Acl>,
    outbound: Option<Acl>,
}

impl Port {
    /// Whether the port serves a DHCP pool.
    fn serves(&self) -> bool {
        matches!(&self.side, Side::Lan(lan) if lan.dhcp)
    }

    /// Whether the port leases its own address.
    fn leases(&self) -> bool {
        matches!(
            &self.side,
            Side::Wan(WanIp {
                addressing: Addressing::Dhcp,
                ..
            })
        )
    }
}

/// What becomes of a frame.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Out through the port at this index, as it now is.
    Send(usize),
    /// Out through `egress` once `next_hop`'s MAC is known;
    /// only the destination MAC is still missing.
    Resolve {
        egress: usize,
        next_hop: Ipv4Addr,
    },
    Drop,
}

/// What becomes of a packet, before its frame's header is
/// settled.
enum Decision {
    Drop,
    /// Rewritten in place into the answer for its sender.
    Answer,
    /// Forwarded through `egress` towards `next_hop`.
    Route {
        egress: usize,
        next_hop: Ipv4Addr,
    },
    /// Replaced by a message of the gateway's own.
    Originate(Message),
}

/// A datagram the gateway sends and how it leaves.
struct Message {
    egress: usize,
    link: Link,
    datagram: Datagram,
}

/// Who a gateway's own frame is addressed to.
enum Link {
    Broadcast,
    /// A station whose MAC came with the request.
    Station([u8; 6]),
    /// A neighbour to resolve like any next hop.
    Neighbor(Ipv4Addr),
}

/// Which of a packet's two ends a translation rewrites.
#[derive(Clone, Copy)]
enum End {
    Source,
    Destination,
}

/// Frames waiting on one neighbour's MAC.
struct Resolution<F> {
    port: usize,
    address: Ipv4Addr,
    frames: Vec<F>,
    /// Requests sent so far.
    tries: u8,
    /// When the next request goes out, or the wait ends.
    retry_at: Instant,
}

/// One worker's forwarding state.
pub(crate) struct Pipeline<F> {
    /// Worker 0 runs the timers for all.
    worker: usize,
    /// In the data plane's port order.
    ports: Vec<Port>,
    reader: Reader,
    shared: Arc<Shared>,
    /// The control panel revision `ports` reflects.
    revision: Option<u64>,
    /// The lease generation `ports` reflects.
    leases: u64,
    /// This worker's copy of the shared neighbours.
    neighbors: Table,
    /// The generation `neighbors` is current as of.
    neighbors_as_of: Option<u64>,
    resolving: Vec<Resolution<F>>,
    next_tick: Instant,
}

impl<F: Frame> Pipeline<F> {
    /// A pipeline for worker `worker` over ports with these
    /// MACs, unconfigured until the first [`Self::begin`].
    pub(crate) fn new(
        worker: usize,
        macs: &[MacAddr],
        reader: Reader,
        shared: Arc<Shared>,
        now: Instant,
    ) -> Self {
        let ports = macs
            .iter()
            .map(|mac| Port {
                mac: mac.0,
                side: Side::Off,
                cidr: None,
                gateway: None,
                inbound: None,
                outbound: None,
            })
            .collect();

        Self {
            worker,
            ports,
            reader,
            shared,
            revision: None,
            leases: 0,
            neighbors: Table::new(),
            neighbors_as_of: None,
            resolving: Vec::new(),
            next_tick: now,
        }
    }

    /// Starts a pass: catches up with the configuration and
    /// the shared tables. False once the control panel has
    /// stopped, which ends the worker.
    pub(crate) fn begin(&mut self) -> bool {
        if !self.configure() {
            return false;
        }
        self.learn();

        true
    }

    /// Decides the frame that arrived on port `ingress` and
    /// puts it on `output`, unless it waits for a neighbour.
    pub(crate) fn handle(
        &mut self,
        ingress: usize,
        mut frame: F,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        let verdict = self.decide(ingress, &mut frame, now);
        self.dispatch(verdict, frame, now, allocate, output);
    }

    /// Ends a pass: releases frames whose neighbour has
    /// answered, retries or gives up on the others, and
    /// runs the timers when they are due.
    pub(crate) fn finish(
        &mut self,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        if !self.resolving.is_empty() {
            // A reply handled this pass is already in the
            // shared table.
            self.learn();
            self.resolve(now, allocate, output);
        }
        if self.worker == 0 && now >= self.next_tick {
            self.next_tick = now + TICK;
            self.tick(now, allocate, output);
        }
    }

    /// Rebuilds the ports when the control panel or a lease
    /// has moved on. False once the control panel has
    /// stopped.
    fn configure(&mut self) -> bool {
        let leases = self.shared.dhcp.generation();
        {
            let Some(state) = self.reader.enter() else {
                return false;
            };
            let revision = Some(state.revision());
            if self.revision == revision && self.leases == leases {
                return true;
            }
            self.revision = revision;
            read(&mut self.ports, &state);
            // The guard goes before any lock is taken: the
            // control panel cannot publish while it is held.
        }
        self.leases = leases;
        self.apply();

        true
    }

    /// Settles each port's address from its configuration
    /// and lease, and has the shared DHCP state run what the
    /// configuration asks for.
    fn apply(&mut self) {
        let dhcp = &self.shared.dhcp;
        let external = self.uplink().map(|(_, cidr, _)| cidr.address);

        // The WAN ports first: the LAN servers hand out
        // their resolvers.
        let mut resolvers = Vec::new();
        for (index, port) in self.ports.iter_mut().enumerate() {
            let Side::Wan(wan) = &port.side else {
                dhcp.lease_as(index, None);
                (port.cidr, port.gateway) = (None, None);
                continue;
            };
            dhcp.serve(index, None);
            let leased = match wan.addressing {
                Addressing::Static { cidr, gateway } => {
                    dhcp.lease_as(index, None);
                    (port.cidr, port.gateway) = (Some(cidr), Some(gateway));

                    Vec::new()
                }
                Addressing::Dhcp => {
                    dhcp.lease_as(index, Some(port.mac));
                    let lease = dhcp.lease(index);
                    port.cidr = lease.as_ref().map(|lease| lease.cidr);
                    port.gateway = lease.as_ref().and_then(|lease| lease.gateway);

                    lease.map(|lease| lease.dns).unwrap_or_default()
                }
            };
            if resolvers.is_empty() {
                resolvers = match wan.dns {
                    Dns::Auto => leased,
                    Dns::Manual { primary, secondary } => {
                        std::iter::once(primary).chain(secondary).collect()
                    }
                };
            }
        }
        for (index, port) in self.ports.iter_mut().enumerate() {
            match &port.side {
                Side::Wan(_) => {}
                Side::Lan(lan) => {
                    port.cidr = Some(lan.cidr);
                    dhcp.serve(index, lan.dhcp.then_some((lan, &resolvers)));
                }
                Side::Off => dhcp.serve(index, None),
            }
        }

        // Sessions translated to an address the gateway no
        // longer holds can never be answered. One worker
        // clears them, so none made since is lost twice.
        let now_external = self.uplink().map(|(_, cidr, _)| cidr.address);
        if self.worker == 0 && external.is_some() && external != now_external {
            self.shared.nat.clear();
        }
    }

    /// Refreshes this worker's neighbours if the shared
    /// table has changed.
    fn learn(&mut self) {
        let neighbors = &self.shared.neighbors;
        if self.neighbors_as_of != Some(neighbors.generation()) {
            let (generation, table) = neighbors.snapshot();
            self.neighbors = table;
            self.neighbors_as_of = Some(generation);
        }
    }

    /// Acts on a verdict for `frame`.
    fn dispatch(
        &mut self,
        verdict: Verdict,
        frame: F,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        match verdict {
            Verdict::Send(egress) => output.send[egress].push(frame),
            Verdict::Resolve { egress, next_hop } => {
                self.park(frame, egress, next_hop, now, allocate, output);
            }
            Verdict::Drop => output.drop.push(frame),
        }
    }

    /// Decides a frame that arrived on port `ingress`,
    /// rewriting it in place unless it is dropped.
    fn decide(&mut self, ingress: usize, frame: &mut F, now: Instant) -> Verdict {
        let mac = self.ports[ingress].mac;
        let Ok(mut parsed) = mangonel_wire::parse(frame.data_mut()) else {
            return Verdict::Drop;
        };
        let (destination, source) = (parsed.destination(), parsed.source());
        let broadcast = destination == BROADCAST;
        // TODO: VLANs and multicast. A tagged frame belongs
        // to a VLAN no port is configured for, and a frame
        // for another station is only here because the port
        // is promiscuous.
        if parsed.vlan().is_some() || !(broadcast || destination == mac) || !is_station(source) {
            return Verdict::Drop;
        }

        let decision = match parsed.packet_mut() {
            Packet::Arp(arp) => self.arp(ingress, arp, now),
            Packet::Ipv4(ip) => self.ipv4(ingress, broadcast, ip, now),
            // TODO: IPv6.
            Packet::Ipv6(_) | Packet::Other { .. } => Decision::Drop,
        };
        match decision {
            Decision::Drop => Verdict::Drop,
            Decision::Answer => {
                parsed.set_destination(source);
                parsed.set_source(mac);

                Verdict::Send(ingress)
            }
            Decision::Route { egress, next_hop } => {
                parsed.set_source(self.ports[egress].mac);
                match self.neighbors.get(&(egress, next_hop)) {
                    Some(&neighbor) => {
                        parsed.set_destination(neighbor);

                        Verdict::Send(egress)
                    }
                    None => Verdict::Resolve { egress, next_hop },
                }
            }
            Decision::Originate(message) => self.originate(frame, message),
        }
    }

    /// Answers a request for the port's own address and
    /// learns who is asking or answering.
    fn arp(&self, ingress: usize, arp: &mut Arp<&mut [u8]>, now: Instant) -> Decision {
        let port = &self.ports[ingress];
        let Some(cidr) = port.cidr else {
            return Decision::Drop;
        };
        let (sender, sender_mac) = (arp.sender_ip(), arp.sender_mac());
        let for_us = arp.target_ip() == cidr.address;

        // A probe has no sender address yet, and nobody
        // else may claim ours. A lease may name a router
        // from outside its subnet, which is on the segment
        // all the same. A stranger is learned only when it
        // talks to us: a busy segment's chatter must not
        // fill the table.
        let neighbor = is_station(sender_mac)
            && sender_mac != port.mac
            && (cidr.is_host(sender) || port.gateway == Some(sender))
            && sender != cidr.address;
        if neighbor && (for_us || self.neighbors.contains_key(&(ingress, sender))) {
            self.shared
                .neighbors
                .learn(ingress, sender, sender_mac, now);
        }

        if !for_us || arp.operation() != Operation::REQUEST {
            return Decision::Drop;
        }
        arp.set_operation(Operation::REPLY);
        arp.set_target_mac(sender_mac);
        arp.set_target_ip(sender);
        arp.set_sender_mac(port.mac);
        arp.set_sender_ip(cidr.address);

        Decision::Answer
    }

    /// Decides an IPv4 packet, rewriting it in place when it
    /// is answered or forwarded.
    fn ipv4(
        &self,
        ingress: usize,
        broadcast: bool,
        ip: &mut Ipv4<&mut [u8]>,
        now: Instant,
    ) -> Decision {
        if !ip.verify_checksum() || !self.permits(ingress, Direction::Inbound, ip) {
            return Decision::Drop;
        }
        // Before anything looks at addresses: a client has
        // none of its own yet.
        if let Some(decision) = self.dhcp(ingress, broadcast, ip, now) {
            return decision;
        }

        let (source, destination) = (ip.source(), ip.destination());
        let port = &self.ports[ingress];
        let Some(cidr) = port.cidr else {
            return Decision::Drop;
        };
        // DHCP aside, nothing is taken off a broadcast
        // frame, nor from a source no reply could reach.
        if broadcast || !is_host(source) {
            return Decision::Drop;
        }

        match port.side {
            Side::Off => Decision::Drop,
            Side::Lan(_) => {
                // A source from off the segment is spoofed or
                // has strayed.
                if !cidr.is_host(source) || source == cidr.address {
                    return Decision::Drop;
                }
                if self.is_ours(destination) {
                    return deliver(ip);
                }
                // On-link traffic is not ours to route, and a
                // packet out of hops is not worth a session.
                if cidr.contains(destination) || !is_host(destination) || ip.ttl() <= 1 {
                    return Decision::Drop;
                }
                if let Some((egress, subnet)) = self.lan_for(destination) {
                    // Between LANs: routed, not translated.
                    // A subnet's broadcast address is not
                    // forwarded into it.
                    if !subnet.is_host(destination) {
                        return Decision::Drop;
                    }

                    return self.route(ip, egress, destination);
                }

                let Some((egress, uplink, gateway)) = self.uplink() else {
                    return Decision::Drop;
                };
                let next_hop = if !uplink.contains(destination) {
                    gateway
                } else if uplink.is_host(destination) {
                    Some(destination)
                } else {
                    None
                };
                let Some(next_hop) = next_hop else {
                    return Decision::Drop;
                };
                if !self.translate_source(ip, uplink.address, now) {
                    return Decision::Drop;
                }

                self.route(ip, egress, next_hop)
            }
            Side::Wan(_) => {
                if destination != cidr.address {
                    return Decision::Drop;
                }
                // A reply to a translated flow, or else a
                // packet for the gateway itself.
                let Some(inside) = self.translate_destination(ip, now) else {
                    return deliver(ip);
                };
                match self.lan_for(inside) {
                    Some((egress, _)) => self.route(ip, egress, inside),
                    None => Decision::Drop,
                }
            }
        }
    }

    /// Hands a DHCP message to the state machine the port
    /// runs for it; `None` if the packet is none of the
    /// port's DHCP business.
    fn dhcp(
        &self,
        ingress: usize,
        broadcast: bool,
        ip: &Ipv4<&mut [u8]>,
        now: Instant,
    ) -> Option<Decision> {
        let port = &self.ports[ingress];
        match ip.dhcp()? {
            DhcpMessage::Server { payload } if port.serves() => {
                let cidr = port.cidr?;
                // A message relayed on to some other server
                // is forwarded like any packet.
                if !broadcast && ip.destination() != cidr.address {
                    return None;
                }
                let Some(reply) = self.shared.dhcp.request(ingress, payload, now) else {
                    return Some(Decision::Drop);
                };
                let (link, to, to_port) = match reply.to {
                    Destination::Broadcast => (Link::Broadcast, Ipv4Addr::BROADCAST, CLIENT_PORT),
                    Destination::Unicast { ip, mac } => (Link::Station(mac), ip, CLIENT_PORT),
                    Destination::Relay(relay) if cidr.is_host(relay) => {
                        (Link::Neighbor(relay), relay, SERVER_PORT)
                    }
                    // TODO: relays beyond the segment.
                    Destination::Relay(_) => return Some(Decision::Drop),
                };

                Some(Decision::Originate(Message {
                    egress: ingress,
                    link,
                    datagram: Datagram {
                        source: SocketAddrV4::new(cidr.address, SERVER_PORT),
                        destination: SocketAddrV4::new(to, to_port),
                        payload: reply.packet,
                    },
                }))
            }
            DhcpMessage::Client { payload } if port.leases() => {
                Some(match self.shared.dhcp.reply(ingress, payload, now) {
                    Some(transmit) => Decision::Originate(self.lease_message(ingress, transmit)),
                    None => Decision::Drop,
                })
            }
            _ => None,
        }
    }

    /// Frames what `port`'s DHCP client sends.
    fn lease_message(&self, port: usize, transmit: Transmit) -> Message {
        let to = transmit.destination;
        let Port { cidr, gateway, .. } = self.ports[port];
        // A renewal goes straight to the server that
        // granted the lease: on the segment, or past the
        // router. Without a route yet, everyone hears it.
        let link = match (cidr, gateway) {
            _ if to.is_broadcast() => Link::Broadcast,
            (Some(cidr), _) if cidr.contains(to) => Link::Neighbor(to),
            (_, Some(gateway)) => Link::Neighbor(gateway),
            _ => Link::Broadcast,
        };

        Message {
            egress: port,
            link,
            datagram: Datagram {
                source: SocketAddrV4::new(transmit.source, CLIENT_PORT),
                destination: SocketAddrV4::new(to, SERVER_PORT),
                payload: transmit.packet,
            },
        }
    }

    /// Replaces `frame` with a message of the gateway's own.
    fn originate(&self, frame: &mut F, message: Message) -> Verdict {
        let egress = message.egress;
        let (destination, unresolved) = match message.link {
            Link::Broadcast => (BROADCAST, None),
            Link::Station(mac) => (mac, None),
            Link::Neighbor(address) => match self.neighbors.get(&(egress, address)) {
                Some(&mac) => (mac, None),
                // Filled in once the neighbour answers.
                None => ([0; 6], Some(address)),
            },
        };
        if !build::udp(
            frame,
            self.ports[egress].mac,
            destination,
            &message.datagram,
        ) {
            return Verdict::Drop;
        }

        match unresolved {
            Some(next_hop) => Verdict::Resolve { egress, next_hop },
            None => Verdict::Send(egress),
        }
    }

    /// Sends a packet on through `egress` towards
    /// `next_hop`, if the port lets it out and it has a hop
    /// left to live.
    fn route(&self, ip: &mut Ipv4<&mut [u8]>, egress: usize, next_hop: Ipv4Addr) -> Decision {
        // TODO: tell the sender its packet's time ran out.
        if !self.permits(egress, Direction::Outbound, ip) || !ip.decrement_ttl() {
            return Decision::Drop;
        }

        Decision::Route { egress, next_hop }
    }

    /// Whether the ACL attached to `port` in `direction`,
    /// when there is one, lets the packet through.
    fn permits(&self, port: usize, direction: Direction, ip: &Ipv4<&mut [u8]>) -> bool {
        let port = &self.ports[port];
        let acl = match direction {
            Direction::Inbound => &port.inbound,
            Direction::Outbound => &port.outbound,
        };

        acl.as_ref()
            .is_none_or(|acl| acl.action(&describe(ip)) == acl::Action::Permit)
    }

    /// Rewrites a LAN packet's source to `external` and the
    /// port its flow was given. False if it cannot be
    /// translated.
    fn translate_source(&self, ip: &mut Ipv4<&mut [u8]>, external: Ipv4Addr, now: Instant) -> bool {
        let Some((source_port, destination_port, segment)) = ports(ip, End::Source) else {
            return false;
        };
        let flow = Flow {
            protocol: ip.protocol(),
            inside: SocketAddrV4::new(ip.source(), source_port),
            remote: SocketAddrV4::new(ip.destination(), destination_port),
        };
        let Some(port) = self.shared.nat.outbound(flow, segment, now) else {
            return false;
        };
        rewrite(ip, End::Source, external, port);

        true
    }

    /// Rewrites a WAN packet's destination to the LAN host
    /// whose flow it answers, and returns that host; `None`
    /// if it answers no flow.
    fn translate_destination(&self, ip: &mut Ipv4<&mut [u8]>, now: Instant) -> Option<Ipv4Addr> {
        let (source_port, destination_port, segment) = ports(ip, End::Destination)?;
        let remote = SocketAddrV4::new(ip.source(), source_port);
        let inside =
            self.shared
                .nat
                .inbound(ip.protocol(), destination_port, remote, segment, now)?;
        rewrite(ip, End::Destination, *inside.ip(), inside.port());

        Some(*inside.ip())
    }

    /// Whether `address` is one of the gateway's own.
    fn is_ours(&self, address: Ipv4Addr) -> bool {
        self.ports
            .iter()
            .any(|port| port.cidr.is_some_and(|cidr| cidr.address == address))
    }

    /// The LAN port whose subnet holds `address`, and that
    /// subnet.
    fn lan_for(&self, address: Ipv4Addr) -> Option<(usize, Cidr<Ipv4Addr>)> {
        self.ports
            .iter()
            .enumerate()
            .find_map(|(index, port)| match (&port.side, port.cidr) {
                (Side::Lan(_), Some(cidr)) if cidr.contains(address) => Some((index, cidr)),
                _ => None,
            })
    }

    /// The first WAN port holding an address: its index,
    /// address and subnet, and default router.
    fn uplink(&self) -> Option<(usize, Cidr<Ipv4Addr>, Option<Ipv4Addr>)> {
        self.ports
            .iter()
            .enumerate()
            .find_map(|(index, port)| match (&port.side, port.cidr) {
                (Side::Wan(_), Some(cidr)) => Some((index, cidr, port.gateway)),
                _ => None,
            })
    }

    /// Holds `frame` until `next_hop` on port `egress` is
    /// resolved, asking for it if nobody has yet.
    fn park(
        &mut self,
        frame: F,
        egress: usize,
        next_hop: Ipv4Addr,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        let waiting = self
            .resolving
            .iter_mut()
            .find(|resolution| resolution.port == egress && resolution.address == next_hop);
        if let Some(resolution) = waiting {
            if resolution.frames.len() < PARKED_PER_NEIGHBOR {
                resolution.frames.push(frame);
            } else {
                output.drop.push(frame);
            }

            return;
        }
        if self.resolving.len() == RESOLVING_LIMIT {
            output.drop.push(frame);

            return;
        }

        self.resolving.push(Resolution {
            port: egress,
            address: next_hop,
            frames: vec![frame],
            tries: 1,
            retry_at: now + ARP_RETRY,
        });
        self.request(egress, next_hop, allocate, output);
    }

    /// Asks port `port`'s segment who holds `target`.
    fn request(
        &self,
        port: usize,
        target: Ipv4Addr,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        let Port { mac, cidr, .. } = self.ports[port];
        // Without an address there is nothing to ask as, so
        // no frame is taken. Without a frame, whoever asked
        // asks again later.
        let Some(cidr) = cidr else {
            return;
        };
        let Some(mut frame) = allocate() else {
            return;
        };
        if build::arp_request(&mut frame, mac, cidr.address, target) {
            output.send[port].push(frame);
        } else {
            output.drop.push(frame);
        }
    }

    /// Releases the frames of every neighbour that has
    /// answered, and asks again or gives up on those whose
    /// wait has run out.
    fn resolve(
        &mut self,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        let mut index = 0;
        while index < self.resolving.len() {
            let Resolution {
                port,
                address,
                tries,
                retry_at,
                ..
            } = self.resolving[index];
            if let Some(&mac) = self.neighbors.get(&(port, address)) {
                for mut frame in self.resolving.swap_remove(index).frames {
                    match Ethernet::parse(frame.data_mut()) {
                        Ok(mut ethernet) => {
                            ethernet.set_destination(mac);
                            output.send[port].push(frame);
                        }
                        Err(_) => output.drop.push(frame),
                    }
                }
            } else if now < retry_at {
                index += 1;
            } else if tries == ARP_TRIES {
                output.drop.extend(self.resolving.swap_remove(index).frames);
            } else {
                let resolution = &mut self.resolving[index];
                resolution.tries += 1;
                resolution.retry_at = now + ARP_RETRY;
                self.request(port, address, allocate, output);
                index += 1;
            }
        }
    }

    /// Ages the shared tables, asks after neighbours about
    /// to lapse and runs the DHCP clients' timers.
    fn tick(
        &mut self,
        now: Instant,
        allocate: &mut impl FnMut() -> Option<F>,
        output: &mut Output<F>,
    ) {
        self.shared.nat.expire(now);
        self.shared.neighbors.expire(now);
        self.shared.dhcp.expire(now);

        // A neighbour in use need not speak ARP on its own
        // for a lifetime, and forgetting it would cost a
        // burst of frames.
        for (port, address) in self.shared.neighbors.lapsing(now) {
            self.request(port, address, allocate, output);
        }

        for port in 0..self.ports.len() {
            if !self.ports[port].leases() {
                continue;
            }
            let Some(transmit) = self.shared.dhcp.poll(port, now) else {
                continue;
            };
            // Without a frame the message is lost like any
            // other, and the client's own timer resends it.
            let Some(mut frame) = allocate() else {
                continue;
            };
            let message = self.lease_message(port, transmit);
            let verdict = self.originate(&mut frame, message);
            self.dispatch(verdict, frame, now, allocate, output);
        }
    }
}

/// Copies what each port needs out of `state`.
fn read(ports: &mut [Port], state: &State) {
    for port in ports {
        let mac = MacAddr(port.mac);
        port.side = if let Some(wan) = state.wan(mac) {
            wan.ipv4.clone().map_or(Side::Off, Side::Wan)
        } else if let Some(lan) = state.lan(mac) {
            lan.ipv4.clone().map_or(Side::Off, Side::Lan)
        } else {
            Side::Off
        };
        port.inbound = state.port_acl(mac, Direction::Inbound).cloned();
        port.outbound = state.port_acl(mac, Direction::Outbound).cloned();
    }
}

/// Answers an echo request to the gateway itself, in place.
fn deliver(ip: &mut Ipv4<&mut [u8]>) -> Decision {
    // TODO: a host path for everything else addressed to
    // the gateway. A fragment would need reassembling.
    if ip.is_fragment() || ip.protocol() != Protocol::ICMP {
        return Decision::Drop;
    }
    let (source, destination) = (ip.source(), ip.destination());
    let Ok(mut icmp) = Icmp::parse(ip.payload_mut()) else {
        return Decision::Drop;
    };
    if icmp.kind() != Kind::ECHO_REQUEST || icmp.code() != 0 {
        return Decision::Drop;
    }
    // Only the type changes, so the checksum is patched for
    // that one word rather than summed over the payload.
    let patched = checksum::update(
        icmp.checksum(),
        &[Kind::ECHO_REQUEST.0, 0],
        &[Kind::ECHO_REPLY.0, 0],
    );
    icmp.set_kind(Kind::ECHO_REPLY);
    icmp.set_checksum(patched);
    ip.set_source(destination);
    ip.set_destination(source);
    ip.set_ttl(build::TTL);
    ip.fill_checksum();

    Decision::Answer
}

/// The fields an ACL matches on.
fn describe(ip: &Ipv4<&mut [u8]>) -> acl::Packet {
    let protocol = ip.protocol();
    let payload = ip.payload();
    // Only a first fragment carries the transport header.
    let transport = match protocol {
        _ if ip.fragment_offset() != 0 => None,
        Protocol::TCP => Tcp::parse(payload).ok().map(|tcp| acl::Transport::Tcp {
            source: tcp.source_port(),
            destination: tcp.destination_port(),
            flags: tcp.flags().0,
        }),
        Protocol::UDP => Udp::parse(payload).ok().map(|udp| acl::Transport::Udp {
            source: udp.source_port(),
            destination: udp.destination_port(),
        }),
        Protocol::ICMP => Icmp::parse(payload).ok().map(|icmp| acl::Transport::Icmp {
            kind: icmp.kind().0,
            code: icmp.code(),
        }),
        _ => None,
    };

    acl::Packet {
        source: ip.source().into(),
        destination: ip.destination().into(),
        transport: transport.unwrap_or(acl::Transport::Other(protocol.0)),
    }
}

/// The source and destination ports NAT keys a packet on
/// when it translates the packet's `end`, and what the
/// packet does to its session. An ICMP echo's identifier
/// stands for the port at that end, on a request going out
/// and a reply coming back. `None` for anything else, and
/// for fragments, which may not carry the header.
fn ports(ip: &Ipv4<&mut [u8]>, end: End) -> Option<(u16, u16, Segment)> {
    if ip.is_fragment() {
        return None;
    }
    let payload = ip.payload();
    match ip.protocol() {
        Protocol::TCP => {
            let tcp = Tcp::parse(payload).ok()?;
            let flags = tcp.flags();
            let segment = if flags.contains(Flags::FIN) || flags.contains(Flags::RST) {
                Segment::Closes
            } else if flags.contains(Flags::SYN) && !flags.contains(Flags::ACK) {
                Segment::Opens
            } else {
                Segment::Continues
            };

            Some((tcp.source_port(), tcp.destination_port(), segment))
        }
        Protocol::UDP => {
            let udp = Udp::parse(payload).ok()?;

            Some((
                udp.source_port(),
                udp.destination_port(),
                Segment::Continues,
            ))
        }
        Protocol::ICMP => {
            let icmp = Icmp::parse(payload).ok()?;
            match (end, icmp.kind()) {
                _ if icmp.code() != 0 => None,
                (End::Source, Kind::ECHO_REQUEST) => {
                    Some((icmp.identifier(), 0, Segment::Continues))
                }
                (End::Destination, Kind::ECHO_REPLY) => {
                    Some((0, icmp.identifier(), Segment::Continues))
                }
                // TODO: errors about a translated flow.
                _ => None,
            }
        }
        _ => None,
    }
}

/// Sets the address at `end` and the port or echo
/// identifier beside it, patching every checksum that
/// covers them. Only for packets [`ports`] accepted.
fn rewrite(ip: &mut Ipv4<&mut [u8]>, end: End, address: Ipv4Addr, port: u16) {
    let old_address = match end {
        End::Source => ip.source(),
        End::Destination => ip.destination(),
    };
    let (old, new) = (old_address.octets(), address.octets());
    let new_port = port.to_be_bytes();
    let protocol = ip.protocol();
    let payload = ip.payload_mut();
    match protocol {
        Protocol::TCP => {
            if let Ok(mut tcp) = Tcp::parse(payload) {
                let old_port = match end {
                    End::Source => tcp.source_port(),
                    End::Destination => tcp.destination_port(),
                };
                // The pseudo-header carries the address.
                let patched = checksum::update(tcp.checksum(), &old, &new);
                let patched = checksum::update(patched, &old_port.to_be_bytes(), &new_port);
                match end {
                    End::Source => tcp.set_source_port(port),
                    End::Destination => tcp.set_destination_port(port),
                }
                tcp.set_checksum(patched);
            }
        }
        Protocol::UDP => {
            if let Ok(mut udp) = Udp::parse(payload) {
                let old_port = match end {
                    End::Source => udp.source_port(),
                    End::Destination => udp.destination_port(),
                };
                // Zero means no checksum was sent; a
                // computed zero goes out as all ones.
                if udp.checksum() != 0 {
                    let patched = checksum::update(udp.checksum(), &old, &new);
                    let patched = checksum::update(patched, &old_port.to_be_bytes(), &new_port);
                    udp.set_checksum(if patched == 0 { 0xFFFF } else { patched });
                }
                match end {
                    End::Source => udp.set_source_port(port),
                    End::Destination => udp.set_destination_port(port),
                }
            }
        }
        Protocol::ICMP => {
            if let Ok(mut icmp) = Icmp::parse(payload) {
                // No pseudo-header: only the identifier
                // changes.
                let old_port = icmp.identifier().to_be_bytes();
                let patched = checksum::update(icmp.checksum(), &old_port, &new_port);
                icmp.set_identifier(port);
                icmp.set_checksum(patched);
            }
        }
        _ => {}
    }

    let patched = checksum::update(ip.checksum(), &old, &new);
    match end {
        End::Source => ip.set_source(address),
        End::Destination => ip.set_destination(address),
    }
    ip.set_checksum(patched);
}

/// Whether `mac` names one station: not a group, and not
/// nobody.
fn is_station(mac: [u8; 6]) -> bool {
    mac[0] & 0x01 == 0 && mac != [0; 6]
}

/// Whether `address` can be one host's: not a group, and
/// not a placeholder.
fn is_host(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast())
}

#[cfg(test)]
mod tests {
    use mangonel_dhcp::v4::{
        client,
        server,
    };
    use mangonel_wire::{
        data_link::ethernet::{
            EtherType,
            HEADER_LEN,
        },
        transport::tcp::Flags,
    };

    use super::*;
    use crate::{
        control::{
            AclEntry,
            ControlPanel,
            LanPort,
            PortAcls,
            WanPort,
        },
        data::frame::tests::Buffer,
    };

    const WAN: usize = 0;
    const LAN_0: usize = 1;
    const LAN_1: usize = 2;
    const MACS: [[u8; 6]; 3] = [[2, 0, 0, 1, 0, 1], [2, 0, 0, 1, 0, 2], [2, 0, 0, 1, 0, 3]];

    const EXTERNAL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);
    const UPSTREAM: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const UPSTREAM_MAC: [u8; 6] = [2, 0, 0, 2, 0, 1];
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const GATEWAY_0: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const GATEWAY_1: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 1);
    const HOST_0: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 100);
    const HOST_0_MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];
    const HOST_1: Ipv4Addr = Ipv4Addr::new(10, 0, 1, 100);
    const HOST_1_MAC: [u8; 6] = [2, 0, 0, 4, 0, 1];

    /// A gateway with one WAN and two LAN ports, and as many
    /// workers as asked for sharing its tables.
    struct Gateway {
        panel: ControlPanel,
        shared: Arc<Shared>,
        workers: Vec<Pipeline<Buffer>>,
        now: Instant,
    }

    impl Gateway {
        /// The WAN port holds a static address.
        fn new(workers: usize) -> Self {
            Self::with_wan(
                workers,
                wan(Addressing::Static {
                    cidr: Cidr::new(EXTERNAL, 24),
                    gateway: UPSTREAM,
                }),
            )
        }

        fn with_wan(workers: usize, wan: WanPort) -> Self {
            let panel = ControlPanel::spawn().unwrap();
            panel.set_wan(wan).unwrap();
            panel.set_lan(lan(MACS[LAN_0], GATEWAY_0)).unwrap();
            panel.set_lan(lan(MACS[LAN_1], GATEWAY_1)).unwrap();
            let shared = Arc::new(Shared::new(MACS.len()));
            let now = Instant::now();
            let macs = MACS.map(MacAddr);
            let workers = (0..workers)
                .map(|worker| Pipeline::new(worker, &macs, panel.reader(), shared.clone(), now))
                .collect();

            Self {
                panel,
                shared,
                workers,
                now,
            }
        }

        /// One pass of `worker` in which `frame` arrives on
        /// `ingress`.
        fn receive(&mut self, worker: usize, ingress: usize, frame: Vec<u8>) -> Output<Buffer> {
            let pipeline = &mut self.workers[worker];
            let mut output = Output::new(MACS.len());
            let mut allocate = || Some(Buffer(Vec::new()));
            assert!(pipeline.begin());
            pipeline.handle(ingress, Buffer(frame), self.now, &mut allocate, &mut output);
            pipeline.finish(self.now, &mut allocate, &mut output);

            output
        }

        /// One pass of `worker` in which nothing arrives.
        fn idle(&mut self, worker: usize) -> Output<Buffer> {
            let pipeline = &mut self.workers[worker];
            let mut output = Output::new(MACS.len());
            let mut allocate = || Some(Buffer(Vec::new()));
            assert!(pipeline.begin());
            pipeline.finish(self.now, &mut allocate, &mut output);

            output
        }

        /// Has `mac` at `address` ask for the gateway on
        /// `port`, which is how a host becomes a neighbour.
        fn introduce(&mut self, port: usize, mac: [u8; 6], address: Ipv4Addr) {
            // A pass first, so the port's address is current.
            assert!(self.workers[0].begin());
            let ours = self.workers[0].ports[port].cidr.unwrap().address;
            let request = arp(
                Operation::REQUEST,
                BROADCAST,
                (mac, address),
                ([0; 6], ours),
            );
            let reply = sent(self.receive(0, port, request), port);
            assert_eq!(Ethernet::parse(&reply.0[..]).unwrap().destination(), mac);
        }

        /// Makes every neighbour the tests talk to known.
        fn introduce_all(&mut self) {
            self.introduce(WAN, UPSTREAM_MAC, UPSTREAM);
            self.introduce(LAN_0, HOST_0_MAC, HOST_0);
            self.introduce(LAN_1, HOST_1_MAC, HOST_1);
        }
    }

    fn wan(addressing: Addressing<Ipv4Addr>) -> WanPort {
        let dns = match addressing {
            Addressing::Dhcp => Dns::Auto,
            Addressing::Static { .. } => Dns::Manual {
                primary: UPSTREAM,
                secondary: None,
            },
        };

        WanPort {
            mac: MacAddr(MACS[WAN]),
            ipv4: Some(WanIp { addressing, dns }),
            ipv6: None,
            acls: PortAcls::default(),
        }
    }

    fn lan(mac: [u8; 6], address: Ipv4Addr) -> LanPort {
        let [a, b, c, _] = address.octets();

        LanPort {
            mac: MacAddr(mac),
            ipv4: Some(LanIp {
                cidr: Cidr::new(address, 24),
                pool_start: Ipv4Addr::new(a, b, c, 100),
                pool_end: Ipv4Addr::new(a, b, c, 199),
                dhcp: true,
            }),
            ipv6: None,
            acls: PortAcls::default(),
        }
    }

    /// The one frame a pass sent, which left through `port`.
    fn sent(mut output: Output<Buffer>, port: usize) -> Buffer {
        assert!(output.drop.is_empty(), "a frame was dropped");
        for (index, frames) in output.send.iter().enumerate() {
            let expected = usize::from(index == port);
            assert_eq!(frames.len(), expected, "frames sent through port {index}");
        }

        output.send[port].remove(0)
    }

    /// Asserts a pass dropped its one frame and sent none.
    fn dropped(output: Output<Buffer>) {
        assert!(output.send.iter().all(Vec::is_empty), "a frame was sent");
        assert_eq!(output.drop.len(), 1);
    }

    fn arp(
        operation: Operation,
        to: [u8; 6],
        sender: ([u8; 6], Ipv4Addr),
        target: ([u8; 6], Ipv4Addr),
    ) -> Vec<u8> {
        let mut data = vec![0; 60];
        let mut ethernet = Ethernet::parse(&mut data[..]).unwrap();
        ethernet.set_destination(to);
        ethernet.set_source(sender.0);
        ethernet.set_ethertype(EtherType::ARP);
        let mut arp = Arp::init(ethernet.payload_mut()).unwrap();
        arp.set_operation(operation);
        arp.set_sender_mac(sender.0);
        arp.set_sender_ip(sender.1);
        arp.set_target_mac(target.0);
        arp.set_target_ip(target.1);

        data
    }

    /// An IPv4 frame from `from` to `to`, by MAC and address.
    fn ipv4(
        from: ([u8; 6], Ipv4Addr),
        to: ([u8; 6], Ipv4Addr),
        protocol: Protocol,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut data = vec![0; HEADER_LEN + 20 + payload.len()];
        let mut ethernet = Ethernet::parse(&mut data[..]).unwrap();
        ethernet.set_destination(to.0);
        ethernet.set_source(from.0);
        ethernet.set_ethertype(EtherType::IPV4);
        let mut ip = Ipv4::init(ethernet.payload_mut()).unwrap();
        ip.set_total_length(u16::try_from(20 + payload.len()).unwrap())
            .unwrap();
        ip.set_ttl(64);
        ip.set_protocol(protocol);
        ip.set_source(from.1);
        ip.set_destination(to.1);
        ip.payload_mut().copy_from_slice(payload);
        ip.fill_checksum();

        data
    }

    fn udp(from: SocketAddrV4, to: SocketAddrV4, body: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 8 + body.len()];
        let mut udp = Udp::init(&mut data[..]).unwrap();
        udp.set_source_port(from.port());
        udp.set_destination_port(to.port());
        udp.set_length(u16::try_from(8 + body.len()).unwrap())
            .unwrap();
        udp.payload_mut().copy_from_slice(body);
        udp.fill_checksum((*from.ip()).into(), (*to.ip()).into());

        data
    }

    fn tcp(from: SocketAddrV4, to: SocketAddrV4, flags: Flags) -> Vec<u8> {
        let mut data = vec![0; 20];
        let mut tcp = Tcp::init(&mut data[..]).unwrap();
        tcp.set_source_port(from.port());
        tcp.set_destination_port(to.port());
        tcp.set_flags(flags);
        tcp.fill_checksum((*from.ip()).into(), (*to.ip()).into());

        data
    }

    fn echo(kind: Kind, identifier: u16) -> Vec<u8> {
        let mut data = vec![0; 8 + 32];
        let mut icmp = Icmp::parse(&mut data[..]).unwrap();
        icmp.set_kind(kind);
        icmp.set_identifier(identifier);
        icmp.set_sequence(1);
        icmp.payload_mut().fill(0x5A);
        icmp.fill_checksum();

        data
    }

    /// A UDP frame from a LAN host to its gateway's MAC.
    fn udp_from(
        host: ([u8; 6], Ipv4Addr),
        gateway_mac: [u8; 6],
        port: u16,
        to: SocketAddrV4,
    ) -> Vec<u8> {
        let from = SocketAddrV4::new(host.1, port);

        ipv4(
            host,
            (gateway_mac, *to.ip()),
            Protocol::UDP,
            &udp(from, to, b"mangonel"),
        )
    }

    /// The frame's addresses, having checked its IPv4 header
    /// sums up.
    fn addresses(frame: &Buffer) -> ([u8; 6], [u8; 6], Ipv4Addr, Ipv4Addr) {
        let ethernet = Ethernet::parse(&frame.0[..]).unwrap();
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum(), "the IPv4 header checksum is wrong");

        (
            ethernet.source(),
            ethernet.destination(),
            ip.source(),
            ip.destination(),
        )
    }

    /// The frame's UDP ports and body, having checked the
    /// datagram sums up.
    fn udp_of(frame: &Buffer) -> (u16, u16, Vec<u8>) {
        let ethernet = Ethernet::parse(&frame.0[..]).unwrap();
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert_eq!(ip.protocol(), Protocol::UDP);
        let udp = Udp::parse(ip.payload()).unwrap();
        assert!(
            udp.verify_checksum(ip.source().into(), ip.destination().into()),
            "the UDP checksum is wrong"
        );

        (
            udp.source_port(),
            udp.destination_port(),
            udp.payload().to_vec(),
        )
    }

    #[test]
    fn arp_for_the_gateway_is_answered_and_the_asker_learned() {
        let mut gateway = Gateway::new(1);
        let request = arp(
            Operation::REQUEST,
            BROADCAST,
            (HOST_0_MAC, HOST_0),
            ([0; 6], GATEWAY_0),
        );
        let reply = sent(gateway.receive(0, LAN_0, request), LAN_0);

        let ethernet = Ethernet::parse(&reply.0[..]).unwrap();
        assert_eq!(ethernet.destination(), HOST_0_MAC);
        assert_eq!(ethernet.source(), MACS[LAN_0]);
        let arp = Arp::parse(ethernet.payload()).unwrap();
        assert_eq!(arp.operation(), Operation::REPLY);
        assert_eq!(
            (arp.sender_mac(), arp.sender_ip()),
            (MACS[LAN_0], GATEWAY_0)
        );
        assert_eq!((arp.target_mac(), arp.target_ip()), (HOST_0_MAC, HOST_0));
        let (_, neighbors) = gateway.shared.neighbors.snapshot();
        assert_eq!(neighbors.get(&(LAN_0, HOST_0)), Some(&HOST_0_MAC));
    }

    #[test]
    fn arp_between_others_is_neither_answered_nor_learned() {
        let mut gateway = Gateway::new(1);
        let request = arp(
            Operation::REQUEST,
            BROADCAST,
            (HOST_0_MAC, HOST_0),
            ([0; 6], Ipv4Addr::new(10, 0, 0, 50)),
        );
        dropped(gateway.receive(0, LAN_0, request));
        assert!(gateway.shared.neighbors.snapshot().1.is_empty());

        // Nor is an address from off the segment, or ours.
        for sender in [HOST_1, GATEWAY_0, Ipv4Addr::UNSPECIFIED] {
            let request = arp(
                Operation::REQUEST,
                BROADCAST,
                (HOST_0_MAC, sender),
                ([0; 6], GATEWAY_0),
            );
            sent(gateway.receive(0, LAN_0, request), LAN_0);
        }
        assert!(gateway.shared.neighbors.snapshot().1.is_empty());
    }

    #[test]
    fn a_known_neighbour_is_followed_when_it_moves() {
        let mut gateway = Gateway::new(1);
        gateway.introduce(LAN_0, HOST_0_MAC, HOST_0);
        // Announcing itself to the segment, not asking us.
        let moved = [2, 0, 0, 4, 0, 9];
        let announcement = arp(
            Operation::REQUEST,
            BROADCAST,
            (moved, HOST_0),
            ([0; 6], HOST_0),
        );
        dropped(gateway.receive(0, LAN_0, announcement));

        let (_, neighbors) = gateway.shared.neighbors.snapshot();
        assert_eq!(neighbors.get(&(LAN_0, HOST_0)), Some(&moved));
    }

    #[test]
    fn a_neighbour_is_asked_again_before_it_lapses() {
        let mut gateway = Gateway::new(1);
        gateway.introduce(LAN_0, HOST_0_MAC, HOST_0);
        let start = gateway.now;

        // Nothing while the entry is fresh.
        gateway.now = start + Duration::from_secs(200);
        assert!(gateway.idle(0).send.iter().all(Vec::is_empty));

        // Near its end the host is asked, and its answer
        // keeps it known past where it would have lapsed.
        gateway.now = start + Duration::from_secs(280);
        let request = sent(gateway.idle(0), LAN_0);
        let ethernet = Ethernet::parse(&request.0[..]).unwrap();
        let asked = Arp::parse(ethernet.payload()).unwrap();
        assert_eq!(asked.operation(), Operation::REQUEST);
        assert_eq!(asked.target_ip(), HOST_0);
        let reply = arp(
            Operation::REPLY,
            MACS[LAN_0],
            (HOST_0_MAC, HOST_0),
            (MACS[LAN_0], GATEWAY_0),
        );
        dropped(gateway.receive(0, LAN_0, reply));

        gateway.now = start + Duration::from_secs(400);
        gateway.idle(0);
        let (_, neighbors) = gateway.shared.neighbors.snapshot();
        assert_eq!(neighbors.get(&(LAN_0, HOST_0)), Some(&HOST_0_MAC));
    }

    #[test]
    fn a_router_from_outside_the_subnet_is_learned() {
        let mut gateway = Gateway::new(1);
        gateway.introduce(LAN_0, HOST_0_MAC, HOST_0);
        // As a lease of a single address would leave the
        // port: the router is on the segment, not the subnet.
        let router = Ipv4Addr::new(100, 64, 0, 1);
        let port = &mut gateway.workers[0].ports[WAN];
        port.cidr = Some(Cidr::new(EXTERNAL, 32));
        port.gateway = Some(router);

        let reply = arp(
            Operation::REPLY,
            MACS[WAN],
            (UPSTREAM_MAC, router),
            (MACS[WAN], EXTERNAL),
        );
        dropped(gateway.receive(0, WAN, reply));
        let remote = SocketAddrV4::new(REMOTE, 53);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        let translated = sent(gateway.receive(0, LAN_0, packet), WAN);
        assert_eq!(
            addresses(&translated),
            (MACS[WAN], UPSTREAM_MAC, EXTERNAL, REMOTE)
        );

        // Anyone else from outside the subnet stays a stranger.
        let stranger = Ipv4Addr::new(100, 64, 0, 9);
        let reply = arp(
            Operation::REPLY,
            MACS[WAN],
            ([2, 0, 0, 2, 0, 9], stranger),
            (MACS[WAN], EXTERNAL),
        );
        dropped(gateway.receive(0, WAN, reply));
        let (_, neighbors) = gateway.shared.neighbors.snapshot();
        assert_eq!(neighbors.get(&(WAN, stranger)), None);
    }

    #[test]
    fn a_port_without_an_address_asks_nothing_and_takes_no_frame() {
        let mut gateway = Gateway::with_wan(1, wan(Addressing::Dhcp));
        assert!(gateway.workers[0].begin());
        let mut output = Output::new(MACS.len());
        let mut taken = 0;
        let mut allocate = || {
            taken += 1;

            Some(Buffer(Vec::new()))
        };
        gateway.workers[0].request(WAN, UPSTREAM, &mut allocate, &mut output);

        assert_eq!(taken, 0);
        assert!(output.send.iter().all(Vec::is_empty) && output.drop.is_empty());
    }

    #[test]
    fn echo_to_any_gateway_address_is_answered() {
        let mut gateway = Gateway::new(1);
        for address in [GATEWAY_0, GATEWAY_1, EXTERNAL] {
            let request = ipv4(
                (HOST_0_MAC, HOST_0),
                (MACS[LAN_0], address),
                Protocol::ICMP,
                &echo(Kind::ECHO_REQUEST, 7),
            );
            let reply = sent(gateway.receive(0, LAN_0, request), LAN_0);

            assert_eq!(
                addresses(&reply),
                (MACS[LAN_0], HOST_0_MAC, address, HOST_0)
            );
            let ethernet = Ethernet::parse(&reply.0[..]).unwrap();
            let ip = Ipv4::parse(ethernet.payload()).unwrap();
            let icmp = Icmp::parse(ip.payload()).unwrap();
            assert_eq!(icmp.kind(), Kind::ECHO_REPLY);
            assert_eq!(icmp.identifier(), 7);
            assert!(icmp.verify_checksum());
            assert_eq!(icmp.payload(), &[0x5A; 32][..]);
        }
    }

    #[test]
    fn echo_from_the_wan_is_answered() {
        let mut gateway = Gateway::new(1);
        let request = ipv4(
            (UPSTREAM_MAC, UPSTREAM),
            (MACS[WAN], EXTERNAL),
            Protocol::ICMP,
            &echo(Kind::ECHO_REQUEST, 7),
        );
        let reply = sent(gateway.receive(0, WAN, request), WAN);
        assert_eq!(
            addresses(&reply),
            (MACS[WAN], UPSTREAM_MAC, EXTERNAL, UPSTREAM)
        );
    }

    #[test]
    fn a_packet_between_lans_waits_for_its_neighbour() {
        let mut gateway = Gateway::new(1);
        let to = SocketAddrV4::new(HOST_1, 9000);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, to);

        // The packet is held, and the segment is asked.
        let request = sent(gateway.receive(0, LAN_0, packet), LAN_1);
        let ethernet = Ethernet::parse(&request.0[..]).unwrap();
        assert_eq!(ethernet.destination(), BROADCAST);
        let asked = Arp::parse(ethernet.payload()).unwrap();
        assert_eq!(asked.operation(), Operation::REQUEST);
        assert_eq!(
            (asked.sender_mac(), asked.sender_ip()),
            (MACS[LAN_1], GATEWAY_1)
        );
        assert_eq!(asked.target_ip(), HOST_1);

        // The answer releases it, routed but not translated.
        let reply = arp(
            Operation::REPLY,
            MACS[LAN_1],
            (HOST_1_MAC, HOST_1),
            (MACS[LAN_1], GATEWAY_1),
        );
        let mut output = gateway.receive(0, LAN_1, reply);
        assert_eq!(output.drop.len(), 1, "the reply itself is consumed");
        output.drop.clear();
        let forwarded = sent(output, LAN_1);
        assert_eq!(
            addresses(&forwarded),
            (MACS[LAN_1], HOST_1_MAC, HOST_0, HOST_1)
        );
        assert_eq!(udp_of(&forwarded), (4000, 9000, b"mangonel".to_vec()));
        let ethernet = Ethernet::parse(&forwarded.0[..]).unwrap();
        assert_eq!(Ipv4::parse(ethernet.payload()).unwrap().ttl(), 63);

        // And the next one goes straight through.
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, to);
        let forwarded = sent(gateway.receive(0, LAN_0, packet), LAN_1);
        assert_eq!(addresses(&forwarded).1, HOST_1_MAC);
    }

    #[test]
    fn frames_waiting_on_a_silent_neighbour_are_given_up() {
        let mut gateway = Gateway::new(1);
        let to = SocketAddrV4::new(HOST_1, 9000);
        let mut requests = 0;
        for _ in 0..PARKED_PER_NEIGHBOR {
            let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, to);
            let output = gateway.receive(0, LAN_0, packet);
            assert!(output.drop.is_empty());
            requests += output.send[LAN_1].len();
        }
        // One request however many frames wait, and no room
        // for one frame more.
        assert_eq!(requests, 1);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, to);
        dropped(gateway.receive(0, LAN_0, packet));

        for _ in 1..ARP_TRIES {
            gateway.now += ARP_RETRY;
            let output = gateway.idle(0);
            assert!(output.drop.is_empty());
            assert_eq!(output.send[LAN_1].len(), 1, "the request is repeated");
        }
        gateway.now += ARP_RETRY;
        let output = gateway.idle(0);
        assert!(output.send.iter().all(Vec::is_empty));
        assert_eq!(output.drop.len(), PARKED_PER_NEIGHBOR);
        assert!(gateway.workers[0].resolving.is_empty());
    }

    #[test]
    fn lan_traffic_leaves_translated_and_its_replies_return() {
        let mut gateway = Gateway::new(1);
        gateway.introduce_all();
        let inside = SocketAddrV4::new(HOST_0, 4000);
        let remote = SocketAddrV4::new(REMOTE, 53);

        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        let translated = sent(gateway.receive(0, LAN_0, packet), WAN);
        assert_eq!(
            addresses(&translated),
            (MACS[WAN], UPSTREAM_MAC, EXTERNAL, REMOTE)
        );
        let (external_port, to_port, body) = udp_of(&translated);
        assert!(external_port >= 1024);
        assert_eq!((to_port, body), (53, b"mangonel".to_vec()));

        let external = SocketAddrV4::new(EXTERNAL, external_port);
        let reply = ipv4(
            (UPSTREAM_MAC, REMOTE),
            (MACS[WAN], EXTERNAL),
            Protocol::UDP,
            &udp(remote, external, b"answer"),
        );
        let returned = sent(gateway.receive(0, WAN, reply), LAN_0);
        assert_eq!(
            addresses(&returned),
            (MACS[LAN_0], HOST_0_MAC, REMOTE, HOST_0)
        );
        assert_eq!(udp_of(&returned), (53, inside.port(), b"answer".to_vec()));

        // A stranger aiming at the same port gets nowhere.
        let stranger = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), 53);
        let probe = ipv4(
            (UPSTREAM_MAC, *stranger.ip()),
            (MACS[WAN], EXTERNAL),
            Protocol::UDP,
            &udp(stranger, external, b"probe"),
        );
        dropped(gateway.receive(0, WAN, probe));
    }

    #[test]
    fn tcp_is_translated_with_its_checksum() {
        let mut gateway = Gateway::new(1);
        gateway.introduce_all();
        let inside = SocketAddrV4::new(HOST_1, 51000);
        let remote = SocketAddrV4::new(REMOTE, 443);

        let syn = ipv4(
            (HOST_1_MAC, HOST_1),
            (MACS[LAN_1], REMOTE),
            Protocol::TCP,
            &tcp(inside, remote, Flags::SYN),
        );
        let translated = sent(gateway.receive(0, LAN_1, syn), WAN);
        let ethernet = Ethernet::parse(&translated.0[..]).unwrap();
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!((ip.source(), ip.destination()), (EXTERNAL, REMOTE));
        let segment = Tcp::parse(ip.payload()).unwrap();
        assert!(segment.verify_checksum(EXTERNAL.into(), REMOTE.into()));
        let external = SocketAddrV4::new(EXTERNAL, segment.source_port());

        let syn_ack = ipv4(
            (UPSTREAM_MAC, REMOTE),
            (MACS[WAN], EXTERNAL),
            Protocol::TCP,
            &tcp(remote, external, Flags(Flags::SYN.0 | Flags::ACK.0)),
        );
        let returned = sent(gateway.receive(0, WAN, syn_ack), LAN_1);
        let ethernet = Ethernet::parse(&returned.0[..]).unwrap();
        assert_eq!(ethernet.destination(), HOST_1_MAC);
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!((ip.source(), ip.destination()), (REMOTE, HOST_1));
        let segment = Tcp::parse(ip.payload()).unwrap();
        assert!(segment.verify_checksum(REMOTE.into(), HOST_1.into()));
        assert_eq!(segment.destination_port(), inside.port());
    }

    #[test]
    fn echo_through_the_wan_is_translated_by_its_identifier() {
        let mut gateway = Gateway::new(1);
        gateway.introduce_all();
        let request = ipv4(
            (HOST_0_MAC, HOST_0),
            (MACS[LAN_0], UPSTREAM),
            Protocol::ICMP,
            &echo(Kind::ECHO_REQUEST, 7),
        );
        let translated = sent(gateway.receive(0, LAN_0, request), WAN);
        // On the WAN's own segment the next hop is the
        // destination itself.
        assert_eq!(
            addresses(&translated),
            (MACS[WAN], UPSTREAM_MAC, EXTERNAL, UPSTREAM)
        );
        let ethernet = Ethernet::parse(&translated.0[..]).unwrap();
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        let icmp = Icmp::parse(ip.payload()).unwrap();
        assert!(icmp.verify_checksum());
        let identifier = icmp.identifier();
        assert!(identifier >= 1024);

        let reply = ipv4(
            (UPSTREAM_MAC, UPSTREAM),
            (MACS[WAN], EXTERNAL),
            Protocol::ICMP,
            &echo(Kind::ECHO_REPLY, identifier),
        );
        let returned = sent(gateway.receive(0, WAN, reply), LAN_0);
        assert_eq!(
            addresses(&returned),
            (MACS[LAN_0], HOST_0_MAC, UPSTREAM, HOST_0)
        );
        let ethernet = Ethernet::parse(&returned.0[..]).unwrap();
        let ip = Ipv4::parse(ethernet.payload()).unwrap();
        let icmp = Icmp::parse(ip.payload()).unwrap();
        assert!(icmp.verify_checksum());
        assert_eq!((icmp.kind(), icmp.identifier()), (Kind::ECHO_REPLY, 7));
    }

    #[test]
    fn a_reply_is_translated_by_whichever_worker_it_reaches() {
        let mut gateway = Gateway::new(2);
        gateway.introduce_all();
        let remote = SocketAddrV4::new(REMOTE, 53);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        let translated = sent(gateway.receive(0, LAN_0, packet), WAN);
        let external = SocketAddrV4::new(EXTERNAL, udp_of(&translated).0);

        // The reply hashes to the other worker's queue, which
        // has never seen the flow or the neighbours.
        let reply = ipv4(
            (UPSTREAM_MAC, REMOTE),
            (MACS[WAN], EXTERNAL),
            Protocol::UDP,
            &udp(remote, external, b"answer"),
        );
        let returned = sent(gateway.receive(1, WAN, reply), LAN_0);
        assert_eq!(
            addresses(&returned),
            (MACS[LAN_0], HOST_0_MAC, REMOTE, HOST_0)
        );
        assert_eq!(udp_of(&returned).1, 4000);
    }

    #[test]
    fn a_frame_parked_on_one_worker_leaves_when_another_hears_the_answer() {
        let mut gateway = Gateway::new(2);
        let to = SocketAddrV4::new(HOST_1, 9000);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, to);
        sent(gateway.receive(1, LAN_0, packet), LAN_1);

        let reply = arp(
            Operation::REPLY,
            MACS[LAN_1],
            (HOST_1_MAC, HOST_1),
            (MACS[LAN_1], GATEWAY_1),
        );
        dropped(gateway.receive(0, LAN_1, reply));
        let forwarded = sent(gateway.idle(1), LAN_1);
        assert_eq!(addresses(&forwarded).1, HOST_1_MAC);
    }

    #[test]
    fn what_the_gateway_has_no_business_with_is_dropped() {
        let mut gateway = Gateway::new(1);
        gateway.introduce_all();
        let remote = SocketAddrV4::new(REMOTE, 53);
        let good = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        sent(gateway.receive(0, LAN_0, good.clone()), WAN);

        // For another station on the segment.
        let mut frame = good.clone();
        frame[..6].copy_from_slice(&HOST_1_MAC);
        dropped(gateway.receive(0, LAN_0, frame));

        // A corrupted header.
        let mut frame = good.clone();
        frame[HEADER_LEN + 8] ^= 0xFF;
        dropped(gateway.receive(0, LAN_0, frame));

        // Out of hops.
        let mut frame = good.clone();
        let mut ip = Ipv4::parse(&mut frame[HEADER_LEN..]).unwrap();
        ip.set_ttl(1);
        ip.fill_checksum();
        dropped(gateway.receive(0, LAN_0, frame));

        // A source from another segment.
        let stray = udp_from((HOST_0_MAC, HOST_1), MACS[LAN_0], 4000, remote);
        dropped(gateway.receive(0, LAN_0, stray));

        // A destination on the sender's own segment.
        let on_link = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 50), 53);
        let frame = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, on_link);
        dropped(gateway.receive(0, LAN_0, frame));

        // Another LAN's broadcast address.
        let directed = SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 255), 53);
        let frame = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, directed);
        dropped(gateway.receive(0, LAN_0, frame));

        // Anything from the WAN that answers no flow, or is
        // not for the gateway's address at all.
        let external = SocketAddrV4::new(EXTERNAL, 4000);
        for to in [EXTERNAL, HOST_0] {
            let frame = ipv4(
                (UPSTREAM_MAC, REMOTE),
                (MACS[WAN], to),
                Protocol::UDP,
                &udp(remote, external, b"probe"),
            );
            dropped(gateway.receive(0, WAN, frame));
        }

        // A protocol NAT has no ports for, and a fragment.
        let frame = ipv4(
            (HOST_0_MAC, HOST_0),
            (MACS[LAN_0], REMOTE),
            Protocol::ESP,
            &[0; 16],
        );
        dropped(gateway.receive(0, LAN_0, frame));
        let mut frame = good.clone();
        let mut ip = Ipv4::parse(&mut frame[HEADER_LEN..]).unwrap();
        ip.set_identification(1);
        // The more-fragments bit.
        frame[HEADER_LEN + 6] |= 0x20;
        let mut ip = Ipv4::parse(&mut frame[HEADER_LEN..]).unwrap();
        ip.fill_checksum();
        dropped(gateway.receive(0, LAN_0, frame));

        // IPv6 and a VLAN tag, for now.
        let mut frame = good.clone();
        frame[12..14].copy_from_slice(&EtherType::IPV6.0.to_be_bytes());
        dropped(gateway.receive(0, LAN_0, frame));
        let mut frame = good;
        frame[12..14].copy_from_slice(&EtherType::VLAN.0.to_be_bytes());
        dropped(gateway.receive(0, LAN_0, frame));
    }

    #[test]
    fn a_lan_client_leases_an_address() {
        let mut gateway = Gateway::new(1);
        let mut client = client::Client::with_seed(client::Config::new(HOST_0_MAC), 1);
        let from_client = |transmit: Transmit| {
            let from = SocketAddrV4::new(transmit.source, CLIENT_PORT);
            let to = SocketAddrV4::new(transmit.destination, SERVER_PORT);

            ipv4(
                (HOST_0_MAC, transmit.source),
                (BROADCAST, transmit.destination),
                Protocol::UDP,
                &udp(from, to, &transmit.packet),
            )
        };

        let discover = client.poll(gateway.now).transmit.unwrap();
        let offer = sent(gateway.receive(0, LAN_0, from_client(discover)), LAN_0);
        // Straight to the client's MAC and the address it is
        // being offered.
        assert_eq!(
            addresses(&offer),
            (MACS[LAN_0], HOST_0_MAC, GATEWAY_0, HOST_0)
        );
        let (from_port, to_port, message) = udp_of(&offer);
        assert_eq!((from_port, to_port), (SERVER_PORT, CLIENT_PORT));

        let request = client
            .handle(&message, gateway.now)
            .unwrap()
            .transmit
            .unwrap();
        let ack = sent(gateway.receive(0, LAN_0, from_client(request)), LAN_0);
        let (_, _, message) = udp_of(&ack);
        let bound = client.handle(&message, gateway.now).unwrap().event;
        assert!(matches!(bound, Some(client::Event::Bound(_))));
        let lease = client.lease().unwrap();
        assert_eq!((lease.address, lease.prefix), (HOST_0, 24));
        assert_eq!(lease.router, Some(GATEWAY_0));
        assert_eq!(lease.dns, [UPSTREAM]);
    }

    #[test]
    fn the_wan_address_can_be_leased() {
        let mut gateway = Gateway::with_wan(1, wan(Addressing::Dhcp));
        let resolver = Ipv4Addr::new(9, 9, 9, 9);
        let mut upstream = server::Server::new(server::Config {
            address: UPSTREAM,
            prefix: 24,
            pool_start: EXTERNAL,
            pool_end: EXTERNAL,
            dns: vec![resolver],
            reservations: std::collections::HashMap::new(),
            lease_time: Duration::from_secs(3600),
        })
        .unwrap();
        let from_server = |reply: server::Reply| {
            let (mac, to) = match reply.to {
                server::Destination::Unicast { ip, mac } => (mac, ip),
                _ => (BROADCAST, Ipv4Addr::BROADCAST),
            };
            let from = SocketAddrV4::new(UPSTREAM, SERVER_PORT);

            ipv4(
                (UPSTREAM_MAC, UPSTREAM),
                (mac, to),
                Protocol::UDP,
                &udp(from, SocketAddrV4::new(to, CLIENT_PORT), &reply.packet),
            )
        };

        // The first pass asks for a lease, and until one is
        // granted nothing else leaves by the WAN.
        let discover = sent(gateway.idle(0), WAN);
        gateway.introduce(LAN_0, HOST_0_MAC, HOST_0);
        let remote = SocketAddrV4::new(REMOTE, 53);
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        dropped(gateway.receive(0, LAN_0, packet.clone()));

        assert_eq!(
            addresses(&discover),
            (
                MACS[WAN],
                BROADCAST,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST
            )
        );
        let (from_port, to_port, message) = udp_of(&discover);
        assert_eq!((from_port, to_port), (CLIENT_PORT, SERVER_PORT));
        let offer = upstream.handle(&message, gateway.now).unwrap().unwrap();
        let request = sent(gateway.receive(0, WAN, from_server(offer)), WAN);
        let (_, _, message) = udp_of(&request);
        let ack = upstream.handle(&message, gateway.now).unwrap().unwrap();
        dropped(gateway.receive(0, WAN, from_server(ack)));

        // Now the gateway answers for the address and routes
        // through the router the lease named.
        gateway.introduce(WAN, UPSTREAM_MAC, UPSTREAM);
        let translated = sent(gateway.receive(0, LAN_0, packet), WAN);
        assert_eq!(
            addresses(&translated),
            (MACS[WAN], UPSTREAM_MAC, EXTERNAL, REMOTE)
        );

        // And LAN clients are handed the lease's resolvers.
        let mut client = client::Client::with_seed(client::Config::new(HOST_1_MAC), 1);
        let discover = client.poll(gateway.now).transmit.unwrap();
        let from = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT);
        let to = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);
        let frame = ipv4(
            (HOST_1_MAC, *from.ip()),
            (BROADCAST, *to.ip()),
            Protocol::UDP,
            &udp(from, to, &discover.packet),
        );
        let offer = sent(gateway.receive(0, LAN_1, frame), LAN_1);
        let request = client
            .handle(&udp_of(&offer).2, gateway.now)
            .unwrap()
            .transmit
            .unwrap();
        let frame = ipv4(
            (HOST_1_MAC, *from.ip()),
            (BROADCAST, *to.ip()),
            Protocol::UDP,
            &udp(from, to, &request.packet),
        );
        let ack = sent(gateway.receive(0, LAN_1, frame), LAN_1);
        client.handle(&udp_of(&ack).2, gateway.now).unwrap();
        assert_eq!(client.lease().unwrap().dns, [resolver]);
    }

    #[test]
    fn an_attached_acl_filters_what_arrives() {
        let mut gateway = Gateway::new(1);
        gateway.introduce_all();
        let ping = || {
            ipv4(
                (HOST_0_MAC, HOST_0),
                (MACS[LAN_0], GATEWAY_0),
                Protocol::ICMP,
                &echo(Kind::ECHO_REQUEST, 7),
            )
        };
        let remote = SocketAddrV4::new(REMOTE, 53);
        sent(gateway.receive(0, LAN_0, ping()), LAN_0);

        // Only UDP may come in from the LAN.
        gateway.panel.set_acl(Acl::new("lan-in")).unwrap();
        gateway
            .panel
            .set_acl_entry(
                "lan-in",
                AclEntry {
                    seq: 10,
                    action: acl::Action::Permit,
                    protocol: acl::Protocol::Udp {
                        source: acl::PortMatch::Any,
                        destination: acl::PortMatch::Any,
                    },
                    source: acl::AddrMatch::Any,
                    destination: acl::AddrMatch::Any,
                    log: false,
                },
            )
            .unwrap();
        gateway
            .panel
            .attach_acl(MacAddr(MACS[LAN_0]), Direction::Inbound, "lan-in")
            .unwrap();
        dropped(gateway.receive(0, LAN_0, ping()));
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        sent(gateway.receive(0, LAN_0, packet), WAN);

        // And nothing may leave by the WAN.
        gateway.panel.set_acl(Acl::new("none")).unwrap();
        gateway
            .panel
            .attach_acl(MacAddr(MACS[WAN]), Direction::Outbound, "none")
            .unwrap();
        let packet = udp_from((HOST_0_MAC, HOST_0), MACS[LAN_0], 4000, remote);
        dropped(gateway.receive(0, LAN_0, packet));

        gateway
            .panel
            .detach_acl(MacAddr(MACS[LAN_0]), Direction::Inbound)
            .unwrap();
        sent(gateway.receive(0, LAN_0, ping()), LAN_0);
    }

    #[test]
    fn a_stopped_control_panel_ends_the_pass() {
        let Gateway {
            panel, mut workers, ..
        } = Gateway::new(1);
        assert!(workers[0].begin());
        drop(panel);
        assert!(!workers[0].begin());
    }
}
