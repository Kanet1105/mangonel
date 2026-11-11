//! Source NAT for LAN traffic leaving through the WAN.
//!
//! One table serves every worker. The two directions of a
//! flow arrive on different queues, because each port
//! hashes on its own and translation changes what is
//! hashed, so no worker could keep the table to itself. It
//! is split into shards, each behind its own lock. A flow's
//! external port is drawn from the ports that carry its
//! shard's index, so the packet going out and the reply
//! coming back take the same single lock.

use std::{
    collections::HashMap,
    hash::{
        BuildHasher,
        RandomState,
    },
    net::SocketAddrV4,
    sync::{
        Mutex,
        MutexGuard,
        PoisonError,
    },
    time::{
        Duration,
        Instant,
    },
};

use mangonel_wire::network::ipv4::Protocol;

/// Shards the table is split into. It divides both the
/// port range and a byte's range evenly.
const SHARDS: u16 = 64;
/// External ports below this are never handed out.
const FIRST_PORT: u16 = 1024;
/// External ports each shard hands out, per protocol.
const SLOTS: u16 = (u16::MAX - FIRST_PORT) / SHARDS + 1;
/// RFC 5382's floor for an established TCP session.
const TCP_TIMEOUT: Duration = Duration::from_secs(7440);
/// RFC 5382's floor for a TCP session that is still opening
/// or already closing, which is most of them at any time.
const TCP_TRANSITORY_TIMEOUT: Duration = Duration::from_secs(240);
/// RFC 4787's recommendation for UDP.
const UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// RFC 5508's floor for ICMP queries.
const ICMP_TIMEOUT: Duration = Duration::from_secs(60);

/// A connection as the LAN host opened it. An ICMP echo
/// carries its identifier as the inside port and no remote
/// port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Flow {
    pub(crate) protocol: Protocol,
    pub(crate) inside: SocketAddrV4,
    pub(crate) remote: SocketAddrV4,
}

/// What a packet does to the session it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Segment {
    /// A TCP SYN that is not an answer: the connection
    /// starts over.
    Opens,
    /// Anything else, TCP or not.
    Continues,
    /// A TCP FIN or RST: one end is done.
    Closes,
}

struct Session {
    flow: Flow,
    last_seen: Instant,
    /// Whether the remote has answered.
    answered: bool,
    /// Whether either end has said it is done.
    closing: bool,
}

impl Session {
    /// Counts `segment`, which arrived at `now`.
    fn touch(&mut self, segment: Segment, now: Instant) {
        self.last_seen = now;
        match segment {
            Segment::Opens => (self.answered, self.closing) = (false, false),
            Segment::Continues => {}
            Segment::Closes => self.closing = true,
        }
    }

    /// How long the session may sit idle.
    fn timeout(&self) -> Duration {
        match self.flow.protocol {
            Protocol::TCP if self.answered && !self.closing => TCP_TIMEOUT,
            Protocol::TCP => TCP_TRANSITORY_TIMEOUT,
            Protocol::UDP => UDP_TIMEOUT,
            _ => ICMP_TIMEOUT,
        }
    }
}

/// The flows whose external ports carry one shard index.
#[derive(Default)]
struct Shard {
    /// Which of the shard's ports the next allocation tries
    /// first.
    next: u16,
    ports: HashMap<Flow, u16>,
    /// By protocol and external port.
    sessions: HashMap<(Protocol, u16), Session>,
}

impl Shard {
    /// The first of shard `index`'s ports free for
    /// `protocol`, from `next` on and wrapping.
    fn allocate(&mut self, index: u16, protocol: Protocol) -> Option<u16> {
        for _ in 0..SLOTS {
            let port = port(index, self.next);
            self.next = (self.next + 1) % SLOTS;
            if !self.sessions.contains_key(&(protocol, port)) {
                return Some(port);
            }
        }

        None
    }
}

/// Every worker's translations.
pub(crate) struct Nat {
    hasher: RandomState,
    shards: Vec<Mutex<Shard>>,
}

impl Nat {
    pub(crate) fn new() -> Self {
        Self {
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    /// The external port for `flow`, allocated on its first
    /// packet, of which `segment` is the latest; `None` once
    /// its shard's ports are used up.
    pub(crate) fn outbound(&self, flow: Flow, segment: Segment, now: Instant) -> Option<u16> {
        let index = self.shard_of(&flow);
        let mut shard = self.lock(index);
        if let Some(&port) = shard.ports.get(&flow) {
            shard
                .sessions
                .get_mut(&(flow.protocol, port))
                .expect("Every mapped port has a session. This is a bug.")
                .touch(segment, now);

            return Some(port);
        }

        let port = shard.allocate(index, flow.protocol)?;
        shard.ports.insert(flow, port);
        shard.sessions.insert(
            (flow.protocol, port),
            Session {
                flow,
                last_seen: now,
                answered: false,
                closing: segment == Segment::Closes,
            },
        );

        Some(port)
    }

    /// The LAN endpoint the packet `segment` from `remote`
    /// to external `port` belongs to; `None` unless a host
    /// here opened that session to `remote`.
    pub(crate) fn inbound(
        &self,
        protocol: Protocol,
        port: u16,
        remote: SocketAddrV4,
        segment: Segment,
        now: Instant,
    ) -> Option<SocketAddrV4> {
        let mut shard = self.lock(port.checked_sub(FIRST_PORT)? % SHARDS);
        let session = shard.sessions.get_mut(&(protocol, port))?;
        if session.flow.remote != remote {
            return None;
        }
        // The remote opens nothing: its SYN can only answer.
        let segment = match segment {
            Segment::Opens => Segment::Continues,
            segment => segment,
        };
        session.touch(segment, now);
        session.answered = true;

        Some(session.flow.inside)
    }

    /// Forgets sessions idle past their protocol's timeout,
    /// freeing their ports.
    pub(crate) fn expire(&self, now: Instant) {
        for index in 0..SHARDS {
            let mut shard = self.lock(index);
            let Shard {
                ports, sessions, ..
            } = &mut *shard;
            sessions.retain(|_, session| {
                let live = now.saturating_duration_since(session.last_seen) < session.timeout();
                if !live {
                    ports.remove(&session.flow);
                }

                live
            });
        }
    }

    /// Forgets every session, as when the external address
    /// they were translated to is gone.
    pub(crate) fn clear(&self) {
        for index in 0..SHARDS {
            let mut shard = self.lock(index);
            shard.ports.clear();
            shard.sessions.clear();
        }
    }

    /// The shard `flow`'s session lives in.
    fn shard_of(&self, flow: &Flow) -> u16 {
        // One byte of the hash spreads evenly over the
        // shards.
        u16::from(self.hasher.hash_one(flow).to_le_bytes()[0]) % SHARDS
    }

    fn lock(&self, index: u16) -> MutexGuard<'_, Shard> {
        // A shard is consistent between statements, so one
        // left by a panicking worker is still usable.
        self.shards[usize::from(index)]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Shard `index`'s `slot`th port. The ports of a shard are
/// those that leave its index when divided by the shard
/// count, which is what lets a reply find its shard.
fn port(index: u16, slot: u16) -> u16 {
    let port = u32::from(FIRST_PORT) + u32::from(slot) * u32::from(SHARDS) + u32::from(index);

    u16::try_from(port).expect("A shard's ports end at u16::MAX. This is a bug.")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn flow(protocol: Protocol, inside_port: u16) -> Flow {
        flow_from(protocol, 10, inside_port)
    }

    fn flow_from(protocol: Protocol, host: u8, inside_port: u16) -> Flow {
        Flow {
            protocol,
            inside: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, host), inside_port),
            remote: SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
        }
    }

    /// Flows that all land in one shard: several times what
    /// the shard has ports for, whichever way they hash.
    fn flows_sharing_a_shard(nat: &Nat, protocol: Protocol) -> impl Iterator<Item = Flow> + '_ {
        let shard = nat.shard_of(&flow(protocol, 0));

        (10..18)
            .flat_map(move |host| (0..=u16::MAX).map(move |port| flow_from(protocol, host, port)))
            .filter(move |flow| nat.shard_of(flow) == shard)
    }

    #[test]
    fn shards_partition_the_ports() {
        assert_eq!(port(0, 0), FIRST_PORT);
        assert_eq!(port(SHARDS - 1, SLOTS - 1), u16::MAX);
        let mut seen = std::collections::HashSet::new();
        for index in 0..SHARDS {
            for slot in 0..SLOTS {
                let port = port(index, slot);
                assert_eq!((port - FIRST_PORT) % SHARDS, index);
                assert!(seen.insert(port));
            }
        }
        assert_eq!(seen.len(), usize::from(u16::MAX - FIRST_PORT) + 1);
    }

    #[test]
    fn translates_both_ways() {
        let nat = Nat::new();
        let now = Instant::now();
        let flow = flow(Protocol::TCP, 51000);
        let port = nat.outbound(flow, Segment::Continues, now).unwrap();
        assert!(port >= FIRST_PORT);
        assert_eq!(nat.outbound(flow, Segment::Continues, now), Some(port));
        assert_eq!(
            nat.inbound(Protocol::TCP, port, flow.remote, Segment::Continues, now),
            Some(flow.inside)
        );

        // Only the remote the host contacted may answer.
        let stranger = SocketAddrV4::new(*flow.remote.ip(), 444);
        assert_eq!(
            nat.inbound(Protocol::TCP, port, stranger, Segment::Continues, now),
            None
        );
        assert_eq!(
            nat.inbound(Protocol::UDP, port, flow.remote, Segment::Continues, now),
            None
        );
        assert_eq!(
            nat.inbound(Protocol::TCP, 80, flow.remote, Segment::Continues, now),
            None
        );
    }

    #[test]
    fn each_flow_gets_its_own_port() {
        let nat = Nat::new();
        let now = Instant::now();
        let mut ports = std::collections::HashSet::new();
        for inside_port in 1..=2000 {
            let flow = flow(Protocol::UDP, inside_port);
            let port = nat.outbound(flow, Segment::Continues, now).unwrap();
            assert!(ports.insert(port), "port {port} was handed out twice");
            assert_eq!(
                nat.inbound(Protocol::UDP, port, flow.remote, Segment::Continues, now),
                Some(flow.inside)
            );
        }
    }

    #[test]
    fn a_shard_runs_out_per_protocol() {
        let nat = Nat::new();
        let now = Instant::now();
        let mut flows = flows_sharing_a_shard(&nat, Protocol::UDP);
        for flow in flows.by_ref().take(usize::from(SLOTS)) {
            assert!(nat.outbound(flow, Segment::Continues, now).is_some());
        }
        let one_more = flows.next().unwrap();
        assert_eq!(nat.outbound(one_more, Segment::Continues, now), None);

        // Each protocol has its own ports.
        let tcp = Flow {
            protocol: Protocol::TCP,
            ..one_more
        };
        if nat.shard_of(&tcp) == nat.shard_of(&one_more) {
            assert!(nat.outbound(tcp, Segment::Continues, now).is_some());
        }
    }

    #[test]
    fn idle_sessions_expire_and_free_their_ports() {
        let nat = Nat::new();
        let start = Instant::now();
        let mut flows = flows_sharing_a_shard(&nat, Protocol::UDP);
        let old: Vec<Flow> = flows.by_ref().take(usize::from(SLOTS) - 1).collect();
        let fresh = flows.next().unwrap();
        let waiting = flows.next().unwrap();
        for flow in &old {
            nat.outbound(*flow, Segment::Continues, start).unwrap();
        }
        let kept = nat
            .outbound(fresh, Segment::Continues, start + UDP_TIMEOUT / 2)
            .unwrap();
        // An answered connection outlives them all.
        let tcp = flow(Protocol::TCP, 1);
        let tcp_port = nat.outbound(tcp, Segment::Opens, start).unwrap();
        nat.inbound(
            Protocol::TCP,
            tcp_port,
            tcp.remote,
            Segment::Continues,
            start,
        )
        .unwrap();
        assert_eq!(nat.outbound(waiting, Segment::Continues, start), None);

        nat.expire(start + UDP_TIMEOUT);
        let first = nat.outbound(old[0], Segment::Continues, start);
        assert!(first.is_some(), "an expired session frees its port");
        assert_eq!(
            nat.inbound(Protocol::UDP, kept, fresh.remote, Segment::Continues, start),
            Some(fresh.inside)
        );
        assert!(
            nat.inbound(
                Protocol::TCP,
                tcp_port,
                tcp.remote,
                Segment::Continues,
                start
            )
            .is_some()
        );
    }

    #[test]
    fn a_tcp_session_is_held_long_only_while_it_is_established() {
        let nat = Nat::new();
        let start = Instant::now();
        let answer = |flow: &Flow, port: u16, segment: Segment, now: Instant| {
            nat.inbound(Protocol::TCP, port, flow.remote, segment, now)
        };
        let soon = start + TCP_TRANSITORY_TIMEOUT;

        // A SYN nobody answered.
        let unanswered = flow(Protocol::TCP, 1);
        let unanswered_port = nat.outbound(unanswered, Segment::Opens, start).unwrap();
        // An established connection.
        let open = flow(Protocol::TCP, 2);
        let open_port = nat.outbound(open, Segment::Opens, start).unwrap();
        answer(&open, open_port, Segment::Opens, start).unwrap();
        // One the remote has closed.
        let closed = flow(Protocol::TCP, 3);
        let closed_port = nat.outbound(closed, Segment::Opens, start).unwrap();
        answer(&closed, closed_port, Segment::Continues, start).unwrap();
        answer(&closed, closed_port, Segment::Closes, start).unwrap();
        // One closed and then opened again from the same port.
        let reopened = flow(Protocol::TCP, 4);
        let reopened_port = nat.outbound(reopened, Segment::Opens, start).unwrap();
        answer(&reopened, reopened_port, Segment::Continues, start).unwrap();
        nat.outbound(reopened, Segment::Closes, start).unwrap();
        assert_eq!(
            nat.outbound(reopened, Segment::Opens, start),
            Some(reopened_port)
        );
        answer(&reopened, reopened_port, Segment::Continues, start).unwrap();

        nat.expire(soon);
        assert!(answer(&unanswered, unanswered_port, Segment::Continues, soon).is_none());
        assert!(answer(&closed, closed_port, Segment::Continues, soon).is_none());
        // Looked up at the start, so neither is kept alive by
        // the looking.
        assert!(answer(&open, open_port, Segment::Continues, start).is_some());
        assert!(answer(&reopened, reopened_port, Segment::Continues, start).is_some());

        nat.expire(start + TCP_TIMEOUT);
        assert!(answer(&open, open_port, Segment::Continues, start).is_none());
    }

    #[test]
    fn clear_forgets_everything() {
        let nat = Nat::new();
        let now = Instant::now();
        let flow = flow(Protocol::TCP, 51000);
        let port = nat.outbound(flow, Segment::Continues, now).unwrap();
        nat.clear();
        assert_eq!(
            nat.inbound(Protocol::TCP, port, flow.remote, Segment::Continues, now),
            None
        );
    }
}
