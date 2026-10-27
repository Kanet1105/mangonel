//! Source NAT for LAN traffic leaving through the WAN.
//!
//! Each worker translates with its own table and hands out
//! external ports from its own slice of the port range, so
//! no table is shared. A reply that lands on another
//! worker's queue goes to the worker that owns its
//! destination port, which [`Nat::owner`] names.

use std::{
    collections::HashMap,
    net::SocketAddrV4,
    time::{
        Duration,
        Instant,
    },
};

use crate::data::wire::{
    ICMP,
    TCP,
    UDP,
};

/// External ports below this are never handed out.
const FIRST_PORT: u16 = 1024;
/// RFC 5382's floor for an established TCP session.
const TCP_TIMEOUT: Duration = Duration::from_secs(7440);
/// RFC 4787's recommendation for UDP.
const UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// RFC 5508's floor for ICMP queries.
const ICMP_TIMEOUT: Duration = Duration::from_secs(60);

/// A connection as the LAN host opened it. ICMP echo uses
/// its identifier as both ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Flow {
    pub(crate) protocol: u8,
    pub(crate) inside: SocketAddrV4,
    pub(crate) remote: SocketAddrV4,
}

struct Session {
    flow: Flow,
    last_seen: Instant,
}

/// One worker's translations.
pub(crate) struct Nat {
    worker: usize,
    workers: usize,
    /// This worker's external ports, inclusive.
    first: u16,
    last: u16,
    /// Where the next allocation starts looking.
    next: u16,
    ports: HashMap<Flow, u16>,
    /// By protocol and external port.
    sessions: HashMap<(u8, u16), Session>,
}

impl Nat {
    pub(crate) fn new(worker: usize, workers: usize) -> Self {
        assert!(
            worker < workers && workers <= span(1),
            "Worker {worker} of {workers} cannot own a port range. This is a bug."
        );
        let span = span(workers);
        let first = usize::from(FIRST_PORT) + worker * span;
        // The last worker also takes the remainder.
        let last = if worker + 1 == workers {
            usize::from(u16::MAX)
        } else {
            first + span - 1
        };
        let port =
            |port: usize| u16::try_from(port).expect("Ranges end at u16::MAX. This is a bug.");

        Self {
            worker,
            workers,
            first: port(first),
            last: port(last),
            next: port(first),
            ports: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    pub(crate) fn worker(&self) -> usize {
        self.worker
    }

    /// The worker whose range holds external `port`; `None`
    /// below the range.
    pub(crate) fn owner(&self, port: u16) -> Option<usize> {
        let offset = usize::from(port.checked_sub(FIRST_PORT)?);

        Some((offset / span(self.workers)).min(self.workers - 1))
    }

    /// The external port for `flow`, allocated on its first
    /// packet; `None` once this worker's range is used up.
    pub(crate) fn outbound(&mut self, flow: Flow, now: Instant) -> Option<u16> {
        if let Some(&port) = self.ports.get(&flow) {
            self.sessions
                .get_mut(&(flow.protocol, port))
                .expect("Every mapped port has a session. This is a bug.")
                .last_seen = now;

            return Some(port);
        }

        let port = self.allocate(flow.protocol)?;
        self.ports.insert(flow, port);
        self.sessions.insert(
            (flow.protocol, port),
            Session {
                flow,
                last_seen: now,
            },
        );

        Some(port)
    }

    /// The LAN endpoint a packet from `remote` to external
    /// `port` belongs to; `None` unless a host here opened
    /// that session to `remote`.
    pub(crate) fn inbound(
        &mut self,
        protocol: u8,
        port: u16,
        remote: SocketAddrV4,
        now: Instant,
    ) -> Option<SocketAddrV4> {
        let session = self.sessions.get_mut(&(protocol, port))?;
        // An echo reply carries our identifier, not a port
        // of the remote's.
        let expected = session.flow.remote;
        if expected.ip() != remote.ip() || (protocol != ICMP && expected.port() != remote.port()) {
            return None;
        }
        session.last_seen = now;

        Some(session.flow.inside)
    }

    /// Forgets sessions idle past their protocol's timeout,
    /// freeing their ports.
    pub(crate) fn expire(&mut self, now: Instant) {
        let ports = &mut self.ports;
        self.sessions.retain(|_, session| {
            let live = now.duration_since(session.last_seen) < timeout(session.flow.protocol);
            if !live {
                ports.remove(&session.flow);
            }

            live
        });
    }

    /// The first port free for `protocol` from `next` on,
    /// wrapping within this worker's range.
    fn allocate(&mut self, protocol: u8) -> Option<u16> {
        let start = self.next;
        let mut port = start;
        loop {
            let next = if port == self.last {
                self.first
            } else {
                port + 1
            };
            if !self.sessions.contains_key(&(protocol, port)) {
                self.next = next;

                return Some(port);
            }
            port = next;
            if port == start {
                return None;
            }
        }
    }
}

/// Ports per worker, before the last one's remainder.
fn span(workers: usize) -> usize {
    (usize::from(u16::MAX - FIRST_PORT) + 1) / workers
}

fn timeout(protocol: u8) -> Duration {
    match protocol {
        TCP => TCP_TIMEOUT,
        UDP => UDP_TIMEOUT,
        _ => ICMP_TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn flow(protocol: u8, inside_port: u16) -> Flow {
        Flow {
            protocol,
            inside: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), inside_port),
            remote: SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443),
        }
    }

    #[test]
    fn ranges_partition_the_ports() {
        for workers in [1, 3, 7, 16] {
            let nats: Vec<Nat> = (0..workers)
                .map(|worker| Nat::new(worker, workers))
                .collect();
            assert_eq!(nats[0].first, FIRST_PORT);
            assert_eq!(nats[workers - 1].last, u16::MAX);
            for pair in nats.windows(2) {
                assert_eq!(pair[0].last + 1, pair[1].first);
            }
            for nat in &nats {
                for port in [nat.first, nat.last] {
                    assert_eq!(nat.owner(port), Some(nat.worker));
                }
            }
            assert_eq!(nats[0].owner(FIRST_PORT - 1), None);
        }
    }

    #[test]
    fn translates_both_ways() {
        let mut nat = Nat::new(1, 4);
        let now = Instant::now();
        let flow = flow(TCP, 51000);
        let port = nat.outbound(flow, now).unwrap();
        assert_eq!(nat.owner(port), Some(1));
        assert_eq!(nat.outbound(flow, now), Some(port));
        assert_eq!(nat.inbound(TCP, port, flow.remote, now), Some(flow.inside));

        // Only the remote the host contacted may answer.
        let stranger = SocketAddrV4::new(*flow.remote.ip(), 444);
        assert_eq!(nat.inbound(TCP, port, stranger, now), None);
        assert_eq!(nat.inbound(UDP, port, flow.remote, now), None);
    }

    #[test]
    fn echo_replies_match_on_address() {
        let mut nat = Nat::new(0, 1);
        let now = Instant::now();
        let flow = flow(ICMP, 0x1234);
        let id = nat.outbound(flow, now).unwrap();
        let reply_from = SocketAddrV4::new(*flow.remote.ip(), id);
        assert_eq!(nat.inbound(ICMP, id, reply_from, now), Some(flow.inside));
    }

    #[test]
    fn allocation_wraps_and_runs_out() {
        // Two ports per worker.
        let mut nat = Nat::new(0, span(1) / 2);
        let now = Instant::now();
        let first = nat.outbound(flow(UDP, 1), now).unwrap();
        let second = nat.outbound(flow(UDP, 2), now).unwrap();
        assert_eq!((first, second), (nat.first, nat.last));
        assert_eq!(nat.outbound(flow(UDP, 3), now), None);
        // Each protocol has its own ports.
        assert_eq!(nat.outbound(flow(TCP, 3), now), Some(nat.first));
    }

    #[test]
    fn idle_sessions_expire() {
        // Two ports per worker.
        let mut nat = Nat::new(0, span(1) / 2);
        let start = Instant::now();
        let udp = nat.outbound(flow(UDP, 1), start).unwrap();
        nat.outbound(flow(UDP, 2), start + UDP_TIMEOUT / 2).unwrap();
        let tcp = nat.outbound(flow(TCP, 1), start).unwrap();
        assert_eq!(nat.outbound(flow(UDP, 3), start), None);

        nat.expire(start + UDP_TIMEOUT);
        assert_eq!(nat.inbound(UDP, udp, flow(UDP, 1).remote, start), None);
        assert!(nat.inbound(TCP, tcp, flow(TCP, 1).remote, start).is_some());
        // The freed port goes to the next flow.
        assert_eq!(nat.outbound(flow(UDP, 3), start), Some(udp));
    }
}
