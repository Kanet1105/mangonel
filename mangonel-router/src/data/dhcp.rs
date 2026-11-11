//! The DHCP state machines the ports run: a server on a LAN
//! port, a client on a WAN port.
//!
//! A message reaches whichever worker owns the queue it
//! hashed to, so the state is shared, one lock per port.
//! Only DHCP messages and the once-a-second timers take it.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Mutex,
        MutexGuard,
        PoisonError,
        atomic::{
            AtomicU64,
            Ordering,
        },
    },
    time::{
        Duration,
        Instant,
    },
};

use mangonel_dhcp::v4::{
    client::{
        self,
        Client,
        Event,
        Output,
        Transmit,
    },
    server::{
        self,
        Reply,
        Server,
    },
};

use crate::control::{
    Cidr,
    LanIp,
};

/// How long an address handed to a LAN client stays its.
const LEASE_TIME: Duration = Duration::from_secs(3600);

/// What a WAN port's lease gives the forwarding path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lease {
    /// The port's address and its subnet.
    pub(crate) cidr: Cidr<Ipv4Addr>,
    /// The default router, if the server named one.
    pub(crate) gateway: Option<Ipv4Addr>,
    /// The resolvers the server named.
    pub(crate) dns: Vec<Ipv4Addr>,
}

impl From<&client::Lease> for Lease {
    fn from(lease: &client::Lease) -> Self {
        Self {
            cidr: Cidr::new(lease.address, lease.prefix),
            gateway: lease.router,
            dns: lease.dns.clone(),
        }
    }
}

/// What one port runs.
#[derive(Default)]
struct Slot {
    server: Option<Server>,
    client: Option<Client>,
    lease: Option<Lease>,
}

/// Every port's DHCP state.
pub(crate) struct Dhcp {
    /// Moves whenever a lease is gained, changed or lost.
    generation: AtomicU64,
    /// In the data plane's port order.
    ports: Vec<Mutex<Slot>>,
}

impl Dhcp {
    /// Nothing running on any of `ports` ports.
    pub(crate) fn new(ports: usize) -> Self {
        Self {
            generation: AtomicU64::new(0),
            ports: (0..ports).map(|_| Mutex::default()).collect(),
        }
    }

    /// A number that differs from an earlier one if any
    /// port's lease changed in between.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Makes `port` serve `lan`'s pool with `dns` as its
    /// resolvers, or serve nothing for `None`. A server
    /// already serving that pool keeps its leases.
    pub(crate) fn serve(&self, port: usize, lan: Option<(&LanIp<Ipv4Addr>, &[Ipv4Addr])>) {
        let config = lan.map(|(lan, dns)| server::Config {
            address: lan.cidr.address,
            prefix: lan.cidr.prefix,
            pool_start: lan.pool_start,
            pool_end: lan.pool_end,
            dns: dns.to_vec(),
            reservations: HashMap::new(),
            lease_time: LEASE_TIME,
        });
        let mut slot = self.lock(port);
        if let (Some(server), Some(config)) = (slot.server.as_mut(), &config) {
            // New resolvers, as when the WAN lease names
            // them, are no reason to forget who holds which
            // address.
            let same_pool = server::Config {
                dns: config.dns.clone(),
                ..server.config().clone()
            } == *config;
            if same_pool {
                if server.config().dns != config.dns {
                    server.set_dns(config.dns.clone());
                }

                return;
            }
        } else if slot.server.is_none() && config.is_none() {
            return;
        }
        // The control panel checked the pool already, so a
        // refusal here would be the two disagreeing.
        slot.server = config.and_then(|config| match Server::new(config) {
            Ok(server) => Some(server),
            Err(error) => {
                eprintln!("mangonel-router: port {port} cannot serve DHCP: {error}");

                None
            }
        });
    }

    /// Makes `port` lease its address as `mac`, or lease
    /// nothing for `None`. A client already running as
    /// `mac` keeps its lease.
    pub(crate) fn lease_as(&self, port: usize, mac: Option<[u8; 6]>) {
        let mut slot = self.lock(port);
        match (mac, slot.client.is_some()) {
            (Some(mac), false) => slot.client = Some(Client::new(client::Config::new(mac))),
            (None, true) => {
                slot.client = None;
                if slot.lease.take().is_some() {
                    self.advance();
                }
            }
            _ => {}
        }
    }

    /// What `port` currently holds from its lease.
    pub(crate) fn lease(&self, port: usize) -> Option<Lease> {
        self.lock(port).lease.clone()
    }

    /// Hands a client's message to `port`'s server; the
    /// reply, if the protocol calls for one.
    pub(crate) fn request(&self, port: usize, message: &[u8], now: Instant) -> Option<Reply> {
        // A message that does not decode is dropped like any
        // other the server has no answer to.
        self.lock(port)
            .server
            .as_mut()?
            .handle(message, now)
            .ok()
            .flatten()
    }

    /// Hands a server's message to `port`'s client; what
    /// the client sends next, if anything.
    pub(crate) fn reply(&self, port: usize, message: &[u8], now: Instant) -> Option<Transmit> {
        let mut slot = self.lock(port);
        let output = slot.client.as_mut()?.handle(message, now).ok()?;

        self.absorb(&mut slot, output)
    }

    /// Runs `port`'s client timers; what it sends, if
    /// anything is due.
    pub(crate) fn poll(&self, port: usize, now: Instant) -> Option<Transmit> {
        let mut slot = self.lock(port);
        let output = slot.client.as_mut()?.poll(now);

        self.absorb(&mut slot, output)
    }

    /// Frees every server's lapsed leases.
    pub(crate) fn expire(&self, now: Instant) {
        for port in 0..self.ports.len() {
            if let Some(server) = self.lock(port).server.as_mut() {
                server.expire(now);
            }
        }
    }

    /// Records what a client step changed and passes on
    /// what it sends.
    fn absorb(&self, slot: &mut Slot, output: Output) -> Option<Transmit> {
        let lease = match &output.event {
            Some(Event::Bound(lease)) => Some(Lease::from(lease)),
            Some(Event::Lost) => None,
            None => return output.transmit,
        };
        // A renewal on the same terms changes nothing the
        // forwarding path reads.
        if slot.lease != lease {
            slot.lease = lease;
            self.advance();
        }

        output.transmit
    }

    /// Called with a port's lock held, so a reader that
    /// sees the new generation finds the new lease.
    fn advance(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn lock(&self, port: usize) -> MutexGuard<'_, Slot> {
        // A slot is consistent between statements, so one
        // left by a panicking worker is still usable.
        self.ports[port]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];

    fn lan() -> LanIp<Ipv4Addr> {
        LanIp {
            cidr: Cidr::new(Ipv4Addr::new(10, 0, 0, 1), 24),
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end: Ipv4Addr::new(10, 0, 0, 199),
            dhcp: true,
        }
    }

    #[test]
    fn a_client_leases_from_a_server_through_the_ports() {
        // Port 0 leases, port 1 serves.
        let dhcp = Dhcp::new(2);
        let dns = [Ipv4Addr::new(9, 9, 9, 9)];
        dhcp.serve(1, Some((&lan(), &dns)));
        dhcp.lease_as(0, Some(MAC));
        let generation = dhcp.generation();
        let now = Instant::now();

        let discover = dhcp.poll(0, now).unwrap();
        let offer = dhcp.request(1, &discover.packet, now).unwrap();
        let request = dhcp.reply(0, &offer.packet, now).unwrap();
        assert_eq!(dhcp.lease(0), None);
        let ack = dhcp.request(1, &request.packet, now).unwrap();
        assert!(dhcp.reply(0, &ack.packet, now).is_none());

        assert_ne!(dhcp.generation(), generation);
        assert_eq!(
            dhcp.lease(0),
            Some(Lease {
                cidr: Cidr::new(Ipv4Addr::new(10, 0, 0, 100), 24),
                gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
                dns: dns.to_vec(),
            })
        );
    }

    #[test]
    fn serving_the_same_again_keeps_the_leases() {
        let dhcp = Dhcp::new(1);
        dhcp.serve(0, Some((&lan(), &[])));
        let now = Instant::now();
        let mut client = Client::with_seed(client::Config::new(MAC), 1);
        let discover = client.poll(now).transmit.unwrap();
        let offer = dhcp.request(0, &discover.packet, now).unwrap();
        let request = client.handle(&offer.packet, now).unwrap().transmit.unwrap();
        dhcp.request(0, &request.packet, now).unwrap();
        let leases = |dhcp: &Dhcp| {
            dhcp.lock(0)
                .server
                .as_ref()
                .map(|server| server.leases().count())
        };
        assert_eq!(leases(&dhcp), Some(1));

        dhcp.serve(0, Some((&lan(), &[])));
        assert_eq!(leases(&dhcp), Some(1));

        // New resolvers are advertised from then on, to the
        // same clients.
        let resolver = Ipv4Addr::new(9, 9, 9, 9);
        dhcp.serve(0, Some((&lan(), &[resolver])));
        assert_eq!(leases(&dhcp), Some(1));
        let config = |dhcp: &Dhcp| {
            dhcp.lock(0)
                .server
                .as_ref()
                .map(|server| server.config().clone())
        };
        assert_eq!(config(&dhcp).unwrap().dns, [resolver]);

        // Another pool starts a new server.
        let mut moved = lan();
        moved.pool_end = Ipv4Addr::new(10, 0, 0, 150);
        dhcp.serve(0, Some((&moved, &[resolver])));
        assert_eq!(leases(&dhcp), Some(0));
        dhcp.serve(0, None);
        assert_eq!(leases(&dhcp), None);
    }

    #[test]
    fn stopping_a_client_drops_its_lease() {
        let dhcp = Dhcp::new(2);
        dhcp.serve(1, Some((&lan(), &[])));
        dhcp.lease_as(0, Some(MAC));
        let now = Instant::now();
        let discover = dhcp.poll(0, now).unwrap();
        let offer = dhcp.request(1, &discover.packet, now).unwrap();
        let request = dhcp.reply(0, &offer.packet, now).unwrap();
        let ack = dhcp.request(1, &request.packet, now).unwrap();
        dhcp.reply(0, &ack.packet, now);
        assert!(dhcp.lease(0).is_some());
        let generation = dhcp.generation();

        dhcp.lease_as(0, None);
        assert_eq!(dhcp.lease(0), None);
        assert_ne!(dhcp.generation(), generation);
        assert!(dhcp.poll(0, now).is_none());
    }

    #[test]
    fn a_port_running_nothing_answers_nothing() {
        let dhcp = Dhcp::new(1);
        let now = Instant::now();
        assert!(dhcp.request(0, &[0; 300], now).is_none());
        assert!(dhcp.reply(0, &[0; 300], now).is_none());
        assert!(dhcp.poll(0, now).is_none());
    }
}
