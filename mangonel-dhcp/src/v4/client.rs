//! A DHCPv4 client for one interface.

use std::{
    net::Ipv4Addr,
    time::{
        Duration,
        Instant,
    },
};

use dhcproto::{
    Decodable,
    Encodable,
    v4::{
        DhcpOption,
        Message,
        MessageType,
        Opcode,
        OptionCode,
    },
};

use crate::{
    Error,
    rng::Rng,
    v4,
};

/// First retransmission delay, doubled up to `MAX_BACKOFF`.
const FIRST_BACKOFF: Duration = Duration::from_secs(4);
const MAX_BACKOFF: Duration = Duration::from_secs(64);
/// Retransmission jitter, either way.
const JITTER: Duration = Duration::from_secs(1);
/// Requests sent for one offer before starting over.
const MAX_REQUESTS: u32 = 4;
/// Shortest wait between retransmissions while renewing or
/// rebinding.
const MIN_RENEW_WAIT: Duration = Duration::from_secs(60);
/// Pause before starting over after a NAK.
const NAK_PAUSE: Duration = Duration::from_secs(10);

/// Who the client says it is.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v4::client::Config;
///
/// let mut config = Config::new([2, 0, 0, 1, 0, 1]);
/// config.hostname = Some("gateway".to_owned());
/// assert!(config.client_id.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The interface's hardware address.
    pub mac: [u8; 6],
    /// The client identifier to send; `None` derives one
    /// from the MAC.
    pub client_id: Option<Vec<u8>>,
    /// The host name to send, if any.
    pub hostname: Option<String>,
}

impl Config {
    /// A configuration that identifies itself by `mac` alone.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v4::client::Config;
    ///
    /// let config = Config::new([2, 0, 0, 1, 0, 1]);
    /// assert_eq!(config.mac, [2, 0, 0, 1, 0, 1]);
    /// ```
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            client_id: None,
            hostname: None,
        }
    }

    fn client_id(&self) -> Vec<u8> {
        self.client_id
            .clone()
            .unwrap_or_else(|| v4::default_client_id(self.mac))
    }
}

/// What a server granted and when it has to be refreshed.
///
/// # Examples
/// ```
/// use std::{net::Ipv4Addr, time::{Duration, Instant}};
///
/// use mangonel_dhcp::v4::{client, server};
///
/// let mut server = server::Server::new(server::Config {
///     address: Ipv4Addr::new(10, 0, 0, 1),
///     prefix: 24,
///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
///     dns: vec![],
///     lease_time: Duration::from_secs(3600),
/// })?;
/// let mut client = client::Client::with_seed(client::Config::new([2, 0, 0, 4, 0, 0]), 1);
/// let now = Instant::now();
/// let discover = client.poll(now).transmit.unwrap();
/// let offer = server.handle(&discover.packet, now)?.unwrap();
/// let request = client.handle(&offer.packet, now)?.transmit.unwrap();
/// let ack = server.handle(&request.packet, now)?.unwrap();
/// client.handle(&ack.packet, now)?;
/// let lease = client.lease().unwrap();
/// assert_eq!(lease.address, Ipv4Addr::new(10, 0, 0, 10));
/// assert_eq!(lease.renew_at, now + Duration::from_secs(1800));
/// # Ok::<(), mangonel_dhcp::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The address granted.
    pub address: Ipv4Addr,
    /// The subnet's prefix length.
    pub prefix: u8,
    /// The default router, if the server named one.
    pub router: Option<Ipv4Addr>,
    /// The resolvers the server named.
    pub dns: Vec<Ipv4Addr>,
    /// The server that granted the lease.
    pub server: Ipv4Addr,
    /// T1: when the client starts asking that server to renew.
    pub renew_at: Instant,
    /// T2: when the client starts asking any server to renew.
    pub rebind_at: Instant,
    /// When the address stops being the client's.
    pub expires: Instant,
}

/// What changed for the caller.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v4::client::Event;
///
/// fn describe(event: &Event) -> &'static str {
///     match event {
///         Event::Bound(_) => "configure the interface",
///         Event::Lost => "clear the interface",
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A lease was granted or renewed.
    Bound(Lease),
    /// The lease lapsed or was refused; the client starts over.
    Lost,
}

/// A message to send from the client port.
///
/// # Examples
/// ```
/// use std::{net::Ipv4Addr, time::Instant};
///
/// use mangonel_dhcp::v4::client::{Client, Config};
///
/// let mut client = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 1);
/// let discover = client.poll(Instant::now()).transmit.unwrap();
/// assert_eq!(discover.source, Ipv4Addr::UNSPECIFIED);
/// assert_eq!(discover.destination, Ipv4Addr::BROADCAST);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// The encoded message, a UDP payload.
    pub packet: Vec<u8>,
    /// The source address to use, unspecified before a lease.
    pub source: Ipv4Addr,
    /// The server, or the limited broadcast address.
    pub destination: Ipv4Addr,
}

/// What one step of the client produced.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v4::client::Output;
///
/// let idle = Output::default();
/// assert!(idle.transmit.is_none() && idle.event.is_none());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// A message to send, if any.
    pub transmit: Option<Transmit>,
    /// A change to act on, if any.
    pub event: Option<Event>,
}

impl Output {
    fn send(transmit: Transmit) -> Self {
        Self {
            transmit: Some(transmit),
            event: None,
        }
    }
}

#[derive(Debug, Clone)]
enum State {
    Init,
    Selecting {
        started: Instant,
    },
    Requesting {
        started: Instant,
        attempts: u32,
        address: Ipv4Addr,
        server: Ipv4Addr,
    },
    Bound(Lease),
    Renewing(Lease),
    Rebinding(Lease),
    Stopped,
}

/// The RFC 2131 client state machine, driven by the caller's
/// clock and packets.
///
/// # Examples
/// ```
/// use std::time::Instant;
///
/// use mangonel_dhcp::v4::client::{Client, Config};
///
/// let mut client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
/// let now = Instant::now();
/// let out = client.poll(now);
/// assert!(out.transmit.is_some());
/// assert!(client.next_wake().unwrap() > now);
/// ```
#[derive(Debug)]
pub struct Client {
    config: Config,
    state: State,
    xid: u32,
    /// When `poll` next has something to do.
    wake: Option<Instant>,
    backoff: Duration,
    rng: Rng,
}

impl Client {
    /// A client in INIT, seeded from entropy.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
    /// assert!(client.lease().is_none());
    /// ```
    pub fn new(config: Config) -> Self {
        Self::with_rng(config, Rng::from_entropy())
    }

    /// A client in INIT whose ids and jitter `seed` fixes.
    ///
    /// # Examples
    /// ```
    /// use std::time::Instant;
    ///
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let now = Instant::now();
    /// let mut a = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 7);
    /// let mut b = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 7);
    /// assert_eq!(a.poll(now), b.poll(now));
    /// ```
    pub fn with_seed(config: Config, seed: u64) -> Self {
        Self::with_rng(config, Rng::seeded(seed))
    }

    fn with_rng(config: Config, rng: Rng) -> Self {
        Self {
            config,
            state: State::Init,
            xid: 0,
            wake: None,
            backoff: FIRST_BACKOFF,
            rng,
        }
    }

    /// The lease held, while one is.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
    /// assert!(client.lease().is_none());
    /// ```
    pub fn lease(&self) -> Option<&Lease> {
        match &self.state {
            State::Bound(lease) | State::Renewing(lease) | State::Rebinding(lease) => Some(lease),
            _ => None,
        }
    }

    /// When [`Self::poll`] next has work; `None` once released.
    ///
    /// # Examples
    /// ```
    /// use std::time::Instant;
    ///
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let mut client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
    /// assert!(client.next_wake().is_none());
    /// client.poll(Instant::now());
    /// assert!(client.next_wake().is_some());
    /// ```
    pub fn next_wake(&self) -> Option<Instant> {
        self.wake
    }

    /// Runs the timers: starts, retransmits, renews, rebinds
    /// or gives up, as `now` requires.
    ///
    /// # Examples
    /// ```
    /// use std::time::{Duration, Instant};
    ///
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let mut client = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 1);
    /// let now = Instant::now();
    /// assert!(client.poll(now).transmit.is_some());
    /// assert!(client.poll(now).transmit.is_none());
    /// assert!(client.poll(now + Duration::from_secs(6)).transmit.is_some());
    /// ```
    pub fn poll(&mut self, now: Instant) -> Output {
        if self.wake.is_some_and(|wake| now < wake) {
            return Output::default();
        }

        match self.state.clone() {
            State::Init => self.start(now),
            State::Selecting { started } => {
                self.back_off(now);

                Output::send(self.discover(started, now))
            }
            State::Requesting {
                started,
                attempts,
                address,
                server,
            } => {
                if attempts >= MAX_REQUESTS {
                    return self.start(now);
                }
                self.state = State::Requesting {
                    started,
                    attempts: attempts + 1,
                    address,
                    server,
                };
                self.back_off(now);

                Output::send(self.request(started, now, address, server))
            }
            State::Bound(lease) | State::Renewing(lease) | State::Rebinding(lease) => {
                self.refresh(lease, now)
            }
            State::Stopped => Output::default(),
        }
    }

    /// Handles one message from a server; anything not for
    /// this client is ignored, not an error.
    ///
    /// # Examples
    /// ```
    /// use std::{net::Ipv4Addr, time::{Duration, Instant}};
    ///
    /// use mangonel_dhcp::v4::{client, server};
    ///
    /// let mut server = server::Server::new(server::Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// })?;
    /// let mut client = client::Client::with_seed(client::Config::new([2, 0, 0, 4, 0, 0]), 1);
    /// let now = Instant::now();
    /// let discover = client.poll(now).transmit.unwrap();
    /// let offer = server.handle(&discover.packet, now)?.unwrap();
    /// let request = client.handle(&offer.packet, now)?.transmit.unwrap();
    /// let ack = server.handle(&request.packet, now)?.unwrap();
    /// let bound = client.handle(&ack.packet, now)?.event.unwrap();
    /// assert!(matches!(bound, client::Event::Bound(_)));
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn handle(&mut self, packet: &[u8], now: Instant) -> Result<Output, Error> {
        let msg = Message::from_bytes(packet)?;
        if msg.opcode() != Opcode::BootReply
            || msg.xid() != self.xid
            || v4::mac_of(&msg) != Some(self.config.mac)
        {
            return Ok(Output::default());
        }
        let Some(kind) = msg.opts().msg_type() else {
            return Ok(Output::default());
        };

        let out = match (self.state.clone(), kind) {
            (State::Selecting { started }, MessageType::Offer) => {
                let address = msg.yiaddr();
                let Some(server) = v4::server_id_of(&msg) else {
                    return Ok(Output::default());
                };
                if address.is_unspecified() {
                    return Ok(Output::default());
                }
                self.state = State::Requesting {
                    started,
                    attempts: 1,
                    address,
                    server,
                };
                self.backoff = FIRST_BACKOFF;
                self.wake = Some(now + self.rng.around(FIRST_BACKOFF, JITTER));

                Output::send(self.request(started, now, address, server))
            }
            (State::Requesting { server, .. }, MessageType::Ack) => {
                if v4::server_id_of(&msg) != Some(server) {
                    return Ok(Output::default());
                }

                self.bind(&msg, now)
            }
            (State::Renewing(_) | State::Rebinding(_), MessageType::Ack) => self.bind(&msg, now),
            (State::Requesting { .. }, MessageType::Nak) => {
                self.restart_after_nak(now);

                Output::default()
            }
            (State::Renewing(_) | State::Rebinding(_), MessageType::Nak) => {
                self.restart_after_nak(now);

                Output {
                    transmit: None,
                    event: Some(Event::Lost),
                }
            }
            _ => Output::default(),
        };

        Ok(out)
    }

    /// Gives the lease back and stops; the message to send,
    /// if a lease was held.
    ///
    /// # Examples
    /// ```
    /// use std::time::Instant;
    ///
    /// use mangonel_dhcp::v4::client::{Client, Config};
    ///
    /// let mut client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
    /// assert!(client.release(Instant::now()).is_none());
    /// assert!(client.next_wake().is_none());
    /// ```
    pub fn release(&mut self, now: Instant) -> Option<Transmit> {
        let lease = self.lease().cloned();
        self.state = State::Stopped;
        self.wake = None;
        let lease = lease?;
        self.xid = self.rng.next_u32();
        let mut msg = self.base(now, now, lease.address);
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Release));
        opts.insert(DhcpOption::ServerIdentifier(lease.server));

        Some(Transmit {
            packet: encode(&msg),
            source: lease.address,
            destination: lease.server,
        })
    }

    /// Renews, rebinds or gives up on `lease`, whichever `now`
    /// calls for, even when polled late.
    fn refresh(&mut self, lease: Lease, now: Instant) -> Output {
        if now >= lease.expires {
            let mut out = self.start(now);
            out.event = Some(Event::Lost);

            return out;
        }
        if now >= lease.rebind_at {
            if !matches!(self.state, State::Rebinding(_)) {
                self.state = State::Rebinding(lease.clone());
            }
            self.wake = Some(now + half_way(now, lease.expires));

            return Output::send(self.renew(&lease, now, true));
        }
        if now >= lease.renew_at {
            if matches!(self.state, State::Bound(_)) {
                self.xid = self.rng.next_u32();
                self.state = State::Renewing(lease.clone());
            }
            self.wake = Some(now + half_way(now, lease.rebind_at));

            return Output::send(self.renew(&lease, now, false));
        }
        self.wake = Some(lease.renew_at);

        Output::default()
    }

    /// Leaves INIT: a fresh transaction and the first DISCOVER.
    fn start(&mut self, now: Instant) -> Output {
        self.xid = self.rng.next_u32();
        self.state = State::Selecting { started: now };
        self.backoff = FIRST_BACKOFF;
        self.wake = Some(now + self.rng.around(FIRST_BACKOFF, JITTER));

        Output::send(self.discover(now, now))
    }

    fn back_off(&mut self, now: Instant) {
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
        self.wake = Some(now + self.rng.around(self.backoff, JITTER));
    }

    fn restart_after_nak(&mut self, now: Instant) {
        self.state = State::Init;
        self.wake = Some(now + self.rng.around(NAK_PAUSE, JITTER));
    }

    fn bind(&mut self, msg: &Message, now: Instant) -> Output {
        let Some(lease) = lease_of(msg, now) else {
            return Output::default();
        };
        self.state = State::Bound(lease.clone());
        self.wake = Some(lease.renew_at);

        Output {
            transmit: None,
            event: Some(Event::Bound(lease)),
        }
    }

    /// The fields every client message shares.
    fn base(&self, started: Instant, now: Instant, ciaddr: Ipv4Addr) -> Message {
        let mut msg = Message::new_with_id(
            self.xid,
            ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &self.config.mac,
        );
        let secs = now.saturating_duration_since(started).as_secs();
        msg.set_secs(u16::try_from(secs).unwrap_or(u16::MAX));
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::ClientIdentifier(self.config.client_id()));
        if let Some(hostname) = &self.config.hostname {
            opts.insert(DhcpOption::Hostname(hostname.clone()));
        }

        msg
    }

    fn discover(&self, started: Instant, now: Instant) -> Transmit {
        let mut msg = self.base(started, now, Ipv4Addr::UNSPECIFIED);
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Discover));
        opts.insert(DhcpOption::ParameterRequestList(wanted()));

        broadcast(&msg, Ipv4Addr::UNSPECIFIED)
    }

    /// The REQUEST that accepts an offer.
    fn request(
        &self,
        started: Instant,
        now: Instant,
        address: Ipv4Addr,
        server: Ipv4Addr,
    ) -> Transmit {
        let mut msg = self.base(started, now, Ipv4Addr::UNSPECIFIED);
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Request));
        opts.insert(DhcpOption::RequestedIpAddress(address));
        opts.insert(DhcpOption::ServerIdentifier(server));
        opts.insert(DhcpOption::ParameterRequestList(wanted()));

        broadcast(&msg, Ipv4Addr::UNSPECIFIED)
    }

    /// The REQUEST that extends a lease: to the server while
    /// renewing, to everyone while rebinding.
    fn renew(&self, lease: &Lease, now: Instant, rebinding: bool) -> Transmit {
        let mut msg = self.base(now, now, lease.address);
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Request));
        opts.insert(DhcpOption::ParameterRequestList(wanted()));
        if rebinding {
            broadcast(&msg, lease.address)
        } else {
            Transmit {
                packet: encode(&msg),
                source: lease.address,
                destination: lease.server,
            }
        }
    }
}

/// The options every request asks for.
fn wanted() -> Vec<OptionCode> {
    vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::AddressLeaseTime,
        OptionCode::Renewal,
        OptionCode::Rebinding,
    ]
}

fn encode(msg: &Message) -> Vec<u8> {
    msg.to_vec()
        .expect("a message the client built encodes. This is a bug.")
}

fn broadcast(msg: &Message, source: Ipv4Addr) -> Transmit {
    Transmit {
        packet: encode(msg),
        source,
        destination: Ipv4Addr::BROADCAST,
    }
}

/// Half the time left until `until`, but at least a minute.
fn half_way(now: Instant, until: Instant) -> Duration {
    (until.saturating_duration_since(now) / 2).max(MIN_RENEW_WAIT)
}

/// The lease an ACK describes, or `None` if it lacks the
/// address, mask, lease time or server.
fn lease_of(msg: &Message, now: Instant) -> Option<Lease> {
    let address = msg.yiaddr();
    if address.is_unspecified() {
        return None;
    }
    let server = v4::server_id_of(msg)?;
    let opts = msg.opts();
    let prefix = match opts.get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(mask)) => v4::prefix_of(*mask)?,
        _ => return None,
    };
    let lease = match opts.get(OptionCode::AddressLeaseTime) {
        Some(DhcpOption::AddressLeaseTime(secs)) if *secs > 0 => *secs,
        _ => return None,
    };
    let t1 = match opts.get(OptionCode::Renewal) {
        Some(DhcpOption::Renewal(secs)) if *secs > 0 => (*secs).min(lease),
        _ => lease / 2,
    };
    let t2 = match opts.get(OptionCode::Rebinding) {
        Some(DhcpOption::Rebinding(secs)) if *secs > 0 => (*secs).clamp(t1, lease),
        _ => (lease - lease / 8).max(t1),
    };
    let router = match opts.get(OptionCode::Router) {
        Some(DhcpOption::Router(routers)) => routers.first().copied(),
        _ => None,
    };
    let dns = match opts.get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(servers)) => servers.clone(),
        _ => Vec::new(),
    };
    let after = |secs: u32| now + Duration::from_secs(u64::from(secs));

    Some(Lease {
        address,
        prefix,
        router,
        dns,
        server,
        renew_at: after(t1),
        rebind_at: after(t2),
        expires: after(lease),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::server;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];

    fn server() -> server::Server {
        server::Server::new(server::Config {
            address: GATEWAY,
            prefix: 24,
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 12),
            dns: vec![GATEWAY],
            lease_time: Duration::from_secs(600),
        })
        .unwrap()
    }

    fn client() -> Client {
        Client::with_seed(Config::new(MAC), 42)
    }

    fn decode(t: &Transmit) -> Message {
        Message::from_bytes(&t.packet).unwrap()
    }

    /// Runs the four-way handshake and returns the lease.
    fn acquire(client: &mut Client, server: &mut server::Server, now: Instant) -> Lease {
        let discover = client.poll(now).transmit.unwrap();
        let offer = server.handle(&discover.packet, now).unwrap().unwrap();
        let request = client.handle(&offer.packet, now).unwrap().transmit.unwrap();
        let ack = server.handle(&request.packet, now).unwrap().unwrap();
        match client.handle(&ack.packet, now).unwrap().event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    #[test]
    fn acquires_a_lease() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let discover = client.poll(now).transmit.unwrap();
        let msg = decode(&discover);
        assert_eq!(msg.opts().msg_type(), Some(MessageType::Discover));
        assert_eq!(
            msg.opts().get(OptionCode::ClientIdentifier),
            Some(&DhcpOption::ClientIdentifier(vec![1, 2, 0, 0, 4, 0, 0]))
        );
        let offer = server.handle(&discover.packet, now).unwrap().unwrap();
        let request = client.handle(&offer.packet, now).unwrap().transmit.unwrap();
        let msg = decode(&request);
        assert_eq!(msg.opts().msg_type(), Some(MessageType::Request));
        assert_eq!(v4::server_id_of(&msg), Some(GATEWAY));
        assert_eq!(request.destination, Ipv4Addr::BROADCAST);
        let ack = server.handle(&request.packet, now).unwrap().unwrap();
        let lease = match client.handle(&ack.packet, now).unwrap().event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("{other:?}"),
        };
        assert_eq!(lease.address, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(lease.prefix, 24);
        assert_eq!(lease.router, Some(GATEWAY));
        assert_eq!(lease.dns, vec![GATEWAY]);
        assert_eq!(lease.renew_at, now + Duration::from_secs(300));
        assert_eq!(lease.rebind_at, now + Duration::from_secs(525));
        assert_eq!(lease.expires, now + Duration::from_secs(600));
        assert_eq!(client.lease(), Some(&lease));
        assert_eq!(client.next_wake(), Some(lease.renew_at));
    }

    #[test]
    fn retransmits_with_backoff() {
        let mut client = client();
        let now = Instant::now();
        assert!(client.poll(now).transmit.is_some());
        let first = client.next_wake().unwrap();
        assert!(first >= now + Duration::from_secs(3) && first <= now + Duration::from_secs(5));
        assert!(client.poll(now + Duration::from_secs(2)).transmit.is_none());
        let again = client.poll(first).transmit.unwrap();
        assert!((3..=5).contains(&decode(&again).secs()));
        let second = client.next_wake().unwrap();
        let gap = second - first;
        assert!(gap >= Duration::from_secs(7) && gap <= Duration::from_secs(9));
    }

    #[test]
    fn renews_then_rebinds_then_loses() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let lease = acquire(&mut client, &mut server, now);

        // T1: a unicast REQUEST to the server, answered.
        let renew = client.poll(lease.renew_at).transmit.unwrap();
        assert_eq!(renew.destination, GATEWAY);
        assert_eq!(renew.source, lease.address);
        assert_eq!(decode(&renew).ciaddr(), lease.address);
        let ack = server
            .handle(&renew.packet, lease.renew_at)
            .unwrap()
            .unwrap();
        let out = client.handle(&ack.packet, lease.renew_at).unwrap();
        let renewed = match out.event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("{other:?}"),
        };
        assert_eq!(renewed.expires, lease.renew_at + Duration::from_secs(600));

        // Ignore the server: T2 switches to broadcast, expiry starts over.
        let rebind = client.poll(renewed.rebind_at).transmit.unwrap();
        assert_eq!(rebind.destination, Ipv4Addr::BROADCAST);
        assert_eq!(rebind.source, lease.address);
        let out = client.poll(renewed.expires);
        assert_eq!(out.event, Some(Event::Lost));
        let discover = out.transmit.unwrap();
        assert_eq!(
            decode(&discover).opts().msg_type(),
            Some(MessageType::Discover)
        );
        assert!(client.lease().is_none());
    }

    #[test]
    fn nak_restarts() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        acquire(&mut client, &mut server, now);
        let mut other = server::Server::new(server::Config {
            address: Ipv4Addr::new(10, 0, 1, 1),
            prefix: 24,
            pool_start: Ipv4Addr::new(10, 0, 1, 10),
            pool_end: Ipv4Addr::new(10, 0, 1, 12),
            dns: vec![],
            lease_time: Duration::from_secs(600),
        })
        .unwrap();
        let rebind_at = client.lease().unwrap().rebind_at;
        client.poll(client.lease().unwrap().renew_at);
        let rebind = client.poll(rebind_at).transmit.unwrap();
        let nak = other.handle(&rebind.packet, rebind_at).unwrap().unwrap();
        let out = client.handle(&nak.packet, rebind_at).unwrap();
        assert_eq!(out.event, Some(Event::Lost));
        assert!(client.lease().is_none());
        let restart = client.next_wake().unwrap();
        assert!(restart > rebind_at + Duration::from_secs(8));
        assert!(client.poll(restart).transmit.is_some());
    }

    #[test]
    fn gives_up_on_an_offer_after_four_requests() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let discover = client.poll(now).transmit.unwrap();
        let offer = server.handle(&discover.packet, now).unwrap().unwrap();
        client.handle(&offer.packet, now).unwrap();
        for _ in 0..3 {
            let at = client.next_wake().unwrap();
            let kind = decode(&client.poll(at).transmit.unwrap()).opts().msg_type();
            assert_eq!(kind, Some(MessageType::Request));
        }
        let at = client.next_wake().unwrap();
        let kind = decode(&client.poll(at).transmit.unwrap()).opts().msg_type();
        assert_eq!(kind, Some(MessageType::Discover));
    }

    #[test]
    fn ignores_strangers() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        client.poll(now);
        let mut other = Client::with_seed(Config::new([2, 0, 0, 4, 0, 1]), 9);
        let discover = other.poll(now).transmit.unwrap();
        let offer = server.handle(&discover.packet, now).unwrap().unwrap();
        assert_eq!(
            client.handle(&offer.packet, now).unwrap(),
            Output::default()
        );
        assert!(matches!(client.handle(&[0; 4], now), Err(Error::Decode(_))));
    }

    #[test]
    fn release_tells_the_server() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let lease = acquire(&mut client, &mut server, now);
        let release = client.release(now).unwrap();
        assert_eq!(release.destination, GATEWAY);
        assert_eq!(
            decode(&release).opts().msg_type(),
            Some(MessageType::Release)
        );
        assert!(server.handle(&release.packet, now).unwrap().is_none());
        assert_eq!(server.leases().count(), 0);
        assert!(client.lease().is_none());
        assert_eq!(client.poll(lease.expires), Output::default());
    }
}
