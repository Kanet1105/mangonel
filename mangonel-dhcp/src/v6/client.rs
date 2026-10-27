//! A DHCPv6 client for one interface, asking for one
//! non-temporary address.

use std::{
    net::Ipv6Addr,
    time::{
        Duration,
        Instant,
    },
};

use dhcproto::{
    Decodable,
    Encodable,
    v6::{
        DhcpOption,
        DhcpOptions,
        IAAddr,
        IANA,
        Message,
        MessageType,
        ORO,
        OptionCode,
        Status,
    },
};

use crate::{
    Error,
    rng::Rng,
    v6::{
        self,
        ALL_SERVERS,
    },
};

/// RFC 8415 section 7.6: the retransmission parameters.
const SOL_IRT: Duration = Duration::from_secs(1);
const SOL_MRT: Duration = Duration::from_secs(3600);
const REQ_IRT: Duration = Duration::from_secs(1);
const REQ_MRT: Duration = Duration::from_secs(30);
const REQ_MRC: u32 = 10;
const REN_IRT: Duration = Duration::from_secs(10);
const REN_MRT: Duration = Duration::from_secs(600);

/// Who the client says it is.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v6::client::Config;
///
/// let mut config = Config::new([2, 0, 0, 1, 0, 1]);
/// config.rapid_commit = true;
/// assert!(config.client_id.is_none() && config.iaid.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The interface's hardware address.
    pub mac: [u8; 6],
    /// The DUID to send; `None` derives a DUID-LL from the MAC.
    pub client_id: Option<Vec<u8>>,
    /// The IA_NA's identifier; `None` derives one from the MAC.
    pub iaid: Option<u32>,
    /// Whether to ask for a lease in one round trip.
    pub rapid_commit: bool,
}

impl Config {
    /// A configuration that identifies itself by `mac` alone.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v6::client::Config;
    ///
    /// let config = Config::new([2, 0, 0, 1, 0, 1]);
    /// assert!(!config.rapid_commit);
    /// ```
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            client_id: None,
            iaid: None,
            rapid_commit: false,
        }
    }

    fn client_id(&self) -> Vec<u8> {
        self.client_id
            .clone()
            .unwrap_or_else(|| v6::duid_ll(self.mac))
    }

    fn iaid(&self) -> u32 {
        self.iaid.unwrap_or_else(|| {
            u32::from_be_bytes([self.mac[2], self.mac[3], self.mac[4], self.mac[5]])
        })
    }
}

/// What a server granted and when it has to be refreshed.
///
/// # Examples
/// ```
/// use std::time::{Duration, Instant};
///
/// use mangonel_dhcp::v6::{client, server};
///
/// let mut server = server::Server::new(server::Config {
///     mac: [2, 0, 0, 1, 0, 2],
///     prefix: "2001:db8:1::".parse()?,
///     prefix_len: 64,
///     pool_start: "2001:db8:1::100".parse()?,
///     pool_end: "2001:db8:1::1ff".parse()?,
///     dns: vec![],
///     preferred_lifetime: Duration::from_secs(1800),
///     valid_lifetime: Duration::from_secs(3600),
///     rapid_commit: false,
/// })?;
/// let mut client = client::Client::with_seed(client::Config::new([2, 0, 0, 4, 0, 0]), 1);
/// let (now, from, mac) = (Instant::now(), "fe80::1".parse()?, [2, 0, 0, 4, 0, 0]);
/// let solicit = client.poll(now).transmit.unwrap();
/// let advertise = server.handle(&solicit.packet, from, mac, now)?.unwrap();
/// let request = client.handle(&advertise.packet, now)?.transmit.unwrap();
/// let reply = server.handle(&request.packet, from, mac, now)?.unwrap();
/// client.handle(&reply.packet, now)?;
/// let lease = client.lease().unwrap();
/// assert_eq!(lease.address, "2001:db8:1::100".parse::<std::net::Ipv6Addr>()?);
/// assert_eq!(lease.renew_at, now + Duration::from_secs(900));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The address granted.
    pub address: Ipv6Addr,
    /// When the address stops being preferred for new connections.
    pub preferred_until: Instant,
    /// When the address stops being the client's.
    pub expires: Instant,
    /// T1: when the client starts asking that server to renew.
    pub renew_at: Instant,
    /// T2: when the client starts asking any server to renew.
    pub rebind_at: Instant,
    /// The DUID of the server that granted the lease.
    pub server_id: Vec<u8>,
    /// The resolvers the server named.
    pub dns: Vec<Ipv6Addr>,
}

/// What changed for the caller.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v6::client::Event;
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

/// A message to send from the client port and the
/// interface's link-local address.
///
/// # Examples
/// ```
/// use std::time::Instant;
///
/// use mangonel_dhcp::v6::{ALL_SERVERS, client::{Client, Config}};
///
/// let mut client = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 1);
/// let solicit = client.poll(Instant::now()).transmit.unwrap();
/// assert_eq!(solicit.destination, ALL_SERVERS);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// The encoded message, a UDP payload.
    pub packet: Vec<u8>,
    /// The multicast group every message goes to.
    pub destination: Ipv6Addr,
}

/// What one step of the client produced.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v6::client::Output;
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
    Soliciting {
        started: Instant,
    },
    Requesting {
        started: Instant,
        attempts: u32,
        server_id: Vec<u8>,
        address: Ipv6Addr,
    },
    Bound(Lease),
    Renewing {
        lease: Lease,
        started: Instant,
    },
    Rebinding {
        lease: Lease,
        started: Instant,
    },
    Stopped,
}

/// The RFC 8415 client state machine, driven by the caller's
/// clock and packets.
///
/// # Examples
/// ```
/// use std::time::Instant;
///
/// use mangonel_dhcp::v6::client::{Client, Config};
///
/// let mut client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
/// let now = Instant::now();
/// assert!(client.poll(now).transmit.is_some());
/// assert!(client.next_wake().unwrap() > now);
/// ```
#[derive(Debug)]
pub struct Client {
    config: Config,
    state: State,
    xid: [u8; 3],
    /// When `poll` next has something to do.
    wake: Option<Instant>,
    /// The current retransmission timeout.
    rt: Duration,
    rng: Rng,
}

impl Client {
    /// A client in INIT, seeded from entropy.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v6::client::{Client, Config};
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
    /// use mangonel_dhcp::v6::client::{Client, Config};
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
            xid: [0; 3],
            wake: None,
            rt: SOL_IRT,
            rng,
        }
    }

    /// The lease held, while one is.
    ///
    /// # Examples
    /// ```
    /// use mangonel_dhcp::v6::client::{Client, Config};
    ///
    /// let client = Client::new(Config::new([2, 0, 0, 1, 0, 1]));
    /// assert!(client.lease().is_none());
    /// ```
    pub fn lease(&self) -> Option<&Lease> {
        match &self.state {
            State::Bound(lease)
            | State::Renewing { lease, .. }
            | State::Rebinding { lease, .. } => Some(lease),
            _ => None,
        }
    }

    /// When [`Self::poll`] next has work; `None` once released.
    ///
    /// # Examples
    /// ```
    /// use std::time::Instant;
    ///
    /// use mangonel_dhcp::v6::client::{Client, Config};
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
    /// use mangonel_dhcp::v6::client::{Client, Config};
    ///
    /// let mut client = Client::with_seed(Config::new([2, 0, 0, 1, 0, 1]), 1);
    /// let now = Instant::now();
    /// assert!(client.poll(now).transmit.is_some());
    /// assert!(client.poll(now).transmit.is_none());
    /// assert!(client.poll(now + Duration::from_secs(2)).transmit.is_some());
    /// ```
    pub fn poll(&mut self, now: Instant) -> Output {
        if self.wake.is_some_and(|wake| now < wake) {
            return Output::default();
        }

        match self.state.clone() {
            State::Init => self.start(now),
            State::Soliciting { started } => {
                self.rt = self.next_rt(SOL_MRT);
                self.wake = Some(now + self.rt);

                Output::send(self.solicit(started, now))
            }
            State::Requesting {
                started,
                attempts,
                server_id,
                address,
            } => {
                if attempts >= REQ_MRC {
                    return self.start(now);
                }
                self.state = State::Requesting {
                    started,
                    attempts: attempts + 1,
                    server_id: server_id.clone(),
                    address,
                };
                self.rt = self.next_rt(REQ_MRT);
                self.wake = Some(now + self.rt);

                Output::send(self.request(started, now, &server_id, address))
            }
            State::Bound(lease)
            | State::Renewing { lease, .. }
            | State::Rebinding { lease, .. } => self.refresh(lease, now),
            State::Stopped => Output::default(),
        }
    }

    /// Handles one message from a server; anything not for
    /// this client is ignored, not an error.
    ///
    /// # Examples
    /// ```
    /// use std::time::{Duration, Instant};
    ///
    /// use mangonel_dhcp::v6::{client, server};
    ///
    /// let mut server = server::Server::new(server::Config {
    ///     mac: [2, 0, 0, 1, 0, 2],
    ///     prefix: "2001:db8:1::".parse()?,
    ///     prefix_len: 64,
    ///     pool_start: "2001:db8:1::100".parse()?,
    ///     pool_end: "2001:db8:1::1ff".parse()?,
    ///     dns: vec![],
    ///     preferred_lifetime: Duration::from_secs(1800),
    ///     valid_lifetime: Duration::from_secs(3600),
    ///     rapid_commit: false,
    /// })?;
    /// let mut client = client::Client::with_seed(client::Config::new([2, 0, 0, 4, 0, 0]), 1);
    /// let (now, from, mac) = (Instant::now(), "fe80::1".parse()?, [2, 0, 0, 4, 0, 0]);
    /// let solicit = client.poll(now).transmit.unwrap();
    /// let advertise = server.handle(&solicit.packet, from, mac, now)?.unwrap();
    /// let request = client.handle(&advertise.packet, now)?.transmit.unwrap();
    /// let reply = server.handle(&request.packet, from, mac, now)?.unwrap();
    /// let bound = client.handle(&reply.packet, now)?.event.unwrap();
    /// assert!(matches!(bound, client::Event::Bound(_)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn handle(&mut self, packet: &[u8], now: Instant) -> Result<Output, Error> {
        let msg = Message::from_bytes(packet)?;
        if msg.xid() != self.xid
            || v6::client_id_of(&msg) != Some(self.config.client_id().as_slice())
        {
            return Ok(Output::default());
        }
        let Some(server_id) = v6::server_id_of(&msg).map(<[u8]>::to_vec) else {
            return Ok(Output::default());
        };
        let rapid = self.config.rapid_commit && msg.opts().get(OptionCode::RapidCommit).is_some();

        let out = match (self.state.clone(), msg.msg_type()) {
            (State::Soliciting { started }, MessageType::Advertise) => {
                let Some(address) = self.offered(&msg) else {
                    return Ok(Output::default());
                };
                self.state = State::Requesting {
                    started,
                    attempts: 1,
                    server_id: server_id.clone(),
                    address,
                };
                self.rt = self.first_rt(REQ_IRT, false);
                self.wake = Some(now + self.rt);

                Output::send(self.request(started, now, &server_id, address))
            }
            (State::Soliciting { .. }, MessageType::Reply) if rapid => self.bind(&msg, now, false),
            (
                State::Requesting {
                    server_id: expected,
                    ..
                },
                MessageType::Reply,
            ) => {
                if server_id != expected {
                    return Ok(Output::default());
                }

                self.bind(&msg, now, false)
            }
            (State::Renewing { .. } | State::Rebinding { .. }, MessageType::Reply) => {
                self.bind(&msg, now, true)
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
    /// use mangonel_dhcp::v6::client::{Client, Config};
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
        self.new_xid();
        let mut msg = self.base(MessageType::Release, now, now);
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::ServerId(lease.server_id.clone()));
        opts.insert(self.ia_na(Some(lease.address)));

        Some(transmit(&msg))
    }

    /// Leaves INIT: a fresh transaction and the first Solicit.
    fn start(&mut self, now: Instant) -> Output {
        self.new_xid();
        self.state = State::Soliciting { started: now };
        self.rt = self.first_rt(SOL_IRT, true);
        self.wake = Some(now + self.rt);

        Output::send(self.solicit(now, now))
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
            let started = match self.state {
                State::Rebinding { started, .. } => {
                    self.rt = self.next_rt(REN_MRT);

                    started
                }
                _ => {
                    self.state = State::Rebinding {
                        lease: lease.clone(),
                        started: now,
                    };
                    self.rt = self.first_rt(REN_IRT, false);

                    now
                }
            };
            self.wake = Some((now + self.rt).min(lease.expires));

            return Output::send(self.rebind(&lease, started, now));
        }
        if now >= lease.renew_at {
            let started = match self.state {
                State::Renewing { started, .. } => {
                    self.rt = self.next_rt(REN_MRT);

                    started
                }
                _ => {
                    self.new_xid();
                    self.state = State::Renewing {
                        lease: lease.clone(),
                        started: now,
                    };
                    self.rt = self.first_rt(REN_IRT, false);

                    now
                }
            };
            self.wake = Some((now + self.rt).min(lease.rebind_at));

            return Output::send(self.renew(&lease, started, now));
        }
        self.wake = Some(lease.renew_at);

        Output::default()
    }

    /// Takes the lease a Reply grants, or starts over when
    /// it grants none; `held` says a lease was in hand.
    fn bind(&mut self, msg: &Message, now: Instant, held: bool) -> Output {
        match self.lease_of(msg, now) {
            Some(lease) => {
                self.state = State::Bound(lease.clone());
                self.wake = Some(lease.renew_at);

                Output {
                    transmit: None,
                    event: Some(Event::Bound(lease)),
                }
            }
            None => {
                let mut out = self.start(now);
                out.event = held.then_some(Event::Lost);

                out
            }
        }
    }

    fn new_xid(&mut self) {
        let bytes = self.rng.next_u32().to_be_bytes();
        self.xid = [bytes[1], bytes[2], bytes[3]];
    }

    /// RFC 8415 section 15: the first RT is IRT with a tenth
    /// of jitter, only upwards for a Solicit.
    fn first_rt(&mut self, irt: Duration, upwards: bool) -> Duration {
        if upwards {
            irt + self.rng.within(irt / 10)
        } else {
            self.rng.around(irt, irt / 10)
        }
    }

    /// RFC 8415 section 15: each RT doubles with a tenth of
    /// jitter, then sits at MRT with the same jitter.
    fn next_rt(&mut self, mrt: Duration) -> Duration {
        let doubled = self.rng.around(self.rt * 2, self.rt / 10);
        if doubled > mrt {
            self.rng.around(mrt, mrt / 10)
        } else {
            doubled
        }
    }

    /// The address an Advertise offers for this client's IA_NA.
    fn offered(&self, msg: &Message) -> Option<Ipv6Addr> {
        let ia = v6::ianas(msg).find(|ia| ia.id == self.config.iaid())?;
        if v6::status_of(ia) != Status::Success {
            return None;
        }

        v6::addresses(ia)
            .find(|addr| addr.valid_life > 0)
            .map(|addr| addr.addr)
    }

    /// The lease a Reply grants, or `None` if it grants
    /// nothing usable.
    fn lease_of(&self, msg: &Message, now: Instant) -> Option<Lease> {
        if msg.opts().get(OptionCode::StatusCode).is_some_and(
            |opt| !matches!(opt, DhcpOption::StatusCode(code) if code.status == Status::Success),
        ) {
            return None;
        }
        let ia = v6::ianas(msg).find(|ia| ia.id == self.config.iaid())?;
        if v6::status_of(ia) != Status::Success {
            return None;
        }
        let addr = v6::addresses(ia).find(|addr| addr.valid_life > 0)?;
        let valid = addr.valid_life;
        let preferred = addr.preferred_life.min(valid);
        // Zero means the client picks; RFC 8415 section 21.4 suggests these.
        let t1 = if ia.t1 == 0 { preferred / 2 } else { ia.t1 }.min(valid);
        let t2 = if ia.t2 == 0 { preferred / 5 * 4 } else { ia.t2 }.clamp(t1, valid);
        let after = |secs: u32| now + Duration::from_secs(u64::from(secs));

        Some(Lease {
            address: addr.addr,
            preferred_until: after(preferred),
            expires: after(valid),
            renew_at: after(t1),
            rebind_at: after(t2),
            server_id: v6::server_id_of(msg)?.to_vec(),
            dns: v6::dns_of(msg),
        })
    }

    /// The fields every client message shares.
    fn base(&self, kind: MessageType, started: Instant, now: Instant) -> Message {
        let mut msg = Message::new_with_id(kind, self.xid);
        let centis = now.saturating_duration_since(started).as_millis() / 10;
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::ClientId(self.config.client_id()));
        opts.insert(DhcpOption::ElapsedTime(
            u16::try_from(centis).unwrap_or(u16::MAX),
        ));
        opts.insert(DhcpOption::ORO(ORO {
            opts: vec![OptionCode::DomainNameServers],
        }));

        msg
    }

    /// This client's IA_NA, carrying `address` when it has one.
    fn ia_na(&self, address: Option<Ipv6Addr>) -> DhcpOption {
        let mut opts = DhcpOptions::new();
        if let Some(address) = address {
            opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: address,
                preferred_life: 0,
                valid_life: 0,
                opts: DhcpOptions::new(),
            }));
        }

        DhcpOption::IANA(IANA {
            id: self.config.iaid(),
            t1: 0,
            t2: 0,
            opts,
        })
    }

    fn solicit(&self, started: Instant, now: Instant) -> Transmit {
        let mut msg = self.base(MessageType::Solicit, started, now);
        msg.opts_mut().insert(self.ia_na(None));
        if self.config.rapid_commit {
            msg.opts_mut().insert(DhcpOption::RapidCommit);
        }

        transmit(&msg)
    }

    fn request(
        &self,
        started: Instant,
        now: Instant,
        server_id: &[u8],
        address: Ipv6Addr,
    ) -> Transmit {
        let mut msg = self.base(MessageType::Request, started, now);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(server_id.to_vec()));
        msg.opts_mut().insert(self.ia_na(Some(address)));

        transmit(&msg)
    }

    fn renew(&self, lease: &Lease, started: Instant, now: Instant) -> Transmit {
        let mut msg = self.base(MessageType::Renew, started, now);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(lease.server_id.clone()));
        msg.opts_mut().insert(self.ia_na(Some(lease.address)));

        transmit(&msg)
    }

    fn rebind(&self, lease: &Lease, started: Instant, now: Instant) -> Transmit {
        let mut msg = self.base(MessageType::Rebind, started, now);
        msg.opts_mut().insert(self.ia_na(Some(lease.address)));

        transmit(&msg)
    }
}

fn transmit(msg: &Message) -> Transmit {
    Transmit {
        packet: msg
            .to_vec()
            .expect("a message the client built encodes. This is a bug."),
        destination: ALL_SERVERS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v6::server;

    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn server() -> server::Server {
        server::Server::new(server::Config {
            mac: [2, 0, 0, 1, 0, 2],
            prefix: addr("2001:db8:1::"),
            prefix_len: 64,
            pool_start: addr("2001:db8:1::10"),
            pool_end: addr("2001:db8:1::12"),
            dns: vec![addr("2001:db8:1::1")],
            preferred_lifetime: Duration::from_secs(600),
            valid_lifetime: Duration::from_secs(900),
            rapid_commit: true,
        })
        .unwrap()
    }

    fn client() -> Client {
        Client::with_seed(Config::new(MAC), 42)
    }

    fn decode(t: &Transmit) -> Message {
        Message::from_bytes(&t.packet).unwrap()
    }

    fn elapsed(msg: &Message) -> u16 {
        match msg.opts().get(OptionCode::ElapsedTime) {
            Some(DhcpOption::ElapsedTime(centis)) => *centis,
            _ => panic!("no elapsed time"),
        }
    }

    /// Runs the four-message exchange and returns the lease.
    fn acquire(client: &mut Client, server: &mut server::Server, now: Instant) -> Lease {
        let from = addr("fe80::1");
        let solicit = client.poll(now).transmit.unwrap();
        let advertise = server
            .handle(&solicit.packet, from, MAC, now)
            .unwrap()
            .unwrap();
        let request = client
            .handle(&advertise.packet, now)
            .unwrap()
            .transmit
            .unwrap();
        let reply = server
            .handle(&request.packet, from, MAC, now)
            .unwrap()
            .unwrap();
        match client.handle(&reply.packet, now).unwrap().event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    #[test]
    fn acquires_a_lease() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let from = addr("fe80::1");
        let solicit = client.poll(now).transmit.unwrap();
        let msg = decode(&solicit);
        assert_eq!(msg.msg_type(), MessageType::Solicit);
        assert_eq!(v6::client_id_of(&msg), Some(v6::duid_ll(MAC).as_slice()));
        assert_eq!(elapsed(&msg), 0);
        assert_eq!(v6::ianas(&msg).next().unwrap().id, 0x0004_0000);
        assert_eq!(solicit.destination, ALL_SERVERS);

        let advertise = server
            .handle(&solicit.packet, from, MAC, now)
            .unwrap()
            .unwrap();
        let request = client
            .handle(&advertise.packet, now)
            .unwrap()
            .transmit
            .unwrap();
        let msg = decode(&request);
        assert_eq!(msg.msg_type(), MessageType::Request);
        assert_eq!(v6::server_id_of(&msg), Some(server.server_id()));
        let reply = server
            .handle(&request.packet, from, MAC, now)
            .unwrap()
            .unwrap();
        let lease = match client.handle(&reply.packet, now).unwrap().event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("{other:?}"),
        };
        assert_eq!(lease.address, addr("2001:db8:1::10"));
        assert_eq!(lease.server_id, server.server_id());
        assert_eq!(lease.dns, vec![addr("2001:db8:1::1")]);
        assert_eq!(lease.renew_at, now + Duration::from_secs(300));
        assert_eq!(lease.rebind_at, now + Duration::from_secs(480));
        assert_eq!(lease.preferred_until, now + Duration::from_secs(600));
        assert_eq!(lease.expires, now + Duration::from_secs(900));
        assert_eq!(client.lease(), Some(&lease));
        assert_eq!(client.next_wake(), Some(lease.renew_at));
    }

    #[test]
    fn rapid_commit_takes_one_round_trip() {
        let mut client = Client::with_seed(
            Config {
                rapid_commit: true,
                ..Config::new(MAC)
            },
            1,
        );
        let mut server = server();
        let now = Instant::now();
        let solicit = client.poll(now).transmit.unwrap();
        assert!(
            decode(&solicit)
                .opts()
                .get(OptionCode::RapidCommit)
                .is_some()
        );
        let reply = server
            .handle(&solicit.packet, addr("fe80::1"), MAC, now)
            .unwrap()
            .unwrap();
        let out = client.handle(&reply.packet, now).unwrap();
        assert!(matches!(out.event, Some(Event::Bound(_))));
        assert!(server.leases().next().unwrap().is_bound());
    }

    #[test]
    fn solicit_retransmits_per_rfc() {
        let mut client = client();
        let now = Instant::now();
        client.poll(now);
        let first = client.next_wake().unwrap() - now;
        assert!(first >= Duration::from_secs(1) && first <= Duration::from_millis(1100));
        let at = now + first;
        let again = client.poll(at).transmit.unwrap();
        assert_eq!(
            u64::from(elapsed(&decode(&again))),
            u64::try_from(first.as_millis() / 10).unwrap()
        );
        let second = client.next_wake().unwrap() - at;
        assert!(second >= Duration::from_millis(1800) && second <= Duration::from_millis(2200));
        // Long after, RT sits at MRT.
        let mut at = now + second;
        for _ in 0..20 {
            client.poll(at);
            at = client.next_wake().unwrap();
        }
        client.poll(at);
        let capped = client.next_wake().unwrap() - at;
        assert!(capped >= Duration::from_secs(3240) && capped <= Duration::from_secs(3960));
    }

    #[test]
    fn renews_then_rebinds_then_loses() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let from = addr("fe80::1");
        let lease = acquire(&mut client, &mut server, now);

        let renew = client.poll(lease.renew_at).transmit.unwrap();
        let msg = decode(&renew);
        assert_eq!(msg.msg_type(), MessageType::Renew);
        assert_eq!(v6::server_id_of(&msg), Some(server.server_id()));
        let reply = server
            .handle(&renew.packet, from, MAC, lease.renew_at)
            .unwrap()
            .unwrap();
        let renewed = match client.handle(&reply.packet, lease.renew_at).unwrap().event {
            Some(Event::Bound(lease)) => lease,
            other => panic!("{other:?}"),
        };
        assert_eq!(renewed.expires, lease.renew_at + Duration::from_secs(900));

        // Ignore the server: T2 switches to Rebind, expiry starts over.
        let rebind = client.poll(renewed.rebind_at).transmit.unwrap();
        let msg = decode(&rebind);
        assert_eq!(msg.msg_type(), MessageType::Rebind);
        assert!(v6::server_id_of(&msg).is_none());
        let out = client.poll(renewed.expires);
        assert_eq!(out.event, Some(Event::Lost));
        assert_eq!(
            decode(&out.transmit.unwrap()).msg_type(),
            MessageType::Solicit
        );
        assert!(client.lease().is_none());
    }

    #[test]
    fn no_binding_on_renew_starts_over() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let lease = acquire(&mut client, &mut server, now);
        let mut other = server::Server::new(server::Config {
            mac: [2, 0, 0, 1, 0, 2],
            ..server.config().clone()
        })
        .unwrap();
        let renew = client.poll(lease.renew_at).transmit.unwrap();
        let reply = other
            .handle(&renew.packet, addr("fe80::1"), MAC, lease.renew_at)
            .unwrap()
            .unwrap();
        let out = client.handle(&reply.packet, lease.renew_at).unwrap();
        assert_eq!(out.event, Some(Event::Lost));
        assert_eq!(
            decode(&out.transmit.unwrap()).msg_type(),
            MessageType::Solicit
        );
    }

    #[test]
    fn gives_up_on_a_server_after_ten_requests() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let solicit = client.poll(now).transmit.unwrap();
        let advertise = server
            .handle(&solicit.packet, addr("fe80::1"), MAC, now)
            .unwrap()
            .unwrap();
        client.handle(&advertise.packet, now).unwrap();
        for _ in 0..9 {
            let at = client.next_wake().unwrap();
            let kind = decode(&client.poll(at).transmit.unwrap()).msg_type();
            assert_eq!(kind, MessageType::Request);
        }
        let at = client.next_wake().unwrap();
        assert_eq!(
            decode(&client.poll(at).transmit.unwrap()).msg_type(),
            MessageType::Solicit
        );
    }

    #[test]
    fn ignores_strangers_and_exhaustion() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        client.poll(now);
        let mut other = Client::with_seed(Config::new([2, 0, 0, 4, 0, 1]), 9);
        let solicit = other.poll(now).transmit.unwrap();
        let advertise = server
            .handle(&solicit.packet, addr("fe80::2"), [2, 0, 0, 4, 0, 1], now)
            .unwrap()
            .unwrap();
        assert_eq!(
            client.handle(&advertise.packet, now).unwrap(),
            Output::default()
        );
        assert!(matches!(client.handle(&[0; 2], now), Err(Error::Decode(_))));

        // An Advertise with no address is not an offer.
        let mut full = server::Server::new(server::Config {
            pool_end: addr("2001:db8:1::10"),
            ..server.config().clone()
        })
        .unwrap();
        let taken = Client::with_seed(Config::new([2, 0, 0, 4, 0, 2]), 3)
            .poll(now)
            .transmit
            .unwrap();
        full.handle(&taken.packet, addr("fe80::3"), [2, 0, 0, 4, 0, 2], now)
            .unwrap();
        let mut client = Client::with_seed(Config::new(MAC), 42);
        let solicit = client.poll(now).transmit.unwrap();
        let refusal = full
            .handle(&solicit.packet, addr("fe80::1"), MAC, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            client.handle(&refusal.packet, now).unwrap(),
            Output::default()
        );
        assert!(client.lease().is_none());
    }

    #[test]
    fn release_tells_the_server() {
        let (mut client, mut server) = (client(), server());
        let now = Instant::now();
        let lease = acquire(&mut client, &mut server, now);
        let release = client.release(now).unwrap();
        let msg = decode(&release);
        assert_eq!(msg.msg_type(), MessageType::Release);
        let reply = server
            .handle(&release.packet, addr("fe80::1"), MAC, now)
            .unwrap()
            .unwrap();
        assert_eq!(server.leases().count(), 0);
        assert_eq!(
            client.handle(&reply.packet, now).unwrap(),
            Output::default()
        );
        assert!(client.lease().is_none());
        assert_eq!(client.poll(lease.expires), Output::default());
    }
}
