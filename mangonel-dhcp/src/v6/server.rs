//! A stateful DHCPv6 server for one link with one address
//! pool, handing out non-temporary addresses.

use std::{
    collections::HashMap,
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
        OptionCode,
        Status,
        StatusCode,
    },
};

use crate::{
    Error,
    v6::{
        self,
        SCAN_LIMIT,
    },
};

/// How long an advertised address is held for the client it
/// was advertised to.
const OFFER_HOLD: Duration = Duration::from_secs(60);
/// How long a declined address stays out of the pool.
const DECLINE_HOLD: Duration = Duration::from_secs(10 * 60);

/// What a server hands out on one link.
///
/// # Examples
/// ```
/// use std::time::Duration;
///
/// use mangonel_dhcp::v6::server::Config;
///
/// let config = Config {
///     mac: [2, 0, 0, 1, 0, 2],
///     prefix: "2001:db8:1::".parse()?,
///     prefix_len: 64,
///     pool_start: "2001:db8:1::100".parse()?,
///     pool_end: "2001:db8:1::1ff".parse()?,
///     dns: vec!["2001:db8:1::1".parse()?],
///     preferred_lifetime: Duration::from_secs(1800),
///     valid_lifetime: Duration::from_secs(3600),
///     rapid_commit: false,
/// };
/// assert!(config.validate().is_ok());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The server's hardware address, which its DUID is built from.
    pub mac: [u8; 6],
    /// The link's prefix.
    pub prefix: Ipv6Addr,
    /// The prefix length.
    pub prefix_len: u8,
    /// First address handed out.
    pub pool_start: Ipv6Addr,
    /// Last address handed out, inclusive.
    pub pool_end: Ipv6Addr,
    /// Resolvers advertised to clients; empty advertises none.
    pub dns: Vec<Ipv6Addr>,
    /// How long an address stays preferred.
    pub preferred_lifetime: Duration,
    /// How long an address stays valid.
    pub valid_lifetime: Duration,
    /// Whether a Solicit asking for rapid commit gets a lease
    /// in one round trip.
    pub rapid_commit: bool,
}

impl Config {
    /// Checks that the pool lies inside the prefix and the
    /// lifetimes make sense.
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    ///
    /// use mangonel_dhcp::{Error, v6::server::Config};
    ///
    /// let config = Config {
    ///     mac: [2, 0, 0, 1, 0, 2],
    ///     prefix: "2001:db8:1::".parse()?,
    ///     prefix_len: 64,
    ///     pool_start: "2001:db8:1::100".parse()?,
    ///     pool_end: "2001:db8:1::1ff".parse()?,
    ///     dns: vec![],
    ///     preferred_lifetime: Duration::from_secs(3600),
    ///     valid_lifetime: Duration::from_secs(1800),
    ///     rapid_commit: false,
    /// };
    /// assert!(matches!(config.validate(), Err(Error::PreferredOutlivesValid)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        if self.prefix_len > 128 {
            return Err(Error::PrefixTooLong(self.prefix_len));
        }
        if u128::from(self.pool_start) > u128::from(self.pool_end) {
            return Err(Error::PoolReversed(
                self.pool_start.into(),
                self.pool_end.into(),
            ));
        }
        if !self.on_link(self.pool_start) || !self.on_link(self.pool_end) {
            return Err(Error::PoolOutsideSubnet(
                self.pool_start.into(),
                self.pool_end.into(),
            ));
        }
        if self.preferred_lifetime.is_zero() || self.valid_lifetime.is_zero() {
            return Err(Error::ZeroLifetime);
        }
        if self.preferred_lifetime > self.valid_lifetime {
            return Err(Error::PreferredOutlivesValid);
        }

        Ok(())
    }

    /// Whether the pool holds `address`.
    fn contains(&self, address: Ipv6Addr) -> bool {
        (u128::from(self.pool_start)..=u128::from(self.pool_end)).contains(&u128::from(address))
    }

    /// Whether `address` is inside the link's prefix.
    fn on_link(&self, address: Ipv6Addr) -> bool {
        v6::in_prefix(address, self.prefix, self.prefix_len)
    }
}

/// An address the server has advertised or granted to one
/// IA_NA of one client.
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
/// let now = Instant::now();
/// let solicit = client.poll(now).transmit.unwrap();
/// server.handle(&solicit.packet, "fe80::1".parse()?, [2, 0, 0, 4, 0, 0], now)?;
/// let lease = server.leases().next().unwrap();
/// assert_eq!(lease.mac, [2, 0, 0, 4, 0, 0]);
/// assert!(!lease.is_bound());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The address advertised or granted.
    pub address: Ipv6Addr,
    /// The client's DUID.
    pub client_id: Vec<u8>,
    /// The IA_NA the address belongs to.
    pub iaid: u32,
    /// The hardware address the client's messages came from.
    pub mac: [u8; 6],
    /// When the advertisement or lease lapses.
    pub expires: Instant,
    bound: bool,
}

impl Lease {
    /// Whether the client requested the address, rather than
    /// only being advertised it.
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
    /// server.handle(&request.packet, from, mac, now)?;
    /// assert!(server.leases().next().unwrap().is_bound());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_bound(&self) -> bool {
        self.bound
    }
}

/// A reply ready to be sent from the server port to the
/// client's link-local address.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v6::server::Reply;
///
/// fn frame(reply: &Reply) -> (std::net::Ipv6Addr, [u8; 6], usize) {
///     (reply.to, reply.mac, reply.packet.len())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The encoded message, a UDP payload.
    pub packet: Vec<u8>,
    /// The address the request came from.
    pub to: Ipv6Addr,
    /// The MAC the request came from.
    pub mac: [u8; 6],
}

/// A server for one link, keyed by client DUID and IAID.
///
/// # Examples
/// ```
/// use std::time::Duration;
///
/// use mangonel_dhcp::v6::server::{Config, Server};
///
/// let server = Server::new(Config {
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
/// assert_eq!(server.server_id(), &[0, 3, 0, 1, 2, 0, 0, 1, 0, 2]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Server {
    config: Config,
    server_id: Vec<u8>,
    leases: HashMap<(Vec<u8>, u32), Lease>,
    by_address: HashMap<Ipv6Addr, (Vec<u8>, u32)>,
    declined: HashMap<Ipv6Addr, Instant>,
    /// Where the next pool scan starts, as an offset into the pool.
    cursor: u128,
}

impl Server {
    /// A server with an empty lease table; fails as
    /// [`Config::validate`] does.
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    ///
    /// use mangonel_dhcp::v6::server::{Config, Server};
    ///
    /// let server = Server::new(Config {
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
    /// assert_eq!(server.leases().count(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let server_id = v6::duid_ll(config.mac);

        Ok(Self {
            config,
            server_id,
            leases: HashMap::new(),
            by_address: HashMap::new(),
            declined: HashMap::new(),
            cursor: 0,
        })
    }

    /// The configuration the server was built with.
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    ///
    /// use mangonel_dhcp::v6::server::{Config, Server};
    ///
    /// let config = Config {
    ///     mac: [2, 0, 0, 1, 0, 2],
    ///     prefix: "2001:db8:1::".parse()?,
    ///     prefix_len: 64,
    ///     pool_start: "2001:db8:1::100".parse()?,
    ///     pool_end: "2001:db8:1::1ff".parse()?,
    ///     dns: vec![],
    ///     preferred_lifetime: Duration::from_secs(1800),
    ///     valid_lifetime: Duration::from_secs(3600),
    ///     rapid_commit: false,
    /// };
    /// let server = Server::new(config.clone())?;
    /// assert_eq!(server.config(), &config);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The server's DUID, which replies carry and clients echo.
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    ///
    /// use mangonel_dhcp::v6::server::{Config, Server};
    ///
    /// let server = Server::new(Config {
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
    /// assert_eq!(server.server_id().len(), 10);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn server_id(&self) -> &[u8] {
        &self.server_id
    }

    /// Every advertisement and lease still held, in no
    /// particular order.
    ///
    /// # Examples
    /// ```
    /// use std::time::Duration;
    ///
    /// use mangonel_dhcp::v6::server::{Config, Server};
    ///
    /// let server = Server::new(Config {
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
    /// assert!(server.leases().next().is_none());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values()
    }

    /// Drops advertisements and leases that lapsed by `now`,
    /// and returns how many.
    ///
    /// # Examples
    /// ```
    /// use std::time::{Duration, Instant};
    ///
    /// use mangonel_dhcp::v6::server::{Config, Server};
    ///
    /// let mut server = Server::new(Config {
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
    /// assert_eq!(server.expire(Instant::now()), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.leases.len();
        let by_address = &mut self.by_address;
        self.leases.retain(|_, lease| {
            let keep = lease.expires > now;
            if !keep {
                by_address.remove(&lease.address);
            }

            keep
        });
        self.declined.retain(|_, until| *until > now);

        before - self.leases.len()
    }

    /// Handles one message that arrived from `from` and `mac`,
    /// and returns the reply, if the protocol calls for one.
    ///
    /// # Examples
    /// ```
    /// use std::time::{Duration, Instant};
    ///
    /// use dhcproto::{Decodable, v6::{Message, MessageType}};
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
    /// let now = Instant::now();
    /// let solicit = client.poll(now).transmit.unwrap();
    /// let reply = server.handle(&solicit.packet, "fe80::1".parse()?, [2, 0, 0, 4, 0, 0], now)?;
    /// let advertise = Message::from_bytes(&reply.unwrap().packet)?;
    /// assert_eq!(advertise.msg_type(), MessageType::Advertise);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn handle(
        &mut self,
        packet: &[u8],
        from: Ipv6Addr,
        mac: [u8; 6],
        now: Instant,
    ) -> Result<Option<Reply>, Error> {
        let msg = Message::from_bytes(packet)?;
        self.expire(now);
        let server_id = v6::server_id_of(&msg);
        let ours = server_id == Some(self.server_id.as_slice());
        let client_id = v6::client_id_of(&msg).map(<[u8]>::to_vec);

        let reply = match (msg.msg_type(), client_id) {
            (MessageType::InformationRequest, client_id) if server_id.is_none() || ours => {
                let mut reply = self.base(&msg, MessageType::Reply, client_id.as_deref());
                self.add_dns(&mut reply);

                Some(reply)
            }
            (_, None) => None,
            (MessageType::Solicit, Some(id)) if server_id.is_none() => {
                let rapid =
                    self.config.rapid_commit && msg.opts().get(OptionCode::RapidCommit).is_some();
                let kind = if rapid {
                    MessageType::Reply
                } else {
                    MessageType::Advertise
                };
                let ias = self.assign(&msg, &id, mac, rapid, now);
                let mut reply = self.base(&msg, kind, Some(&id));
                if rapid {
                    reply.opts_mut().insert(DhcpOption::RapidCommit);
                }
                for ia in ias {
                    reply.opts_mut().insert(DhcpOption::IANA(ia));
                }
                self.add_dns(&mut reply);

                Some(reply)
            }
            (MessageType::Request, Some(id)) if ours => {
                let ias = self.assign(&msg, &id, mac, true, now);

                Some(self.granting(&msg, &id, ias))
            }
            (MessageType::Renew, Some(id)) if ours => {
                let ias = self.extend(&msg, &id, now, false);

                Some(self.granting(&msg, &id, ias))
            }
            (MessageType::Rebind, Some(id)) if server_id.is_none() => {
                let ias = self.extend(&msg, &id, now, true);

                (!ias.is_empty()).then(|| self.granting(&msg, &id, ias))
            }
            (MessageType::Release, Some(id)) if ours => {
                for iaid in v6::ianas(&msg).map(|ia| ia.id).collect::<Vec<_>>() {
                    self.forget(&(id.clone(), iaid));
                }

                Some(self.with_status(&msg, &id, Status::Success, "released"))
            }
            (MessageType::Decline, Some(id)) if ours => {
                let declined: Vec<Ipv6Addr> = v6::ianas(&msg)
                    .flat_map(v6::addresses)
                    .map(|addr| addr.addr)
                    .collect();
                for address in declined {
                    self.decline(address, now);
                }

                Some(self.with_status(&msg, &id, Status::Success, "declined"))
            }
            (MessageType::Confirm, Some(id)) if server_id.is_none() => {
                let addresses: Vec<Ipv6Addr> = v6::ianas(&msg)
                    .flat_map(v6::addresses)
                    .map(|addr| addr.addr)
                    .collect();
                if addresses.is_empty() {
                    None
                } else if addresses.iter().all(|a| self.config.on_link(*a)) {
                    Some(self.with_status(&msg, &id, Status::Success, "on link"))
                } else {
                    Some(self.with_status(&msg, &id, Status::NotOnLink, "not on this link"))
                }
            }
            _ => None,
        };

        Ok(reply.map(|reply| Reply {
            packet: reply
                .to_vec()
                .expect("a reply the server built encodes. This is a bug."),
            to: from,
            mac,
        }))
    }

    /// Assigns an address to every IA_NA in `msg`, as an
    /// advertisement or, when `bound`, a lease.
    fn assign(
        &mut self,
        msg: &Message,
        id: &[u8],
        mac: [u8; 6],
        bound: bool,
        now: Instant,
    ) -> Vec<IANA> {
        let mut ias = Vec::new();
        for ia in v6::ianas(msg) {
            let key = (id.to_vec(), ia.id);
            let hint = v6::addresses(ia).next().map(|addr| addr.addr);
            match self.choose(&key, hint, now) {
                Some(address) => {
                    let hold = if bound {
                        self.config.valid_lifetime
                    } else {
                        OFFER_HOLD
                    };
                    self.bind(key, mac, address, bound, now + hold);
                    ias.push(self.granted(ia.id, address));
                }
                None => ias.push(status_ia(ia.id, Status::NoAddrsAvail, "pool exhausted")),
            }
        }

        ias
    }

    /// Extends the lease behind every IA_NA in `msg`; what an
    /// unknown IA gets depends on whether this is a Rebind.
    fn extend(&mut self, msg: &Message, id: &[u8], now: Instant, rebind: bool) -> Vec<IANA> {
        let mut ias = Vec::new();
        for ia in v6::ianas(msg) {
            let key = (id.to_vec(), ia.id);
            let asked: Vec<Ipv6Addr> = v6::addresses(ia).map(|addr| addr.addr).collect();
            let held = self.leases.get(&key).map(|lease| lease.address);
            match held {
                Some(address) if asked.is_empty() || asked.contains(&address) => {
                    if let Some(lease) = self.leases.get_mut(&key) {
                        lease.expires = now + self.config.valid_lifetime;
                        lease.bound = true;
                    }
                    ias.push(self.granted(ia.id, address));
                }
                // RFC 8415 section 18.3.5: an unknown binding gets zero
                // lifetimes when its addresses are off-link, silence otherwise.
                _ if rebind => {
                    let mut opts = DhcpOptions::new();
                    for address in asked.iter().filter(|a| !self.config.on_link(**a)) {
                        opts.insert(DhcpOption::IAAddr(IAAddr {
                            addr: *address,
                            preferred_life: 0,
                            valid_life: 0,
                            opts: DhcpOptions::new(),
                        }));
                    }
                    if opts.iter().next().is_some() {
                        ias.push(IANA {
                            id: ia.id,
                            t1: 0,
                            t2: 0,
                            opts,
                        });
                    }
                }
                _ => ias.push(status_ia(ia.id, Status::NoBinding, "no binding")),
            }
        }

        ias
    }

    fn decline(&mut self, address: Ipv6Addr, now: Instant) {
        if !self.config.contains(address) {
            return;
        }
        self.declined.insert(address, now + DECLINE_HOLD);
        if let Some(owner) = self.by_address.get(&address).cloned() {
            self.forget(&owner);
        }
    }

    /// The IA's current address, the one it hinted at, or
    /// the next free one, in that order.
    fn choose(
        &mut self,
        key: &(Vec<u8>, u32),
        hint: Option<Ipv6Addr>,
        now: Instant,
    ) -> Option<Ipv6Addr> {
        if let Some(lease) = self.leases.get(key) {
            return Some(lease.address);
        }
        if let Some(h) = hint
            && self.is_free(h, now)
        {
            return Some(h);
        }
        let start = u128::from(self.config.pool_start);
        let size = u128::from(self.config.pool_end) - start + 1;
        let mut step = 0;
        while step < size.min(SCAN_LIMIT) {
            let offset = (self.cursor + step) % size;
            let address = Ipv6Addr::from(start + offset);
            if self.is_free(address, now) {
                self.cursor = (offset + 1) % size;

                return Some(address);
            }
            step += 1;
        }

        None
    }

    fn is_free(&self, address: Ipv6Addr, now: Instant) -> bool {
        self.config.contains(address)
            && !self.by_address.contains_key(&address)
            && self
                .declined
                .get(&address)
                .is_none_or(|until| *until <= now)
    }

    fn bind(
        &mut self,
        key: (Vec<u8>, u32),
        mac: [u8; 6],
        address: Ipv6Addr,
        bound: bool,
        expires: Instant,
    ) {
        self.forget(&key);
        if let Some(owner) = self.by_address.remove(&address) {
            self.leases.remove(&owner);
        }
        self.by_address.insert(address, key.clone());
        let (client_id, iaid) = key.clone();
        self.leases.insert(
            key,
            Lease {
                address,
                client_id,
                iaid,
                mac,
                expires,
                bound,
            },
        );
    }

    fn forget(&mut self, key: &(Vec<u8>, u32)) {
        if let Some(lease) = self.leases.remove(key) {
            self.by_address.remove(&lease.address);
        }
    }

    /// An IA_NA granting `address` with the configured lifetimes.
    fn granted(&self, iaid: u32, address: Ipv6Addr) -> IANA {
        let preferred = v6::seconds(self.config.preferred_lifetime);
        let mut opts = DhcpOptions::new();
        opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: address,
            preferred_life: preferred,
            valid_life: v6::seconds(self.config.valid_lifetime),
            opts: DhcpOptions::new(),
        }));

        IANA {
            id: iaid,
            t1: preferred / 2,
            t2: preferred / 5 * 4,
            opts,
        }
    }

    /// A reply carrying the server's and client's ids.
    fn base(&self, msg: &Message, kind: MessageType, client_id: Option<&[u8]>) -> Message {
        let mut reply = Message::new_with_id(kind, msg.xid());
        let opts = reply.opts_mut();
        opts.insert(DhcpOption::ServerId(self.server_id.clone()));
        if let Some(id) = client_id {
            opts.insert(DhcpOption::ClientId(id.to_vec()));
        }

        reply
    }

    /// A Reply carrying `ias` and the resolvers.
    fn granting(&self, msg: &Message, client_id: &[u8], ias: Vec<IANA>) -> Message {
        let mut reply = self.base(msg, MessageType::Reply, Some(client_id));
        for ia in ias {
            reply.opts_mut().insert(DhcpOption::IANA(ia));
        }
        self.add_dns(&mut reply);

        reply
    }

    /// A Reply carrying only a status.
    fn with_status(&self, msg: &Message, client_id: &[u8], status: Status, text: &str) -> Message {
        let mut reply = self.base(msg, MessageType::Reply, Some(client_id));
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode {
            status,
            msg: text.to_owned(),
        }));

        reply
    }

    fn add_dns(&self, reply: &mut Message) {
        if !self.config.dns.is_empty() {
            reply
                .opts_mut()
                .insert(DhcpOption::DomainNameServers(self.config.dns.clone()));
        }
    }
}

/// An IA_NA that carries a status instead of an address.
fn status_ia(iaid: u32, status: Status, text: &str) -> IANA {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::StatusCode(StatusCode {
        status,
        msg: text.to_owned(),
    }));

    IANA {
        id: iaid,
        t1: 0,
        t2: 0,
        opts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];
    const XID: [u8; 3] = [1, 2, 3];
    const IAID: u32 = 7;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn config() -> Config {
        Config {
            mac: [2, 0, 0, 1, 0, 2],
            prefix: addr("2001:db8:1::"),
            prefix_len: 64,
            pool_start: addr("2001:db8:1::10"),
            pool_end: addr("2001:db8:1::12"),
            dns: vec![addr("2001:db8:1::1")],
            preferred_lifetime: Duration::from_secs(600),
            valid_lifetime: Duration::from_secs(900),
            rapid_commit: false,
        }
    }

    fn server() -> Server {
        Server::new(config()).unwrap()
    }

    fn duid(mac: [u8; 6]) -> Vec<u8> {
        v6::duid_ll(mac)
    }

    fn ia_na(address: Option<Ipv6Addr>) -> DhcpOption {
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
            id: IAID,
            t1: 0,
            t2: 0,
            opts,
        })
    }

    fn message(kind: MessageType, mac: [u8; 6], address: Option<Ipv6Addr>) -> Message {
        let mut msg = Message::new_with_id(kind, XID);
        msg.opts_mut().insert(DhcpOption::ClientId(duid(mac)));
        msg.opts_mut().insert(ia_na(address));
        if !matches!(
            kind,
            MessageType::Solicit | MessageType::Rebind | MessageType::Confirm
        ) {
            msg.opts_mut()
                .insert(DhcpOption::ServerId(duid([2, 0, 0, 1, 0, 2])));
        }

        msg
    }

    fn send(server: &mut Server, msg: &Message, now: Instant) -> Option<Message> {
        server
            .handle(&msg.to_vec().unwrap(), addr("fe80::1"), MAC, now)
            .unwrap()
            .map(|reply| Message::from_bytes(&reply.packet).unwrap())
    }

    fn granted_address(msg: &Message) -> Option<Ipv6Addr> {
        let ia = v6::ianas(msg).next()?;
        v6::addresses(ia).next().map(|a| a.addr)
    }

    fn top_status(msg: &Message) -> Option<Status> {
        match msg.opts().get(OptionCode::StatusCode) {
            Some(DhcpOption::StatusCode(code)) => Some(code.status),
            _ => None,
        }
    }

    #[test]
    fn validate_rejects_bad_configs() {
        let mut bad = config();
        bad.pool_end = addr("2001:db8:1::1");
        assert!(matches!(bad.validate(), Err(Error::PoolReversed(..))));
        let mut bad = config();
        bad.pool_end = addr("2001:db8:2::12");
        assert!(matches!(bad.validate(), Err(Error::PoolOutsideSubnet(..))));
        let mut bad = config();
        bad.prefix_len = 129;
        assert!(matches!(bad.validate(), Err(Error::PrefixTooLong(129))));
        let mut bad = config();
        bad.valid_lifetime = Duration::ZERO;
        assert!(matches!(bad.validate(), Err(Error::ZeroLifetime)));
        let mut bad = config();
        bad.preferred_lifetime = Duration::from_secs(1000);
        assert!(matches!(bad.validate(), Err(Error::PreferredOutlivesValid)));
    }

    #[test]
    fn solicit_advertise_request_reply() {
        let mut server = server();
        let now = Instant::now();
        let advertise = send(&mut server, &message(MessageType::Solicit, MAC, None), now).unwrap();
        assert_eq!(advertise.msg_type(), MessageType::Advertise);
        assert_eq!(advertise.xid(), XID);
        assert_eq!(v6::server_id_of(&advertise), Some(server.server_id()));
        assert_eq!(v6::client_id_of(&advertise), Some(duid(MAC).as_slice()));
        let offered = granted_address(&advertise).unwrap();
        assert_eq!(offered, addr("2001:db8:1::10"));
        let ia = v6::ianas(&advertise).next().unwrap();
        assert_eq!((ia.t1, ia.t2), (300, 480));
        let ia_addr = v6::addresses(ia).next().unwrap();
        assert_eq!((ia_addr.preferred_life, ia_addr.valid_life), (600, 900));
        assert_eq!(v6::dns_of(&advertise), vec![addr("2001:db8:1::1")]);
        assert!(!server.leases().next().unwrap().is_bound());

        let reply = send(
            &mut server,
            &message(MessageType::Request, MAC, Some(offered)),
            now,
        )
        .unwrap();
        assert_eq!(reply.msg_type(), MessageType::Reply);
        assert_eq!(granted_address(&reply), Some(offered));
        let lease = server.leases().next().unwrap();
        assert!(lease.is_bound());
        assert_eq!(lease.iaid, IAID);
        assert_eq!(lease.expires, now + Duration::from_secs(900));
    }

    #[test]
    fn rapid_commit_when_both_sides_want_it() {
        let mut server = server();
        let now = Instant::now();
        let mut solicit = message(MessageType::Solicit, MAC, None);
        solicit.opts_mut().insert(DhcpOption::RapidCommit);
        let advertise = send(&mut server, &solicit, now).unwrap();
        assert_eq!(advertise.msg_type(), MessageType::Advertise);

        let mut server = Server::new(Config {
            rapid_commit: true,
            ..config()
        })
        .unwrap();
        let reply = send(&mut server, &solicit, now).unwrap();
        assert_eq!(reply.msg_type(), MessageType::Reply);
        assert!(reply.opts().get(OptionCode::RapidCommit).is_some());
        assert!(server.leases().next().unwrap().is_bound());
    }

    #[test]
    fn other_servers_messages_are_ignored() {
        let mut server = server();
        let now = Instant::now();
        let mut request = message(MessageType::Request, MAC, Some(addr("2001:db8:1::10")));
        request
            .opts_mut()
            .insert(DhcpOption::ServerId(duid([9, 9, 9, 9, 9, 9])));
        assert!(send(&mut server, &request, now).is_none());
        let mut solicit = message(MessageType::Solicit, MAC, None);
        solicit.opts_mut().insert(DhcpOption::ServerId(duid(MAC)));
        assert!(send(&mut server, &solicit, now).is_none());
        let mut anonymous = message(MessageType::Solicit, MAC, None);
        anonymous.opts_mut().remove(OptionCode::ClientId);
        assert!(send(&mut server, &anonymous, now).is_none());
    }

    #[test]
    fn renew_extends_and_rebind_answers_bindings_only() {
        let mut server = server();
        let now = Instant::now();
        send(&mut server, &message(MessageType::Solicit, MAC, None), now);
        let address = addr("2001:db8:1::10");
        send(
            &mut server,
            &message(MessageType::Request, MAC, Some(address)),
            now,
        );

        let later = now + Duration::from_secs(300);
        let reply = send(
            &mut server,
            &message(MessageType::Renew, MAC, Some(address)),
            later,
        )
        .unwrap();
        assert_eq!(granted_address(&reply), Some(address));
        assert_eq!(
            server.leases().next().unwrap().expires,
            later + Duration::from_secs(900)
        );

        let stranger = message(MessageType::Renew, [2, 0, 0, 4, 0, 9], Some(address));
        let reply = send(&mut server, &stranger, later).unwrap();
        assert_eq!(
            v6::status_of(v6::ianas(&reply).next().unwrap()),
            Status::NoBinding
        );

        let reply = send(
            &mut server,
            &message(MessageType::Rebind, MAC, Some(address)),
            later,
        )
        .unwrap();
        assert_eq!(granted_address(&reply), Some(address));
        let unknown = message(
            MessageType::Rebind,
            [2, 0, 0, 4, 0, 9],
            Some(addr("2001:db8:1::50")),
        );
        assert!(send(&mut server, &unknown, later).is_none());
        let off_link = message(
            MessageType::Rebind,
            [2, 0, 0, 4, 0, 9],
            Some(addr("2001:db8:9::50")),
        );
        let reply = send(&mut server, &off_link, later).unwrap();
        let zeroed = v6::addresses(v6::ianas(&reply).next().unwrap())
            .next()
            .unwrap();
        assert_eq!((zeroed.preferred_life, zeroed.valid_life), (0, 0));
    }

    #[test]
    fn release_and_decline() {
        let mut server = server();
        let now = Instant::now();
        let advertise = send(&mut server, &message(MessageType::Solicit, MAC, None), now).unwrap();
        let address = granted_address(&advertise).unwrap();
        send(
            &mut server,
            &message(MessageType::Request, MAC, Some(address)),
            now,
        );

        let reply = send(
            &mut server,
            &message(MessageType::Release, MAC, Some(address)),
            now,
        )
        .unwrap();
        assert_eq!(top_status(&reply), Some(Status::Success));
        assert_eq!(server.leases().count(), 0);

        let reply = send(
            &mut server,
            &message(MessageType::Decline, MAC, Some(address)),
            now,
        )
        .unwrap();
        assert_eq!(top_status(&reply), Some(Status::Success));
        let next = send(&mut server, &message(MessageType::Solicit, MAC, None), now).unwrap();
        assert_eq!(granted_address(&next), Some(addr("2001:db8:1::11")));
    }

    #[test]
    fn confirm_checks_the_link() {
        let mut server = server();
        let now = Instant::now();
        let on = message(MessageType::Confirm, MAC, Some(addr("2001:db8:1::77")));
        assert_eq!(
            top_status(&send(&mut server, &on, now).unwrap()),
            Some(Status::Success)
        );
        let off = message(MessageType::Confirm, MAC, Some(addr("2001:db8:2::77")));
        assert_eq!(
            top_status(&send(&mut server, &off, now).unwrap()),
            Some(Status::NotOnLink)
        );
        assert!(send(&mut server, &message(MessageType::Confirm, MAC, None), now).is_none());
    }

    #[test]
    fn information_request_gets_resolvers() {
        let mut server = server();
        let now = Instant::now();
        let mut info = Message::new_with_id(MessageType::InformationRequest, XID);
        info.opts_mut().insert(DhcpOption::ClientId(duid(MAC)));
        let reply = send(&mut server, &info, now).unwrap();
        assert_eq!(reply.msg_type(), MessageType::Reply);
        assert_eq!(v6::dns_of(&reply), vec![addr("2001:db8:1::1")]);
        assert!(v6::ianas(&reply).next().is_none());
        assert_eq!(server.leases().count(), 0);
    }

    #[test]
    fn pool_exhausts_and_expires() {
        let mut server = server();
        let now = Instant::now();
        for i in 0..3 {
            let advertise = send(
                &mut server,
                &message(MessageType::Solicit, [2, 0, 0, 4, 0, i], None),
                now,
            );
            assert!(granted_address(&advertise.unwrap()).is_some());
        }
        let full = send(
            &mut server,
            &message(MessageType::Solicit, [2, 0, 0, 4, 0, 9], None),
            now,
        )
        .unwrap();
        assert_eq!(
            v6::status_of(v6::ianas(&full).next().unwrap()),
            Status::NoAddrsAvail
        );
        assert_eq!(server.expire(now + OFFER_HOLD), 3);
        let again = send(
            &mut server,
            &message(MessageType::Solicit, [2, 0, 0, 4, 0, 9], None),
            now + OFFER_HOLD,
        );
        assert!(granted_address(&again.unwrap()).is_some());
    }

    #[test]
    fn garbage_is_an_error() {
        let mut server = server();
        assert!(matches!(
            server.handle(&[0xff], addr("fe80::1"), MAC, Instant::now()),
            Err(Error::Decode(_))
        ));
    }
}
