//! A DHCPv4 server for one subnet with one address pool.

use std::{
    collections::HashMap,
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
    },
};

use crate::{
    Error,
    v4::{
        self,
        SCAN_LIMIT,
    },
};

/// How long an offered address is held for the client it
/// was offered to.
const OFFER_HOLD: Duration = Duration::from_secs(60);
/// How long a declined address stays out of the pool.
const DECLINE_HOLD: Duration = Duration::from_secs(10 * 60);

/// What a server hands out: one subnet, one pool, itself
/// as the router.
///
/// # Examples
/// ```
/// use std::{net::Ipv4Addr, time::Duration};
///
/// use mangonel_dhcp::v4::server::Config;
///
/// let config = Config {
///     address: Ipv4Addr::new(10, 0, 0, 1),
///     prefix: 24,
///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
///     dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
///     lease_time: Duration::from_secs(3600),
/// };
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The server's own address, advertised as the router too.
    pub address: Ipv4Addr,
    /// The subnet's prefix length.
    pub prefix: u8,
    /// First address handed out.
    pub pool_start: Ipv4Addr,
    /// Last address handed out, inclusive.
    pub pool_end: Ipv4Addr,
    /// Resolvers advertised to clients; empty advertises none.
    pub dns: Vec<Ipv4Addr>,
    /// How long a lease lasts.
    pub lease_time: Duration,
}

impl Config {
    /// Checks that the pool is a host range in the subnet
    /// that leaves the server out.
    ///
    /// # Examples
    /// ```
    /// use std::{net::Ipv4Addr, time::Duration};
    ///
    /// use mangonel_dhcp::{Error, v4::server::Config};
    ///
    /// let config = Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 1, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 1, 20),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// };
    /// assert!(matches!(config.validate(), Err(Error::PoolOutsideSubnet(..))));
    /// ```
    pub fn validate(&self) -> Result<(), Error> {
        if self.prefix > 30 {
            return Err(Error::PrefixTooLong(self.prefix));
        }
        if u32::from(self.pool_start) > u32::from(self.pool_end) {
            return Err(Error::PoolReversed(
                self.pool_start.into(),
                self.pool_end.into(),
            ));
        }
        if !self.is_host(self.pool_start) || !self.is_host(self.pool_end) {
            return Err(Error::PoolOutsideSubnet(
                self.pool_start.into(),
                self.pool_end.into(),
            ));
        }
        if self.contains(self.address) {
            return Err(Error::AddressInPool(self.address.into()));
        }
        if self.lease_time.is_zero() {
            return Err(Error::ZeroLifetime);
        }

        Ok(())
    }

    /// Whether the pool holds `address`.
    fn contains(&self, address: Ipv4Addr) -> bool {
        (u32::from(self.pool_start)..=u32::from(self.pool_end)).contains(&u32::from(address))
    }

    /// Whether `address` is a host in the subnet.
    fn is_host(&self, address: Ipv4Addr) -> bool {
        v4::same_subnet(address, self.address, self.prefix)
            && address != self.network()
            && address != self.broadcast()
    }

    fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) & u32::from(v4::mask(self.prefix)))
    }

    fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) | !u32::from(v4::mask(self.prefix)))
    }
}

/// An address the server has offered or granted.
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
/// server.handle(&discover.packet, now)?;
/// let lease = server.leases().next().unwrap();
/// assert_eq!(lease.mac, [2, 0, 0, 4, 0, 0]);
/// assert!(!lease.is_bound());
/// # Ok::<(), mangonel_dhcp::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The address offered or granted.
    pub address: Ipv4Addr,
    /// The client's hardware address.
    pub mac: [u8; 6],
    /// The client identifier the lease is keyed by.
    pub client_id: Vec<u8>,
    /// The name the client gave itself, if any.
    pub hostname: Option<String>,
    /// When the offer or lease lapses.
    pub expires: Instant,
    bound: bool,
}

impl Lease {
    /// Whether the client accepted the address, rather than
    /// only being offered it.
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
    /// server.handle(&request.packet, now)?;
    /// assert!(server.leases().next().unwrap().is_bound());
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn is_bound(&self) -> bool {
        self.bound
    }
}

/// Where a reply goes, since the client may have no address yet.
///
/// # Examples
/// ```
/// use std::net::Ipv4Addr;
///
/// use mangonel_dhcp::v4::server::Destination;
///
/// let to = Destination::Unicast { ip: Ipv4Addr::new(10, 0, 0, 10), mac: [2, 0, 0, 4, 0, 0] };
/// assert!(matches!(to, Destination::Unicast { .. }));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// To the limited broadcast address and MAC.
    Broadcast,
    /// Straight to a client, which needs no ARP because the
    /// MAC is given.
    Unicast { ip: Ipv4Addr, mac: [u8; 6] },
    /// To the relay agent that forwarded the request, on the
    /// server port.
    Relay(Ipv4Addr),
}

/// A reply ready to be sent from the server port.
///
/// # Examples
/// ```
/// use mangonel_dhcp::v4::server::{Destination, Reply};
///
/// fn send(reply: &Reply) -> usize {
///     match reply.to {
///         Destination::Broadcast => reply.packet.len(),
///         Destination::Unicast { .. } | Destination::Relay(_) => reply.packet.len(),
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The encoded message, a UDP payload.
    pub packet: Vec<u8>,
    /// Who receives it.
    pub to: Destination,
}

/// A server for one subnet, keyed by client identifier.
///
/// # Examples
/// ```
/// use std::{net::Ipv4Addr, time::Duration};
///
/// use mangonel_dhcp::v4::server::{Config, Server};
///
/// let server = Server::new(Config {
///     address: Ipv4Addr::new(10, 0, 0, 1),
///     prefix: 24,
///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
///     dns: vec![],
///     lease_time: Duration::from_secs(3600),
/// })?;
/// assert_eq!(server.leases().count(), 0);
/// # Ok::<(), mangonel_dhcp::Error>(())
/// ```
#[derive(Debug)]
pub struct Server {
    config: Config,
    leases: HashMap<Vec<u8>, Lease>,
    by_address: HashMap<Ipv4Addr, Vec<u8>>,
    declined: HashMap<Ipv4Addr, Instant>,
    /// Where the next pool scan starts, as an offset into the pool.
    cursor: u32,
}

impl Server {
    /// A server with an empty lease table; fails as
    /// [`Config::validate`] does.
    ///
    /// # Examples
    /// ```
    /// use std::{net::Ipv4Addr, time::Duration};
    ///
    /// use mangonel_dhcp::v4::server::{Config, Server};
    ///
    /// let server = Server::new(Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// })?;
    /// assert_eq!(server.config().prefix, 24);
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;

        Ok(Self {
            config,
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
    /// use std::{net::Ipv4Addr, time::Duration};
    ///
    /// use mangonel_dhcp::v4::server::{Config, Server};
    ///
    /// let config = Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// };
    /// let server = Server::new(config.clone())?;
    /// assert_eq!(server.config(), &config);
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Every offer and lease still held, in no particular order.
    ///
    /// # Examples
    /// ```
    /// use std::{net::Ipv4Addr, time::Duration};
    ///
    /// use mangonel_dhcp::v4::server::{Config, Server};
    ///
    /// let server = Server::new(Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// })?;
    /// assert!(server.leases().next().is_none());
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.leases.values()
    }

    /// Drops offers and leases that lapsed by `now`, and
    /// returns how many.
    ///
    /// # Examples
    /// ```
    /// use std::{net::Ipv4Addr, time::{Duration, Instant}};
    ///
    /// use mangonel_dhcp::v4::server::{Config, Server};
    ///
    /// let mut server = Server::new(Config {
    ///     address: Ipv4Addr::new(10, 0, 0, 1),
    ///     prefix: 24,
    ///     pool_start: Ipv4Addr::new(10, 0, 0, 10),
    ///     pool_end: Ipv4Addr::new(10, 0, 0, 200),
    ///     dns: vec![],
    ///     lease_time: Duration::from_secs(3600),
    /// })?;
    /// assert_eq!(server.expire(Instant::now()), 0);
    /// # Ok::<(), mangonel_dhcp::Error>(())
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

    /// Handles one message from a client and returns the
    /// reply, if the protocol calls for one.
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
    /// assert_eq!(offer.to, server::Destination::Unicast {
    ///     ip: Ipv4Addr::new(10, 0, 0, 10),
    ///     mac: [2, 0, 0, 4, 0, 0],
    /// });
    /// # Ok::<(), mangonel_dhcp::Error>(())
    /// ```
    pub fn handle(&mut self, packet: &[u8], now: Instant) -> Result<Option<Reply>, Error> {
        let msg = Message::from_bytes(packet)?;
        if msg.opcode() != Opcode::BootRequest {
            return Ok(None);
        }
        let Some(mac) = v4::mac_of(&msg) else {
            return Ok(None);
        };
        let Some(kind) = msg.opts().msg_type() else {
            return Ok(None);
        };
        self.expire(now);
        let id = v4::client_id_of(&msg, mac);

        match kind {
            MessageType::Discover => Ok(self.discover(&msg, id, mac, now)),
            MessageType::Request => Ok(self.request(&msg, id, mac, now)),
            MessageType::Release => {
                self.release(&id, msg.ciaddr());

                Ok(None)
            }
            MessageType::Decline => {
                self.decline(&msg, &id, now);

                Ok(None)
            }
            MessageType::Inform => Ok(Some(self.reply(&msg, mac, MessageType::Ack, None))),
            _ => Ok(None),
        }
    }

    fn discover(
        &mut self,
        msg: &Message,
        id: Vec<u8>,
        mac: [u8; 6],
        now: Instant,
    ) -> Option<Reply> {
        let address = self.choose(&id, v4::requested_ip_of(msg), now)?;
        self.bind(
            id,
            mac,
            address,
            v4::hostname_of(msg),
            false,
            now + OFFER_HOLD,
        );

        Some(self.reply(msg, mac, MessageType::Offer, Some(address)))
    }

    fn request(&mut self, msg: &Message, id: Vec<u8>, mac: [u8; 6], now: Instant) -> Option<Reply> {
        let requested = v4::requested_ip_of(msg);
        let ciaddr = msg.ciaddr();
        let current = self.leases.get(&id).map(|lease| lease.address);
        let granted = match (v4::server_id_of(msg), requested, ciaddr.is_unspecified()) {
            // SELECTING: the client answers an offer, maybe another server's.
            (Some(server), _, _) => {
                if server != self.config.address {
                    self.forget(&id);

                    return None;
                }
                match requested {
                    Some(r) if current == Some(r) || self.is_free(r, now) => Some(r),
                    _ => None,
                }
            }
            // INIT-REBOOT: the client checks an address it remembers.
            (None, Some(r), true) => match current {
                Some(c) if c == r => Some(r),
                Some(_) => None,
                None if !v4::same_subnet(r, self.config.address, self.config.prefix) => None,
                // No record of this client: RFC 2131 says stay silent.
                None => return None,
            },
            // RENEWING or REBINDING: the client extends the lease it holds.
            (None, None, false) => (current == Some(ciaddr)).then_some(ciaddr),
            _ => return None,
        };

        match granted {
            Some(address) => {
                let expires = now + self.config.lease_time;
                self.bind(id, mac, address, v4::hostname_of(msg), true, expires);

                Some(self.reply(msg, mac, MessageType::Ack, Some(address)))
            }
            None => Some(self.reply(msg, mac, MessageType::Nak, None)),
        }
    }

    fn release(&mut self, id: &[u8], ciaddr: Ipv4Addr) {
        if self
            .leases
            .get(id)
            .is_some_and(|lease| lease.address == ciaddr)
        {
            self.forget(id);
        }
    }

    fn decline(&mut self, msg: &Message, id: &[u8], now: Instant) {
        let declined = v4::requested_ip_of(msg).or_else(|| self.leases.get(id).map(|l| l.address));
        if let Some(address) = declined
            && self.config.contains(address)
        {
            self.declined.insert(address, now + DECLINE_HOLD);
            if let Some(owner) = self.by_address.get(&address).cloned() {
                self.forget(&owner);
            }
        }
    }

    /// The client's current address, the one it asked for,
    /// or the next free one, in that order.
    fn choose(&mut self, id: &[u8], requested: Option<Ipv4Addr>, now: Instant) -> Option<Ipv4Addr> {
        if let Some(lease) = self.leases.get(id) {
            return Some(lease.address);
        }
        if let Some(r) = requested
            && self.is_free(r, now)
        {
            return Some(r);
        }
        let start = u32::from(self.config.pool_start);
        let size = u32::from(self.config.pool_end) - start + 1;
        for step in 0..size.min(SCAN_LIMIT) {
            let offset = (self.cursor + step) % size;
            let address = Ipv4Addr::from(start + offset);
            if self.is_free(address, now) {
                self.cursor = (offset + 1) % size;

                return Some(address);
            }
        }

        None
    }

    fn is_free(&self, address: Ipv4Addr, now: Instant) -> bool {
        self.config.contains(address)
            && !self.by_address.contains_key(&address)
            && self
                .declined
                .get(&address)
                .is_none_or(|until| *until <= now)
    }

    fn bind(
        &mut self,
        id: Vec<u8>,
        mac: [u8; 6],
        address: Ipv4Addr,
        hostname: Option<String>,
        bound: bool,
        expires: Instant,
    ) {
        self.forget(&id);
        if let Some(owner) = self.by_address.remove(&address) {
            self.leases.remove(&owner);
        }
        self.by_address.insert(address, id.clone());
        self.leases.insert(
            id.clone(),
            Lease {
                address,
                mac,
                client_id: id,
                hostname,
                expires,
                bound,
            },
        );
    }

    fn forget(&mut self, id: &[u8]) {
        if let Some(lease) = self.leases.remove(id) {
            self.by_address.remove(&lease.address);
        }
    }

    /// Builds a reply to `msg` and works out where it goes.
    fn reply(
        &self,
        msg: &Message,
        mac: [u8; 6],
        kind: MessageType,
        yiaddr: Option<Ipv4Addr>,
    ) -> Reply {
        let ciaddr = if kind == MessageType::Ack {
            msg.ciaddr()
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let mut reply = Message::new_with_id(
            msg.xid(),
            ciaddr,
            yiaddr.unwrap_or(Ipv4Addr::UNSPECIFIED),
            Ipv4Addr::UNSPECIFIED,
            msg.giaddr(),
            &mac,
        );
        reply.set_opcode(Opcode::BootReply).set_flags(msg.flags());
        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(kind));
        opts.insert(DhcpOption::ServerIdentifier(self.config.address));
        if kind == MessageType::Nak {
            opts.insert(DhcpOption::Message("address not available".to_owned()));
        } else {
            opts.insert(DhcpOption::SubnetMask(v4::mask(self.config.prefix)));
            opts.insert(DhcpOption::Router(vec![self.config.address]));
            opts.insert(DhcpOption::BroadcastAddr(self.config.broadcast()));
            if !self.config.dns.is_empty() {
                opts.insert(DhcpOption::DomainNameServer(self.config.dns.clone()));
            }
            if yiaddr.is_some() {
                let secs = v4::seconds(self.config.lease_time);
                opts.insert(DhcpOption::AddressLeaseTime(secs));
                opts.insert(DhcpOption::Renewal(secs / 2));
                opts.insert(DhcpOption::Rebinding(secs - secs / 8));
            }
        }
        let packet = reply
            .to_vec()
            .expect("a reply the server built encodes. This is a bug.");

        // RFC 2131 section 4.1 decides the destination.
        let to = if !msg.giaddr().is_unspecified() {
            Destination::Relay(msg.giaddr())
        } else if kind == MessageType::Nak {
            Destination::Broadcast
        } else if !msg.ciaddr().is_unspecified() {
            Destination::Unicast {
                ip: msg.ciaddr(),
                mac,
            }
        } else if msg.flags().broadcast() {
            Destination::Broadcast
        } else {
            Destination::Unicast {
                ip: yiaddr.unwrap_or(Ipv4Addr::BROADCAST),
                mac,
            }
        };

        Reply { packet, to }
    }
}

#[cfg(test)]
mod tests {
    use dhcproto::v4::{
        Flags,
        OptionCode,
    };

    use super::*;

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 0];

    fn config() -> Config {
        Config {
            address: GATEWAY,
            prefix: 24,
            pool_start: Ipv4Addr::new(10, 0, 0, 10),
            pool_end: Ipv4Addr::new(10, 0, 0, 12),
            dns: vec![GATEWAY],
            lease_time: Duration::from_secs(600),
        }
    }

    fn server() -> Server {
        Server::new(config()).unwrap()
    }

    fn message(kind: MessageType, mac: [u8; 6]) -> Message {
        let mut msg = Message::new_with_id(
            0x1234,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac,
        );
        msg.opts_mut().insert(DhcpOption::MessageType(kind));

        msg
    }

    fn send(server: &mut Server, msg: &Message, now: Instant) -> Option<Message> {
        server
            .handle(&msg.to_vec().unwrap(), now)
            .unwrap()
            .map(|reply| Message::from_bytes(&reply.packet).unwrap())
    }

    fn reply_to(server: &mut Server, msg: &Message, now: Instant) -> Reply {
        server.handle(&msg.to_vec().unwrap(), now).unwrap().unwrap()
    }

    fn lease_time(msg: &Message) -> Option<u32> {
        match msg.opts().get(OptionCode::AddressLeaseTime) {
            Some(DhcpOption::AddressLeaseTime(secs)) => Some(*secs),
            _ => None,
        }
    }

    #[test]
    fn validate_rejects_bad_pools() {
        let mut bad = config();
        bad.pool_end = Ipv4Addr::new(10, 0, 0, 9);
        assert!(matches!(bad.validate(), Err(Error::PoolReversed(..))));
        let mut bad = config();
        bad.pool_end = Ipv4Addr::new(10, 0, 0, 255);
        assert!(matches!(bad.validate(), Err(Error::PoolOutsideSubnet(..))));
        let mut bad = config();
        bad.pool_start = GATEWAY;
        assert!(matches!(bad.validate(), Err(Error::AddressInPool(..))));
        let mut bad = config();
        bad.prefix = 31;
        assert!(matches!(bad.validate(), Err(Error::PrefixTooLong(31))));
        let mut bad = config();
        bad.lease_time = Duration::ZERO;
        assert!(matches!(bad.validate(), Err(Error::ZeroLifetime)));
    }

    #[test]
    fn discover_offer_request_ack() {
        let mut server = server();
        let now = Instant::now();
        let offer = send(&mut server, &message(MessageType::Discover, MAC), now).unwrap();
        assert_eq!(offer.opts().msg_type(), Some(MessageType::Offer));
        assert_eq!(offer.opcode(), Opcode::BootReply);
        assert_eq!(offer.yiaddr(), Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(offer.xid(), 0x1234);
        assert_eq!(lease_time(&offer), Some(600));
        assert_eq!(
            offer.opts().get(OptionCode::Router),
            Some(&DhcpOption::Router(vec![GATEWAY]))
        );
        assert!(!server.leases().next().unwrap().is_bound());

        let mut request = message(MessageType::Request, MAC);
        request
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offer.yiaddr()));
        request
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(GATEWAY));
        request
            .opts_mut()
            .insert(DhcpOption::Hostname("node".to_owned()));
        let ack = send(&mut server, &request, now).unwrap();
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), Ipv4Addr::new(10, 0, 0, 10));
        let lease = server.leases().next().unwrap();
        assert!(lease.is_bound());
        assert_eq!(lease.hostname.as_deref(), Some("node"));
        assert_eq!(lease.expires, now + Duration::from_secs(600));
    }

    #[test]
    fn offer_goes_where_rfc_says() {
        let mut server = server();
        let now = Instant::now();
        let reply = reply_to(&mut server, &message(MessageType::Discover, MAC), now);
        assert_eq!(
            reply.to,
            Destination::Unicast {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                mac: MAC
            }
        );

        let mut flagged = message(MessageType::Discover, MAC);
        flagged.set_flags(Flags::new(0).set_broadcast());
        assert_eq!(
            reply_to(&mut server, &flagged, now).to,
            Destination::Broadcast
        );

        let mut relayed = message(MessageType::Discover, [2, 0, 0, 4, 0, 1]);
        relayed.set_giaddr(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            reply_to(&mut server, &relayed, now).to,
            Destination::Relay(Ipv4Addr::new(10, 0, 0, 2))
        );
    }

    #[test]
    fn request_for_another_server_drops_the_offer() {
        let mut server = server();
        let now = Instant::now();
        send(&mut server, &message(MessageType::Discover, MAC), now);
        let mut request = message(MessageType::Request, MAC);
        request
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(send(&mut server, &request, now).is_none());
        assert_eq!(server.leases().count(), 0);
    }

    #[test]
    fn init_reboot_acks_known_and_naks_wrong() {
        let mut server = server();
        let now = Instant::now();
        send(&mut server, &message(MessageType::Discover, MAC), now);
        let mut select = message(MessageType::Request, MAC);
        select
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 10)));
        select
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(GATEWAY));
        send(&mut server, &select, now);

        let mut reboot = message(MessageType::Request, MAC);
        reboot
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 10)));
        let ack = send(&mut server, &reboot, now).unwrap();
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));

        let mut wrong = message(MessageType::Request, MAC);
        wrong
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 11)));
        let reply = reply_to(&mut server, &wrong, now);
        let nak = Message::from_bytes(&reply.packet).unwrap();
        assert_eq!(nak.opts().msg_type(), Some(MessageType::Nak));
        assert_eq!(reply.to, Destination::Broadcast);

        // A stranger asking about our subnet gets silence; off-subnet gets a NAK.
        let mut stranger = message(MessageType::Request, [2, 0, 0, 4, 0, 9]);
        stranger
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 12)));
        assert!(send(&mut server, &stranger, now).is_none());
        let mut lost = message(MessageType::Request, [2, 0, 0, 4, 0, 9]);
        lost.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(
                192, 168, 1, 5,
            )));
        assert_eq!(
            send(&mut server, &lost, now).unwrap().opts().msg_type(),
            Some(MessageType::Nak)
        );
    }

    #[test]
    fn renew_extends_and_release_frees() {
        let mut server = server();
        let now = Instant::now();
        send(&mut server, &message(MessageType::Discover, MAC), now);
        let mut select = message(MessageType::Request, MAC);
        select
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(Ipv4Addr::new(10, 0, 0, 10)));
        select
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(GATEWAY));
        send(&mut server, &select, now);

        let later = now + Duration::from_secs(300);
        let mut renew = message(MessageType::Request, MAC);
        renew.set_ciaddr(Ipv4Addr::new(10, 0, 0, 10));
        let reply = reply_to(&mut server, &renew, later);
        assert_eq!(
            reply.to,
            Destination::Unicast {
                ip: Ipv4Addr::new(10, 0, 0, 10),
                mac: MAC
            }
        );
        let ack = Message::from_bytes(&reply.packet).unwrap();
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.ciaddr(), Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(
            server.leases().next().unwrap().expires,
            later + Duration::from_secs(600)
        );

        let mut release = message(MessageType::Release, MAC);
        release.set_ciaddr(Ipv4Addr::new(10, 0, 0, 10));
        assert!(send(&mut server, &release, later).is_none());
        assert_eq!(server.leases().count(), 0);
    }

    #[test]
    fn pool_exhausts_and_expires() {
        let mut server = server();
        let now = Instant::now();
        for i in 0..3 {
            let offer = send(
                &mut server,
                &message(MessageType::Discover, [2, 0, 0, 4, 0, i]),
                now,
            );
            assert_eq!(offer.unwrap().yiaddr(), Ipv4Addr::new(10, 0, 0, 10 + i));
        }
        assert!(
            send(
                &mut server,
                &message(MessageType::Discover, [2, 0, 0, 4, 0, 9]),
                now
            )
            .is_none()
        );
        // Offers lapse after a minute without a request.
        let later = now + OFFER_HOLD;
        assert_eq!(server.expire(later), 3);
        assert!(
            send(
                &mut server,
                &message(MessageType::Discover, [2, 0, 0, 4, 0, 9]),
                later
            )
            .is_some()
        );
    }

    #[test]
    fn decline_parks_the_address() {
        let mut server = server();
        let now = Instant::now();
        let offer = send(&mut server, &message(MessageType::Discover, MAC), now).unwrap();
        let mut decline = message(MessageType::Decline, MAC);
        decline
            .opts_mut()
            .insert(DhcpOption::RequestedIpAddress(offer.yiaddr()));
        decline
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(GATEWAY));
        assert!(send(&mut server, &decline, now).is_none());
        assert_eq!(server.leases().count(), 0);
        // The rest of the pool goes out; the declined address does not.
        for i in 1..3 {
            let offer = send(
                &mut server,
                &message(MessageType::Discover, [2, 0, 0, 4, 0, i]),
                now,
            );
            assert_eq!(offer.unwrap().yiaddr(), Ipv4Addr::new(10, 0, 0, 10 + i));
        }
        assert!(send(&mut server, &message(MessageType::Discover, MAC), now).is_none());
        let later = send(
            &mut server,
            &message(MessageType::Discover, MAC),
            now + DECLINE_HOLD,
        )
        .unwrap();
        assert_eq!(later.yiaddr(), Ipv4Addr::new(10, 0, 0, 10));
    }

    #[test]
    fn inform_gets_config_without_a_lease() {
        let mut server = server();
        let now = Instant::now();
        let mut inform = message(MessageType::Inform, MAC);
        inform.set_ciaddr(Ipv4Addr::new(10, 0, 0, 50));
        let reply = reply_to(&mut server, &inform, now);
        let ack = Message::from_bytes(&reply.packet).unwrap();
        assert_eq!(ack.opts().msg_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(lease_time(&ack), None);
        assert!(ack.opts().get(OptionCode::DomainNameServer).is_some());
        assert_eq!(server.leases().count(), 0);
    }

    #[test]
    fn ignores_what_is_not_a_request() {
        let mut server = server();
        let now = Instant::now();
        let mut reply = message(MessageType::Offer, MAC);
        reply.set_opcode(Opcode::BootReply);
        assert!(send(&mut server, &reply, now).is_none());
        assert!(matches!(
            server.handle(&[1, 2, 3], now),
            Err(Error::Decode(_))
        ));
    }
}
