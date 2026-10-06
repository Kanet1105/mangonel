//! The left-right shared state and the operations that
//! change it.

use left_right::Absorb;

use crate::{
    Acl, AclEntry, Addressing, Cidr, ConfigError, Direction, IpFamily, LanPort, MacAddr, PortAcls,
    Role, WanPort,
};

/// The configuration readers see.
///
/// Ports keep the order they were first added in, and are
/// keyed by MAC: setting a port whose MAC is already
/// present replaces it in place. ACLs are keyed by name the
/// same way.
#[derive(Debug, Clone, Default)]
pub struct State {
    wan: Vec<WanPort>,
    lan: Vec<LanPort>,
    acls: Vec<Acl>,
}

impl Absorb<Op> for State {
    fn absorb_first(&mut self, op: &mut Op, _: &Self) {
        self.apply(op.clone());
    }

    fn absorb_second(&mut self, op: Op, _: &Self) {
        self.apply(op);
    }

    fn sync_with(&mut self, first: &Self) {
        self.clone_from(first);
    }
}

impl State {
    pub fn wan_ports(&self) -> &[WanPort] {
        &self.wan
    }

    pub fn lan_ports(&self) -> &[LanPort] {
        &self.lan
    }

    pub fn wan(&self, mac: MacAddr) -> Option<&WanPort> {
        self.wan.iter().find(|port| port.mac == mac)
    }

    pub fn lan(&self, mac: MacAddr) -> Option<&LanPort> {
        self.lan.iter().find(|port| port.mac == mac)
    }

    pub fn acls(&self) -> &[Acl] {
        &self.acls
    }

    pub fn acl(&self, name: &str) -> Option<&Acl> {
        self.acls.iter().find(|acl| acl.name == name)
    }

    /// The ACLs attached to the WAN or LAN port `mac`.
    pub fn port_acls(&self, mac: MacAddr) -> Option<&PortAcls> {
        self.wan(mac)
            .map(|port| &port.acls)
            .or_else(|| self.lan(mac).map(|port| &port.acls))
    }

    /// The ACL filtering `direction` on port `mac`, if one
    /// is attached.
    pub fn port_acl(&self, mac: MacAddr, direction: Direction) -> Option<&Acl> {
        let name = self.port_acls(mac)?.get(direction)?;
        self.acl(name)
    }

    /// Whether `op` can be applied to this state. Every
    /// operation the writer appends has passed this, so
    /// [`Absorb`] never has to fail.
    pub(crate) fn check(&self, op: &Op) -> Result<(), ConfigError> {
        match op {
            Op::SetWan(port) => {
                port.validate()?;
                self.check_attached(&port.acls)?;
                if self.lan(port.mac).is_some() {
                    return Err(ConfigError::MacInUse(port.mac, Role::Lan));
                }
                // WAN subnets may overlap each other: two
                // uplinks to the same ISP can lease from
                // one range. Only a LAN
                // collision is ambiguous.
                for lan in &self.lan {
                    check_overlap(wan_v4(port), lan_v4(lan), lan.mac)?;
                    check_overlap(wan_v6(port), lan_v6(lan), lan.mac)?;
                }
                Ok(())
            }
            Op::SetLan(port) => {
                port.validate()?;
                self.check_attached(&port.acls)?;
                if self.wan(port.mac).is_some() {
                    return Err(ConfigError::MacInUse(port.mac, Role::Wan));
                }
                for wan in &self.wan {
                    check_overlap(lan_v4(port), wan_v4(wan), wan.mac)?;
                    check_overlap(lan_v6(port), wan_v6(wan), wan.mac)?;
                }
                for lan in self.lan.iter().filter(|lan| lan.mac != port.mac) {
                    check_overlap(lan_v4(port), lan_v4(lan), lan.mac)?;
                    check_overlap(lan_v6(port), lan_v6(lan), lan.mac)?;
                }
                Ok(())
            }
            Op::RemoveWan(mac) => match self.wan(*mac) {
                Some(_) => Ok(()),
                None => Err(ConfigError::NotFound(*mac, Role::Wan)),
            },
            Op::RemoveLan(mac) => match self.lan(*mac) {
                Some(_) => Ok(()),
                None => Err(ConfigError::NotFound(*mac, Role::Lan)),
            },
            Op::SetAcl(acl) => acl.validate(),
            Op::RemoveAcl(name) => {
                self.existing_acl(name)?;
                match self
                    .ports_acls()
                    .find(|(_, acls)| acls.names().any(|n| n == name))
                {
                    Some((mac, _)) => Err(ConfigError::AclInUse(name.clone(), mac)),
                    None => Ok(()),
                }
            }
            Op::SetAclEntry(name, entry) => {
                self.existing_acl(name)?;
                entry.validate()
            }
            Op::RemoveAclEntry(name, seq) => match self.existing_acl(name)?.entry(*seq) {
                Some(_) => Ok(()),
                None => Err(ConfigError::AclEntryNotFound(name.clone(), *seq)),
            },
            Op::SetPortAcl(mac, _, name) => {
                if self.port_acls(*mac).is_none() {
                    return Err(ConfigError::PortNotFound(*mac));
                }
                match name {
                    Some(name) => self.existing_acl(name).map(drop),
                    None => Ok(()),
                }
            }
        }
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::SetWan(port) => upsert(&mut self.wan, port, |p| p.mac),
            Op::SetLan(port) => upsert(&mut self.lan, port, |p| p.mac),
            Op::RemoveWan(mac) => self.wan.retain(|port| port.mac != mac),
            Op::RemoveLan(mac) => self.lan.retain(|port| port.mac != mac),
            Op::SetAcl(mut acl) => {
                acl.sort();
                match self.acls.iter_mut().find(|a| a.name == acl.name) {
                    Some(slot) => *slot = acl,
                    None => self.acls.push(acl),
                }
            }
            Op::RemoveAcl(name) => self.acls.retain(|acl| acl.name != name),
            Op::SetAclEntry(name, entry) => {
                if let Some(acl) = self.acls.iter_mut().find(|acl| acl.name == name) {
                    acl.upsert(entry);
                }
            }
            Op::RemoveAclEntry(name, seq) => {
                if let Some(acl) = self.acls.iter_mut().find(|acl| acl.name == name) {
                    acl.entries.retain(|entry| entry.seq != seq);
                }
            }
            Op::SetPortAcl(mac, direction, name) => {
                let acls = match self.wan.iter_mut().find(|port| port.mac == mac) {
                    Some(port) => Some(&mut port.acls),
                    None => self
                        .lan
                        .iter_mut()
                        .find(|port| port.mac == mac)
                        .map(|port| &mut port.acls),
                };
                if let Some(acls) = acls {
                    *acls.slot(direction) = name;
                }
            }
        }
    }

    fn check_attached(&self, acls: &PortAcls) -> Result<(), ConfigError> {
        acls.names()
            .try_for_each(|name| self.existing_acl(name).map(drop))
    }

    fn ports_acls(&self) -> impl Iterator<Item = (MacAddr, &PortAcls)> {
        let wan = self.wan.iter().map(|port| (port.mac, &port.acls));
        wan.chain(self.lan.iter().map(|port| (port.mac, &port.acls)))
    }

    fn existing_acl(&self, name: &str) -> Result<&Acl, ConfigError> {
        self.acl(name)
            .ok_or_else(|| ConfigError::AclNotFound(name.to_owned()))
    }
}

/// A change to [`State`], applied once to each copy.
#[derive(Debug, Clone)]
pub(crate) enum Op {
    SetWan(WanPort),

    SetLan(LanPort),

    RemoveWan(MacAddr),

    RemoveLan(MacAddr),

    SetAcl(Acl),

    RemoveAcl(String),

    SetAclEntry(String, AclEntry),

    RemoveAclEntry(String, u32),

    SetPortAcl(MacAddr, Direction, Option<String>),
}

fn upsert<T>(ports: &mut Vec<T>, port: T, mac: impl Fn(&T) -> MacAddr) {
    match ports.iter_mut().find(|p| mac(p) == mac(&port)) {
        Some(slot) => *slot = port,
        None => ports.push(port),
    }
}

fn check_overlap<A: IpFamily>(
    subnet: Option<Cidr<A>>,
    other: Option<Cidr<A>>,
    other_mac: MacAddr,
) -> Result<(), ConfigError> {
    match (subnet, other) {
        (Some(a), Some(b)) if a.overlaps(&b) => Err(ConfigError::SubnetOverlap(
            a.to_string(),
            b.to_string(),
            other_mac,
        )),
        _ => Ok(()),
    }
}

// The subnet a port occupies per family. A DHCP WAN port
// has none until it holds a lease.

fn wan_v4(port: &WanPort) -> Option<Cidr<std::net::Ipv4Addr>> {
    match port.ipv4.as_ref()?.addressing {
        Addressing::Static { cidr, .. } => Some(cidr),
        Addressing::Dhcp => None,
    }
}

fn wan_v6(port: &WanPort) -> Option<Cidr<std::net::Ipv6Addr>> {
    match port.ipv6.as_ref()?.addressing {
        Addressing::Static { cidr, .. } => Some(cidr),
        Addressing::Dhcp => None,
    }
}

fn lan_v4(port: &LanPort) -> Option<Cidr<std::net::Ipv4Addr>> {
    Some(port.ipv4.as_ref()?.cidr)
}

fn lan_v6(port: &LanPort) -> Option<Cidr<std::net::Ipv6Addr>> {
    Some(port.ipv6.as_ref()?.cidr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        acl::tests::permit_web,
        port::tests::{LAN_MAC, WAN_MAC, lan, wan_static},
    };

    fn with(ops: impl IntoIterator<Item = Op>) -> State {
        let mut state = State::default();
        for op in ops {
            state.check(&op).unwrap();
            state.apply(op);
        }
        state
    }

    #[test]
    fn set_replaces_by_mac() {
        let state = with([
            Op::SetLan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1")),
            Op::SetLan(lan(LAN_MAC, "192.168.2.1", "fd00:2::1")),
        ]);
        assert_eq!(state.lan_ports().len(), 1);
        let cidr = state.lan(LAN_MAC).unwrap().ipv4.as_ref().unwrap().cidr;
        assert_eq!(cidr.to_string(), "192.168.2.1/24");
    }

    #[test]
    fn mac_cannot_be_wan_and_lan() {
        let state = with([Op::SetLan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1"))]);
        let op = Op::SetWan(wan_static(LAN_MAC, "203.0.113.2", "203.0.113.1"));
        assert_eq!(
            state.check(&op),
            Err(ConfigError::MacInUse(LAN_MAC, Role::Lan))
        );
    }

    #[test]
    fn lan_subnets_must_not_overlap() {
        let other = MacAddr([0x02, 0, 0, 0, 0, 0x03]);
        let state = with([
            Op::SetLan(lan(LAN_MAC, "192.168.1.1", "fd00:1::1")),
            Op::SetWan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1")),
        ]);

        let op = Op::SetLan(lan(other, "192.168.1.2", "fd00:9::1"));
        assert!(matches!(
            state.check(&op),
            Err(ConfigError::SubnetOverlap(..))
        ));

        let op = Op::SetLan(lan(other, "203.0.113.5", "fd00:9::1"));
        assert!(matches!(
            state.check(&op),
            Err(ConfigError::SubnetOverlap(..))
        ));

        // Replacing a port does not collide with its old
        // self.
        let op = Op::SetLan(lan(LAN_MAC, "192.168.1.2", "fd00:1::2"));
        assert_eq!(state.check(&op), Ok(()));
    }

    #[test]
    fn remove_requires_existing_port() {
        let state = with([Op::SetWan(wan_static(
            WAN_MAC,
            "203.0.113.2",
            "203.0.113.1",
        ))]);
        assert_eq!(
            state.check(&Op::RemoveLan(WAN_MAC)),
            Err(ConfigError::NotFound(WAN_MAC, Role::Lan))
        );
        let state = with([
            Op::SetWan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1")),
            Op::RemoveWan(WAN_MAC),
        ]);
        assert!(state.wan_ports().is_empty());
    }

    #[test]
    fn acl_entries_stay_sorted() {
        let mut acl = Acl::new("lan-in");
        acl.entries = vec![permit_web(30), permit_web(10)];
        let state = with([
            Op::SetAcl(acl),
            Op::SetAclEntry("lan-in".to_owned(), permit_web(20)),
            Op::RemoveAclEntry("lan-in".to_owned(), 30),
        ]);
        let seqs: Vec<u32> = state
            .acl("lan-in")
            .unwrap()
            .entries
            .iter()
            .map(|e| e.seq)
            .collect();
        assert_eq!(seqs, [10, 20]);
    }

    #[test]
    fn acl_ops_need_existing_acl() {
        let state = State::default();
        let missing = ConfigError::AclNotFound("nope".to_owned());
        assert_eq!(
            state.check(&Op::RemoveAcl("nope".to_owned())),
            Err(missing.clone())
        );
        assert_eq!(
            state.check(&Op::SetAclEntry("nope".to_owned(), permit_web(10))),
            Err(missing)
        );

        let state = with([Op::SetAcl(Acl::new("empty"))]);
        assert_eq!(
            state.check(&Op::RemoveAclEntry("empty".to_owned(), 10)),
            Err(ConfigError::AclEntryNotFound("empty".to_owned(), 10))
        );
    }

    #[test]
    fn attached_acl_must_exist_and_cannot_be_removed() {
        let mut port = lan(LAN_MAC, "192.168.1.1", "fd00:1::1");
        port.acls.inbound = Some("lan-in".to_owned());
        assert_eq!(
            State::default().check(&Op::SetLan(port.clone())),
            Err(ConfigError::AclNotFound("lan-in".to_owned()))
        );

        let state = with([Op::SetAcl(Acl::new("lan-in")), Op::SetLan(port)]);
        assert_eq!(
            state
                .port_acl(LAN_MAC, Direction::Inbound)
                .map(|acl| acl.name.as_str()),
            Some("lan-in")
        );
        assert!(state.port_acl(LAN_MAC, Direction::Outbound).is_none());
        assert_eq!(
            state.check(&Op::RemoveAcl("lan-in".to_owned())),
            Err(ConfigError::AclInUse("lan-in".to_owned(), LAN_MAC))
        );
    }

    #[test]
    fn set_port_acl_attaches_and_detaches() {
        let state = with([
            Op::SetAcl(Acl::new("wan-in")),
            Op::SetWan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1")),
            Op::SetPortAcl(WAN_MAC, Direction::Inbound, Some("wan-in".to_owned())),
        ]);
        assert!(state.port_acl(WAN_MAC, Direction::Inbound).is_some());

        assert_eq!(
            state.check(&Op::SetPortAcl(LAN_MAC, Direction::Inbound, None)),
            Err(ConfigError::PortNotFound(LAN_MAC))
        );

        let state = with([
            Op::SetAcl(Acl::new("wan-in")),
            Op::SetWan(wan_static(WAN_MAC, "203.0.113.2", "203.0.113.1")),
            Op::SetPortAcl(WAN_MAC, Direction::Inbound, Some("wan-in".to_owned())),
            Op::SetPortAcl(WAN_MAC, Direction::Inbound, None),
            Op::RemoveAcl("wan-in".to_owned()),
        ]);
        assert!(state.acls().is_empty());
    }
}
