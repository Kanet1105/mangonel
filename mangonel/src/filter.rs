//! Access control per direction: a control-plane [`Filter`]
//! edits rules, workers check packets through lock-free
//! [`FilterReader`]s over left-right.

use std::{net::IpAddr, ops::RangeInclusive};

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};

pub use crate::prefix::Prefix;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress,
    Egress,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Action {
    Allow,
    #[default]
    Deny,
}

/// What a rule matches; `None` and full ranges match
/// anything, in either address family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub source: Option<Prefix>,
    pub destination: Option<Prefix>,
    pub protocol: Option<u8>,
    pub source_port: RangeInclusive<u16>,
    pub destination_port: RangeInclusive<u16>,
    pub action: Action,
}

impl Rule {
    /// Matches every packet.
    pub fn any(action: Action) -> Self {
        Self {
            source: None,
            destination: None,
            protocol: None,
            source_port: 0..=u16::MAX,
            destination_port: 0..=u16::MAX,
            action,
        }
    }

    fn matches(&self, packet: &Packet) -> bool {
        self.protocol
            .is_none_or(|protocol| protocol == packet.protocol)
            && self
                .source
                .is_none_or(|prefix| prefix.contains(packet.source))
            && self
                .destination
                .is_none_or(|prefix| prefix.contains(packet.destination))
            && self.source_port.contains(&packet.source_port)
            && self.destination_port.contains(&packet.destination_port)
    }
}

/// The fields a packet is filtered on. Ports are zero for
/// protocols without them; `protocol` is the IPv4 protocol
/// or the IPv6 next header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Packet {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

/// Unique for the lifetime of the [`Filter`] that issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(u64);

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum FilterError {
    #[error("No rule with id {0:?} in that direction.")]
    UnknownRule(RuleId),
}

/// The writer. Every edit is published before it returns.
pub struct Filter {
    write: WriteHandle<Table, Op>,
    next_id: u64,
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter {
    /// Both directions start empty and denying.
    pub fn new() -> Self {
        let (write, _) = left_right::new();

        Self { write, next_id: 0 }
    }

    /// One per worker thread.
    pub fn reader(&self) -> FilterReader {
        FilterReader {
            read: ReadHandle::clone(&self.write),
        }
    }

    /// Appends `rule` after every existing rule in `direction`.
    pub fn insert(&mut self, direction: Direction, rule: Rule) -> RuleId {
        let id = self.next_id();
        self.commit(Op::Insert {
            direction,
            before: None,
            id,
            rule,
        });

        id
    }

    pub fn insert_before(
        &mut self,
        direction: Direction,
        before: RuleId,
        rule: Rule,
    ) -> Result<RuleId, FilterError> {
        self.get(direction, before)
            .ok_or(FilterError::UnknownRule(before))?;
        let id = self.next_id();
        self.commit(Op::Insert {
            direction,
            before: Some(before),
            id,
            rule,
        });

        Ok(id)
    }

    pub fn get(&self, direction: Direction, id: RuleId) -> Option<Rule> {
        self.table().chain(direction).get(id).cloned()
    }

    /// In match order.
    pub fn rules(&self, direction: Direction) -> Vec<(RuleId, Rule)> {
        self.table().chain(direction).rules.clone()
    }

    pub fn update(
        &mut self,
        direction: Direction,
        id: RuleId,
        rule: Rule,
    ) -> Result<(), FilterError> {
        self.get(direction, id)
            .ok_or(FilterError::UnknownRule(id))?;
        self.commit(Op::Update {
            direction,
            id,
            rule,
        });

        Ok(())
    }

    pub fn remove(&mut self, direction: Direction, id: RuleId) -> Result<Rule, FilterError> {
        let rule = self
            .get(direction, id)
            .ok_or(FilterError::UnknownRule(id))?;
        self.commit(Op::Remove { direction, id });

        Ok(rule)
    }

    /// What a packet no rule matches gets.
    pub fn default_action(&self, direction: Direction) -> Action {
        self.table().chain(direction).default
    }

    pub fn set_default(&mut self, direction: Direction, action: Action) {
        self.commit(Op::SetDefault { direction, action });
    }

    fn next_id(&mut self) -> RuleId {
        let id = RuleId(self.next_id);
        self.next_id += 1;

        id
    }

    fn commit(&mut self, op: Op) {
        self.write.append(op);
        self.write.publish();
    }

    fn table(&self) -> ReadGuard<'_, Table> {
        self.write.enter().expect(
            "The write handle is alive, so its read handle cannot be dropped. This is a bug.",
        )
    }
}

/// A worker's view: never blocks, never sees a half-applied
/// edit. `Send`, not `Sync`; clone one per thread.
#[derive(Clone)]
pub struct FilterReader {
    read: ReadHandle<Table>,
}

impl FilterReader {
    /// Pins the published rules for a batch of checks;
    /// `None` once the [`Filter`] is dropped. Drop the
    /// snapshot promptly: the writer's next publish waits
    /// for it.
    pub fn snapshot(&self) -> Option<Snapshot<'_>> {
        self.read.enter().map(|guard| Snapshot { guard })
    }

    /// Fails closed once the [`Filter`] is dropped.
    pub fn check(&self, direction: Direction, packet: &Packet) -> Action {
        self.snapshot()
            .map_or(Action::Deny, |snapshot| snapshot.check(direction, packet))
    }
}

pub struct Snapshot<'a> {
    guard: ReadGuard<'a, Table>,
}

impl Snapshot<'_> {
    /// First matching rule wins, else the direction's default.
    pub fn check(&self, direction: Direction, packet: &Packet) -> Action {
        self.guard.chain(direction).check(packet)
    }
}

#[derive(Clone, Default)]
struct Table {
    ingress: Chain,
    egress: Chain,
}

impl Table {
    fn chain(&self, direction: Direction) -> &Chain {
        match direction {
            Direction::Ingress => &self.ingress,
            Direction::Egress => &self.egress,
        }
    }

    fn chain_mut(&mut self, direction: Direction) -> &mut Chain {
        match direction {
            Direction::Ingress => &mut self.ingress,
            Direction::Egress => &mut self.egress,
        }
    }
}

#[derive(Clone, Default)]
struct Chain {
    rules: Vec<(RuleId, Rule)>,
    default: Action,
}

impl Chain {
    fn check(&self, packet: &Packet) -> Action {
        self.rules
            .iter()
            .find(|(_, rule)| rule.matches(packet))
            .map_or(self.default, |(_, rule)| rule.action)
    }

    fn get(&self, id: RuleId) -> Option<&Rule> {
        self.position(id).map(|i| &self.rules[i].1)
    }

    fn position(&self, id: RuleId) -> Option<usize> {
        self.rules.iter().position(|(rule_id, _)| *rule_id == id)
    }
}

/// Validated by [`Filter`] before it is appended, so applying
/// it cannot fail on either copy.
#[derive(Clone)]
enum Op {
    Insert {
        direction: Direction,
        before: Option<RuleId>,
        id: RuleId,
        rule: Rule,
    },
    Update {
        direction: Direction,
        id: RuleId,
        rule: Rule,
    },
    Remove {
        direction: Direction,
        id: RuleId,
    },
    SetDefault {
        direction: Direction,
        action: Action,
    },
}

impl Absorb<Op> for Table {
    fn absorb_first(&mut self, op: &mut Op, _: &Self) {
        match op.clone() {
            Op::Insert {
                direction,
                before,
                id,
                rule,
            } => {
                let chain = self.chain_mut(direction);
                let at = before
                    .and_then(|before| chain.position(before))
                    .unwrap_or(chain.rules.len());
                chain.rules.insert(at, (id, rule));
            }
            Op::Update {
                direction,
                id,
                rule,
            } => {
                let chain = self.chain_mut(direction);
                if let Some(at) = chain.position(id) {
                    chain.rules[at].1 = rule;
                }
            }
            Op::Remove { direction, id } => {
                self.chain_mut(direction)
                    .rules
                    .retain(|(rule_id, _)| *rule_id != id);
            }
            Op::SetDefault { direction, action } => {
                self.chain_mut(direction).default = action;
            }
        }
    }

    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    const TCP: u8 = 6;
    const UDP: u8 = 17;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn packet(source: &str, destination: &str, protocol: u8, destination_port: u16) -> Packet {
        Packet {
            source: ip(source),
            destination: ip(destination),
            protocol,
            source_port: 40000,
            destination_port,
        }
    }

    fn deny_ssh_from(source: &str) -> Rule {
        Rule {
            source: Some(Prefix::new(ip(source), 24).unwrap()),
            protocol: Some(TCP),
            destination_port: 22..=22,
            ..Rule::any(Action::Deny)
        }
    }

    #[test]
    fn families_share_a_chain() {
        let mut filter = Filter::new();
        let reader = filter.reader();
        filter.insert(
            Direction::Ingress,
            Rule {
                source: Some(Prefix::new(ip("2001:db8::"), 32).unwrap()),
                ..Rule::any(Action::Deny)
            },
        );
        filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let v6_in = packet("2001:db8::9", "2001:db8:ff::1", TCP, 443);
        let v6_out = packet("2001:db9::9", "2001:db8:ff::1", TCP, 443);
        let v4 = packet("10.0.0.9", "10.0.0.1", TCP, 443);
        assert_eq!(reader.check(Direction::Ingress, &v6_in), Action::Deny);
        assert_eq!(reader.check(Direction::Ingress, &v6_out), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &v4), Action::Allow);
    }

    #[test]
    fn empty_filter_denies_until_default_changes() {
        let mut filter = Filter::new();
        let reader = filter.reader();
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p), Action::Deny);
        filter.set_default(Direction::Ingress, Action::Allow);
        assert_eq!(filter.default_action(Direction::Ingress), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p), Action::Allow);
        assert_eq!(reader.check(Direction::Egress, &p), Action::Deny);
    }

    #[test]
    fn first_match_wins_and_directions_are_separate() {
        let mut filter = Filter::new();
        let reader = filter.reader();
        filter.insert(Direction::Ingress, deny_ssh_from("192.168.1.0"));
        filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let ssh = packet("192.168.1.9", "10.0.0.1", TCP, 22);
        let http = packet("192.168.1.9", "10.0.0.1", TCP, 80);
        let ssh_udp = packet("192.168.1.9", "10.0.0.1", UDP, 22);
        let ssh_elsewhere = packet("192.168.2.9", "10.0.0.1", TCP, 22);
        assert_eq!(reader.check(Direction::Ingress, &ssh), Action::Deny);
        assert_eq!(reader.check(Direction::Ingress, &http), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &ssh_udp), Action::Allow);
        assert_eq!(
            reader.check(Direction::Ingress, &ssh_elsewhere),
            Action::Allow
        );
        assert_eq!(reader.check(Direction::Egress, &http), Action::Deny);
    }

    #[test]
    fn crud_round_trip() {
        let mut filter = Filter::new();
        let reader = filter.reader();
        let allow = filter.insert(Direction::Egress, Rule::any(Action::Allow));
        let deny = filter
            .insert_before(Direction::Egress, allow, deny_ssh_from("10.0.0.0"))
            .unwrap();
        let ssh = packet("10.0.0.5", "1.1.1.1", TCP, 22);
        assert_eq!(reader.check(Direction::Egress, &ssh), Action::Deny);
        assert_eq!(
            filter
                .rules(Direction::Egress)
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            [deny, allow]
        );
        assert_eq!(
            filter.get(Direction::Egress, deny),
            Some(deny_ssh_from("10.0.0.0"))
        );
        assert_eq!(filter.get(Direction::Ingress, deny), None);

        let mut updated = deny_ssh_from("10.0.0.0");
        updated.destination_port = 23..=23;
        filter
            .update(Direction::Egress, deny, updated.clone())
            .unwrap();
        assert_eq!(filter.get(Direction::Egress, deny), Some(updated));
        assert_eq!(reader.check(Direction::Egress, &ssh), Action::Allow);

        assert_eq!(
            filter.remove(Direction::Egress, allow),
            Ok(Rule::any(Action::Allow))
        );
        assert_eq!(reader.check(Direction::Egress, &ssh), Action::Deny);
        assert_eq!(filter.rules(Direction::Egress).len(), 1);
    }

    #[test]
    fn unknown_ids_are_rejected() {
        let mut filter = Filter::new();
        let id = filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let missing = RuleId(99);
        assert_eq!(
            filter.update(Direction::Ingress, missing, Rule::any(Action::Deny)),
            Err(FilterError::UnknownRule(missing))
        );
        assert_eq!(
            filter.remove(Direction::Egress, id),
            Err(FilterError::UnknownRule(id))
        );
        assert_eq!(
            filter.insert_before(Direction::Ingress, missing, Rule::any(Action::Deny)),
            Err(FilterError::UnknownRule(missing))
        );
        assert_eq!(filter.rules(Direction::Ingress).len(), 1);
    }

    #[test]
    fn ids_are_never_reused() {
        let mut filter = Filter::new();
        let first = filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        filter.remove(Direction::Ingress, first).unwrap();
        let second = filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        assert_ne!(first, second);
    }

    #[test]
    fn reader_fails_closed_after_writer_drops() {
        let filter = {
            let mut filter = Filter::new();
            filter.set_default(Direction::Ingress, Action::Allow);
            filter
        };
        let reader = filter.reader();
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p), Action::Allow);
        drop(filter);
        assert!(reader.snapshot().is_none());
        assert_eq!(reader.check(Direction::Ingress, &p), Action::Deny);
    }

    #[test]
    fn readers_move_to_other_threads() {
        let mut filter = Filter::new();
        filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let reader = filter.reader();
                thread::spawn(move || reader.check(Direction::Ingress, &p))
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Action::Allow);
        }
        filter.set_default(Direction::Egress, Action::Allow);
    }
}
