//! Access control per direction: a control-plane [`Filter`]
//! edits rules, workers check packets through lock-free
//! [`FilterReader`]s over left-right. Rate limits are
//! published as policy; their buckets live in each reader.

use std::{
    collections::HashMap,
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};

pub use crate::{prefix::Prefix, wire::Tuple};

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

/// A token bucket: `rate` packets per second, holding up
/// to `burst`. Each reader keeps its own, so a limit is per
/// worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limit {
    pub rate: u64,
    pub burst: u64,
}

/// What a rule matches; `None` and full ranges match
/// anything, in either address family. A limited rule
/// stops matching while its bucket is empty, so evaluation
/// falls through to the next rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub source: Option<Prefix>,
    pub destination: Option<Prefix>,
    pub protocol: Option<u8>,
    pub source_port: RangeInclusive<u16>,
    pub destination_port: RangeInclusive<u16>,
    pub limit: Option<Limit>,
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
            limit: None,
            action,
        }
    }

    fn matches(&self, tuple: &Tuple) -> bool {
        self.protocol
            .is_none_or(|protocol| protocol == tuple.protocol)
            && self
                .source
                .is_none_or(|prefix| prefix.contains(tuple.source))
            && self
                .destination
                .is_none_or(|prefix| prefix.contains(tuple.destination))
            && self.source_port.contains(&tuple.source_port)
            && self.destination_port.contains(&tuple.destination_port)
    }
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
            buckets: Buckets::default(),
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
/// edit. `Send`, not `Sync`; clone one per thread. Holds
/// the worker's token buckets, so clones do not share
/// limits.
pub struct FilterReader {
    read: ReadHandle<Table>,
    buckets: Buckets,
}

impl Clone for FilterReader {
    fn clone(&self) -> Self {
        Self {
            read: self.read.clone(),
            buckets: Buckets::default(),
        }
    }
}

impl FilterReader {
    /// Pins the published rules for a batch of checks;
    /// `None` once the [`Filter`] is dropped. Drop the
    /// snapshot promptly: the writer's next publish waits
    /// for it.
    pub fn snapshot(&mut self) -> Option<Snapshot<'_>> {
        let guard = self.read.enter()?;
        self.buckets.prune(&guard);

        Some(Snapshot {
            guard,
            buckets: &mut self.buckets,
        })
    }

    /// Fails closed once the [`Filter`] is dropped.
    pub fn check(&mut self, direction: Direction, tuple: &Tuple, now: Instant) -> Action {
        self.snapshot().map_or(Action::Deny, |mut snapshot| {
            snapshot.check(direction, tuple, now)
        })
    }
}

pub struct Snapshot<'a> {
    guard: ReadGuard<'a, Table>,
    buckets: &'a mut Buckets,
}

impl Snapshot<'_> {
    /// First matching rule wins, else the direction's default.
    pub fn check(&mut self, direction: Direction, tuple: &Tuple, now: Instant) -> Action {
        let chain = self.guard.chain(direction);
        for (id, rule) in &chain.rules {
            if !rule.matches(tuple) {
                continue;
            }
            if let Some(limit) = rule.limit
                && !self.buckets.take(*id, limit, now)
            {
                continue;
            }

            return rule.action;
        }

        chain.default
    }
}

/// One bucket per limited rule this reader has seen.
#[derive(Default)]
struct Buckets {
    buckets: HashMap<RuleId, Bucket>,
}

impl Buckets {
    /// Takes one token from `id`'s bucket, made full on
    /// first sight or when its limit changed.
    fn take(&mut self, id: RuleId, limit: Limit, now: Instant) -> bool {
        let bucket = self
            .buckets
            .entry(id)
            .and_modify(|bucket| {
                if bucket.limit != limit {
                    *bucket = Bucket::new(limit, now);
                }
            })
            .or_insert_with(|| Bucket::new(limit, now));

        bucket.take(now)
    }

    /// Drops buckets of removed rules once they outnumber
    /// the rules, so a churning rule set cannot grow this.
    fn prune(&mut self, table: &Table) {
        let rules = table.ingress.rules.len() + table.egress.rules.len();
        if self.buckets.len() <= rules {
            return;
        }
        self.buckets.retain(|id, _| {
            table.ingress.position(*id).is_some() || table.egress.position(*id).is_some()
        });
    }
}

/// Tokens are scaled by [`Self::SCALE`] so refill needs no
/// division per packet.
struct Bucket {
    limit: Limit,
    tokens: u128,
    filled: Instant,
}

impl Bucket {
    const SCALE: u128 = 1_000_000_000;

    fn new(limit: Limit, now: Instant) -> Self {
        Self {
            limit,
            tokens: u128::from(limit.burst) * Self::SCALE,
            filled: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.filled);
        if elapsed > Duration::ZERO {
            let cap = u128::from(self.limit.burst) * Self::SCALE;
            self.tokens = (self.tokens + elapsed.as_nanos() * u128::from(self.limit.rate)).min(cap);
            self.filled = now;
        }
        if self.tokens < Self::SCALE {
            return false;
        }
        self.tokens -= Self::SCALE;

        true
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
    use std::{net::IpAddr, thread};

    use super::*;

    const TCP: u8 = 6;
    const UDP: u8 = 17;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn packet(source: &str, destination: &str, protocol: u8, destination_port: u16) -> Tuple {
        Tuple {
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
        let mut reader = filter.reader();
        let now = Instant::now();
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
        assert_eq!(reader.check(Direction::Ingress, &v6_in, now), Action::Deny);
        assert_eq!(
            reader.check(Direction::Ingress, &v6_out, now),
            Action::Allow
        );
        assert_eq!(reader.check(Direction::Ingress, &v4, now), Action::Allow);
    }

    #[test]
    fn empty_filter_denies_until_default_changes() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
        filter.set_default(Direction::Ingress, Action::Allow);
        assert_eq!(filter.default_action(Direction::Ingress), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(reader.check(Direction::Egress, &p, now), Action::Deny);
    }

    #[test]
    fn first_match_wins_and_directions_are_separate() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        filter.insert(Direction::Ingress, deny_ssh_from("192.168.1.0"));
        filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let ssh = packet("192.168.1.9", "10.0.0.1", TCP, 22);
        let http = packet("192.168.1.9", "10.0.0.1", TCP, 80);
        let ssh_udp = packet("192.168.1.9", "10.0.0.1", UDP, 22);
        let ssh_elsewhere = packet("192.168.2.9", "10.0.0.1", TCP, 22);
        assert_eq!(reader.check(Direction::Ingress, &ssh, now), Action::Deny);
        assert_eq!(reader.check(Direction::Ingress, &http, now), Action::Allow);
        assert_eq!(
            reader.check(Direction::Ingress, &ssh_udp, now),
            Action::Allow
        );
        assert_eq!(
            reader.check(Direction::Ingress, &ssh_elsewhere, now),
            Action::Allow
        );
        assert_eq!(reader.check(Direction::Egress, &http, now), Action::Deny);
    }

    #[test]
    fn crud_round_trip() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        let allow = filter.insert(Direction::Egress, Rule::any(Action::Allow));
        let deny = filter
            .insert_before(Direction::Egress, allow, deny_ssh_from("10.0.0.0"))
            .unwrap();
        let ssh = packet("10.0.0.5", "1.1.1.1", TCP, 22);
        assert_eq!(reader.check(Direction::Egress, &ssh, now), Action::Deny);
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
        assert_eq!(reader.check(Direction::Egress, &ssh, now), Action::Allow);

        assert_eq!(
            filter.remove(Direction::Egress, allow),
            Ok(Rule::any(Action::Allow))
        );
        assert_eq!(reader.check(Direction::Egress, &ssh, now), Action::Deny);
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
        let mut reader = filter.reader();
        let now = Instant::now();
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        drop(filter);
        assert!(reader.snapshot().is_none());
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
    }

    fn limited(rate: u64, burst: u64, action: Action) -> Rule {
        Rule {
            limit: Some(Limit { rate, burst }),
            ..Rule::any(action)
        }
    }

    #[test]
    fn exhausted_limit_falls_through() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        filter.insert(Direction::Ingress, limited(1, 3, Action::Allow));
        filter.insert(Direction::Ingress, Rule::any(Action::Deny));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        for _ in 0..3 {
            assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        }
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
        let later = now + Duration::from_millis(1500);
        assert_eq!(reader.check(Direction::Ingress, &p, later), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p, later), Action::Deny);
        let much_later = later + Duration::from_secs(60);
        for _ in 0..3 {
            assert_eq!(
                reader.check(Direction::Ingress, &p, much_later),
                Action::Allow
            );
        }
        assert_eq!(
            reader.check(Direction::Ingress, &p, much_later),
            Action::Deny
        );
    }

    #[test]
    fn zero_burst_never_matches() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        filter.insert(Direction::Ingress, limited(100, 0, Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
        assert_eq!(
            reader.check(Direction::Ingress, &p, now + Duration::from_secs(5)),
            Action::Deny
        );
    }

    #[test]
    fn changed_limit_refills_the_bucket() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        let id = filter.insert(Direction::Ingress, limited(0, 1, Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
        filter
            .update(Direction::Ingress, id, limited(0, 2, Action::Allow))
            .unwrap();
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(reader.check(Direction::Ingress, &p, now), Action::Deny);
    }

    #[test]
    fn readers_do_not_share_buckets() {
        let mut filter = Filter::new();
        let mut a = filter.reader();
        let mut b = a.clone();
        let now = Instant::now();
        filter.insert(Direction::Ingress, limited(0, 1, Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        assert_eq!(a.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(a.check(Direction::Ingress, &p, now), Action::Deny);
        assert_eq!(b.check(Direction::Ingress, &p, now), Action::Allow);
    }

    #[test]
    fn buckets_of_removed_rules_are_pruned() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        for _ in 0..4 {
            let id = filter.insert(Direction::Ingress, limited(0, 1, Action::Allow));
            reader.check(Direction::Ingress, &p, now);
            filter.remove(Direction::Ingress, id).unwrap();
        }
        filter.insert(Direction::Ingress, limited(0, 1, Action::Allow));
        reader.check(Direction::Ingress, &p, now);
        assert_eq!(reader.buckets.buckets.len(), 1);
    }

    #[test]
    fn snapshot_serves_a_batch() {
        let mut filter = Filter::new();
        let mut reader = filter.reader();
        let now = Instant::now();
        filter.insert(Direction::Ingress, limited(0, 2, Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        let mut snapshot = reader.snapshot().unwrap();
        assert_eq!(snapshot.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(snapshot.check(Direction::Ingress, &p, now), Action::Allow);
        assert_eq!(snapshot.check(Direction::Ingress, &p, now), Action::Deny);
    }

    #[test]
    fn readers_move_to_other_threads() {
        let mut filter = Filter::new();
        filter.insert(Direction::Ingress, Rule::any(Action::Allow));
        let p = packet("10.0.0.1", "10.0.0.2", UDP, 53);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let mut reader = filter.reader();
                let now = Instant::now();
                thread::spawn(move || reader.check(Direction::Ingress, &p, now))
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Action::Allow);
        }
        filter.set_default(Direction::Egress, Action::Allow);
    }
}
