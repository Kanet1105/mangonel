//! Next-hop MAC addresses, learned from ARP.
//!
//! An ARP reply reaches whichever worker owns the queue it
//! hashed to, but every worker forwards to that neighbour,
//! so the table is shared. It changes rarely: workers keep
//! a private copy to look up in and take the lock only to
//! refresh it when the generation moves.

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

/// How long an entry is trusted after the neighbour last
/// spoke ARP.
const LIFETIME: Duration = Duration::from_secs(300);
/// How long before an entry lapses its neighbour is asked
/// to speak again, so one in use is not forgotten.
const REFRESH: Duration = Duration::from_secs(30);
/// How long a neighbour asked is given before it is asked
/// once more.
const PATIENCE: Duration = Duration::from_secs(5);
/// Entries held at most, so a segment cannot grow the table
/// without bound.
const CAPACITY: usize = 4096;

/// A neighbour's address, by the port it is on.
pub(crate) type Table = HashMap<(usize, Ipv4Addr), [u8; 6]>;

struct Entry {
    mac: [u8; 6],
    expires: Instant,
    /// When the neighbour was last asked to speak again.
    asked: Option<Instant>,
}

/// Every worker's neighbours.
pub(crate) struct Neighbors {
    /// Moves whenever a lookup could answer differently.
    generation: AtomicU64,
    entries: Mutex<HashMap<(usize, Ipv4Addr), Entry>>,
}

impl Neighbors {
    pub(crate) fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            entries: Mutex::default(),
        }
    }

    /// A number that differs from an earlier one if the
    /// table changed in between.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Records that `address` on `port` answers at `mac`.
    pub(crate) fn learn(&self, port: usize, address: Ipv4Addr, mac: [u8; 6], now: Instant) {
        let mut entries = self.lock();
        let expires = now + LIFETIME;
        if let Some(entry) = entries.get_mut(&(port, address)) {
            entry.expires = expires;
            entry.asked = None;
            if entry.mac != mac {
                entry.mac = mac;
                self.advance();
            }
        } else if entries.len() < CAPACITY {
            entries.insert(
                (port, address),
                Entry {
                    mac,
                    expires,
                    asked: None,
                },
            );
            self.advance();
        }
    }

    /// Every neighbour, with the generation the copy is
    /// current as of.
    pub(crate) fn snapshot(&self) -> (u64, Table) {
        let entries = self.lock();
        let table = entries
            .iter()
            .map(|(key, entry)| (*key, entry.mac))
            .collect();

        (self.generation(), table)
    }

    /// The neighbours about to lapse that have not been
    /// asked to speak lately. The caller asks them now.
    pub(crate) fn lapsing(&self, now: Instant) -> Vec<(usize, Ipv4Addr)> {
        let mut entries = self.lock();

        entries
            .iter_mut()
            .filter(|(_, entry)| {
                entry.expires.saturating_duration_since(now) <= REFRESH
                    && entry
                        .asked
                        .is_none_or(|asked| now.saturating_duration_since(asked) >= PATIENCE)
            })
            .map(|(key, entry)| {
                entry.asked = Some(now);

                *key
            })
            .collect()
    }

    /// Forgets neighbours not heard from for a lifetime.
    pub(crate) fn expire(&self, now: Instant) {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() != before {
            self.advance();
        }
    }

    /// Called with the lock held, so a snapshot's generation
    /// matches its entries.
    fn advance(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(usize, Ipv4Addr), Entry>> {
        // The map is consistent between statements, so one
        // left by a panicking worker is still usable.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
    const MAC: [u8; 6] = [2, 0, 0, 4, 0, 7];

    #[test]
    fn a_learned_neighbour_shows_in_the_next_snapshot() {
        let neighbors = Neighbors::new();
        let (before, table) = neighbors.snapshot();
        assert!(table.is_empty());

        neighbors.learn(1, HOST, MAC, Instant::now());
        assert_ne!(neighbors.generation(), before);
        let (generation, table) = neighbors.snapshot();
        assert_eq!(generation, neighbors.generation());
        assert_eq!(table.get(&(1, HOST)), Some(&MAC));
        // The same address on another port is someone else.
        assert_eq!(table.get(&(2, HOST)), None);
    }

    #[test]
    fn hearing_the_same_again_changes_nothing_but_the_lifetime() {
        let neighbors = Neighbors::new();
        let start = Instant::now();
        neighbors.learn(1, HOST, MAC, start);
        let generation = neighbors.generation();

        neighbors.learn(1, HOST, MAC, start + LIFETIME / 2);
        assert_eq!(neighbors.generation(), generation);
        neighbors.expire(start + LIFETIME);
        assert_eq!(neighbors.snapshot().1.len(), 1);

        neighbors.expire(start + LIFETIME * 2);
        assert!(neighbors.snapshot().1.is_empty());
        assert_ne!(neighbors.generation(), generation);
    }

    #[test]
    fn a_neighbour_about_to_lapse_is_due_a_question() {
        let neighbors = Neighbors::new();
        let start = Instant::now();
        neighbors.learn(1, HOST, MAC, start);
        assert!(neighbors.lapsing(start + LIFETIME - REFRESH * 2).is_empty());

        // Asked once, then again only after a while.
        let due = start + LIFETIME - REFRESH;
        assert_eq!(neighbors.lapsing(due), [(1, HOST)]);
        assert!(neighbors.lapsing(due + PATIENCE / 2).is_empty());
        assert_eq!(neighbors.lapsing(due + PATIENCE), [(1, HOST)]);

        // Its answer settles it for another lifetime.
        neighbors.learn(1, HOST, MAC, due + PATIENCE);
        assert!(neighbors.lapsing(due + PATIENCE * 2).is_empty());
        neighbors.expire(start + LIFETIME);
        assert_eq!(neighbors.snapshot().1.len(), 1);
    }

    #[test]
    fn a_moved_address_replaces_its_entry() {
        let neighbors = Neighbors::new();
        let now = Instant::now();
        neighbors.learn(1, HOST, MAC, now);
        let generation = neighbors.generation();

        let moved = [2, 0, 0, 4, 0, 8];
        neighbors.learn(1, HOST, moved, now);
        assert_ne!(neighbors.generation(), generation);
        assert_eq!(neighbors.snapshot().1.get(&(1, HOST)), Some(&moved));
    }

    #[test]
    fn a_full_table_takes_no_new_neighbours() {
        let neighbors = Neighbors::new();
        let now = Instant::now();
        for host in 0..=CAPACITY {
            let address = Ipv4Addr::from(0x0A00_0000 + u32::try_from(host).unwrap());
            neighbors.learn(1, address, MAC, now);
        }
        assert_eq!(neighbors.snapshot().1.len(), CAPACITY);
    }
}
