//! A small seedable generator for transaction ids and
//! retransmission jitter.

use std::{
    hash::{
        BuildHasher,
        Hasher,
        RandomState,
    },
    time::Duration,
};

/// xorshift64*: cheap, seedable, and plenty for ids and jitter.
#[derive(Debug, Clone)]
pub(crate) struct Rng(u64);

impl Rng {
    /// A generator whose sequence `seed` fixes.
    pub(crate) fn seeded(seed: u64) -> Self {
        // xorshift never leaves zero, so map it elsewhere.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// A generator seeded from the standard library's entropy.
    pub(crate) fn from_entropy() -> Self {
        Self::seeded(RandomState::new().build_hasher().finish())
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;

        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() >> 32)
            .expect("a u64 shifted by 32 fits a u32. This is a bug.")
    }

    /// A duration drawn uniformly from `0..=range`.
    pub(crate) fn within(&mut self, range: Duration) -> Duration {
        let nanos = u64::try_from(range.as_nanos()).unwrap_or(u64::MAX);
        if nanos == 0 {
            return Duration::ZERO;
        }

        Duration::from_nanos(self.next_u64() % nanos.saturating_add(1))
    }

    /// A duration drawn uniformly from `base - spread..=base + spread`.
    pub(crate) fn around(&mut self, base: Duration, spread: Duration) -> Duration {
        base.saturating_sub(spread) + self.within(spread * 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_and_bounded() {
        let (mut a, mut b) = (Rng::seeded(7), Rng::seeded(7));
        assert_eq!(a.next_u32(), b.next_u32());
        let (base, spread) = (Duration::from_secs(4), Duration::from_secs(1));
        for _ in 0..100 {
            let d = a.around(base, spread);
            assert!(d >= base - spread && d <= base + spread);
        }
        assert_eq!(a.within(Duration::ZERO), Duration::ZERO);
    }
}
