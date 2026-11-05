//! Rate limits (token buckets) used against protocol abuse (v0.7).
//!
//! A [`TokenBucket`] holds up to `burst` tokens and refills at `per_sec`
//! tokens per second; each action takes one token, and an action with no
//! token left is refused. [`KeyedBuckets`] keeps one bucket per key (for
//! example per client IP address) with a bound on how many keys it tracks,
//! so the limiter itself cannot be used to exhaust memory.
//!
//! Where they are used:
//! - entry relays: circuit creations per client IP address;
//! - rendezvous-role relays: introductions per introduction point;
//! - hidden-service hosts: introductions processed per second.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Instant;

/// A rate: `per_sec` actions per second on average, bursts up to `burst`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rate {
    pub per_sec: f64,
    pub burst: u32,
}

impl Rate {
    pub const fn new(per_sec: f64, burst: u32) -> Self {
        Self { per_sec, burst }
    }

    /// No limit at all (tests and trusted local setups).
    pub const UNLIMITED: Self = Self {
        per_sec: f64::INFINITY,
        burst: u32::MAX,
    };

    pub fn is_unlimited(&self) -> bool {
        self.per_sec.is_infinite()
    }
}

#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: Rate,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            tokens: f64::from(rate.burst),
            last: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate.per_sec).min(f64::from(self.rate.burst));
    }

    /// Take one token if there is one.
    pub fn try_take(&mut self) -> bool {
        if self.rate.is_unlimited() {
            return true;
        }
        self.refill(Instant::now());
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// True if the bucket is full again (its key can be forgotten).
    fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= f64::from(self.rate.burst)
    }
}

/// One bucket per key, tracking at most `max_keys` keys.
#[derive(Debug)]
pub struct KeyedBuckets<K> {
    rate: Rate,
    max_keys: usize,
    buckets: HashMap<K, TokenBucket>,
}

impl<K: Hash + Eq + Clone> KeyedBuckets<K> {
    pub fn new(rate: Rate, max_keys: usize) -> Self {
        Self {
            rate,
            max_keys: max_keys.max(1),
            buckets: HashMap::new(),
        }
    }

    /// Take a token from `key`'s bucket. When the table is full, buckets
    /// that have refilled completely are forgotten first; if none has, the
    /// action is refused (fail closed rather than grow without bound).
    pub fn try_take(&mut self, key: &K) -> bool {
        if self.rate.is_unlimited() {
            return true;
        }
        if !self.buckets.contains_key(key) && self.buckets.len() >= self.max_keys {
            let now = Instant::now();
            self.buckets.retain(|_, b| !b.is_full(now));
            if self.buckets.len() >= self.max_keys {
                return false;
            }
        }
        self.buckets
            .entry(key.clone())
            .or_insert_with(|| TokenBucket::new(self.rate))
            .try_take()
    }

    pub fn forget(&mut self, key: &K) {
        self.buckets.remove(key);
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_allows_a_burst_then_refills() {
        let mut b = TokenBucket::new(Rate::new(50.0, 3));
        assert!(b.try_take() && b.try_take() && b.try_take());
        assert!(!b.try_take(), "burst exhausted");
        std::thread::sleep(Duration::from_millis(60)); // ~3 tokens at 50/s
        assert!(b.try_take());
    }

    #[test]
    fn unlimited_never_refuses() {
        let mut b = TokenBucket::new(Rate::UNLIMITED);
        assert!((0..10_000).all(|_| b.try_take()));
    }

    #[test]
    fn keyed_buckets_are_independent_and_bounded() {
        let mut k = KeyedBuckets::new(Rate::new(0.001, 1), 2);
        assert!(k.try_take(&"a"));
        assert!(!k.try_take(&"a"));
        assert!(k.try_take(&"b"), "another key has its own bucket");
        // Table full of non-full buckets: a third key is refused, not added.
        assert!(!k.try_take(&"c"));
        assert_eq!(k.len(), 2);
        k.forget(&"a");
        assert!(k.try_take(&"c"));
    }
}
