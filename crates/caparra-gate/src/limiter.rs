//! Fixed-window counters per key: the per-address and per-offer bounds on
//! the work unauthenticated requests can cause (draft-00 12, DECISIONS row
//! 24).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};

/// The window length, seconds.
pub const WINDOW: u64 = 60;

/// Most keys tracked at once; past it, keys of ended windows are dropped,
/// and if none ended the request is refused (fail closed under a flood of
/// fresh addresses).
pub const MAX_KEYS: usize = 100_000;

/// Counts events per key per [`WINDOW`].
#[derive(Debug)]
pub struct Limiter<K> {
    limit: u32,
    counts: Mutex<HashMap<K, (u64, u32)>>,
}

impl<K: Eq + Hash + Clone> Limiter<K> {
    /// At most `limit` events per key per window; 0 refuses every event.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one event for `key` at `now`. `Err(retry_after)` when the
    /// key's window is full; the event is then not counted.
    pub fn hit(&self, key: &K, now: u64) -> Result<(), u64> {
        let window = now / WINDOW;
        let retry = (window + 1) * WINDOW - now;
        let mut m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if m.len() >= MAX_KEYS && !m.contains_key(key) {
            m.retain(|_, (w, _)| *w == window);
            if m.len() >= MAX_KEYS {
                return Err(retry);
            }
        }
        let e = m.entry(key.clone()).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        if e.1 >= self.limit {
            return Err(retry);
        }
        e.1 += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_key_per_window() {
        let l = Limiter::new(2);
        assert_eq!(l.hit(&1, 120), Ok(()));
        assert_eq!(l.hit(&1, 121), Ok(()));
        assert_eq!(l.hit(&1, 130), Err(50));
        assert_eq!(l.hit(&2, 130), Ok(()), "another key has its own count");
        assert_eq!(l.hit(&1, 180), Ok(()), "a new window starts from 0");
        assert_eq!(Limiter::new(0).hit(&1, 0), Err(60));
    }
}
