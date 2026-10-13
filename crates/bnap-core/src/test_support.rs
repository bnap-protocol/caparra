//! Test support: an in-memory [`UseStore`] and a minimal `block_on`.
//!
//! Enabled by the `test-support` feature. [`MemoryStore`] runs the
//! functions of [`crate::store::logic`] under one mutex, which makes every
//! call serializable, but it keeps nothing on disk: it is the reference
//! the durable stores are tested against, never a store for a gate.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::task::{Poll, Waker};

use crate::hash::{CounterKey, ReplayKey};
use crate::store::{
    Commit, CommitPlan, OutcomeRecord, Settle, Settlement, StoreError, UseStore, UseTable, logic,
};

/// The three tables of a use store, in memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryTable {
    outcomes: HashMap<ReplayKey, OutcomeRecord>,
    used: HashMap<[u8; 32], ReplayKey>,
    counters: HashMap<CounterKey, u64>,
}

impl MemoryTable {
    /// The `ReplayKey` an ID is used under.
    #[must_use]
    pub fn used_by(&self, id: &[u8; 32]) -> Option<ReplayKey> {
        self.used.get(id).copied()
    }

    /// How many IDs are used.
    #[must_use]
    pub fn used_len(&self) -> usize {
        self.used.len()
    }

    /// How many outcome records exist.
    #[must_use]
    pub fn outcomes_len(&self) -> usize {
        self.outcomes.len()
    }
}

impl UseTable for MemoryTable {
    fn outcome(&self, rk: &ReplayKey) -> Option<&OutcomeRecord> {
        self.outcomes.get(rk)
    }

    fn outcome_mut(&mut self, rk: &ReplayKey) -> Option<&mut OutcomeRecord> {
        self.outcomes.get_mut(rk)
    }

    fn put_outcome(&mut self, rk: ReplayKey, rec: OutcomeRecord) {
        self.outcomes.insert(rk, rec);
    }

    fn delete_outcome(&mut self, rk: &ReplayKey) {
        self.outcomes.remove(rk);
    }

    fn outcome_keys(&self) -> Vec<ReplayKey> {
        self.outcomes.keys().copied().collect()
    }

    fn is_used(&self, id: &[u8; 32]) -> bool {
        self.used.contains_key(id)
    }

    fn mark_used(&mut self, id: [u8; 32], rk: ReplayKey) {
        self.used.insert(id, rk);
    }

    fn counter(&self, key: &CounterKey) -> u64 {
        self.counters.get(key).copied().unwrap_or(0)
    }

    fn set_counter(&mut self, key: CounterKey, value: u64) {
        if value == 0 {
            self.counters.remove(&key);
        } else {
            self.counters.insert(key, value);
        }
    }
}

/// An in-memory [`UseStore`]. Not durable.
#[derive(Debug, Default)]
pub struct MemoryStore {
    table: Mutex<MemoryTable>,
    down: AtomicBool,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every call fail with [`StoreError`] while `down` is true, to
    /// test that the gate fails closed.
    pub fn set_unavailable(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// Reads the tables.
    ///
    /// # Panics
    ///
    /// If a thread panicked while holding the lock.
    pub fn inspect<R>(&self, f: impl FnOnce(&MemoryTable) -> R) -> R {
        f(&self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    fn tx(&self) -> Result<MutexGuard<'_, MemoryTable>, StoreError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(StoreError("memory store set unavailable".into()));
        }
        self.table
            .lock()
            .map_err(|_| StoreError("memory store lock poisoned".into()))
    }
}

#[async_trait::async_trait]
impl UseStore for MemoryStore {
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
        Ok(logic::commit(&mut *self.tx()?, plan))
    }

    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
        Ok(self.tx()?.counter(key))
    }

    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
        Ok(UseTable::outcome(&*self.tx()?, rk).cloned())
    }

    async fn settle(&self, rk: &ReplayKey, s: &Settlement) -> Result<Settle, StoreError> {
        Ok(logic::settle(&mut *self.tx()?, rk, s))
    }

    async fn expire_pending(
        &self,
        created_before: u64,
        now: u64,
    ) -> Result<Vec<ReplayKey>, StoreError> {
        Ok(logic::expire_pending(&mut *self.tx()?, created_before, now))
    }

    async fn record_refund(
        &self,
        rk: &ReplayKey,
        scheme_result: &[u8],
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        Ok(logic::record_refund(&mut *self.tx()?, rk, scheme_result))
    }

    async fn purge(&self, created_before: u64) -> Result<u64, StoreError> {
        Ok(logic::purge(&mut *self.tx()?, created_before))
    }
}

/// Runs a future to completion on the current thread.
///
/// Enough for futures that never wait on I/O, such as [`MemoryStore`]'s;
/// it polls in a loop and yields between polls.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}
