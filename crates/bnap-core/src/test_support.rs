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
    Commit, CommitPlan, OutcomeRecord, RefundRequest, Settle, SettleRequest, StoreError,
    SweepWindow, UseStore, UseTable, logic,
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
        f(&self
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
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

    async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
        Ok(logic::settle(&mut *self.tx()?, req))
    }

    async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
        Ok(logic::expire_pending(&mut *self.tx()?, window))
    }

    async fn record_refund(
        &self,
        req: &RefundRequest<'_>,
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        Ok(logic::record_refund(&mut *self.tx()?, req))
    }

    async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
        Ok(logic::purge(&mut *self.tx()?, window))
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

/// Conformance scenarios for any [`UseStore`]: the rules of
/// [`crate::store::logic`] as a gate observes them through the trait,
/// including the counter limit under concurrent commits, which only a
/// serializable commit transaction keeps.
///
/// A durable store's test suite runs [`conformance::run`] with a fresh,
/// empty store per scenario and an [`conformance::Executor`] for its
/// runtime; [`MemoryStore`] passes it with [`conformance::Spin`].
///
/// # Panics
///
/// Every scenario panics, as a test does, when the store breaks the rule
/// it checks or returns a [`StoreError`].
#[allow(clippy::missing_panics_doc)]
pub mod conformance {
    use std::future::Future;
    use std::sync::Barrier;

    use crate::hash::ReplayKey;
    use crate::hash::{Context, Scope};
    use crate::offer::{OfferFields, PayEntry};
    use crate::pricing::{self, AdmitInput, PayValue, Refund};
    use crate::response::Status;
    use crate::schnorr::Key;
    use crate::store::{
        Commit, CommitPlan, OutcomeStatus, RefundRequest, SchemeUses, Settle, SettleRequest,
        Settlement, SweepWindow, UseModel, UseStore, Uses,
    };

    const T0: u64 = 1_791_700_000;
    const TIMEOUT: u64 = 300;

    /// Runs a store's futures to completion on the calling thread. The
    /// concurrent scenario calls it from several threads at once.
    pub trait Executor: Sync {
        /// Drives `f` to completion.
        fn block_on<F: Future>(&self, f: F) -> F::Output;
    }

    /// [`super::block_on`], for stores whose futures never wait on I/O.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Spin;

    impl Executor for Spin {
        fn block_on<F: Future>(&self, f: F) -> F::Output {
            super::block_on(f)
        }
    }

    /// A plan for credential `c` naming single IDs `singles` and, with
    /// `rate`, a rate counter of `k` per minute on the identity "client".
    fn plan(c: u8, singles: &[&[u8]], rate: Option<u64>, now: u64) -> CommitPlan {
        let mut o = OfferFields::new(Scope([1; 32]), now + 300, Key([9; 32]), [0; 16]);
        o.pay.push(PayEntry::new("bnap:notes", 0, "sat"));
        let admission = pricing::admit(
            &AdmitInput {
                offer: &o,
                pay: Some(PayValue {
                    scheme: "bnap:notes",
                    claimed: 0,
                    backing: Vec::new(),
                    refund: Refund::Atomic,
                }),
                attest: &[],
                now,
            },
            |_| 0,
        )
        .expect("a price of 0 admits");
        let notes: Vec<Vec<u8>> = singles.iter().map(|s| s.to_vec()).collect();
        let client = [b"client".to_vec()];
        let mut schemes = vec![SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &notes,
        }];
        if let Some(k) = rate {
            schemes.push(SchemeUses {
                scheme: "vnd.example",
                model: UseModel::Rate { k, epoch: 60 },
                local_ids: &client,
            });
        }
        let uses = Uses::collect(&Context([c; 32]), b"body", &[], &schemes, &[], now)
            .expect("no zero epoch");
        CommitPlan::build(uses, &admission, o.expires, now, 86_400).expect("the plan builds")
    }

    fn settlement(plan: &CommitPlan, status: Status, at: u64) -> Settlement {
        Settlement::from_parts(*plan.replay_key(), status, 0, None, at)
            .with_scheme_result(Some(b"result".to_vec()))
    }

    /// The store's settle of `s`, under [`TIMEOUT`].
    fn settle<S: UseStore + ?Sized>(store: &S, exec: &impl Executor, s: &Settlement) -> Settle {
        exec.block_on(store.settle(&SettleRequest::new(s, TIMEOUT)))
            .unwrap()
    }

    /// The store's `record_refund`.
    fn refund<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
        rk: &ReplayKey,
        result: &[u8],
    ) -> crate::store::OutcomeRecord {
        exec.block_on(store.record_refund(&RefundRequest::new(*rk, Some(result))))
            .unwrap()
            .unwrap()
    }

    /// Runs every scenario, each on a store from `make`. Panics on the
    /// first rule a store breaks.
    pub fn run<S: UseStore>(make: impl Fn() -> S, exec: &impl Executor) {
        commit_is_all_or_nothing(&make(), exec);
        counters_hold_their_limit_under_concurrent_commits(&make(), exec);
        settle_changes_the_status_once(&make(), exec);
        timeout_and_refund(&make(), exec);
        purge_keeps_what_must_stay(&make(), exec);
    }

    /// 6.3: replay first, then singles, then counters; an abort writes
    /// nothing.
    pub fn commit_is_all_or_nothing<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
        let a = plan(1, &[b"s1"], None, T0);
        assert_eq!(exec.block_on(store.commit(&a)).unwrap(), Commit::New);
        let Commit::Replay(rec) = exec.block_on(store.commit(&a)).unwrap() else {
            panic!("the same plan again must be a replay");
        };
        assert_eq!(rec.status, OutcomeStatus::Pending);
        assert_eq!((rec.created, rec.keep_until), (T0, a.keep_until()));
        let b = plan(2, &[b"s2", b"s1"], None, T0);
        assert!(matches!(
            exec.block_on(store.commit(&b)).unwrap(),
            Commit::Spent { .. }
        ));
        // s2 was not consumed by the aborted commit.
        let c = plan(3, &[b"s2"], None, T0);
        assert_eq!(exec.block_on(store.commit(&c)).unwrap(), Commit::New);
        assert!(
            exec.block_on(store.outcome(b.replay_key()))
                .unwrap()
                .is_none()
        );
    }

    /// 6.3, 7: 16 credentials of one identity under a rate of 3, committed
    /// together. Exactly 3 commit; the counter reads 3. A store that checks
    /// and increments a counter in two steps without serializable
    /// isolation fails here.
    pub fn counters_hold_their_limit_under_concurrent_commits<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
    ) {
        const N: u8 = 16;
        let barrier = Barrier::new(usize::from(N));
        let answers: Vec<Commit> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..N)
                .map(|c| {
                    let barrier = &barrier;
                    s.spawn(move || {
                        let single = [c];
                        let p = plan(c, &[&single], Some(3), T0);
                        barrier.wait();
                        exec.block_on(store.commit(&p)).unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let new = answers.iter().filter(|a| **a == Commit::New).count();
        let limited = answers
            .iter()
            .filter(|a| matches!(a, Commit::RateLimited { .. }))
            .count();
        assert_eq!((new, limited), (3, usize::from(N) - 3));
        let key = plan(0, &[], Some(3), T0).counters()[0].key;
        assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 3);
    }

    /// 6.4: the status leaves PENDING once; FAILED gives the counters back;
    /// a settle past `pending_timeout` times the outcome out.
    pub fn settle_changes_the_status_once<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
        let a = plan(1, &[b"a"], Some(5), T0);
        let key = a.counters()[0].key;
        exec.block_on(store.commit(&a)).unwrap();
        assert!(matches!(
            settle(store, exec, &settlement(&a, Status::Ok, T0 + 1)),
            Settle::Settled(_)
        ));
        let Settle::AlreadySettled(rec) =
            settle(store, exec, &settlement(&a, Status::Failed, T0 + 2))
        else {
            panic!("a second settle must be refused");
        };
        assert_eq!(rec.status, OutcomeStatus::Ok);
        assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 1);
        // FAILED gives the counter back.
        let b = plan(2, &[b"b"], Some(5), T0);
        exec.block_on(store.commit(&b)).unwrap();
        settle(store, exec, &settlement(&b, Status::Failed, T0 + 1));
        assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 1);
        // Past the deadline: timed out in the same call, counter back.
        let c = plan(3, &[b"c"], Some(5), T0);
        exec.block_on(store.commit(&c)).unwrap();
        let late = settlement(&c, Status::Ok, T0 + TIMEOUT + 1);
        let Settle::AlreadySettled(rec) = settle(store, exec, &late) else {
            panic!("a late settle must lose to the timeout");
        };
        assert!(rec.timed_out && rec.needs_refund());
        assert_eq!(rec.scheme_result, None);
        assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 1);
        let unknown = plan(4, &[b"d"], None, T0);
        assert_eq!(
            settle(store, exec, &settlement(&unknown, Status::Ok, T0 + 1)),
            Settle::Unknown
        );
    }

    /// 6.4: the timeout moves only old PENDING records, gives counters back
    /// once, and the first recorded refund wins.
    pub fn timeout_and_refund<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
        let old = plan(1, &[b"old"], Some(5), T0);
        let young = plan(2, &[b"young"], Some(5), T0 + 100);
        let key = old.counters()[0].key;
        exec.block_on(store.commit(&old)).unwrap();
        exec.block_on(store.commit(&young)).unwrap();
        let window = |now| SweepWindow::from_parts(now, T0 + 50, 0);
        let expired = exec
            .block_on(store.expire_pending(&window(T0 + TIMEOUT + 1)))
            .unwrap();
        assert_eq!(expired, vec![*old.replay_key()]);
        let again = exec
            .block_on(store.expire_pending(&window(T0 + TIMEOUT + 2)))
            .unwrap();
        assert!(again.is_empty(), "a timed-out record times out once");
        let rec = exec
            .block_on(store.outcome(old.replay_key()))
            .unwrap()
            .unwrap();
        assert!(rec.timed_out && rec.needs_refund());
        assert_eq!(rec.settled_at, Some(T0 + TIMEOUT + 1));
        // The old outcome's count is given back; the young one keeps its
        // own, which shares the key only inside one epoch.
        let young_key = young.counters()[0].key;
        assert_eq!(
            exec.block_on(store.counter(&key)).unwrap(),
            u64::from(key == young_key)
        );
        assert_eq!(exec.block_on(store.counter(&young_key)).unwrap(), 1);
        let first = refund(store, exec, old.replay_key(), b"one");
        let second = refund(store, exec, old.replay_key(), b"two");
        assert_eq!(first.scheme_result.as_deref(), Some(&b"one"[..]));
        assert_eq!(second, first, "the first refund wins");
        // A record that did not time out takes no refund.
        let young_rec = refund(store, exec, young.replay_key(), b"x");
        assert_eq!(young_rec.scheme_result, None);
    }

    /// Section 12 "Retention", 6.1: purge deletes settled records past the
    /// window and a clock skew past `keep_until`, never PENDING ones and
    /// never `used` entries.
    pub fn purge_keeps_what_must_stay<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
        let settled = plan(1, &[b"s"], None, T0);
        let pending = plan(2, &[b"p"], None, T0);
        exec.block_on(store.commit(&settled)).unwrap();
        exec.block_on(store.commit(&pending)).unwrap();
        settle(store, exec, &settlement(&settled, Status::Ok, T0 + 1));
        // The window has passed but the offer is still valid, to this
        // clock or to one a skew behind it: kept.
        let keep = settled.keep_until();
        let purge = |now| {
            exec.block_on(store.purge(&SweepWindow::from_parts(now, 0, T0 + 1)))
                .unwrap()
        };
        assert_eq!(purge(keep), 0);
        assert_eq!(purge(keep + 60), 0);
        assert_eq!(purge(keep + 61), 1);
        assert!(
            exec.block_on(store.outcome(settled.replay_key()))
                .unwrap()
                .is_none()
        );
        assert!(
            exec.block_on(store.outcome(pending.replay_key()))
                .unwrap()
                .is_some()
        );
        // The single use stays spent.
        let reuse = plan(3, &[b"s"], None, T0 + 10);
        assert!(matches!(
            exec.block_on(store.commit(&reuse)).unwrap(),
            Commit::Spent { .. }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_store_conforms() {
        conformance::run(MemoryStore::new, &conformance::Spin);
    }

    /// A store that checks a plan in one locked step and writes it in
    /// another, as a SQL store would with a `SELECT` and an `UPDATE` outside
    /// a serializable transaction.
    struct TwoStep(MemoryStore);

    #[async_trait::async_trait]
    impl UseStore for TwoStep {
        async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
            let full = {
                let t = self.0.tx()?;
                plan.counters()
                    .iter()
                    .find(|c| t.counter(&c.key) >= c.limit)
                    .copied()
            };
            if let Some(counter) = full {
                return Ok(Commit::RateLimited { counter });
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            let mut t = self.0.tx()?;
            for c in plan.counters() {
                let v = t.counter(&c.key);
                t.set_counter(c.key, v + 1);
            }
            t.put_outcome(*plan.replay_key(), OutcomeRecord::pending(plan));
            Ok(Commit::New)
        }

        async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
            self.0.counter(key).await
        }

        async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
            self.0.outcome(rk).await
        }

        async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
            self.0.settle(req).await
        }

        async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
            self.0.expire_pending(window).await
        }

        async fn record_refund(
            &self,
            req: &RefundRequest<'_>,
        ) -> Result<Option<OutcomeRecord>, StoreError> {
            self.0.record_refund(req).await
        }

        async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
            self.0.purge(window).await
        }
    }

    #[test]
    fn a_store_that_checks_and_counts_in_two_steps_fails_conformance() {
        // Security review, store lead (c): the concurrent counter scenario
        // catches a commit whose check and increment are not one atomic
        // step.
        let racy = TwoStep(MemoryStore::new());
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            conformance::counters_hold_their_limit_under_concurrent_commits(
                &racy,
                &conformance::Spin,
            );
        }));
        assert!(caught.is_err(), "a two-step commit must fail the scenario");
    }
}
