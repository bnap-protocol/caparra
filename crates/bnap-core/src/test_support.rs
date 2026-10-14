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
/// [`crate::store::logic`] as a gate observes them through the trait, one
/// call at a time and concurrently. The concurrent scenarios release
/// several threads together behind a barrier, round after round, on every
/// write of the money path: commits of one plan, commits sharing a single,
/// commits against one counter, settles racing the timeout on an outcome
/// that shares its rate counter with another, and refunds of one timed-out
/// outcome. Only a store whose every method decides and writes in one
/// serializable step passes them; the tests of this module show a store
/// that splits any one of those writes in two failing.
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
        Commit, CommitPlan, OutcomeRecord, OutcomeStatus, RefundRequest, SchemeUses, Settle,
        SettleRequest, Settlement, SweepWindow, UseModel, UseStore, Uses,
    };

    const T0: u64 = 1_791_700_000;
    const TIMEOUT: u64 = 300;
    /// Calls released together in each concurrent round.
    const THREADS: usize = 8;
    /// Rounds of each concurrent scenario, each on fresh outcomes.
    const ROUNDS: u8 = 10;

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
        plan_on(c, singles, rate.map(|k| (k, &b"client"[..])), now)
    }

    /// A plan for credential `c` naming single IDs `singles` and, with
    /// `rate = (k, identity)`, a rate counter of `k` per minute on that
    /// identity.
    fn plan_on(c: u8, singles: &[&[u8]], rate: Option<(u64, &[u8])>, now: u64) -> CommitPlan {
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
        let client = [rate.map_or_else(Vec::new, |(_, id)| id.to_vec())];
        let mut schemes = vec![SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &notes,
        }];
        if let Some((k, _)) = rate {
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

    /// `outcome[rk]`, which must exist.
    fn outcome<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
        rk: &ReplayKey,
    ) -> OutcomeRecord {
        exec.block_on(store.outcome(rk))
            .unwrap()
            .expect("the outcome record exists")
    }

    /// Runs `f(0)` to `f(n - 1)` on `n` threads that a barrier releases
    /// together, and returns what each returned, in order.
    fn race<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
        let barrier = Barrier::new(n);
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let (barrier, f) = (&barrier, &f);
                    s.spawn(move || {
                        barrier.wait();
                        f(i)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    /// A sweep window past [`TIMEOUT`] for outcomes committed at `T0`.
    fn past_the_deadline() -> SweepWindow {
        SweepWindow::from_parts(T0 + TIMEOUT + 1, T0 + 1, 0)
    }

    /// Runs every scenario, each on a store from `make`. Panics on the
    /// first rule a store breaks.
    pub fn run<S: UseStore>(make: impl Fn() -> S, exec: &impl Executor) {
        commit_is_all_or_nothing(&make(), exec);
        counters_hold_their_limit_under_concurrent_commits(&make(), exec);
        concurrent_commits_of_one_plan_make_one_outcome(&make(), exec);
        concurrent_commits_sharing_a_single_spend_it_once(&make(), exec);
        settle_changes_the_status_once(&make(), exec);
        settle_and_timeout_race_to_one_transition(&make(), exec);
        timeout_and_refund(&make(), exec);
        concurrent_refunds_record_once(&make(), exec);
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

    /// 6.3, concurrently: [`THREADS`] copies of one plan, committed
    /// together. One is New and the rest are replays of its PENDING record;
    /// its rate counter is incremented once.
    pub fn concurrent_commits_of_one_plan_make_one_outcome<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
    ) {
        for round in 0..ROUNDS {
            let id = [&b"copies "[..], &[round]].concat();
            let p = plan_on(round, &[&[b'c', round]], Some((100, &id)), T0);
            let answers = race(THREADS, |_| exec.block_on(store.commit(&p)).unwrap());
            let new = answers.iter().filter(|a| **a == Commit::New).count();
            assert_eq!(new, 1, "one copy commits: {answers:?}");
            for a in &answers {
                if let Commit::Replay(rec) = a {
                    assert_eq!(rec.status, OutcomeStatus::Pending);
                } else {
                    assert_eq!(*a, Commit::New, "the others are replays");
                }
            }
            let key = p.counters()[0].key;
            assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 1);
        }
    }

    /// 6.3, concurrently: [`THREADS`] credentials that share one single ID,
    /// each with one of its own, committed together. One is New and the
    /// rest are SPENT, with no record and nothing of theirs consumed.
    pub fn concurrent_commits_sharing_a_single_spend_it_once<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
    ) {
        for round in 0..ROUNDS {
            let plans: Vec<CommitPlan> = (0..THREADS)
                .map(|i| {
                    let (i, n) = (u8::try_from(i).unwrap(), u8::try_from(THREADS).unwrap());
                    let c = round * n + i;
                    plan(c, &[&[b's', round], &[b'o', round, i]], None, T0)
                })
                .collect();
            let answers = race(THREADS, |i| exec.block_on(store.commit(&plans[i])).unwrap());
            let winners: Vec<usize> = (0..THREADS)
                .filter(|i| answers[*i] == Commit::New)
                .collect();
            assert_eq!(
                winners.len(),
                1,
                "one credential spends the ID: {answers:?}"
            );
            for (i, (a, p)) in answers.iter().zip(&plans).enumerate() {
                if i == winners[0] {
                    continue;
                }
                assert!(
                    matches!(a, Commit::Spent { .. }),
                    "the others are SPENT: {a:?}"
                );
                assert!(
                    exec.block_on(store.outcome(p.replay_key()))
                        .unwrap()
                        .is_none()
                );
                let own = u8::try_from(i).unwrap();
                let reuse = plan(200 + own, &[&[b'o', round, own]], None, T0);
                assert_eq!(
                    exec.block_on(store.commit(&reuse)).unwrap(),
                    Commit::New,
                    "a SPENT commit consumed nothing of its own"
                );
            }
        }
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

    /// What one call of [`settle_and_timeout_race_to_one_transition`] got.
    #[derive(Debug)]
    enum Raced {
        /// A settle with this status, and the store's answer.
        Settle(Status, Settle),
        /// A sweep; true when it timed the outcome out.
        Expire(bool),
    }

    /// 6.4, concurrently (security review, store leads b and d): one PENDING
    /// outcome shares a rate counter with an OK one. Round after round,
    /// [`THREADS`] calls race behind a barrier: half settle it, OK and
    /// FAILED, at its deadline (`created + TIMEOUT`, still in time), half
    /// sweep past the deadline, the roles rotating each round. Exactly one call moves the outcome, and the
    /// record is what that call wrote; every refused settle sees that
    /// record; the counter is given back exactly once when the outcome ends
    /// FAILED and never when it ends OK, so the OK outcome keeps its count.
    /// A store whose settle or timeout decides on a snapshot and writes in a
    /// second step fails here.
    pub fn settle_and_timeout_race_to_one_transition<S: UseStore + ?Sized>(
        store: &S,
        exec: &impl Executor,
    ) {
        for round in 0..ROUNDS {
            let id = [&b"racer "[..], &[round]].concat();
            let ok = plan_on(2 * round, &[&[b'k', round]], Some((5, &id)), T0);
            let pending = plan_on(2 * round + 1, &[&[b'p', round]], Some((5, &id)), T0);
            let key = pending.counters()[0].key;
            assert_eq!(ok.counters()[0].key, key, "one shared counter");
            exec.block_on(store.commit(&ok)).unwrap();
            settle(store, exec, &settlement(&ok, Status::Ok, T0 + 1));
            exec.block_on(store.commit(&pending)).unwrap();
            assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 2);
            // The roles rotate each round, so the thread a barrier releases
            // first is a settle in one round and a sweep in the next.
            let raced = race(THREADS, |i| {
                if (i + usize::from(round)) % 2 == 0 {
                    let status = if (i / 2) % 2 == 0 {
                        Status::Ok
                    } else {
                        Status::Failed
                    };
                    let s = settlement(&pending, status, T0 + TIMEOUT);
                    Raced::Settle(status, settle(store, exec, &s))
                } else {
                    let expired = exec
                        .block_on(store.expire_pending(&past_the_deadline()))
                        .unwrap();
                    Raced::Expire(expired.contains(pending.replay_key()))
                }
            });
            let rec = outcome(store, exec, pending.replay_key());
            one_transition(&raced, &rec);
            let given_back = u64::from(rec.status == OutcomeStatus::Failed);
            assert_eq!(
                exec.block_on(store.counter(&key)).unwrap(),
                2 - given_back,
                "the counter is given back once on FAILED, never on OK: {rec:?}"
            );
            assert_eq!(
                outcome(store, exec, ok.replay_key()).status,
                OutcomeStatus::Ok
            );
        }
    }

    /// Exactly one of `raced` moved the outcome, and `rec` is what it wrote.
    fn one_transition(raced: &[Raced], rec: &OutcomeRecord) {
        let mut won = raced.iter().filter_map(|r| match r {
            Raced::Settle(status, Settle::Settled(after)) => Some((*status, after)),
            _ => None,
        });
        let settled = won.next();
        let expired = raced
            .iter()
            .filter(|r| matches!(r, Raced::Expire(true)))
            .count();
        assert!(won.next().is_none(), "two settles won: {raced:?}");
        assert_eq!(
            usize::from(settled.is_some()) + expired,
            1,
            "exactly one transition: {raced:?}"
        );
        if let Some((status, after)) = settled {
            assert_eq!(after, rec, "the record is the winning settle's");
            assert_eq!(rec.status, OutcomeStatus::from(status));
            assert!(!rec.timed_out);
        } else {
            assert_eq!(rec.status, OutcomeStatus::Failed);
            assert!(rec.timed_out && rec.needs_refund(), "{rec:?}");
        }
        for r in raced {
            match r {
                Raced::Settle(_, Settle::AlreadySettled(seen)) => {
                    assert_eq!(seen, rec, "a refused settle sees the record left");
                }
                Raced::Settle(_, Settle::Unknown) => panic!("the outcome exists"),
                _ => {}
            }
        }
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

    /// 6.4, concurrently (security review, store lead b): [`THREADS`]
    /// replays that all found one timed-out outcome's refund missing record
    /// theirs together, each with a different result. One is written, and
    /// every call returns the record as stored: no caller is told that its
    /// own refund was recorded when another one was.
    pub fn concurrent_refunds_record_once<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
        for round in 0..ROUNDS {
            let p = plan(round, &[&[b'r', round]], None, T0);
            exec.block_on(store.commit(&p)).unwrap();
            let expired = exec
                .block_on(store.expire_pending(&past_the_deadline()))
                .unwrap();
            assert_eq!(expired, vec![*p.replay_key()]);
            let results: Vec<[u8; 2]> = (0..THREADS)
                .map(|i| [round, u8::try_from(i).unwrap()])
                .collect();
            let answers = race(THREADS, |i| {
                refund(store, exec, p.replay_key(), &results[i])
            });
            let rec = outcome(store, exec, p.replay_key());
            assert!(rec.refund_recorded && !rec.needs_refund());
            let written = rec.scheme_result.clone().expect("one refund was written");
            assert!(results.iter().any(|r| written == r));
            for a in &answers {
                assert_eq!(a, &rec, "every caller gets the refund that was recorded");
            }
        }
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

    /// The write a [`TwoStep`] store splits.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Split {
        Commit,
        Settle,
        Timeout,
        Refund,
    }

    /// A store that runs one of its writes in two steps: it decides on a
    /// snapshot of the tables, then writes what the decision changed in a
    /// second locked step, as a SQL store would with a `SELECT` and an
    /// `UPDATE` outside a serializable transaction. Its other methods are
    /// [`MemoryStore`]'s. Every rule holds when calls come one at a time.
    struct TwoStep {
        inner: MemoryStore,
        split: Split,
    }

    impl TwoStep {
        fn new(split: Split) -> Self {
            Self {
                inner: MemoryStore::new(),
                split,
            }
        }

        /// Runs `decide` on a snapshot, waits, then writes back every row
        /// the decision changed, with the values the snapshot gave it.
        fn two_steps<R>(
            &self,
            decide: impl FnOnce(&mut MemoryTable) -> R,
        ) -> Result<R, StoreError> {
            let before = self.inner.tx()?.clone();
            let mut after = before.clone();
            let r = decide(&mut after);
            std::thread::sleep(std::time::Duration::from_millis(2));
            let mut live = self.inner.tx()?;
            for (rk, rec) in &after.outcomes {
                if before.outcomes.get(rk) != Some(rec) {
                    live.outcomes.insert(*rk, rec.clone());
                }
            }
            for (id, rk) in &after.used {
                live.used.entry(*id).or_insert(*rk);
            }
            for key in before.counters.keys().chain(after.counters.keys()) {
                if before.counters.get(key) != after.counters.get(key) {
                    let v = after.counter(key);
                    live.set_counter(*key, v);
                }
            }
            Ok(r)
        }
    }

    #[async_trait::async_trait]
    impl UseStore for TwoStep {
        async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
            if self.split == Split::Commit {
                return self.two_steps(|t| logic::commit(t, plan));
            }
            self.inner.commit(plan).await
        }

        async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
            self.inner.counter(key).await
        }

        async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
            self.inner.outcome(rk).await
        }

        async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
            if self.split == Split::Settle {
                return self.two_steps(|t| logic::settle(t, req));
            }
            self.inner.settle(req).await
        }

        async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
            if self.split == Split::Timeout {
                return self.two_steps(|t| logic::expire_pending(t, window));
            }
            self.inner.expire_pending(window).await
        }

        async fn record_refund(
            &self,
            req: &RefundRequest<'_>,
        ) -> Result<Option<OutcomeRecord>, StoreError> {
            if self.split == Split::Refund {
                return self.two_steps(|t| logic::record_refund(t, req));
            }
            self.inner.record_refund(req).await
        }

        async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
            self.inner.purge(window).await
        }
    }

    /// True when the scenario `f` panics, as a test does.
    fn fails(f: impl FnOnce()) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
    }

    #[test]
    fn a_two_step_store_passes_every_scenario_one_call_at_a_time() {
        // The negative stores below break no rule sequentially, so what
        // fails them is the concurrency the scenarios add.
        for split in [Split::Commit, Split::Settle, Split::Timeout, Split::Refund] {
            let exec = &conformance::Spin;
            conformance::commit_is_all_or_nothing(&TwoStep::new(split), exec);
            conformance::settle_changes_the_status_once(&TwoStep::new(split), exec);
            conformance::timeout_and_refund(&TwoStep::new(split), exec);
            conformance::purge_keeps_what_must_stay(&TwoStep::new(split), exec);
        }
    }

    #[test]
    fn a_store_that_settles_in_two_steps_fails_conformance() {
        // The checker's ReadThenWrite store: settle decides on a snapshot
        // and writes in a second step. The suite used to pass it.
        let exec = &conformance::Spin;
        assert!(fails(|| {
            conformance::settle_and_timeout_race_to_one_transition(
                &TwoStep::new(Split::Settle),
                exec,
            );
        }));
        assert!(fails(|| conformance::run(
            || TwoStep::new(Split::Settle),
            exec
        )));
    }

    #[test]
    fn a_store_that_times_out_in_two_steps_fails_conformance() {
        let exec = &conformance::Spin;
        assert!(fails(|| {
            conformance::settle_and_timeout_race_to_one_transition(
                &TwoStep::new(Split::Timeout),
                exec,
            );
        }));
        assert!(fails(|| conformance::run(
            || TwoStep::new(Split::Timeout),
            exec
        )));
    }

    #[test]
    fn a_store_that_records_refunds_in_two_steps_fails_conformance() {
        let exec = &conformance::Spin;
        assert!(fails(|| conformance::concurrent_refunds_record_once(
            &TwoStep::new(Split::Refund),
            exec
        )));
        assert!(fails(|| conformance::run(
            || TwoStep::new(Split::Refund),
            exec
        )));
    }

    #[test]
    fn a_store_that_commits_in_two_steps_fails_the_commit_races() {
        let exec = &conformance::Spin;
        assert!(fails(|| {
            conformance::concurrent_commits_of_one_plan_make_one_outcome(
                &TwoStep::new(Split::Commit),
                exec,
            );
        }));
        assert!(fails(|| {
            conformance::concurrent_commits_sharing_a_single_spend_it_once(
                &TwoStep::new(Split::Commit),
                exec,
            );
        }));
    }

    #[test]
    fn a_store_that_checks_and_counts_in_two_steps_fails_conformance() {
        // Security review, store lead (c): the concurrent counter scenario
        // catches a commit whose check and increment are not one atomic
        // step.
        let racy = TwoStep::new(Split::Commit);
        assert!(
            fails(
                || conformance::counters_hold_their_limit_under_concurrent_commits(
                    &racy,
                    &conformance::Spin,
                )
            ),
            "a two-step commit must fail the scenario"
        );
    }
}
