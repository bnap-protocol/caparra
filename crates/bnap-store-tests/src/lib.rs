//! Shared conformance test suite that every storage backend must pass.
//!
//! Every durable [`UseStore`] in this workspace runs, in `tests/`:
//!
//! 1. bnap-core's own conformance suite,
//!    [`bnap_core::test_support::conformance::run`], one call at a time and
//!    concurrently, with [`Tokio`] as its executor;
//! 2. the scenarios of [`scenarios`]: many tasks behind a barrier, each on
//!    its own pool connection, driving the store through the whole socket
//!    flow (`bnap_core::outcome::process`, `settle`, `sweep`,
//!    `record_refund`, `reserve_change`), as several gate instances on one
//!    store would;
//! 3. a crash test per backend: the store is dropped while transactions
//!    are in flight, reopened, and checked with [`check_consistent`].
//!
//! The Postgres tests read `DATABASE_URL` and skip, with a message, when it
//! is unset.

use std::future::Future;
use std::sync::Barrier;

use bnap_core::store::{
    ChangeRequest, Commit, CommitPlan, OutcomeRecord, OutcomeStatus, RefundRequest, Reserve,
    Settle, SettleRequest, SweepWindow, UseStore,
};
use bnap_core::test_support::conformance::Executor;
use bnap_core::{CounterKey, ReplayKey, StoreError};

pub mod scenarios;

/// A multi-thread tokio runtime as the conformance suite's executor. Its
/// `block_on` may be called from several threads at once; each call drives
/// its future on the calling thread with the runtime's I/O and timers.
#[derive(Debug)]
pub struct Tokio(tokio::runtime::Runtime);

impl Tokio {
    /// A runtime with a few worker threads for the pool's background tasks.
    ///
    /// # Panics
    ///
    /// When the runtime cannot be built.
    #[must_use]
    pub fn new() -> Self {
        Self(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a tokio runtime"),
        )
    }

    /// The runtime, to spawn tasks on.
    #[must_use]
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.0
    }
}

impl Default for Tokio {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor for Tokio {
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.0.block_on(f)
    }
}

/// A store with whatever must live as long as it (a temporary directory,
/// a schema to drop), dropped after the store.
pub struct Held<S> {
    /// The store.
    pub store: S,
    _guard: Box<dyn Send + Sync>,
}

impl<S> Held<S> {
    /// `store`, keeping `guard` alive until it is dropped.
    pub fn new(store: S, guard: impl Send + Sync + 'static) -> Self {
        Self {
            store,
            _guard: Box::new(guard),
        }
    }
}

impl<S: std::fmt::Debug> std::fmt::Debug for Held<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<S: UseStore> UseStore for Held<S> {
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
        self.store.commit(plan).await
    }

    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
        self.store.counter(key).await
    }

    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
        self.store.outcome(rk).await
    }

    async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
        self.store.settle(req).await
    }

    async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
        self.store.expire_pending(window).await
    }

    async fn record_refund(
        &self,
        req: &RefundRequest<'_>,
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        self.store.record_refund(req).await
    }

    async fn reserve_change(&self, req: &ChangeRequest<'_>) -> Result<Reserve, StoreError> {
        self.store.reserve_change(req).await
    }

    async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
        self.store.purge(window).await
    }
}

/// Runs `f(0)` to `f(n - 1)` on `n` threads that a barrier releases
/// together, and returns what each returned, in order.
///
/// # Panics
///
/// When a call panics.
pub fn race<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
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

/// Every row of a store, read through its raw tables (the backend's test
/// fills it) and [`UseStore::outcome`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dump {
    /// `used[id] = rk`.
    pub used: Vec<([u8; 32], ReplayKey)>,
    /// `counter[key]`.
    pub counters: Vec<(CounterKey, u64)>,
    /// `outcome[rk]`, as the store returns it.
    pub outcomes: Vec<(ReplayKey, OutcomeRecord)>,
    /// Counter and output rows whose outcome does not exist.
    pub orphans: u64,
}

/// What a test committed, or tried to: a credential's `ReplayKey` and the
/// single IDs its commit consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tried {
    /// The credential's `ReplayKey`.
    pub replay_key: ReplayKey,
    /// Every single its commit plan holds.
    pub singles: Vec<[u8; 32]>,
}

/// Checks that `dump` is a state the store's rules can reach, so no write
/// was left half done:
///
/// - every `used` row names an outcome that exists (nothing was purged);
/// - every credential in `tried` either committed whole (its record and
///   every one of its singles under its `ReplayKey`) or not at all (no
///   record, none of its singles used);
/// - each counter equals the number of PENDING or OK outcomes that name
///   it (FAILED gave its count back), and no other counter row exists;
/// - each record's change total is the sum of its outputs and at most its
///   refund cap;
/// - no counter or output row outlived its outcome.
///
/// # Panics
///
/// On the first rule `dump` breaks.
pub fn check_consistent(dump: &Dump, tried: &[Tried]) {
    use std::collections::{BTreeMap, BTreeSet};
    let outcomes: BTreeMap<ReplayKey, &OutcomeRecord> =
        dump.outcomes.iter().map(|(rk, r)| (*rk, r)).collect();
    let used: BTreeMap<[u8; 32], ReplayKey> = dump.used.iter().copied().collect();
    for (id, rk) in &dump.used {
        assert!(
            outcomes.contains_key(rk),
            "used id {} names no outcome",
            hex(id)
        );
    }
    for t in tried {
        let committed = outcomes.contains_key(&t.replay_key);
        for id in &t.singles {
            let mine = used.get(id) == Some(&t.replay_key);
            assert_eq!(
                mine,
                committed,
                "credential {} committed {committed} but single {} used by it: {mine}",
                t.replay_key,
                hex(id)
            );
        }
    }
    let mut expected: BTreeMap<CounterKey, u64> = BTreeMap::new();
    for rec in outcomes.values() {
        if rec.status != OutcomeStatus::Failed {
            for key in rec.counters.iter().collect::<BTreeSet<_>>() {
                *expected.entry(*key).or_default() += 1;
            }
        }
        let sum: u64 = rec.change_outputs.iter().map(|o| o.amount).sum();
        assert_eq!(rec.change_total, sum, "the change total is its outputs");
        assert!(rec.change_total <= rec.refund_cap, "{rec:?}");
    }
    let counters: BTreeMap<CounterKey, u64> = dump
        .counters
        .iter()
        .copied()
        .filter(|(_, v)| *v > 0)
        .collect();
    assert_eq!(counters, expected, "each counter counts its live outcomes");
    assert_eq!(dump.orphans, 0, "no row outlives its outcome");
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}
