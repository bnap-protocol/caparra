//! The use store (draft-00 sections 6.2 to 6.4): its records, the
//! [`UseStore`] plug trait, the [`CommitPlan`] bnap-core builds for it, and
//! the commit, settle, timeout and expiry rules as pure logic over a
//! [`UseTable`].
//!
//! The store holds three tables:
//!
//! - `used[id] = ReplayKey`: every single-model `UseId` and every `RailId`
//!   ever committed;
//! - `counter[key]`: rate and quota counters;
//! - `outcome[ReplayKey]`: one [`OutcomeRecord`] per committed credential.
//!
//! [`UseStore`] is defined here rather than in `bnap-plug` because the
//! outcome state machine ([`crate::outcome`]) is generic over it and
//! `bnap-plug` depends on this crate; `bnap-plug` re-exports it.
//!
//! A store backed by a key-value engine can run the functions of [`logic`]
//! inside one serializable transaction by implementing [`UseTable`] over
//! it. A store that speaks SQL implements the same rules in its own
//! statements; either way, every method of [`UseStore`] behaves exactly as
//! the matching function of [`logic`] run atomically, and is durable before
//! it returns.
//!
//! **Every write takes an argument only bnap-core builds.** [`CommitPlan`],
//! [`SettleRequest`] (with the [`Settlement`] it carries), [`RefundRequest`]
//! and [`SweepWindow`] have private fields, public getters for store
//! implementers, and constructors private to this crate: [`crate::outcome`]
//! makes them in `process`, `settle`, `record_refund`, `sweep` and the
//! replay path, so a gate holding the store cannot write an outcome by any
//! other path:
//!
//! ```compile_fail,E0451
//! use bnap_core::store::Settlement;
//! use bnap_core::{ReplayKey, Status};
//! let forged = Settlement {
//!     replay_key: ReplayKey([0; 32]),
//!     status: Status::Ok,
//!     charged: 0,
//!     metered_units: None,
//!     scheme_result: None,
//!     response: None,
//!     settled_at: 0,
//! };
//! ```
//!
//! ```compile_fail,E0624
//! let _ = bnap_core::store::SettleRequest::new;
//! ```
//!
//! ```compile_fail,E0624
//! let _ = bnap_core::store::RefundRequest::new;
//! ```
//!
//! ```compile_fail,E0624
//! let _ = bnap_core::store::SweepWindow::new;
//! ```

use std::collections::BTreeSet;

use crate::error::ErrorCode;
use crate::hash::{Context, CounterKey, RailId, ReplayKey};
use crate::ids::{rate_key, use_id};
use crate::limits::{CLOCK_SKEW, Limits};
use crate::outcome::OutcomeCharge;
use crate::pricing::{Admission, BackingSource, epoch_end};
use crate::response::Status;

/// The state of an outcome record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeStatus {
    /// Committed; the action may be running.
    Pending,
    /// Settled OK.
    Ok,
    /// Settled FAILED, or timed out.
    Failed,
}

impl From<Status> for OutcomeStatus {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => Self::Ok,
            Status::Failed => Self::Failed,
        }
    }
}

impl OutcomeStatus {
    /// The Response status of a settled outcome; `None` while PENDING.
    #[must_use]
    pub fn settled(self) -> Option<Status> {
        match self {
            Self::Pending => None,
            Self::Ok => Some(Status::Ok),
            Self::Failed => Some(Status::Failed),
        }
    }
}

/// `outcome[rk]` (6.3): what the store keeps about one committed
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeRecord {
    /// PENDING, OK or FAILED. Leaves PENDING exactly once.
    pub status: OutcomeStatus,
    /// Commit time, Unix seconds. The replay window runs from here.
    pub created: u64,
    /// The rate and quota counters the commit incremented; given back on
    /// FAILED.
    pub counters: Vec<CounterKey>,
    /// The charge, once settled.
    pub charged: Option<u64>,
    /// The meter's count, once settled, in metered offers.
    pub metered_units: Option<u64>,
    /// What the scheme's `settle` returned, recorded once.
    pub scheme_result: Option<Vec<u8>>,
    /// The response the carrier kept, if any.
    pub response: Option<Vec<u8>>,
    /// Settlement time, kept for replays.
    pub settled_at: Option<u64>,
    /// The outcome moved to FAILED by the timeout, not by `settle`. Its
    /// refund is computed when the client replays, or when the late action
    /// tries to settle (see [`UseStore::record_refund`]).
    pub timed_out: bool,
    /// The refund of a timed-out outcome was recorded, with or without a
    /// `scheme_result` (a scheme may have nothing to refund). Set once.
    pub refund_recorded: bool,
    /// The offer's `expires + 60`, from the commit: past it, a fresh commit
    /// on the offer is STALE. [`UseStore::purge`] never deletes the record
    /// until `keep_until + 60 < now`, whatever window it is given: one more
    /// clock skew, for a request whose clock reads behind the sweep's (taken
    /// before a slow check, or on another gate instance), so a credential
    /// without single uses cannot be admitted again while any of the gate's
    /// clocks still finds its offer valid (6.1).
    pub keep_until: u64,
    /// The most the refund of a timed-out outcome may sign, fixed at commit
    /// ([`CommitPlan::refund_cap`]).
    pub refund_cap: u64,
    /// The pay entry's unit, for the refund; empty without pay.
    pub unit: String,
}

impl OutcomeRecord {
    /// A fresh PENDING record for a plan (6.3).
    #[must_use]
    pub fn pending(plan: &CommitPlan) -> Self {
        Self {
            status: OutcomeStatus::Pending,
            created: plan.now(),
            counters: plan.counters().iter().map(|c| c.key).collect(),
            charged: None,
            metered_units: None,
            scheme_result: None,
            response: None,
            settled_at: None,
            timed_out: false,
            refund_recorded: false,
            keep_until: plan.keep_until(),
            refund_cap: plan.refund_cap(),
            unit: plan.unit().to_owned(),
        }
    }

    /// True for a timed-out FAILED outcome whose refund is not recorded yet.
    /// No receipt is made for it until the refund is
    /// ([`crate::outcome::Recorded::receipt`]).
    #[must_use]
    pub fn needs_refund(&self) -> bool {
        self.status == OutcomeStatus::Failed && self.timed_out && !self.refund_recorded
    }
}

/// A counter a commit increments: `(key, limit)` of 6.3, plus when the
/// counter's epoch ends, for `retry_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CounterUse {
    /// `H_"bnap/rate"(…)` or `H_"bnap/quota"(…)`.
    pub key: CounterKey,
    /// At most this many uses per epoch.
    pub limit: u64,
    /// Start of the next epoch, Unix seconds.
    pub resets_at: u64,
}

/// How the socket counts a scheme's use IDs (6.2), as the registry sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UseModel {
    /// One record per `UseId`, kept as long as the artifact could verify.
    Single,
    /// A counter of at most `k` per `UseId` per `epoch` seconds.
    Rate {
        /// Uses per epoch.
        k: u64,
        /// Epoch length in seconds, at least 1.
        epoch: u64,
    },
    /// Nothing consumed beyond the outcome record.
    Reusable,
}

/// One scheme's verified use IDs, as its `verify` returned them.
#[derive(Debug, Clone, Copy)]
pub struct SchemeUses<'a> {
    /// Scheme ID; prefixes every local ID (6.1).
    pub scheme: &'a str,
    /// The scheme's use model from the registry.
    pub model: UseModel,
    /// Local IDs as the scheme returned them.
    pub local_ids: &'a [Vec<u8>],
}

/// What a request names, collected before any pricing (6.1, 6.2): its
/// `ReplayKey`, every `UseId` and `RailId`, the single uses and the rate
/// counters.
///
/// The `ReplayKey` depends only on the Context, the bodies, the schemes'
/// `UseId`s and the `RailId`s, so it is known before admission, and
/// [`crate::outcome::process`] looks up `outcome[rk]` with it before it
/// prices anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uses {
    replay_key: ReplayKey,
    ids: Vec<[u8; 32]>,
    singles: BTreeSet<[u8; 32]>,
    counters: BTreeSet<CounterUse>,
}

impl Uses {
    /// Collects the request's uses (6.1, 6.2):
    ///
    /// - Every local ID becomes `UseId = H_"bnap/use"(lp(scheme) ‖ local)`.
    /// - Single-model `UseId`s and every `RailId` are single uses, whatever
    ///   the scheme's own model (6.2: `RailId`s are always single).
    /// - Rate-model `UseId`s become `rate(k, epoch)` counters.
    /// - The `ReplayKey` covers every `UseId` and `RailId`, whatever its
    ///   model, sorted and not deduplicated (ERRATA N3a-9).
    /// - Single uses and counters are sets: an ID the request names twice is
    ///   committed once (ERRATA N3b-3).
    pub(crate) fn collect(
        context: &Context,
        pay_body: &[u8],
        attest_bodies: &[&[u8]],
        schemes: &[SchemeUses<'_>],
        rail_ids: &[RailId],
        now: u64,
    ) -> Result<Self, PlanError> {
        let mut ids = Vec::new();
        let mut singles = BTreeSet::new();
        let mut counters = BTreeSet::new();
        for s in schemes {
            for local in s.local_ids {
                let id = use_id(s.scheme, local);
                ids.push(id.0);
                match s.model {
                    UseModel::Single => {
                        singles.insert(id.0);
                    }
                    UseModel::Rate { k, epoch } => {
                        let key = rate_key(&id, k, epoch, now)
                            .ok_or_else(|| PlanError::ZeroEpoch(s.scheme.to_owned()))?;
                        counters.insert(CounterUse {
                            key,
                            limit: k,
                            resets_at: epoch_end(now, epoch),
                        });
                    }
                    UseModel::Reusable => {}
                }
            }
        }
        for r in rail_ids {
            ids.push(r.0);
            singles.insert(r.0);
        }
        let replay_key = crate::ids::replay_key(context, pay_body, attest_bodies, &ids);
        ids.sort_unstable();
        Ok(Self {
            replay_key,
            ids,
            singles,
            counters,
        })
    }

    /// The `ReplayKey`.
    pub(crate) fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }
}

/// Why a commit plan cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// The credential yields no ID under the single model and its offer
    /// outlives the outcome record: `expires + 60 > now + replay_window`
    /// (6.1). Answered with POLICY (ERRATA N3b-4).
    #[error("credential without single-use IDs on an offer that outlives the replay window")]
    OutlivesRecord,
    /// A rate-model scheme with an epoch of 0 (a registry or config error).
    #[error("rate model of {0} has epoch 0")]
    ZeroEpoch(String),
}

impl PlanError {
    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::OutlivesRecord => ErrorCode::Policy,
            Self::ZeroEpoch(_) => ErrorCode::Unavailable,
        }
    }
}

/// The input of the store's commit (6.3): the `ReplayKey`, the single IDs
/// and the counters, all computed by bnap-core, plus what the outcome
/// record keeps from the admission.
///
/// The fields are private and only [`crate::outcome::process`] makes one,
/// after it found no `outcome[rk]` and admitted the request: no plug can
/// name a use ID in another scheme's space or choose a `ReplayKey`, and no
/// gate can commit a request it did not price, or price one it should
/// have answered as a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPlan {
    replay_key: ReplayKey,
    ids: Vec<[u8; 32]>,
    singles: Vec<[u8; 32]>,
    counters: Vec<CounterUse>,
    now: u64,
    keep_until: u64,
    refund_cap: u64,
    unit: String,
}

impl CommitPlan {
    /// Completes `uses` with the admission (6.1, 6.3, 7).
    ///
    /// - The quota counter the admission chose joins the counters, always:
    ///   the plan takes it from the [`Admission`], not from the caller.
    /// - Every payment and note the admission counted as value is a single
    ///   use too, so value is never counted for a request without being
    ///   consumed by it. The ID does not depend on the scheme
    ///   ([`BackingSource::single_id`]): a payment's `RailId`, or
    ///   `H_"bnap/note"(Y)` for a note the signer verified, so one note
    ///   carried by two value schemes is spent once (ERRATA N3b-19). The
    ///   scheme's own `UseId`s for the note stay singles as well. Backing
    ///   joins the singles only; the `ReplayKey` covers what the schemes and
    ///   `rail_ids` name, as 6.1 defines it.
    /// - Without any single use, the offer must expire at least 60 seconds
    ///   before the record can be deleted (6.1).
    /// - The record keeps the refund cap of a FAILED settlement
    ///   ([`Admission::settle`]), so a replay that times the outcome out
    ///   refunds what this commit consumed, never a value priced again, and
    ///   `keep_until = expires + 60`: the store never deletes the record
    ///   while its offer can still be presented, with one more clock skew
    ///   of margin ([`UseStore::purge`]).
    pub(crate) fn build(
        uses: Uses,
        admission: &Admission,
        offer_expires: u64,
        now: u64,
        replay_window: u64,
    ) -> Result<Self, PlanError> {
        let Uses {
            replay_key,
            ids,
            mut singles,
            mut counters,
        } = uses;
        if let Some(q) = admission.decision().quota_counter() {
            counters.insert(*q);
        }
        if let Some(pay) = admission.pay() {
            singles.extend(pay.backing().iter().map(BackingSource::single_id));
        }
        let keep_until = offer_expires.saturating_add(CLOCK_SKEW);
        if singles.is_empty() && keep_until > now.saturating_add(replay_window) {
            return Err(PlanError::OutlivesRecord);
        }
        let refund = admission.settle(Status::Failed, 0);
        Ok(Self {
            replay_key,
            ids,
            singles: singles.into_iter().collect(),
            counters: counters.into_iter().collect(),
            now,
            keep_until,
            refund_cap: refund.change(),
            unit: refund.unit().to_owned(),
        })
    }

    /// The `ReplayKey`.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    /// Every `UseId` and `RailId` the `ReplayKey` covers, sorted.
    #[must_use]
    pub fn ids(&self) -> &[[u8; 32]] {
        &self.ids
    }

    /// Single-model `UseId`s, `RailId`s and backing IDs, sorted, each once.
    #[must_use]
    pub fn singles(&self) -> &[[u8; 32]] {
        &self.singles
    }

    /// Rate and quota counters, each once.
    #[must_use]
    pub fn counters(&self) -> &[CounterUse] {
        &self.counters
    }

    /// The commit time.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// The offer's `expires + 60`: the record stays at least a clock skew
    /// past it ([`UseStore::purge`]).
    #[must_use]
    pub fn keep_until(&self) -> u64 {
        self.keep_until
    }

    /// The most a FAILED refund of this outcome may sign, fixed at commit:
    /// the admitted value for an `atomic` scheme, 0 otherwise.
    #[must_use]
    pub fn refund_cap(&self) -> u64 {
        self.refund_cap
    }

    /// The pay entry's unit; empty without pay.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

/// What the store's commit returns (6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Commit {
    /// Every ID was free: they are now used under the plan's `ReplayKey`,
    /// the counters are incremented, and the outcome is PENDING.
    New,
    /// `outcome[rk]` exists: the same credential for the same request.
    /// Nothing was written.
    Replay(OutcomeRecord),
    /// A single ID is already used under another `ReplayKey`. Nothing was
    /// written.
    Spent {
        /// The first used ID found.
        id: [u8; 32],
    },
    /// A counter is at its limit. Nothing was written.
    RateLimited {
        /// The full counter.
        counter: CounterUse,
    },
}

/// What settlement writes to `outcome[rk]` (6.4).
///
/// Its outcome, status, charge and meter count come only from
/// [`OutcomeCharge`], which only `outcome::Pending::charge` makes; the gate
/// adds the settlement time, the scheme's result and the response it keeps.
/// `outcome::settle` refuses a settlement made for another outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    replay_key: ReplayKey,
    status: Status,
    charged: u64,
    metered_units: Option<u64>,
    scheme_result: Option<Vec<u8>>,
    response: Option<Vec<u8>>,
    settled_at: u64,
}

impl Settlement {
    /// The settlement of a committed outcome's charge, at `settled_at`.
    #[must_use]
    pub fn new(charge: &OutcomeCharge, settled_at: u64) -> Self {
        Self {
            replay_key: *charge.replay_key(),
            status: charge.status(),
            charged: charge.charged(),
            metered_units: charge.metered_units(),
            scheme_result: None,
            response: None,
            settled_at,
        }
    }

    /// A settlement from its parts, for this crate's own store tests.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_parts(
        replay_key: ReplayKey,
        status: Status,
        charged: u64,
        metered_units: Option<u64>,
        settled_at: u64,
    ) -> Self {
        Self {
            replay_key,
            status,
            charged,
            metered_units,
            scheme_result: None,
            response: None,
            settled_at,
        }
    }

    /// With the scheme's result.
    #[must_use]
    pub fn with_scheme_result(mut self, r: Option<Vec<u8>>) -> Self {
        self.scheme_result = r;
        self
    }

    /// With the response the carrier keeps.
    #[must_use]
    pub fn with_response(mut self, r: Option<Vec<u8>>) -> Self {
        self.response = r;
        self
    }

    /// The outcome it settles.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    /// OK or FAILED.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// The charge, from the admission the commit was priced with.
    #[must_use]
    pub fn charged(&self) -> u64 {
        self.charged
    }

    /// The meter's count, in metered offers.
    #[must_use]
    pub fn metered_units(&self) -> Option<u64> {
        self.metered_units
    }

    /// What the scheme's `settle` returned.
    #[must_use]
    pub fn scheme_result(&self) -> Option<&[u8]> {
        self.scheme_result.as_deref()
    }

    /// The response the carrier keeps for replays, if any.
    #[must_use]
    pub fn response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }

    /// Settlement time.
    #[must_use]
    pub fn settled_at(&self) -> u64 {
        self.settled_at
    }
}

/// The input of the store's settle (6.4): a [`Settlement`] and the
/// `pending_timeout` its time is checked against. Only `outcome::settle`
/// makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettleRequest<'a> {
    settlement: &'a Settlement,
    pending_timeout: u64,
}

impl<'a> SettleRequest<'a> {
    pub(crate) fn new(settlement: &'a Settlement, pending_timeout: u64) -> Self {
        Self {
            settlement,
            pending_timeout,
        }
    }

    /// The outcome to settle.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        self.settlement.replay_key()
    }

    /// What to write.
    #[must_use]
    pub fn settlement(&self) -> &'a Settlement {
        self.settlement
    }

    /// The gate's `pending_timeout`: a settlement later than `created +
    /// pending_timeout` loses to the timeout.
    #[must_use]
    pub fn pending_timeout(&self) -> u64 {
        self.pending_timeout
    }
}

/// The input of the store's `record_refund`: the timed-out outcome and what
/// its scheme's FAILED settle returned. Only `outcome::record_refund` makes
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefundRequest<'a> {
    replay_key: ReplayKey,
    scheme_result: Option<&'a [u8]>,
}

impl<'a> RefundRequest<'a> {
    pub(crate) fn new(replay_key: ReplayKey, scheme_result: Option<&'a [u8]>) -> Self {
        Self {
            replay_key,
            scheme_result,
        }
    }

    /// The outcome whose refund this is.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    /// What the scheme's FAILED settle returned; `None` when it had nothing
    /// to refund.
    #[must_use]
    pub fn scheme_result(&self) -> Option<&'a [u8]> {
        self.scheme_result
    }
}

/// The window of one timeout or purge pass (6.4, section 12 "Retention"),
/// computed from the gate's clock and its [`Limits`]. Only bnap-core makes
/// one: `outcome::sweep`, and the replay path when it times an outcome out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepWindow {
    now: u64,
    timeout_before: u64,
    purge_before: u64,
}

impl SweepWindow {
    /// The window at `now`: PENDING outcomes created more than
    /// `pending_timeout` ago time out, and settled records created more
    /// than [`Limits::record_window`] ago may be purged.
    pub(crate) fn new(now: u64, limits: &Limits) -> Self {
        Self {
            now,
            timeout_before: now.saturating_sub(limits.pending_timeout),
            purge_before: now.saturating_sub(limits.record_window()),
        }
    }

    /// A window from its parts, for this crate's own store tests.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_parts(now: u64, timeout_before: u64, purge_before: u64) -> Self {
        Self {
            now,
            timeout_before,
            purge_before,
        }
    }

    /// The gate's clock: a timed-out outcome is settled at it, and a record
    /// is kept until its `keep_until + 60` is before it.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// PENDING outcomes created before this time out.
    #[must_use]
    pub fn timeout_before(&self) -> u64 {
        self.timeout_before
    }

    /// Settled records created before this are past their replay window.
    #[must_use]
    pub fn purge_before(&self) -> u64 {
        self.purge_before
    }
}

/// What the store's settle returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settle {
    /// The record moved from PENDING; this is it after the write.
    Settled(OutcomeRecord),
    /// The record had already left PENDING; it is unchanged.
    AlreadySettled(OutcomeRecord),
    /// No record under that `ReplayKey`.
    Unknown,
}

/// The store failed; the gate fails closed with UNAVAILABLE (6.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("use store unavailable: {0}")]
pub struct StoreError(pub String);

impl StoreError {
    /// Always UNAVAILABLE.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::Unavailable
    }
}

/// The use store plug (operator-trusted).
///
/// Every method runs as one serializable transaction and is durable before
/// it returns (6.3, section 12 "Durability"). Each behaves exactly as the
/// function of the same name in [`logic`]. A store that cannot be reached
/// returns [`StoreError`], and the gate fails closed.
///
/// **Serializable means one atomic step per method.** In [`Self::commit`]
/// the replay check, the check of every single use, the check of every
/// counter against its limit, and every write happen in one transaction
/// that no concurrent commit can interleave with. A store that reads a
/// counter in one statement and increments it in another, without
/// serializable isolation or a conditional write that re-checks the limit,
/// lets two commits pass one free slot. Pricing reads counters
/// ([`Self::counter`]) outside that transaction, so a pricing read may be
/// stale; the commit's re-check is what bounds every counter. The same
/// holds for every write on the money path: [`Self::settle`],
/// [`Self::expire_pending`] and [`Self::record_refund`] each decide and
/// write in one step, so a status leaves PENDING once, a counter is given
/// back once, and one refund is recorded and returned to every caller. A
/// store that decides on a snapshot and writes in a second statement (a
/// `SELECT`, then an `UPDATE` that does not re-check the row) breaks each
/// of these under concurrency. The conformance scenarios in
/// `test_support::conformance` (feature `test-support`) run every one of
/// these methods concurrently, behind a barrier, against any store:
/// commits of one plan and of plans sharing a single, commits against one
/// counter, settles racing the timeout on an outcome that shares its
/// counter, and concurrent refunds of one timed-out outcome.
#[async_trait::async_trait]
pub trait UseStore: Send + Sync {
    /// 6.3 commit: replay check, then every single ID, then every counter;
    /// all or nothing, in one serializable transaction.
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError>;

    /// A counter's current value (0 when absent), for quota room at
    /// pricing. The answer may be stale by the time the commit runs; the
    /// commit re-checks every limit.
    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError>;

    /// Reads `outcome[rk]`.
    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError>;

    /// 6.4 settle: one conditional update of `outcome[req.replay_key()]`
    /// that succeeds only from PENDING and only while
    /// `settled_at <= created + pending_timeout`; on FAILED the outcome's
    /// counters are given back in the same write. A settle that comes later times the outcome out
    /// instead, in the same transaction, and returns it as
    /// [`Settle::AlreadySettled`], so the answer never depends on when the
    /// sweep runs.
    async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError>;

    /// 6.4 timeout: every outcome still PENDING that was created before
    /// `window.timeout_before()` moves to FAILED with charge 0 and
    /// `timed_out`, its counters given back, settled at `window.now()`.
    /// Returns their `ReplayKey`s.
    async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError>;

    /// Records the refund of a timed-out outcome once: only if the outcome
    /// still [needs it](OutcomeRecord::needs_refund), writes
    /// `req.scheme_result()` (which may be `None`) and sets
    /// `refund_recorded`. Returns the record after the call, or `None` when
    /// there is none.
    async fn record_refund(
        &self,
        req: &RefundRequest<'_>,
    ) -> Result<Option<OutcomeRecord>, StoreError>;

    /// Deletes OK and FAILED outcome records created before
    /// `window.purge_before()` (the replay window has passed) whose
    /// `keep_until + 60` is before `window.now()`: their offer can no longer
    /// be presented, even to a gate clock a skew behind this one. PENDING
    /// records and every `used` entry stay. Returns how many were deleted.
    async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError>;
}

/// The primitive reads and writes of one serializable transaction, for
/// stores that run [`logic`] directly.
pub trait UseTable {
    /// `outcome[rk]`.
    fn outcome(&self, rk: &ReplayKey) -> Option<&OutcomeRecord>;
    /// `outcome[rk]`, for an in-place update.
    fn outcome_mut(&mut self, rk: &ReplayKey) -> Option<&mut OutcomeRecord>;
    /// Writes `outcome[rk]`.
    fn put_outcome(&mut self, rk: ReplayKey, rec: OutcomeRecord);
    /// Deletes `outcome[rk]`.
    fn delete_outcome(&mut self, rk: &ReplayKey);
    /// Every `ReplayKey` with an outcome record.
    fn outcome_keys(&self) -> Vec<ReplayKey>;
    /// True when `used[id]` exists.
    fn is_used(&self, id: &[u8; 32]) -> bool;
    /// Writes `used[id] = rk`.
    fn mark_used(&mut self, id: [u8; 32], rk: ReplayKey);
    /// `counter[key]`, 0 when absent.
    fn counter(&self, key: &CounterKey) -> u64;
    /// Writes `counter[key]`.
    fn set_counter(&mut self, key: CounterKey, value: u64);
}

/// The rules of 6.3 and 6.4 over one [`UseTable`] transaction.
///
/// Each function reads everything it needs before it writes anything, so an
/// abort consumes nothing.
pub mod logic {
    use super::{
        CLOCK_SKEW, Commit, CommitPlan, OutcomeRecord, OutcomeStatus, RefundRequest, ReplayKey,
        Settle, SettleRequest, SweepWindow, UseTable,
    };
    use crate::response::Status;

    /// 6.3:
    ///
    /// ```text
    /// if outcome[rk] exists:                 return Replay(outcome[rk])
    /// for id in singles:  if used[id] exists:                 abort, return SPENT
    /// for (key, limit) in counters: if counter[key] >= limit:  abort, return RATE_LIMITED
    /// for id in singles:  used[id] = rk
    /// for (key, limit) in counters: counter[key] += 1
    /// outcome[rk] = { status: PENDING, created: now, counters: [keys], … }
    /// return New
    /// ```
    pub fn commit(t: &mut impl UseTable, plan: &CommitPlan) -> Commit {
        let rk = *plan.replay_key();
        if let Some(rec) = t.outcome(&rk) {
            return Commit::Replay(rec.clone());
        }
        if let Some(id) = plan.singles().iter().find(|id| t.is_used(id)) {
            return Commit::Spent { id: *id };
        }
        if let Some(c) = plan
            .counters()
            .iter()
            .find(|c| t.counter(&c.key) >= c.limit)
        {
            return Commit::RateLimited { counter: *c };
        }
        for id in plan.singles() {
            t.mark_used(*id, rk);
        }
        for c in plan.counters() {
            let v = t.counter(&c.key);
            t.set_counter(c.key, v.saturating_add(1));
        }
        t.put_outcome(rk, OutcomeRecord::pending(plan));
        Commit::New
    }

    fn give_back(t: &mut impl UseTable, rec: &OutcomeRecord) {
        for key in &rec.counters {
            let v = t.counter(key);
            t.set_counter(*key, v.saturating_sub(1));
        }
    }

    /// Moves a PENDING record to FAILED by the timeout: charge 0, settled
    /// at `now`, `timed_out`, its counters given back.
    fn time_out(
        t: &mut impl UseTable,
        rk: ReplayKey,
        rec: &OutcomeRecord,
        now: u64,
    ) -> OutcomeRecord {
        let mut rec = rec.clone();
        rec.status = OutcomeStatus::Failed;
        rec.charged = Some(0);
        rec.settled_at = Some(now);
        rec.timed_out = true;
        give_back(t, &rec);
        t.put_outcome(rk, rec.clone());
        rec
    }

    /// 6.4 settle: the status changes exactly once. On FAILED, single uses
    /// stay spent and the outcome's counters are given back.
    ///
    /// A settle at `settled_at > created + pending_timeout` comes after the
    /// outcome's timeout: the record moves to FAILED by the timeout (as
    /// [`expire_pending`] would, settled at `settled_at`) and the settle is
    /// refused with it, whether or not a sweep or a replay ran.
    pub fn settle(t: &mut impl UseTable, req: &SettleRequest<'_>) -> Settle {
        let (rk, s) = (*req.replay_key(), req.settlement());
        let Some(rec) = t.outcome(&rk) else {
            return Settle::Unknown;
        };
        if rec.status != OutcomeStatus::Pending {
            return Settle::AlreadySettled(rec.clone());
        }
        if s.settled_at() > rec.created.saturating_add(req.pending_timeout()) {
            let rec = rec.clone();
            return Settle::AlreadySettled(time_out(t, rk, &rec, s.settled_at()));
        }
        let mut rec = rec.clone();
        rec.status = s.status().into();
        rec.charged = Some(s.charged());
        rec.metered_units = s.metered_units();
        rec.scheme_result = s.scheme_result().map(<[u8]>::to_vec);
        rec.response = s.response().map(<[u8]>::to_vec);
        rec.settled_at = Some(s.settled_at());
        if s.status() == Status::Failed {
            give_back(t, &rec);
        }
        t.put_outcome(rk, rec.clone());
        Settle::Settled(rec)
    }

    /// 6.4 timeout: PENDING outcomes created before `w.timeout_before()`
    /// move to FAILED with charge 0, settled at `w.now()`, their counters
    /// given back.
    pub fn expire_pending(t: &mut impl UseTable, w: &SweepWindow) -> Vec<ReplayKey> {
        let mut out = Vec::new();
        for rk in t.outcome_keys() {
            let Some(rec) = t.outcome(&rk) else { continue };
            if rec.status != OutcomeStatus::Pending || rec.created >= w.timeout_before() {
                continue;
            }
            let rec = rec.clone();
            time_out(t, rk, &rec, w.now());
            out.push(rk);
        }
        out.sort_unstable();
        out
    }

    /// Records a timed-out outcome's refund once (see
    /// [`super::UseStore::record_refund`]).
    pub fn record_refund(t: &mut impl UseTable, req: &RefundRequest<'_>) -> Option<OutcomeRecord> {
        let rec = t.outcome_mut(req.replay_key())?;
        if rec.needs_refund() {
            rec.scheme_result = req.scheme_result().map(<[u8]>::to_vec);
            rec.refund_recorded = true;
        }
        Some(rec.clone())
    }

    /// Deletes settled outcome records created before `w.purge_before()`,
    /// but never one whose offer can still be presented:
    /// `keep_until + CLOCK_SKEW` must be before `w.now()`. This holds
    /// whatever limits the window was computed from, so a sweep run with a
    /// shorter `replay_window` than the commit saw cannot let a credential
    /// without single uses be admitted again (6.1). The extra skew covers a
    /// request whose clock reads up to 60 s behind the sweep's: its fresh
    /// commit is STALE once its `now > keep_until`, and until then it still
    /// finds the record, as `REFUND_MARGIN` assumes of the gate's clocks.
    pub fn purge(t: &mut impl UseTable, w: &SweepWindow) -> u64 {
        let mut n = 0;
        for rk in t.outcome_keys() {
            let old = t.outcome(&rk).is_some_and(|r| {
                r.status != OutcomeStatus::Pending
                    && r.created < w.purge_before()
                    && r.keep_until.saturating_add(CLOCK_SKEW) < w.now()
            });
            if old {
                t.delete_outcome(&rk);
                n += 1;
            }
        }
        n
    }
}
