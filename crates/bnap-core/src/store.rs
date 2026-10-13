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

use std::collections::BTreeSet;

use crate::error::ErrorCode;
use crate::hash::{Context, CounterKey, RailId, ReplayKey};
use crate::ids::{rate_key, use_id};
use crate::limits::CLOCK_SKEW;
use crate::pricing::{QuotaUse, epoch_end};
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
    /// refund is computed when the client replays (see
    /// [`UseStore::record_refund`]).
    pub timed_out: bool,
}

impl OutcomeRecord {
    /// A fresh PENDING record (6.3).
    #[must_use]
    pub fn pending(created: u64, counters: Vec<CounterKey>) -> Self {
        Self {
            status: OutcomeStatus::Pending,
            created,
            counters,
            charged: None,
            metered_units: None,
            scheme_result: None,
            response: None,
            settled_at: None,
            timed_out: false,
        }
    }

    /// True for a timed-out FAILED outcome whose refund is not recorded yet.
    #[must_use]
    pub fn needs_refund(&self) -> bool {
        self.status == OutcomeStatus::Failed && self.timed_out && self.scheme_result.is_none()
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

/// What [`CommitPlan::build`] needs.
#[derive(Debug, Clone, Copy)]
pub struct PlanInput<'a> {
    /// The credential's Context.
    pub context: &'a Context,
    /// The pay body, or empty without pay.
    pub pay_body: &'a [u8],
    /// The attest bodies in the credential's (sorted) order.
    pub attest_bodies: &'a [&'a [u8]],
    /// Every scheme in the request, pay and attestations.
    pub schemes: &'a [SchemeUses<'a>],
    /// `RailId`s the rails confirmed for the request's payments.
    pub rail_ids: &'a [RailId],
    /// The quota chosen at admission ([`crate::pricing::PriceDecision::quota`]).
    pub quota: Option<&'a QuotaUse>,
    /// The offer's `expires`.
    pub offer_expires: u64,
    /// The gate's clock.
    pub now: u64,
    /// The manifest's `replay_window`.
    pub replay_window: u64,
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
/// and the counters, all computed by bnap-core.
///
/// The fields are private so only [`CommitPlan::build`] makes one: no plug
/// can name a use ID in another scheme's space or choose a `ReplayKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPlan {
    replay_key: ReplayKey,
    ids: Vec<[u8; 32]>,
    singles: Vec<[u8; 32]>,
    counters: Vec<CounterUse>,
    now: u64,
}

impl CommitPlan {
    /// Builds the plan from the verified schemes (6.1, 6.2, 6.3).
    ///
    /// - Every local ID becomes `UseId = H_"bnap/use"(lp(scheme) ‖ local)`.
    /// - Single-model `UseId`s and every `RailId` are single uses.
    /// - Rate-model `UseId`s become `rate(k, epoch)` counters.
    /// - The chosen quota's counter joins the counters.
    /// - The `ReplayKey` covers every `UseId` and `RailId`, whatever its
    ///   model, sorted and not deduplicated (ERRATA N3a-9).
    /// - Single uses and counters are sets: an ID the request names twice is
    ///   committed once (ERRATA N3b-3).
    /// - Without any single use, the offer must expire at least 60 seconds
    ///   before the record can be deleted (6.1).
    pub fn build(input: &PlanInput<'_>) -> Result<Self, PlanError> {
        let mut ids = Vec::new();
        let mut singles = BTreeSet::new();
        let mut counters = BTreeSet::new();
        for s in input.schemes {
            for local in s.local_ids {
                let id = use_id(s.scheme, local);
                ids.push(id.0);
                match s.model {
                    UseModel::Single => {
                        singles.insert(id.0);
                    }
                    UseModel::Rate { k, epoch } => {
                        let key = rate_key(&id, k, epoch, input.now)
                            .ok_or_else(|| PlanError::ZeroEpoch(s.scheme.to_owned()))?;
                        counters.insert(CounterUse {
                            key,
                            limit: k,
                            resets_at: epoch_end(input.now, epoch),
                        });
                    }
                    UseModel::Reusable => {}
                }
            }
        }
        for r in input.rail_ids {
            ids.push(r.0);
            singles.insert(r.0);
        }
        if let Some(q) = input.quota {
            counters.insert(q.counter);
        }
        if singles.is_empty()
            && input.offer_expires.saturating_add(CLOCK_SKEW)
                > input.now.saturating_add(input.replay_window)
        {
            return Err(PlanError::OutlivesRecord);
        }
        let replay_key = crate::ids::replay_key(
            input.context,
            input.pay_body,
            input.attest_bodies,
            &ids,
        );
        ids.sort_unstable();
        Ok(Self {
            replay_key,
            ids,
            singles: singles.into_iter().collect(),
            counters: counters.into_iter().collect(),
            now: input.now,
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

    /// Single-model `UseId`s and `RailId`s, sorted, each once.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// OK or FAILED.
    pub status: Status,
    /// The charge from [`crate::pricing::Admission::settle`].
    pub charged: u64,
    /// The meter's count, in metered offers.
    pub metered_units: Option<u64>,
    /// What the scheme's `settle` returned.
    pub scheme_result: Option<Vec<u8>>,
    /// The response the carrier keeps for replays, if any.
    pub response: Option<Vec<u8>>,
    /// Settlement time.
    pub settled_at: u64,
}

impl Settlement {
    /// A settlement for a computed charge.
    #[must_use]
    pub fn new(charge: &crate::pricing::Charge, settled_at: u64) -> Self {
        Self {
            status: charge.status,
            charged: charge.charged,
            metered_units: charge.metered_units,
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
#[async_trait::async_trait]
pub trait UseStore: Send + Sync {
    /// 6.3 commit: replay check, then every single ID, then every counter;
    /// all or nothing.
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError>;

    /// A counter's current value (0 when absent), for quota room at pricing.
    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError>;

    /// Reads `outcome[rk]`.
    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError>;

    /// 6.4 settle: one conditional update that succeeds only from PENDING;
    /// on FAILED the outcome's counters are given back in the same write.
    async fn settle(&self, rk: &ReplayKey, s: &Settlement) -> Result<Settle, StoreError>;

    /// 6.4 timeout: every outcome still PENDING that was created before
    /// `created_before` moves to FAILED with charge 0 and `timed_out`, its
    /// counters given back, settled at `now`. Returns their `ReplayKey`s.
    async fn expire_pending(
        &self,
        created_before: u64,
        now: u64,
    ) -> Result<Vec<ReplayKey>, StoreError>;

    /// Records the refund of a timed-out outcome once: writes
    /// `scheme_result` only if the outcome is FAILED, timed out and has no
    /// `scheme_result` yet. Returns the record after the call, or `None`
    /// when there is none.
    async fn record_refund(
        &self,
        rk: &ReplayKey,
        scheme_result: &[u8],
    ) -> Result<Option<OutcomeRecord>, StoreError>;

    /// Deletes OK and FAILED outcome records created before `created_before`
    /// (the replay window has passed). PENDING records and every `used` entry
    /// stay. Returns how many were deleted.
    async fn purge(&self, created_before: u64) -> Result<u64, StoreError>;
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
        Commit, CommitPlan, OutcomeRecord, OutcomeStatus, ReplayKey, Settle, Settlement, UseTable,
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
        let keys = plan.counters().iter().map(|c| c.key).collect();
        t.put_outcome(rk, OutcomeRecord::pending(plan.now(), keys));
        Commit::New
    }

    fn give_back(t: &mut impl UseTable, rec: &OutcomeRecord) {
        for key in &rec.counters {
            let v = t.counter(key);
            t.set_counter(*key, v.saturating_sub(1));
        }
    }

    /// 6.4 settle: the status changes exactly once. On FAILED, single uses
    /// stay spent and the outcome's counters are given back.
    pub fn settle(t: &mut impl UseTable, rk: &ReplayKey, s: &Settlement) -> Settle {
        let Some(rec) = t.outcome(rk) else {
            return Settle::Unknown;
        };
        if rec.status != OutcomeStatus::Pending {
            return Settle::AlreadySettled(rec.clone());
        }
        let mut rec = rec.clone();
        rec.status = s.status.into();
        rec.charged = Some(s.charged);
        rec.metered_units = s.metered_units;
        rec.scheme_result.clone_from(&s.scheme_result);
        rec.response.clone_from(&s.response);
        rec.settled_at = Some(s.settled_at);
        if s.status == Status::Failed {
            give_back(t, &rec);
        }
        t.put_outcome(*rk, rec.clone());
        Settle::Settled(rec)
    }

    /// 6.4 timeout: PENDING outcomes created before `created_before` move
    /// to FAILED with charge 0, settled at `now`, their counters given back.
    pub fn expire_pending(t: &mut impl UseTable, created_before: u64, now: u64) -> Vec<ReplayKey> {
        let mut out = Vec::new();
        for rk in t.outcome_keys() {
            let Some(rec) = t.outcome(&rk) else { continue };
            if rec.status != OutcomeStatus::Pending || rec.created >= created_before {
                continue;
            }
            let mut rec = rec.clone();
            rec.status = OutcomeStatus::Failed;
            rec.charged = Some(0);
            rec.settled_at = Some(now);
            rec.timed_out = true;
            give_back(t, &rec);
            t.put_outcome(rk, rec);
            out.push(rk);
        }
        out.sort_unstable();
        out
    }

    /// Records a timed-out outcome's refund once (see
    /// [`super::UseStore::record_refund`]).
    pub fn record_refund(
        t: &mut impl UseTable,
        rk: &ReplayKey,
        scheme_result: &[u8],
    ) -> Option<OutcomeRecord> {
        let rec = t.outcome_mut(rk)?;
        if rec.needs_refund() {
            rec.scheme_result = Some(scheme_result.to_vec());
        }
        Some(rec.clone())
    }

    /// Deletes settled outcome records created before `created_before`.
    pub fn purge(t: &mut impl UseTable, created_before: u64) -> u64 {
        let mut n = 0;
        for rk in t.outcome_keys() {
            let old = t
                .outcome(&rk)
                .is_some_and(|r| r.status != OutcomeStatus::Pending && r.created < created_before);
            if old {
                t.delete_outcome(&rk);
                n += 1;
            }
        }
        n
    }
}
