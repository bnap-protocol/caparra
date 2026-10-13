//! The outcome state machine of draft-00 section 6, over any [`UseStore`].
//!
//! ```text
//!            commit (6.3)                 settle once (6.4)
//!   (none) ───────────────▶ PENDING ─────────────────────────▶ OK | FAILED
//!                              │                                    │
//!                              │ pending_timeout                    │ replay_window
//!                              ▼                                    ▼
//!                       FAILED, timed out                  record deleted; single
//!                    (refund on the next replay)           uses stay, a replay is SPENT
//! ```
//!
//! The gate verifies a credential and its binding against the request
//! before every commit, replays included, so a replay is always
//! re-verified. [`commit`] then turns the store's answer into the gate's
//! next step:
//!
//! | Store answer | Gate step |
//! | --- | --- |
//! | New | Run the action, then [`settle`] |
//! | Replay of a PENDING outcome | PENDING with `retry_after`; past `pending_timeout`, the outcome is timed out first |
//! | Replay of OK or FAILED inside `replay_window` | [`Admitted::Replay`]: the recorded outcome, receipt signed afresh with `replayed` |
//! | Replay outside `replay_window` | SPENT |
//! | A single ID used under another `ReplayKey` | SPENT |
//! | A full counter | `RATE_LIMITED` with `retry_after` |
//!
//! The status leaves PENDING exactly once: [`settle`] on a settled outcome
//! is refused with [`SettleError::AlreadySettled`] and changes nothing, and
//! a replay never writes a status.

use crate::error::{ErrorCode, ErrorObject};
use crate::hash::{CounterKey, Digest, OfferId, ReplayKey};
use crate::limits::Limits;
use crate::pricing::{self, AdmitInput, Admission, PriceError};
use crate::response::ResponseFields;
use crate::schnorr::Key;
use crate::store::{
    Commit, CommitPlan, OutcomeRecord, OutcomeStatus, Settle, Settlement, StoreError, UseStore,
};

/// Why a request cannot go past commit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CommitError {
    /// SPENT: a use ID is committed under another `ReplayKey`, or the
    /// replay window of this credential's outcome has passed.
    #[error("a use ID is already committed under another ReplayKey")]
    Spent,
    /// PENDING: the same credential is still in flight.
    #[error("the same credential is still in flight")]
    Pending {
        /// Seconds until `pending_timeout` ends, at least 1.
        retry_after: u64,
    },
    /// `RATE_LIMITED`: a rate or quota counter is full.
    #[error("a rate counter is full")]
    RateLimited {
        /// Seconds until the counter's epoch ends, at least 1.
        retry_after: u64,
    },
    /// UNAVAILABLE: the store failed; the gate fails closed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl CommitError {
    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Spent => ErrorCode::Spent,
            Self::Pending { .. } => ErrorCode::Pending,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::Store(_) => ErrorCode::Unavailable,
        }
    }

    /// The `retry_after` the Error object carries.
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Pending { retry_after } | Self::RateLimited { retry_after } => {
                Some(*retry_after)
            }
            Self::Spent | Self::Store(_) => None,
        }
    }

    /// The 8.2 Error object.
    #[must_use]
    pub fn to_error_object(&self) -> ErrorObject {
        let mut e = ErrorObject::new(self.code());
        e.retry_after = self.retry_after();
        e
    }
}

/// The result of a commit that may proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A fresh commit: the outcome is PENDING. Run the action, then
    /// [`settle`].
    New,
    /// The same credential for the same request, already settled: answer
    /// with the recorded outcome. The action never runs twice.
    Replay(Replay),
}

/// A replay of a settled outcome inside the replay window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    record: OutcomeRecord,
}

impl Replay {
    /// The recorded outcome.
    #[must_use]
    pub fn record(&self) -> &OutcomeRecord {
        &self.record
    }

    /// True when the outcome timed out and its refund is not recorded yet.
    ///
    /// The gate then calls the scheme's `settle` for FAILED with charge 0
    /// and stores the result with [`record_refund`], which writes it only
    /// once; the receipt carries the result the store returns.
    #[must_use]
    pub fn needs_refund(&self) -> bool {
        self.record.needs_refund()
    }

    /// The replay's receipt fields: the recorded status, `charged`,
    /// `metered_units`, `scheme_result` and `settled_at`, with `replayed`
    /// set, over the replaying request's Digest (8.1).
    #[must_use]
    pub fn receipt(&self, r: &ReceiptInput) -> Option<ResponseFields> {
        receipt(&self.record, r, true)
    }
}

/// Request-side inputs of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInput {
    /// The offer the credential used.
    pub offer_id: OfferId,
    /// The Digest of the request this Response answers.
    pub digest: Digest,
    /// The chosen pay entry's unit, when the credential has `pay`.
    pub unit: Option<String>,
    /// The offer is metered, so `metered_units` is required.
    pub metered: bool,
    /// The receipt key that will sign the ack.
    pub receipt_key: Key,
}

/// The Response fields for a settled outcome (8.1); `None` while PENDING.
///
/// A timed-out outcome has no meter count; a metered offer then reports 0.
#[must_use]
pub fn receipt(rec: &OutcomeRecord, r: &ReceiptInput, replayed: bool) -> Option<ResponseFields> {
    let status = rec.status.settled()?;
    Some(ResponseFields {
        status,
        replayed,
        charged: rec.charged.unwrap_or(0),
        unit: r.unit.clone(),
        offer_id: r.offer_id,
        digest: r.digest,
        metered_units: r.metered.then(|| rec.metered_units.unwrap_or(0)),
        scheme_result: rec.scheme_result.clone(),
        receipt_key: r.receipt_key,
        settled_at: rec.settled_at.unwrap_or(rec.created),
        unknown: Vec::new(),
    })
}

fn at_least_one(secs: u64) -> u64 {
    secs.max(1)
}

/// Commits a plan (6.3) and classifies a replay (6.4).
///
/// The caller has verified the credential and its binding against this
/// request; replays are therefore re-verified by construction.
pub async fn commit<S: UseStore + ?Sized>(
    store: &S,
    plan: &CommitPlan,
    limits: &Limits,
) -> Result<Admitted, CommitError> {
    let now = plan.now();
    match store.commit(plan).await? {
        Commit::New => Ok(Admitted::New),
        Commit::Spent { .. } => Err(CommitError::Spent),
        Commit::RateLimited { counter } => Err(CommitError::RateLimited {
            retry_after: at_least_one(counter.resets_at.saturating_sub(now)),
        }),
        Commit::Replay(rec) => replay(store, plan.replay_key(), rec, now, limits).await,
    }
}

async fn replay<S: UseStore + ?Sized>(
    store: &S,
    rk: &ReplayKey,
    mut rec: OutcomeRecord,
    now: u64,
    limits: &Limits,
) -> Result<Admitted, CommitError> {
    if rec.status == OutcomeStatus::Pending {
        let deadline = rec.created.saturating_add(limits.pending_timeout);
        if now <= deadline {
            return Err(CommitError::Pending {
                retry_after: at_least_one(deadline - now),
            });
        }
        // Past pending_timeout: the outcome is FAILED (6.4); time it out
        // now rather than wait for the sweep.
        store
            .expire_pending(now.saturating_sub(limits.pending_timeout), now)
            .await?;
        rec = store.outcome(rk).await?.ok_or(CommitError::Spent)?;
        if rec.status == OutcomeStatus::Pending {
            return Err(CommitError::Pending { retry_after: 1 });
        }
    }
    if now.saturating_sub(rec.created) >= limits.replay_window {
        return Err(CommitError::Spent);
    }
    Ok(Admitted::Replay(Replay { record: rec }))
}

/// Why a settle did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SettleError {
    /// The outcome already left PENDING; nothing changed. This is how a
    /// second settle, or a settle after the timeout, is refused.
    #[error("outcome already settled")]
    AlreadySettled(Box<OutcomeRecord>),
    /// No outcome under that `ReplayKey`.
    #[error("no outcome under that ReplayKey")]
    Unknown,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Settles an outcome exactly once (6.4).
///
/// Compute the charge first ([`Admission::settle`]), call the scheme's
/// deterministic `settle`, then call this. The Response may be sent only
/// after this returns `Ok`.
pub async fn settle<S: UseStore + ?Sized>(
    store: &S,
    rk: &ReplayKey,
    s: &Settlement,
) -> Result<OutcomeRecord, SettleError> {
    match store.settle(rk, s).await? {
        Settle::Settled(r) => Ok(r),
        Settle::AlreadySettled(r) => Err(SettleError::AlreadySettled(Box::new(r))),
        Settle::Unknown => Err(SettleError::Unknown),
    }
}

/// Stores the refund of a timed-out outcome once and returns the record
/// the receipt reports. A concurrent replay that recorded first wins; its
/// result is returned and the scheme MUST NOT pay out anything beyond it.
pub async fn record_refund<S: UseStore + ?Sized>(
    store: &S,
    rk: &ReplayKey,
    scheme_result: &[u8],
) -> Result<OutcomeRecord, SettleError> {
    store
        .record_refund(rk, scheme_result)
        .await?
        .ok_or(SettleError::Unknown)
}

/// What one maintenance sweep did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sweep {
    /// Outcomes that timed out to FAILED.
    pub timed_out: Vec<ReplayKey>,
    /// Settled outcome records deleted after the replay window.
    pub purged: u64,
}

/// The maintenance sweep: PENDING past `pending_timeout` moves to FAILED,
/// and settled records past `replay_window` are deleted. Single-use records
/// are never deleted here (section 12, "Retention").
pub async fn sweep<S: UseStore + ?Sized>(
    store: &S,
    now: u64,
    limits: &Limits,
) -> Result<Sweep, StoreError> {
    let timed_out = store
        .expire_pending(now.saturating_sub(limits.pending_timeout), now)
        .await?;
    let purged = store
        .purge(now.saturating_sub(limits.replay_window))
        .await?;
    Ok(Sweep { timed_out, purged })
}

/// Why admission failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdmitError {
    /// POLICY, UNDERPAID or `NOT_OFFERED`.
    #[error(transparent)]
    Price(#[from] PriceError),
    /// The store failed while reading quota counters.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl AdmitError {
    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Price(e) => e.code(),
            Self::Store(e) => e.code(),
        }
    }
}

/// Section 7 admission with the quota counters read from `store`.
pub async fn admit<S: UseStore + ?Sized>(
    store: &S,
    input: &AdmitInput<'_>,
) -> Result<Admission, AdmitError> {
    let mut values: Vec<(CounterKey, u64)> = Vec::new();
    for q in pricing::quota_candidates(input.offer, input.attest, input.now) {
        let v = store.counter(&q.counter.key).await?;
        values.push((q.counter.key, v));
    }
    let read = |k: &CounterKey| {
        values
            .iter()
            .find(|(key, _)| key == k)
            .map_or(0, |(_, v)| *v)
    };
    Ok(pricing::admit(input, read)?)
}

#[cfg(test)]
mod tests;
