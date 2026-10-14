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
//! **One entry point.** The gate verifies a credential and its binding
//! against the request (4.4, then every scheme's `verify` and every rail's
//! confirmation) and hands everything it learned to [`process`], which runs
//! the rest of the socket in the one order that is safe:
//!
//! 1. collect the request's use IDs and compute its `ReplayKey` (6.1);
//! 2. look up `outcome[rk]` and classify a known credential as a replay,
//!    PENDING or SPENT, **before any pricing**: a replay is answered from
//!    what its commit recorded, so quota counters its own commit consumed
//!    can never misprice or refuse it (6.4);
//! 3. only for a new credential, admit it (section 7, quota counters read
//!    from the store), then commit it (6.3). The store's commit re-checks
//!    every single use and every counter limit in one serializable
//!    transaction, so a pricing read that is stale by then can never admit
//!    more than the store allows: it aborts with `RATE_LIMITED` and
//!    consumes nothing. When the fresh path fails before the commit (STALE,
//!    POLICY, UNDERPAID, ...), `outcome[rk]` is read again: a copy of the
//!    same credential that committed after step 2's lookup is what filled
//!    the quota this copy priced against, and its record answers this copy
//!    (PENDING, or a replay), never a refusal.
//!
//! [`process`] answers:
//!
//! | Outcome | Gate step |
//! | --- | --- |
//! | [`Admitted::New`] | Run the action, then [`settle`] with the [`Pending`] |
//! | [`Admitted::Replay`] | Answer from the [`Recorded`] outcome, receipt signed afresh with `replayed`; a timed-out outcome's refund first |
//! | PENDING (same credential in flight) | [`ProcessError::Pending`] with `retry_after`; past `pending_timeout`, the outcome is timed out and answered as a replay |
//! | Record past `replay_window` | [`ProcessError::Spent`] |
//! | A single ID used under another `ReplayKey` | [`ProcessError::Spent`] |
//! | A full counter | [`ProcessError::RateLimited`] with `retry_after` |
//! | A new credential on an expired offer | [`ProcessError::Stale`] |
//! | Admission refused | [`ProcessError::Price`] (POLICY, UNDERPAID, `NOT_OFFERED`, `BAD_CREDENTIAL`) |
//!
//! The status leaves PENDING exactly once: [`settle`] on a settled outcome
//! is refused with [`SettleError::AlreadySettled`] and changes nothing, a
//! settle that comes after `pending_timeout` loses to the timeout, and a
//! replay never writes a status.
//!
//! **A timed-out outcome is refunded before it is answered.** The timeout
//! moves an outcome to FAILED with no `scheme_result`; the refund it implies
//! is computed later, by whichever request reaches it first:
//!
//! - a replay that gets [`Admitted::Replay`] with [`Recorded::needs_refund`];
//! - the late action itself, whose [`settle`] returns
//!   [`SettleError::AlreadySettled`] because the timeout won. The gate then
//!   discards the `scheme_result` and any change it computed for OK (none
//!   of it was sent) and answers from the recorded FAILED outcome.
//!
//! Either way the gate runs the scheme's `settle` for FAILED, charge 0,
//! with the cap of [`Recorded::refund_cap`] (fixed at commit from the
//! admitted value, never priced again), stores the result with
//! [`record_refund`] (the first write wins), and answers from the
//! [`Recorded`] it returns. [`Recorded::receipt`] makes no receipt for an
//! outcome that still needs its refund, so the refund cannot be skipped.

use crate::error::{ErrorCode, ErrorObject, Stale};
use crate::hash::{Context, CounterKey, Digest, OfferId, RailId, ReplayKey};
use crate::limits::{Limits, expired};
use crate::offer::OfferFields;
use crate::pricing::{
    self, Admission, AdmitInput, ChangeCap, Charge, PayValue, PriceError, VerifiedAttest,
};
use crate::response::{ResponseFields, Status};
use crate::schnorr::Key;
use crate::store::{
    Commit, CommitPlan, OutcomeRecord, OutcomeStatus, PlanError, SchemeUses, Settle, Settlement,
    StoreError, UseStore, Uses,
};

/// Everything the gate verified about one request, for [`process`].
///
/// The gate fills it after the 4.4 checks, every scheme's `verify` and
/// every rail's confirmation. Nothing in it is read from the use store.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The offer the credential uses, checked (4.4).
    pub offer: &'a OfferFields,
    /// The credential's Context.
    pub context: &'a Context,
    /// The pay body, or empty without pay.
    pub pay_body: &'a [u8],
    /// The attest bodies in the credential's (sorted) order.
    pub attest_bodies: &'a [&'a [u8]],
    /// Every scheme in the request, pay and attestations, with the local
    /// IDs its `verify` returned and the model the registry sets.
    pub schemes: &'a [SchemeUses<'a>],
    /// `RailId`s the rails confirmed for the request's payments.
    pub rail_ids: &'a [RailId],
    /// The credential's value scheme, if it has `pay`: its claim, what the
    /// rails and the signer confirmed, and its registered refund property.
    pub pay: Option<PayValue<'a>>,
    /// Every attestation that verified.
    pub attest: &'a [VerifiedAttest],
    /// The gate's clock.
    pub now: u64,
}

/// Why [`process`] did not admit a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProcessError {
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
    /// STALE: a credential the store does not know, on an offer or quote
    /// that has expired. A known credential is still answered from its
    /// outcome (ERRATA N3b-22).
    #[error(transparent)]
    Stale(Stale),
    /// POLICY, UNDERPAID, `NOT_OFFERED` or `BAD_CREDENTIAL` from admission.
    #[error(transparent)]
    Price(#[from] PriceError),
    /// POLICY (an offer that outlives the record) or UNAVAILABLE (a
    /// configuration error) from the commit plan.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// UNAVAILABLE: the store failed; the gate fails closed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ProcessError {
    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Spent => ErrorCode::Spent,
            Self::Pending { .. } => ErrorCode::Pending,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::Stale(_) => ErrorCode::Stale,
            Self::Price(e) => e.code(),
            Self::Plan(e) => e.code(),
            Self::Store(_) => ErrorCode::Unavailable,
        }
    }

    /// The `retry_after` the Error object carries.
    #[must_use]
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Pending { retry_after } | Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
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

/// What [`process`] admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A fresh commit: the outcome is PENDING. Run the action, then
    /// [`settle`].
    New(Pending),
    /// The same credential for the same request, already settled (or just
    /// timed out): answer with the recorded outcome. The action never runs
    /// twice.
    Replay(Recorded),
}

/// A committed, PENDING outcome: the admission it was priced with and its
/// `ReplayKey`. Only [`process`] makes one, and [`settle`] takes one, so a
/// gate cannot settle an outcome it did not commit through [`process`]:
///
/// ```compile_fail,E0451
/// use bnap_core::outcome::Pending;
/// fn forge(rk: bnap_core::ReplayKey, admission: bnap_core::Admission) -> Pending {
///     Pending { replay_key: rk, admission }
/// }
/// ```
///
/// Nor can it build a commit plan of its own, priced or not:
///
/// ```compile_fail,E0624
/// let _ = bnap_core::store::CommitPlan::build;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    replay_key: ReplayKey,
    admission: Admission,
}

impl Pending {
    /// The outcome's `ReplayKey`; the change budget's settlement.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    /// The admission the commit was priced with.
    #[must_use]
    pub fn admission(&self) -> &Admission {
        &self.admission
    }

    /// The charge for this outcome ([`Admission::settle`]): build the
    /// [`Settlement`] from it and give its cap to the scheme's `settle`.
    #[must_use]
    pub fn charge(&self, status: Status, units: u64) -> Charge {
        self.admission.settle(status, units)
    }
}

/// A recorded outcome, as the store returned it, to answer from. Only this
/// module makes one: [`process`] for a replay, [`settle`] for the request
/// that ran the action, [`record_refund`] after a refund.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    replay_key: ReplayKey,
    record: OutcomeRecord,
    replayed: bool,
}

impl Recorded {
    /// The outcome's `ReplayKey`.
    #[must_use]
    pub fn replay_key(&self) -> &ReplayKey {
        &self.replay_key
    }

    /// The recorded outcome.
    #[must_use]
    pub fn record(&self) -> &OutcomeRecord {
        &self.record
    }

    /// True when the answer is a replay (8.1 `replayed`): it came from
    /// [`process`], not from the request that ran the action.
    #[must_use]
    pub fn replayed(&self) -> bool {
        self.replayed
    }

    /// True when the outcome timed out and its refund is not recorded yet.
    ///
    /// The gate then calls the scheme's `settle` for FAILED, charge 0,
    /// under [`Self::refund_cap`], and stores the result with
    /// [`record_refund`], which writes it only once; the answer is the
    /// [`Recorded`] that returns. A credential without pay has no value
    /// scheme to settle and nothing to refund: the gate records `None`.
    #[must_use]
    pub fn needs_refund(&self) -> bool {
        self.record.needs_refund()
    }

    /// The change budget of the refund, while [`Self::needs_refund`]: the
    /// cap the commit recorded (the admitted value for an `atomic` scheme,
    /// 0 otherwise), in the pay entry's unit, for a FAILED settlement. The
    /// replay is never priced, so the refund can only return what the
    /// commit consumed. `None` once the refund is recorded, and for an
    /// outcome that did not time out.
    #[must_use]
    pub fn refund_cap(&self) -> Option<ChangeCap> {
        self.needs_refund().then(|| {
            ChangeCap::new(
                self.record.refund_cap,
                self.record.unit.clone(),
                Status::Failed,
            )
        })
    }

    /// The Response fields (8.1): the recorded status, `charged`,
    /// `metered_units`, `scheme_result` and `settled_at`, with `replayed`
    /// as [`Self::replayed`] says, over the answering request's Digest.
    ///
    /// `None` while [`Self::needs_refund`]: a timed-out outcome is answered
    /// only once its refund is recorded. A timed-out outcome has no meter
    /// count; a metered offer then reports 0.
    #[must_use]
    pub fn receipt(&self, r: &ReceiptInput) -> Option<ResponseFields> {
        receipt(&self.record, r, self.replayed)
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

/// The Response fields for a settled outcome (8.1); `None` while PENDING,
/// and `None` for a timed-out outcome whose refund is not recorded yet.
fn receipt(rec: &OutcomeRecord, r: &ReceiptInput, replayed: bool) -> Option<ResponseFields> {
    if rec.needs_refund() {
        return None;
    }
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

/// The socket's whole decision for one verified request: replay
/// detection, then pricing and commit for a new credential (sections 6
/// and 7). See the module docs for the order and the answers.
///
/// The caller has verified the credential and its binding against this
/// request, so a replay is re-verified by construction. The caller must not
/// price or commit by any other path; this is the only one bnap-core
/// offers.
pub async fn process<S: UseStore + ?Sized>(
    store: &S,
    req: &Request<'_>,
    limits: &Limits,
) -> Result<Admitted, ProcessError> {
    let now = req.now;
    // (ii) Every ID the request names, and its ReplayKey: no pricing yet.
    let uses = Uses::collect(
        req.context,
        req.pay_body,
        req.attest_bodies,
        req.schemes,
        req.rail_ids,
        now,
    )?;
    let rk = *uses.replay_key();
    // (iii) A credential the store knows is a replay, PENDING or SPENT,
    // whatever pricing would say now.
    if let Some(rec) = store.outcome(&rk).await? {
        return classify(store, rk, rec, now, limits).await;
    }
    // (iv) A new credential: its offer must still be valid, then price it
    // and commit. The commit re-checks every single use and every counter.
    let (admission, plan) = match price(store, req, uses, limits).await {
        Ok(priced) => priced,
        Err(ProcessError::Store(e)) => return Err(ProcessError::Store(e)),
        // Another copy of this credential may have committed after the
        // lookup above (a retry racing its lost first attempt), and its
        // commit is what made pricing fail: it filled the quota this copy
        // read. That commit wrote the counter and outcome[rk] in one
        // transaction, so a read that saw the full counter sees the record
        // too: answer this copy from it (PENDING, or a replay).
        Err(e) => {
            return match store.outcome(&rk).await? {
                Some(rec) => classify(store, rk, rec, now, limits).await,
                None => Err(e),
            };
        }
    };
    match store.commit(&plan).await? {
        Commit::New => Ok(Admitted::New(Pending {
            replay_key: rk,
            admission,
        })),
        // The same credential committed between the lookup and this commit.
        Commit::Replay(rec) => classify(store, rk, rec, now, limits).await,
        Commit::Spent { .. } => Err(ProcessError::Spent),
        Commit::RateLimited { counter } => Err(ProcessError::RateLimited {
            retry_after: at_least_one(counter.resets_at.saturating_sub(now)),
        }),
    }
}

/// The fresh path before the commit: the offer must still be valid, then
/// admission (section 7, counters read from `store`) and the commit plan.
async fn price<S: UseStore + ?Sized>(
    store: &S,
    req: &Request<'_>,
    uses: Uses,
    limits: &Limits,
) -> Result<(Admission, CommitPlan), ProcessError> {
    fresh_offer(req)?;
    let admission = admit(
        store,
        &AdmitInput {
            offer: req.offer,
            pay: req.pay.clone(),
            attest: req.attest,
            now: req.now,
        },
    )
    .await?;
    let plan = CommitPlan::build(
        uses,
        &admission,
        req.offer.expires,
        req.now,
        limits.replay_window,
    )?;
    Ok((admission, plan))
}

/// A fresh commit needs an offer, and a quote for the chosen pay entry,
/// that have not expired (4.4, with the 60 s skew). A replay does not: its
/// outcome answers it.
fn fresh_offer(req: &Request<'_>) -> Result<(), ProcessError> {
    let o = req.offer;
    if expired(o.expires, req.now) {
        return Err(ProcessError::Stale(Stale::Expired));
    }
    let quote = req
        .pay
        .as_ref()
        .and_then(|p| o.pay_entry(p.scheme))
        .map(|(_, e)| e.effective_quote_expires(o.expires));
    if quote.is_some_and(|q| expired(q, req.now)) {
        return Err(ProcessError::Stale(Stale::QuoteExpired));
    }
    Ok(())
}

/// Classifies a known credential (6.4): PENDING inside `pending_timeout`,
/// timed out past it, SPENT past the record window, a replay otherwise.
async fn classify<S: UseStore + ?Sized>(
    store: &S,
    rk: ReplayKey,
    mut rec: OutcomeRecord,
    now: u64,
    limits: &Limits,
) -> Result<Admitted, ProcessError> {
    if rec.status == OutcomeStatus::Pending {
        let deadline = rec.created.saturating_add(limits.pending_timeout);
        if now <= deadline {
            return Err(ProcessError::Pending {
                retry_after: at_least_one(deadline - now),
            });
        }
        // Past pending_timeout: the outcome is FAILED (6.4); time it out
        // now rather than wait for the sweep.
        store
            .expire_pending(now.saturating_sub(limits.pending_timeout), now)
            .await?;
        rec = store.outcome(&rk).await?.ok_or(ProcessError::Spent)?;
        if rec.status == OutcomeStatus::Pending {
            return Err(ProcessError::Pending { retry_after: 1 });
        }
    }
    if now.saturating_sub(rec.created) >= limits.record_window() {
        return Err(ProcessError::Spent);
    }
    Ok(Admitted::Replay(Recorded {
        replay_key: rk,
        record: rec,
        replayed: true,
    }))
}

/// Section 7 admission with the quota counters read from `store`. Private:
/// [`process`] runs it only for a credential the store does not know.
async fn admit<S: UseStore + ?Sized>(
    store: &S,
    input: &AdmitInput<'_>,
) -> Result<Admission, ProcessError> {
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

/// Why a settle did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SettleError {
    /// The outcome already left PENDING, or this settle came after
    /// `pending_timeout` and the store timed it out instead; the action's
    /// result is not recorded. The gate answers from the recorded outcome
    /// (its refund first, if [`Recorded::needs_refund`]); the receipt is
    /// not `replayed`, since it answers the request that ran the action.
    #[error("outcome already settled")]
    AlreadySettled(Box<Recorded>),
    /// No outcome under that `ReplayKey`.
    #[error("no outcome under that ReplayKey")]
    Unknown,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Settles the outcome [`process`] committed, exactly once (6.4).
///
/// Compute the charge first ([`Pending::charge`]), call the scheme's
/// deterministic `settle` under its cap, then call this. The Response, and
/// any change in it, may be sent only after this returns `Ok`.
///
/// A settle at `s.settled_at` later than the outcome's `created +
/// pending_timeout` is refused: the store times the outcome out in the same
/// transaction (6.4), so the late action loses to the timeout whether or
/// not a sweep or a replay ran first.
///
/// [`SettleError::AlreadySettled`] means the outcome left PENDING without
/// this write, in practice because the action outlived `pending_timeout`.
/// Discard the `scheme_result` and change computed for this settlement and
/// answer from the [`Recorded`] outcome the error carries: if it
/// [needs a refund](Recorded::needs_refund), run the scheme's `settle` for
/// FAILED under [`Recorded::refund_cap`], [`record_refund`] it and answer
/// from the [`Recorded`] that returns; otherwise answer from it as it is.
pub async fn settle<S: UseStore + ?Sized>(
    store: &S,
    pending: &Pending,
    s: &Settlement,
    limits: &Limits,
) -> Result<Recorded, SettleError> {
    let recorded = |record| Recorded {
        replay_key: pending.replay_key,
        record,
        replayed: false,
    };
    match store
        .settle(&pending.replay_key, s, limits.pending_timeout)
        .await?
    {
        Settle::Settled(r) => Ok(recorded(r)),
        Settle::AlreadySettled(r) => Err(SettleError::AlreadySettled(Box::new(recorded(r)))),
        Settle::Unknown => Err(SettleError::Unknown),
    }
}

/// Stores the refund of a timed-out outcome once and returns the outcome
/// to answer from. `scheme_result` is what the scheme's FAILED `settle`
/// returned under [`Recorded::refund_cap`], `None` when it had nothing to
/// refund. A concurrent request that recorded first wins; its result is
/// returned and the scheme MUST NOT pay out anything beyond it.
pub async fn record_refund<S: UseStore + ?Sized>(
    store: &S,
    recorded: &Recorded,
    scheme_result: Option<&[u8]>,
) -> Result<Recorded, SettleError> {
    let record = store
        .record_refund(&recorded.replay_key, scheme_result)
        .await?
        .ok_or(SettleError::Unknown)?;
    Ok(Recorded {
        replay_key: recorded.replay_key,
        record,
        replayed: recorded.replayed,
    })
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
/// and settled records past `replay_window` ([`Limits::record_window`]) are
/// deleted once their offer can no longer be presented, with a clock skew
/// of margin for the gate's other clocks ([`UseStore::purge`]). Single-use
/// records are never deleted here (section 12, "Retention").
pub async fn sweep<S: UseStore + ?Sized>(
    store: &S,
    now: u64,
    limits: &Limits,
) -> Result<Sweep, StoreError> {
    let timed_out = store
        .expire_pending(now.saturating_sub(limits.pending_timeout), now)
        .await?;
    let purged = store
        .purge(now.saturating_sub(limits.record_window()), now)
        .await?;
    Ok(Sweep { timed_out, purged })
}

#[cfg(test)]
mod tests;
