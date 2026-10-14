//! The signer plug and the capped view of it that schemes get.
//!
//! The signer is operator-trusted and keeps every key in its own process:
//! offer and receipt keys for BIP-340, issuer keys for blind signatures. No
//! plug ever sees a secret key; the trait only moves public data.
//!
//! - [`Signer::schnorr`] takes a [`CoreMessage`], which only bnap-core can
//!   build, so the signer never signs raw bytes:
//!
//!   ```compile_fail,E0308
//!   async fn forge(s: &dyn bnap_plug::Signer) {
//!       // A plug cannot pass its own 32 bytes.
//!       let _ = s.schnorr(&[0u8; 32]).await;
//!   }
//!   ```
//!
//! - A scheme never holds the [`Signer`]. It gets a [`CappedSigner`], which
//!   can check unblinded notes and sign blinded outputs worth at most the
//!   change cap bnap-core computed (`value - charged`), and nothing more: it
//!   has no way to sign a message at all, so a scheme can never get an
//!   offer or a receipt signed.
//! - The change cap is a budget, not a per-call limit. Every
//!   [`CappedSigner::blind_sign`] call takes its outputs out of one shared
//!   remaining amount with a compare-and-swap before the signer is called,
//!   clones share it, and the [`SettleGuard`] the gate holds closes it when
//!   the scheme's `settle` returns, so a clone kept past `settle` signs
//!   nothing.
//! - **The outcome's total is kept in the use store.** Before the signer is
//!   called, [`CappedSigner::blind_sign`] reserves the outputs in the
//!   outcome's record ([`bnap_core::outcome::reserve_change`],
//!   [`UseStore::reserve_change`]), in one durable store transaction: one
//!   running total per `ReplayKey`, across the OK change and the FAILED
//!   refund, each distinct output once, never above the admitted value. The
//!   store is the gate's durable state, shared by every gate instance, so
//!   the bound holds when a signer restarts, when a gate restarts, and
//!   across every signer instance: a scheme that keeps its signatures and
//!   fails every settle, so that no refund is ever recorded and each replay
//!   opens a new budget, still gets at most the value signed for one
//!   outcome (ERRATA N3b-29).
//! - The signer keeps a total of its own as a second line: every call
//!   names its settlement ([`ChangeLimit`]: `ReplayKey`, status, unit, cap
//!   and how long the outcome can still be settled), and [`ChangeLedger`]
//!   keeps one total per `ReplayKey` in the signer's memory. A restart or a
//!   second signer instance starts it from 0, which is why it is not the
//!   bound the gate relies on.
//! - A scheme names a note by its secret, never by its point: the signer
//!   derives `Y = hash_to_curve(secret)` itself
//!   ([`bnap_core::note::hash_to_curve`]) and checks `C = k·Y` against
//!   that. From one note `(Y, C)`, every multiple `(m·Y, m·C)` also passes a
//!   check of `C = k·y` for a `y` the caller picks, so a scheme that could
//!   name `y` could make one note count as many.
//! - The verify-only view a scheme's `verify` gets keeps the notes the
//!   signer accepted, each once, in the view's unit
//!   ([`CappedSigner::notes`]), under the `Y` the view derived from the
//!   secret itself. The gate passes them to admission as backing, so a
//!   notes scheme's value is never more than the notes the signer checked.
//!   The commit consumes each one under `H_"bnap/note"(Y)`, an ID that does
//!   not depend on the scheme ([`bnap_core::pricing::note_id`]): the
//!   signer's keysets are shared by every value scheme on the gate, so a
//!   note admitted under one scheme is SPENT under any other.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bnap_core::ErrorCode;
use bnap_core::hash::ReplayKey;
use bnap_core::limits::CLOCK_SKEW;
use bnap_core::note::hash_to_curve;
use bnap_core::outcome::reserve_change;
use bnap_core::pricing::{Backing, BackingSource, ChangeCap};
use bnap_core::response::Status;
use bnap_core::schnorr::Signature;
use bnap_core::sign::CoreMessage;
use bnap_core::store::{ChangeOutput, Reserve, UseStore};

/// A compressed secp256k1 point, 33 bytes: a note's `Y` or `C`, a blinded
/// output `B'` or a blind signature `C'`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point(pub [u8; 33]);

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Point({})", hex::encode(self.0))
    }
}

/// An issuer keyset ID, as the issuer names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeysetId(pub Vec<u8>);

/// A blinded output to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindedOutput {
    /// Its amount, in the keyset's unit.
    pub amount: u64,
    /// `B'`.
    pub blinded: Point,
}

/// A NUT-12 DLEQ proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dleq {
    /// The challenge.
    pub e: [u8; 32],
    /// The response.
    pub s: [u8; 32],
}

/// A blind signature on one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindSignature {
    /// The output's amount.
    pub amount: u64,
    /// `C'`.
    pub signature: Point,
    /// Proof that `C'` was made with the keyset's key for `amount`.
    pub dleq: Dleq,
}

/// Why the signer did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The outputs are worth more than what is left of the change cap.
    #[error("outputs worth {sum} exceed the cap {cap}")]
    OverCap {
        /// What the outputs add up to (saturating); for an outcome's
        /// running total (the store's or the signer's), the total they
        /// would bring it to.
        sum: u64,
        /// What was left of the cap; for an outcome's running total, the
        /// cap that bounds it.
        cap: u64,
    },
    /// The signer refused: an unknown key or keyset, a key held for another
    /// use, a verify-only capped signer, or a malformed answer.
    #[error("signer refused: {0}")]
    Refused(String),
    /// The signer cannot be reached.
    #[error("signer unavailable: {0}")]
    Unavailable(String),
}

impl SignerError {
    /// UNAVAILABLE: the gate fails closed whenever the signer does not sign
    /// (draft-00 8.2, section 12 "Fail closed").
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::Unavailable
    }
}

/// The signer plug (operator-trusted). Keys stay in its process.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Signs a message bnap-core built, with the key it names.
    ///
    /// MUST refuse unless the signer holds [`CoreMessage::key`] for the use
    /// [`CoreMessage::purpose`] needs (`offer` for an offer signature,
    /// `receipt` for an ack).
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError>;

    /// Checks an unblinded note given its secret (the UTF-8 bytes of the
    /// secret string, `schemes/bnap-notes.md`): computes `Y =
    /// hash_to_curve(secret)` (NUT-00, [`bnap_core::note::hash_to_curve`])
    /// and accepts the note when `c` is the keyset's key for `amount` times
    /// that `Y` and the keyset is in `unit`. Returns the `Y` it checked, or
    /// `None` for a note it does not accept.
    ///
    /// MUST derive `Y` from `secret` itself and never check a point a
    /// caller supplies: from one note `(Y, C)`, every multiple `(m·Y, m·C)`
    /// satisfies `C = k·Y` too. MUST answer `None` for a keyset of another
    /// unit: admission counts the accepted amount in `unit`.
    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        unit: &str,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError>;

    /// Signs blinded outputs as change or a refund for the settlement
    /// `limit` names.
    ///
    /// The gate calls it only through [`CappedSigner::blind_sign`], which
    /// has reserved the outputs in the use store first
    /// ([`UseStore::reserve_change`]): that reservation, durable and shared
    /// by every gate and signer instance, is what bounds an outcome's change
    /// and refund together at its value, across restarts.
    ///
    /// MUST refuse a keyset that is not in `limit.unit`. MUST refuse an
    /// empty batch and any output of amount 0, which carries no value but
    /// costs signer work. MUST keep one running total per outcome
    /// (`limit.replay_key`), across its OK change and its FAILED refund, and
    /// refuse a call that would take that total above `limit.cap`
    /// (bnap-core set it to `value - charged`; the first cap named for a
    /// `ReplayKey` and status bounds that status), and MUST NOT drop an
    /// outcome's total before `limit.keep_until` (plus a clock skew for its
    /// own clock): until then a replay can still settle the outcome. An
    /// output already signed for the same `ReplayKey`, under either status,
    /// MAY be signed again without counting twice, since it makes the same
    /// note. [`ChangeLedger`] does exactly this. Its total is a second line
    /// of defence, not the bound: kept in the signer's memory, it starts
    /// from 0 after a restart and is not shared with another signer
    /// instance. A signer MAY persist and share it as well.
    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError>;
}

/// The settlement a blind signature pays change or a refund for, as every
/// [`Signer::blind_sign`] call names it.
///
/// A `ReplayKey` can be settled more than once: by the gate's own settle
/// (OK, change worth up to `value - charged`), and by the refund of a
/// timed-out outcome (FAILED, up to `value`), which every replay runs again
/// until a refund is recorded. Only one settlement is recorded, but a
/// scheme can keep what it got signed in each and return it inside a later
/// `scheme_result`, so every output is counted against one total per
/// `ReplayKey` across all of them, bounded by each status's cap: never more
/// than `value` in all (ERRATA N3b-16, N3b-29). The use store keeps that
/// total durably ([`UseStore::reserve_change`]); the signer keeps its own
/// as a second line. An honest refund is a superset of the change
/// (`bnap:notes` signs `outputs` and `refund_outputs` on FAILED), so
/// re-signing the change outputs costs it nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeLimit {
    /// The outcome being settled.
    pub replay_key: ReplayKey,
    /// OK pays change, FAILED a refund.
    pub status: Status,
    /// The pay entry's unit; a keyset in another unit MUST be refused.
    pub unit: String,
    /// The most every blind signature for this settlement may be worth
    /// together.
    pub cap: u64,
    /// Until when the outcome can still be settled: the earliest time the
    /// store may purge its record ([`ChangeCap::keep_until`]). A signer
    /// keeps its total for `replay_key` at least until then, plus a clock
    /// skew ([`ChangeLedger::forget_expired`]).
    pub keep_until: u64,
}

/// One output as signed: keyset, amount and `B'`. The same triple always
/// makes the same note.
type SignedOutput = (Vec<u8>, u64, [u8; 33]);

/// Refuses an empty batch and any output of amount 0. Neither carries
/// value, but each is signer work a hostile scheme could ask for without
/// bound under any cap, so the budget and the ledger both refuse them before
/// counting anything.
fn check_outputs(outputs: &[BlindedOutput]) -> Result<(), SignerError> {
    if outputs.is_empty() {
        return Err(SignerError::Refused("no outputs to sign".into()));
    }
    if outputs.iter().any(|o| o.amount == 0) {
        return Err(SignerError::Refused("an output of amount 0".into()));
    }
    Ok(())
}

/// What a [`ChangeLedger`] keeps for one outcome: the cap each status was
/// first named with, what was signed so far under either, and the outputs
/// signed.
#[derive(Debug, Default)]
struct Signed {
    ok_cap: Option<u64>,
    failed_cap: Option<u64>,
    total: u64,
    outputs: BTreeSet<SignedOutput>,
    keep_until: u64,
}

impl Signed {
    /// The cap a status was first named with, pinned on first use.
    fn pin(&mut self, status: Status, cap: u64) -> u64 {
        let slot = match status {
            Status::Ok => &mut self.ok_cap,
            Status::Failed => &mut self.failed_cap,
        };
        *slot.get_or_insert(cap)
    }
}

/// The running total of change and refunds a signer signed, per outcome,
/// for [`Signer::blind_sign`] implementations: the signer's second line of
/// defence behind the use store's reservation.
///
/// [`ChangeLedger::reserve`] is called before signing. It keeps one total
/// per `ReplayKey` across the OK change and the FAILED refund (see
/// [`ChangeLimit`]) and counts each distinct output (keyset, amount, `B'`)
/// once per `ReplayKey`, so a deterministic `settle` that runs again (a
/// replay recomputing a refund after a crash, two concurrent replays) signs
/// the same notes again for nothing, a refund that re-signs the change
/// outputs pays only for its new ones, and new outputs that would take the
/// total beyond the call's cap are refused. The first cap a `ReplayKey` and
/// status is named with bounds that status: a later call with a larger cap
/// does not raise it.
///
/// It is in memory: a signer that restarts starts from 0, and a second
/// signer instance has its own. That alone would let a scheme that keeps
/// its signatures and fails every settle (so no refund is ever recorded and
/// each replay opens a new budget) get a fresh `value` signed after every
/// restart, and on every instance. What bounds an outcome across restarts
/// and instances is the reservation [`CappedSigner::blind_sign`] makes in
/// the use store before every signer call ([`UseStore::reserve_change`]),
/// durable and shared by every gate instance (ERRATA N3b-29). Drop what it
/// keeps only with [`ChangeLedger::forget_expired`], once an outcome can no
/// longer be settled.
#[derive(Debug, Default)]
pub struct ChangeLedger {
    outcomes: Mutex<HashMap<ReplayKey, Signed>>,
}

impl ChangeLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `outputs` to the outcome's total, or refuses with
    /// [`SignerError::OverCap`] and records nothing when the total would
    /// pass the cap. Outputs already reserved for the same `ReplayKey`,
    /// under either status, count nothing, and a batch of only such outputs
    /// is accepted whatever the total, since it makes no new note. An empty
    /// batch, or an output of amount 0, is refused with
    /// [`SignerError::Refused`].
    pub fn reserve(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<(), SignerError> {
        check_outputs(outputs)?;
        let mut all = self.outcomes.lock().unwrap_or_else(PoisonError::into_inner);
        let signed = all.entry(limit.replay_key).or_default();
        signed.keep_until = signed.keep_until.max(limit.keep_until);
        let cap = signed.pin(limit.status, limit.cap).min(limit.cap);
        let fresh: BTreeSet<SignedOutput> = outputs
            .iter()
            .map(|o| (keyset.0.clone(), o.amount, o.blinded.0))
            .filter(|o| !signed.outputs.contains(o))
            .collect();
        if fresh.is_empty() {
            // Every output was signed for this outcome before: the same
            // notes again, which adds nothing to any total.
            return Ok(());
        }
        let total = fresh
            .iter()
            .try_fold(signed.total, |acc, (_, amount, _)| acc.checked_add(*amount));
        match total {
            Some(total) if total <= cap => {
                signed.total = total;
                signed.outputs.extend(fresh);
                Ok(())
            }
            total => Err(SignerError::OverCap {
                sum: total.unwrap_or(u64::MAX),
                cap,
            }),
        }
    }

    /// What was signed for an outcome so far, change and refund together,
    /// each distinct output once.
    #[must_use]
    pub fn total(&self, replay_key: &ReplayKey) -> u64 {
        self.outcomes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(replay_key)
            .map_or(0, |s| s.total)
    }

    /// Drops what was kept for every outcome that can no longer be settled:
    /// its latest [`ChangeLimit::keep_until`] plus a clock skew (the
    /// signer's clock may run ahead of the gate's) is before `now`. Returns
    /// how many outcomes were dropped. An outcome is never dropped earlier,
    /// since a replay could still settle it.
    pub fn forget_expired(&self, now: u64) -> usize {
        let mut all = self.outcomes.lock().unwrap_or_else(PoisonError::into_inner);
        let before = all.len();
        all.retain(|_, s| s.keep_until.saturating_add(CLOCK_SKEW) >= now);
        before - all.len()
    }
}

/// The notes a verify-only view accepted: amount by `Y`, each note once.
type Tally = Mutex<BTreeMap<[u8; 33], u64>>;

/// A change budget: what is left of the cap, whether the settlement it was
/// made for is over, and the store that keeps the outcome's total.
struct Budget {
    limit: ChangeLimit,
    cap: ChangeCap,
    store: Arc<dyn UseStore>,
    remaining: AtomicU64,
    closed: AtomicBool,
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Budget")
            .field("limit", &self.limit)
            .field("remaining", &self.remaining)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Budget {
    /// Takes `sum` out of what is left, with a compare-and-swap, or
    /// refuses: after the guard closed the budget, or past the cap.
    fn take(&self, sum: Option<u64>) -> Result<(), SignerError> {
        let mut left = self.remaining.load(Ordering::SeqCst);
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(SignerError::Refused(
                    "the settlement this signer was made for is over".into(),
                ));
            }
            let Some(rest) = sum.and_then(|sum| left.checked_sub(sum)) else {
                return Err(SignerError::OverCap {
                    sum: sum.unwrap_or(u64::MAX),
                    cap: left,
                });
            };
            match self
                .remaining
                .compare_exchange(left, rest, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(()),
                Err(now) => left = now,
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.remaining.store(0, Ordering::SeqCst);
    }
}

/// Closes a change budget when dropped. The gate holds it while the
/// scheme's `settle` runs and drops it as soon as `settle` returns; from
/// then on every clone of the [`CappedSigner`] refuses to sign.
///
/// Dropping it at once (`let (s, _) = ...`) closes the budget before the
/// scheme can use it, which fails closed.
#[derive(Debug)]
#[must_use = "dropping the guard closes the change budget at once"]
pub struct SettleGuard {
    budget: Arc<Budget>,
}

impl SettleGuard {
    /// Closes the budget now; the same as dropping the guard.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for SettleGuard {
    fn drop(&mut self) {
        self.budget.close();
    }
}

/// What a [`CappedSigner`] may do.
#[derive(Clone)]
enum Mode {
    /// Check notes, keep the accepted ones, sign nothing.
    Verify(Arc<Tally>),
    /// Sign change out of one budget.
    Change(Arc<Budget>),
}

/// The signer as a scheme sees it: unblinded-note checks, and blind
/// signatures out of the change budget. See the module docs.
///
/// Clones share their state: a clone of a verify-only view adds to the
/// same notes, and a clone of a change view takes from the same budget and
/// stops when the [`SettleGuard`] closes it.
#[derive(Clone)]
pub struct CappedSigner {
    inner: Arc<dyn Signer>,
    unit: String,
    mode: Mode,
}

impl fmt::Debug for CappedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CappedSigner")
            .field("unit", &self.unit)
            .field("cap", &self.cap())
            .finish_non_exhaustive()
    }
}

impl CappedSigner {
    /// The view a scheme's `verify` gets: it can check notes in `unit` (the
    /// pay entry's) and sign nothing. It keeps every note the signer
    /// accepted; read them with [`Self::notes`] once `verify` returned.
    #[must_use]
    pub fn verify_only(inner: Arc<dyn Signer>, unit: impl Into<String>) -> Self {
        Self {
            inner,
            unit: unit.into(),
            mode: Mode::Verify(Arc::new(Mutex::new(BTreeMap::new()))),
        }
    }

    /// The view a scheme's `settle` gets: blind signatures worth at most
    /// `cap` in all, for the outcome the cap was computed for, each output
    /// reserved in `store` first, and only until the returned
    /// [`SettleGuard`] is dropped.
    ///
    /// Only bnap-core makes a [`ChangeCap`], from one committed outcome
    /// (`Pending::charge` for its own settle, `Recorded::refund_cap` for the
    /// refund of a timed-out one), and the cap carries that outcome's
    /// `ReplayKey`, so the budget, the store's reservation and the
    /// settlement the signer counts it against always belong together.
    /// `store` is the gate's use store, the one that committed the outcome:
    /// its record keeps the outcome's change ledger.
    ///
    /// Hold the guard while `settle` runs and drop it when `settle`
    /// returns. No plug or gate can make a cap of its own:
    ///
    /// ```compile_fail,E0624
    /// let _ = bnap_plug::ChangeCap::new;
    /// ```
    pub fn for_change(
        inner: Arc<dyn Signer>,
        store: Arc<dyn UseStore>,
        cap: &ChangeCap,
    ) -> (Self, SettleGuard) {
        let budget = Arc::new(Budget {
            limit: ChangeLimit {
                replay_key: *cap.replay_key(),
                status: cap.status(),
                unit: cap.unit().to_owned(),
                cap: cap.get(),
                keep_until: cap.keep_until(),
            },
            cap: cap.clone(),
            store,
            remaining: AtomicU64::new(cap.get()),
            closed: AtomicBool::new(false),
        });
        let signer = Self {
            inner,
            unit: cap.unit().to_owned(),
            mode: Mode::Change(budget.clone()),
        };
        (signer, SettleGuard { budget })
    }

    /// The whole change cap; `None` for a verify-only view.
    #[must_use]
    pub fn cap(&self) -> Option<u64> {
        match &self.mode {
            Mode::Verify(_) => None,
            Mode::Change(b) => Some(b.limit.cap),
        }
    }

    /// What is left of the change budget: 0 once the guard closed it;
    /// `None` for a verify-only view.
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        match &self.mode {
            Mode::Verify(_) => None,
            Mode::Change(b) => Some(b.remaining.load(Ordering::SeqCst)),
        }
    }

    /// The unit notes are checked in.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }

    /// Checks an unblinded note in the view's unit, given its secret (see
    /// [`Signer::verify_unblinded`]), and returns its `Y` when the signer
    /// accepted it.
    ///
    /// The view derives `Y = hash_to_curve(secret)` itself and refuses a
    /// signer answer naming any other point, so the `Y` a scheme gets back,
    /// and the one a verify-only view keeps, is always the secret's: a
    /// scheme cannot make one note count twice by scaling its point. A
    /// verify-only view keeps a note the signer accepted, once per `Y`.
    pub async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        let Some(y) = hash_to_curve(secret) else {
            return Ok(None);
        };
        let Some(checked) = self
            .inner
            .verify_unblinded(keyset, &self.unit, amount, secret, c)
            .await?
        else {
            return Ok(None);
        };
        if checked.0 != y {
            return Err(SignerError::Refused(
                "the signer checked a point that is not hash_to_curve(secret)".into(),
            ));
        }
        if let Mode::Verify(tally) = &self.mode {
            tally
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(y)
                .or_insert(amount);
        }
        Ok(Some(Point(y)))
    }

    /// The notes this verify-only view accepted, each once, as admission's
    /// backing ([`bnap_core::pricing::PayValue`]), named by their 33-byte
    /// `Y`, which the view derived from each note's secret. The commit consumes each under `H_"bnap/note"(Y)`, whichever
    /// scheme's view accepted it. Empty for a change view.
    #[must_use]
    pub fn notes(&self) -> Vec<Backing> {
        let Mode::Verify(tally) = &self.mode else {
            return Vec::new();
        };
        tally
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(y, amount)| Backing {
                source: BackingSource::Note(y.to_vec()),
                amount: *amount,
                unit: self.unit.clone(),
            })
            .collect()
    }

    /// The outputs the use store already reserved as this outcome's change
    /// or refund, under either status ([`UseStore::reserve_change`]), read
    /// from the outcome's record; empty for a verify-only view or an
    /// outcome without a record.
    ///
    /// Read-only. It lets an atomic scheme make its refund a superset of
    /// what was reserved before (a late OK settle that lost to the timeout,
    /// or a settle whose signer failed after the reservation), so that the
    /// refund re-signs those outputs at no cost instead of being refused by
    /// the outcome's change ledger.
    pub async fn reserved(&self) -> Result<Vec<ChangeOutput>, SignerError> {
        let Mode::Change(budget) = &self.mode else {
            return Ok(Vec::new());
        };
        match budget.store.outcome(budget.cap.replay_key()).await {
            Ok(Some(rec)) => Ok(rec.change_outputs.into_iter().collect()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(SignerError::Unavailable(e.to_string())),
        }
    }

    /// Signs blinded outputs out of the change budget.
    ///
    /// Before the signer is called, in this order:
    ///
    /// 1. refuses when the view is verify-only, or when the batch is empty
    ///    or holds an output of amount 0 (the budget is not touched);
    /// 2. refuses when the guard closed the budget, and takes the outputs'
    ///    sum out of what is left with a compare-and-swap, refusing past 0;
    ///    a sum that overflows is above any cap;
    /// 3. reserves the outputs in the use store, against the outcome's one
    ///    durable total ([`bnap_core::outcome::reserve_change`]): refused
    ///    with [`SignerError::OverCap`] when they would take it past the
    ///    cap or the outcome's value, whichever process, gate or signer
    ///    instance signed before, and with [`SignerError::Refused`] when the
    ///    outcome has no record, or when its result is already recorded and
    ///    an output is new (only the outputs reserved before may be signed
    ///    again once it left PENDING, or once its refund is recorded). A
    ///    store that cannot be reached is [`SignerError::Unavailable`]:
    ///    nothing is signed unreserved.
    ///
    /// A call that fails after step 2 keeps its share spent, and one that
    /// fails after step 3 keeps its reservation, since the signer may have
    /// signed before failing. The signer gets the settlement's
    /// [`ChangeLimit`] and keeps a total of its own too. Refuses an answer
    /// that does not hold exactly one signature per output, with the
    /// output's amount.
    pub async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let Mode::Change(budget) = &self.mode else {
            return Err(SignerError::Refused(
                "a verify-only signer signs nothing".into(),
            ));
        };
        check_outputs(outputs)?;
        let sum = outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount));
        budget.take(sum)?;
        let reserved: Vec<ChangeOutput> = outputs
            .iter()
            .map(|o| ChangeOutput {
                keyset: keyset.0.clone(),
                amount: o.amount,
                blinded: o.blinded.0,
            })
            .collect();
        match reserve_change(&*budget.store, &budget.cap, &reserved).await {
            Ok(Reserve::Reserved { .. }) => {}
            Ok(Reserve::OverCap { total, cap }) => {
                return Err(SignerError::OverCap { sum: total, cap });
            }
            Ok(Reserve::NoValue) => {
                return Err(SignerError::Refused("no value to sign".into()));
            }
            Ok(Reserve::Settled) => {
                return Err(SignerError::Refused(
                    "the outcome's result is recorded: no new output can be signed for it".into(),
                ));
            }
            Ok(Reserve::Unknown) => {
                return Err(SignerError::Refused(
                    "the outcome has no record to reserve change in".into(),
                ));
            }
            Err(e) => return Err(SignerError::Unavailable(e.to_string())),
        }
        let sigs = self
            .inner
            .blind_sign(keyset, outputs, &budget.limit)
            .await?;
        let matches = sigs.len() == outputs.len()
            && sigs.iter().zip(outputs).all(|(s, o)| s.amount == o.amount);
        if !matches {
            return Err(SignerError::Refused(
                "the signer's answer does not match the outputs".into(),
            ));
        }
        Ok(sigs)
    }
}
