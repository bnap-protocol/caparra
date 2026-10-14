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
//! - The signer enforces the total as well: every call names its
//!   settlement ([`ChangeLimit`]: `ReplayKey`, status, unit and total cap),
//!   and the signer keeps a running total per settlement
//!   ([`ChangeLedger`]), which bounds an out-of-process signer and every
//!   budget made for the same settlement together.
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
use bnap_core::note::hash_to_curve;
use bnap_core::pricing::{Backing, BackingSource, ChangeCap};
use bnap_core::response::Status;
use bnap_core::schnorr::Signature;
use bnap_core::sign::CoreMessage;

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
        /// What the outputs add up to (saturating); for a signer's running
        /// total, the total they would bring it to.
        sum: u64,
        /// What was left of the cap; for a signer's running total, the
        /// settlement's whole cap.
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
    /// MUST refuse a keyset that is not in `limit.unit`. MUST keep a
    /// running total per settlement (`limit.replay_key` and
    /// `limit.status`) and refuse a call that would take it above
    /// `limit.cap`, which bnap-core set to `value - charged`; an output
    /// already signed for the same settlement MAY be signed again without
    /// counting twice, since it makes the same note. MUST refuse an empty
    /// batch and any output of amount 0, which carries no value but costs
    /// signer work. [`ChangeLedger`] does exactly this.
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
/// A `ReplayKey` can be settled twice: once by the gate's own settle, and
/// again by the refund of a timed-out outcome (on a late settle or on a
/// replay). The status leaves PENDING exactly once (6.4), so at most one of
/// the two is ever recorded, and the gate sends no change before that
/// write; the totals are therefore kept per status.
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

/// What a [`ChangeLedger`] keeps for one settlement: the cap it was first
/// named with, what was signed so far, and the outputs signed.
#[derive(Debug)]
struct Signed {
    cap: u64,
    total: u64,
    outputs: BTreeSet<SignedOutput>,
}

/// The running total of change a signer signed, per settlement, for
/// [`Signer::blind_sign`] implementations.
///
/// [`ChangeLedger::reserve`] is called before signing. It counts each
/// distinct output (keyset, amount, `B'`) once per settlement, so a
/// deterministic `settle` that runs again (a replay recomputing a refund
/// after a crash, two concurrent replays) signs the same notes again for
/// nothing, while new outputs beyond the cap are refused. The first cap a
/// settlement is named with bounds it: a later call with a larger cap does
/// not raise it. It is in memory:
/// a signer that restarts starts from 0, which is safe only because the
/// gate never sends change before the outcome is durable (6.4).
#[derive(Debug, Default)]
pub struct ChangeLedger {
    settlements: Mutex<HashMap<(ReplayKey, Status), Signed>>,
}

impl ChangeLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes `outputs` out of the settlement's cap, or refuses with
    /// [`SignerError::OverCap`] and records nothing. Outputs already
    /// reserved for the same settlement count nothing. An empty batch, or
    /// an output of amount 0, is refused with [`SignerError::Refused`].
    pub fn reserve(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<(), SignerError> {
        check_outputs(outputs)?;
        let mut all = self
            .settlements
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let signed = all
            .entry((limit.replay_key, limit.status))
            .or_insert_with(|| Signed {
                cap: limit.cap,
                total: 0,
                outputs: BTreeSet::new(),
            });
        let cap = signed.cap.min(limit.cap);
        let fresh: BTreeSet<SignedOutput> = outputs
            .iter()
            .map(|o| (keyset.0.clone(), o.amount, o.blinded.0))
            .filter(|o| !signed.outputs.contains(o))
            .collect();
        let total = fresh
            .iter()
            .try_fold(signed.total, |acc, (_, amount, _)| acc.checked_add(*amount));
        match total {
            Some(total) if total <= cap => {
                signed.cap = cap;
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

    /// What was signed for a settlement so far.
    #[must_use]
    pub fn total(&self, replay_key: &ReplayKey, status: Status) -> u64 {
        self.settlements
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(*replay_key, status))
            .map_or(0, |s| s.total)
    }

    /// Drops both settlements of `replay_key`, once its replay window has
    /// passed and no replay can settle it again.
    pub fn forget(&self, replay_key: &ReplayKey) {
        self.settlements
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(rk, _), _| rk != replay_key);
    }
}

/// The notes a verify-only view accepted: amount by `Y`, each note once.
type Tally = Mutex<BTreeMap<[u8; 33], u64>>;

/// A change budget: what is left of the cap, and whether the settlement
/// it was made for is over.
#[derive(Debug)]
struct Budget {
    limit: ChangeLimit,
    remaining: AtomicU64,
    closed: AtomicBool,
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

    /// The view a scheme's `settle` gets, for the outcome under
    /// `replay_key`: blind signatures worth at most `cap` in all, which
    /// only [`bnap_core::pricing::Admission::settle`] makes, and only until
    /// the returned [`SettleGuard`] is dropped.
    ///
    /// Hold the guard while `settle` runs and drop it when `settle`
    /// returns.
    pub fn for_change(
        inner: Arc<dyn Signer>,
        cap: &ChangeCap,
        replay_key: ReplayKey,
    ) -> (Self, SettleGuard) {
        let budget = Arc::new(Budget {
            limit: ChangeLimit {
                replay_key,
                status: cap.status(),
                unit: cap.unit().to_owned(),
                cap: cap.get(),
            },
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

    /// Signs blinded outputs out of the change budget.
    ///
    /// Before the signer is called, refuses when the view is verify-only,
    /// when the batch is empty or holds an output of amount 0 (the budget
    /// is not touched), or when the guard closed the budget, and takes the
    /// outputs' sum out of
    /// what is left with a compare-and-swap, refusing past 0; a sum that
    /// overflows is above any cap. A call that fails afterwards keeps its
    /// share spent, since the signer may have signed before failing. The
    /// signer gets the settlement's [`ChangeLimit`] and enforces the
    /// running total too. Refuses an answer that does not hold exactly one
    /// signature per output, with the output's amount.
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
