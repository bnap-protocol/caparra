//! [`FileSigner`]: the [`Signer`] over keys loaded from a key file.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bnap_core::limits::CLOCK_SKEW;
use bnap_core::note::hash_to_curve;
use bnap_core::schnorr::{Key, Signature};
use bnap_core::secp256k1::rand::{RngCore, thread_rng};
use bnap_core::secp256k1::{self, Secp256k1, SignOnly};
use bnap_core::sign::{CoreMessage, Purpose};
use bnap_plug::{
    BlindSignature, BlindedOutput, ChangeLedger, ChangeLimit, Dleq, KeysetId, Point, Signer,
    SignerError,
};

use crate::keyfile::{self, LoadError, Parsed};
use crate::keys::HeldKey;
use crate::keyset::{NotesKeyset, UNIT};
use crate::object;

/// The most outputs one [`Signer::blind_sign`] call may carry. The notes
/// draft caps a credential at `max_outputs` (16 by default); this bounds the
/// signer's work per call whatever a gate or scheme sends.
pub const MAX_OUTPUTS_PER_CALL: usize = 256;

/// The signer's clock: Unix seconds. Used for key `not_after`, keyset final
/// expiry and dropping settled outcomes from the in-memory ledger.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// How often, at most, the ledger drops outcomes that can no longer be
/// settled, in seconds.
const FORGET_EVERY: u64 = 60;

/// A [`Signer`] that holds its keys in this process, loaded from a key file.
/// See the crate docs.
///
/// - [`Signer::schnorr`] signs offers with an `offer` key and acks with a
///   `receipt` key, after recomputing the message from the object
///   ([`FileSigner::sign_object`]).
/// - [`Signer::verify_unblinded`] derives `Y = hash_to_curve(secret)` itself
///   and accepts a note on any listed keyset in `sat`, active or not, until
///   its final expiry plus the 60 s clock skew (notes draft 6.2, 10).
/// - [`Signer::blind_sign`] signs only on an active keyset in the
///   settlement's unit, refuses empty batches, outputs of amount 0, amounts
///   the keyset has no key for and points that are not on the curve, and
///   keeps one running total per `ReplayKey` in a [`ChangeLedger`]: outputs
///   that would take it past the cap it is given are refused. That total is
///   the signer's second line; the bound across restarts is the use store's
///   reservation, which [`bnap_plug::CappedSigner::for_change`] makes before
///   it calls this signer.
pub struct FileSigner {
    keys: Vec<HeldKey>,
    keysets: Vec<NotesKeyset>,
    ledger: ChangeLedger,
    clock: Clock,
    secp: Secp256k1<SignOnly>,
    last_forget: AtomicU64,
}

impl fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSigner")
            .field("keys", &self.keys)
            .field("keysets", &self.keysets)
            .finish_non_exhaustive()
    }
}

impl FileSigner {
    /// Loads a key file, refusing it when others could read or change it
    /// ([`keyfile::read`]).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let text = keyfile::read(path.as_ref())?;
        Self::from_toml(&text)
    }

    /// A signer from the text of a key file, with no file check: for tests
    /// and for callers that read the file themselves.
    pub fn from_toml(text: &str) -> Result<Self, LoadError> {
        let Parsed { keys, keysets } = keyfile::parse(text)?;
        Ok(Self::from_parts(keys, keysets))
    }

    /// A signer from keys and keysets built in code.
    #[must_use]
    pub fn from_parts(keys: Vec<HeldKey>, keysets: Vec<NotesKeyset>) -> Self {
        Self {
            keys,
            keysets,
            ledger: ChangeLedger::new(),
            clock: Arc::new(system_clock),
            secp: Secp256k1::signing_only(),
            last_forget: AtomicU64::new(0),
        }
    }

    /// Replaces the system clock, for tests.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// The online keys held, with their uses.
    #[must_use]
    pub fn keys(&self) -> &[HeldKey] {
        &self.keys
    }

    /// The notes keysets held.
    #[must_use]
    pub fn keysets(&self) -> &[NotesKeyset] {
        &self.keysets
    }

    /// The keyset with this full ID.
    #[must_use]
    pub fn keyset(&self, id: &[u8]) -> Option<&NotesKeyset> {
        self.keysets.iter().find(|k| k.id()[..] == *id)
    }

    /// The signer's own running totals of change and refunds.
    #[must_use]
    pub fn ledger(&self) -> &ChangeLedger {
        &self.ledger
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Signs the message of a bnap object: the one signing path, for
    /// [`Signer::schnorr`] in process and for a signer process that received
    /// the object's bytes.
    ///
    /// `signed` is what [`CoreMessage::signed_bytes`] returns. Refused
    /// unless this signer holds `key` for `purpose.key_use()` and is within
    /// its `not_after`, and `signed` parses with bnap-core as that object
    /// under `key` ([`object::recompute`]); the signature is over the tagged
    /// hash recomputed here, with fresh auxiliary randomness, and is checked
    /// before it is returned.
    pub fn sign_object(
        &self,
        purpose: Purpose,
        key: &Key,
        signed: &[u8],
    ) -> Result<Signature, SignerError> {
        let key_use = purpose.key_use();
        let held = self
            .keys
            .iter()
            .find(|h| h.public_key() == *key && *h.key_use() == key_use)
            .ok_or_else(|| {
                SignerError::Refused(format!("no key held for use {}", key_use.as_str()))
            })?;
        if held.not_after().is_some_and(|t| self.now() > t) {
            return Err(SignerError::Refused("the key is past its not_after".into()));
        }
        let digest = object::recompute(purpose, key, signed)
            .map_err(|e| SignerError::Refused(format!("not a message bnap-core builds: {e}")))?;
        let mut aux = [0u8; 32];
        thread_rng().fill_bytes(&mut aux);
        let sig = held.sign_digest(&self.secp, &digest, &aux);
        key.verify(&digest, &sig)
            .map_err(|_| SignerError::Refused("the signature failed its own check".into()))?;
        Ok(sig)
    }

    /// Drops ledger totals of outcomes that can no longer be settled, at
    /// most once a minute.
    fn forget_expired(&self, now: u64) {
        let last = self.last_forget.load(Ordering::SeqCst);
        if now >= last.saturating_add(FORGET_EVERY)
            && self
                .last_forget
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.ledger.forget_expired(now);
        }
    }

    /// Every check of [`Signer::blind_sign`] that needs no ledger.
    fn check_blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
        now: u64,
    ) -> Result<&NotesKeyset, SignerError> {
        let refuse = |why: &str| Err(SignerError::Refused(why.into()));
        let Some(ks) = self.keyset(&keyset.0) else {
            return refuse("unknown keyset");
        };
        if limit.unit != UNIT {
            return refuse("the keyset's unit is not the settlement's");
        }
        if !ks.active() {
            return refuse("the keyset does not sign outputs");
        }
        if now > ks.final_expiry() {
            return refuse("the keyset is past its final expiry");
        }
        if limit.keep_until.saturating_add(CLOCK_SKEW) < now {
            return refuse("the settlement's outcome can no longer be settled");
        }
        if outputs.is_empty() {
            return refuse("no outputs to sign");
        }
        if outputs.iter().any(|o| o.amount == 0) {
            return refuse("an output of amount 0");
        }
        if outputs.len() > MAX_OUTPUTS_PER_CALL {
            return refuse("too many outputs in one call");
        }
        for o in outputs {
            if !ks.has_amount(o.amount) {
                return refuse("an output amount the keyset has no key for");
            }
            if secp256k1::PublicKey::from_slice(&o.blinded.0).is_err() {
                return refuse("an output that is not a point on the curve");
            }
        }
        Ok(ks)
    }
}

#[async_trait::async_trait]
impl Signer for FileSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let sig = self.sign_object(msg.purpose(), msg.key(), msg.signed_bytes())?;
        // The sealed message's own digest, too.
        msg.verify(&sig)
            .map_err(|_| SignerError::Refused("the message's digest is not its object's".into()))?;
        Ok(sig)
    }

    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        unit: &str,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        let Some(ks) = self.keyset(&keyset.0) else {
            return Ok(None);
        };
        if unit != ks.unit() || self.now() > ks.final_expiry().saturating_add(CLOCK_SKEW) {
            return Ok(None);
        }
        let Some(y) = hash_to_curve(secret) else {
            return Ok(None);
        };
        Ok(ks.check(amount, &y, &c.0).then_some(Point(y)))
    }

    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let now = self.now();
        let ks = self.check_blind_sign(keyset, outputs, limit, now)?;
        self.forget_expired(now);
        self.ledger.reserve(keyset, outputs, limit)?;
        outputs
            .iter()
            .map(|o| {
                let (c, e, s) = ks
                    .sign(o.amount, &o.blinded.0)
                    .map_err(|e| SignerError::Refused(e.to_string()))?;
                Ok(BlindSignature {
                    amount: o.amount,
                    signature: Point(c),
                    dleq: Dleq { e, s },
                })
            })
            .collect()
    }
}
