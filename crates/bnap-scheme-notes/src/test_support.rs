//! Test helpers (feature `test-support`): the test keysets of 18.1, a
//! signer that holds keysets, and the in-memory issuer store. Not durable
//! and holding keys in memory: never use them in a gate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError, RwLock};

use bnap_core::hash::sha256;
use bnap_core::manifest::KeyUse;
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::CoreMessage;
use bnap_plug::{
    BlindSignature, BlindedOutput, ChangeLedger, ChangeLimit, Dleq, KeysetId, Point, Signer,
    SignerError,
};

pub use crate::issuer::MemoryIssuerStore;
use crate::keyset::{IssuerKeyset, KeysetState};
use crate::wire::KeysetIdBytes;

/// The amounts of every test keyset: 2^0 to 2^15 (18.1).
pub const TEST_AMOUNTS: std::ops::RangeInclusive<u32> = 0..=15;

/// The private key `a` for amount `m` of test keyset `label` (18.1):
/// SHA-256 of `bnap notes test keyset {label} {m}`.
#[must_use]
pub fn test_key(label: &str, m: u64) -> [u8; 32] {
    sha256(format!("bnap notes test keyset {label} {m}").as_bytes())
}

/// Test keyset `label` of 18.1, in `state`, published at 0 and, when
/// active, activated at 0.
///
/// # Panics
///
/// Never for the labels of 18.1: their keys are valid scalars.
#[must_use]
pub fn test_keyset(
    label: &str,
    input_fee_ppk: u64,
    final_expiry: u64,
    state: KeysetState,
) -> IssuerKeyset {
    let secrets: BTreeMap<u64, [u8; 32]> = TEST_AMOUNTS
        .map(|i| {
            let m = 1u64 << i;
            (m, test_key(label, m))
        })
        .collect();
    let mut k = IssuerKeyset::from_secrets(&secrets, input_fee_ppk, final_expiry, 0)
        .expect("the test keys are valid scalars");
    k.info_mut().state = state;
    if state == KeysetState::Active {
        k.info_mut().activated_at = Some(0);
    }
    k
}

/// Keyset A of 18.1: 100 ppk, final expiry 1830000000, active.
#[must_use]
pub fn keyset_a() -> IssuerKeyset {
    test_keyset("A", 100, 1_830_000_000, KeysetState::Active)
}

/// Keyset B of 18.1: no fee, final expiry 1800000000, inputs only.
#[must_use]
pub fn keyset_b() -> IssuerKeyset {
    test_keyset("B", 0, 1_800_000_000, KeysetState::InputsOnly)
}

/// Keyset C of 18.1 (the fee vector): 2,000 ppk, final expiry 1830000000,
/// inputs only.
#[must_use]
pub fn keyset_c() -> IssuerKeyset {
    test_keyset("C", 2000, 1_830_000_000, KeysetState::InputsOnly)
}

/// One output as the signer signed it: keyset, amount and `B'`.
type Minted = (Vec<u8>, u64, [u8; 33]);

/// A signer holding the offer and receipt keys and the issuer keysets, with
/// the real BDHKE and DLEQ math, a [`ChangeLedger`] as its second line, and
/// a record of what it minted.
pub struct KeysetSigner {
    offer: SigningKey,
    receipt: SigningKey,
    keysets: RwLock<BTreeMap<KeysetIdBytes, IssuerKeyset>>,
    revoked: RwLock<BTreeSet<KeysetIdBytes>>,
    ledger: ChangeLedger,
    signed: AtomicU64,
    minted: Mutex<BTreeSet<Minted>>,
}

impl std::fmt::Debug for KeysetSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeysetSigner").finish_non_exhaustive()
    }
}

impl KeysetSigner {
    /// A signer with these keys and keysets.
    ///
    /// # Panics
    ///
    /// When an offer or receipt key is not a valid scalar.
    #[must_use]
    pub fn new(offer: &[u8; 32], receipt: &[u8; 32], keysets: Vec<IssuerKeyset>) -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(offer).expect("a valid offer key"),
            receipt: SigningKey::from_secret_bytes(receipt).expect("a valid receipt key"),
            keysets: RwLock::new(keysets.into_iter().map(|k| (k.info().id, k)).collect()),
            revoked: RwLock::new(BTreeSet::new()),
            ledger: ChangeLedger::new(),
            signed: AtomicU64::new(0),
            minted: Mutex::new(BTreeSet::new()),
        }
    }

    /// The offer key.
    #[must_use]
    pub fn offer_key(&self) -> Key {
        self.offer.public_key()
    }

    /// The receipt key.
    #[must_use]
    pub fn receipt_key(&self) -> Key {
        self.receipt.public_key()
    }

    /// Adds a keyset.
    pub fn add_keyset(&self, k: IssuerKeyset) {
        self.keysets
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(k.info().id, k);
    }

    /// Refuses a keyset from now on.
    pub fn revoke(&self, id: &KeysetIdBytes) {
        self.revoked
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*id);
    }

    /// Every amount the signer signed, an output signed twice counted twice.
    #[must_use]
    pub fn signed(&self) -> u64 {
        self.signed.load(Ordering::SeqCst)
    }

    /// The value of the distinct notes the signer made: an output signed
    /// again makes the same note and counts once.
    #[must_use]
    pub fn minted(&self) -> u64 {
        self.minted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|m| m.1)
            .sum()
    }

    fn keyset(&self, id: &[u8]) -> Option<IssuerKeyset> {
        let id: KeysetIdBytes = id.try_into().ok()?;
        if self
            .revoked
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&id)
        {
            return None;
        }
        self.keysets
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
    }
}

#[async_trait::async_trait]
impl Signer for KeysetSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let key = match msg.purpose().key_use() {
            KeyUse::Offer => &self.offer,
            KeyUse::Receipt => &self.receipt,
            KeyUse::Other(_) => return Err(SignerError::Refused("no key for that use".into())),
        };
        msg.sign_with(key, &[0; 32])
            .map_err(|_| SignerError::Refused("key not held for this use".into()))
    }

    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        unit: &str,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        let Some(k) = self.keyset(&keyset.0) else {
            return Ok(None);
        };
        if k.info().unit != unit {
            return Ok(None);
        }
        Ok(k.verify_note(amount, secret, &c.0).map(Point))
    }

    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let k = self
            .keyset(&keyset.0)
            .ok_or_else(|| SignerError::Refused("unknown keyset".into()))?;
        if k.info().unit != limit.unit {
            return Err(SignerError::Refused("the keyset is in another unit".into()));
        }
        self.ledger.reserve(keyset, outputs, limit)?;
        let mut out = Vec::with_capacity(outputs.len());
        for o in outputs {
            let s = k
                .sign(o.amount, &o.blinded.0)
                .map_err(|e| SignerError::Refused(e.to_string()))?;
            out.push(BlindSignature {
                amount: o.amount,
                signature: Point(s.c),
                dleq: Dleq { e: s.e, s: s.s },
            });
        }
        self.signed.fetch_add(
            outputs.iter().map(|o| o.amount).sum::<u64>(),
            Ordering::SeqCst,
        );
        self.minted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(
                outputs
                    .iter()
                    .map(|o| (keyset.0.clone(), o.amount, o.blinded.0)),
            );
        Ok(out)
    }
}
