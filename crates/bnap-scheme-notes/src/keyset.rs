//! BNAP keysets (4.2, 5.2, section 10): their public table, their NUT-02
//! version-01 IDs, the issuer's key math for a signer, and rotation.
//!
//! The curve math is cashu's (`cashu::dhke`, NUT-12 DLEQ in
//! `cashu::nuts::nut12`): this module only names keys and amounts.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use cashu::nuts::{BlindSignatureDleq, CurrencyUnit, Id, Keys};
use cashu::{Amount, PublicKey as CashuPublicKey, SecretKey as CashuSecretKey};

use bnap_core::limits::{CLOCK_SKEW, expired};
use bnap_core::note::hash_to_curve;

use crate::wire::{KeysetEntry, KeysetIdBytes, PointBytes};

/// The only unit of a BNAP keyset (4.2).
pub const UNIT: &str = "sat";

/// Why a keyset cannot be built or used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeysetError {
    /// A key is not a valid point or scalar, or an amount is not a power of
    /// two.
    #[error("bad key material: {0}")]
    BadKey(String),
    /// No key for this amount.
    #[error("no key for amount {0}")]
    NoKey(u64),
    /// The unit is not one cashu knows.
    #[error("unknown unit {0}")]
    Unit(String),
    /// The curve math failed (a point at infinity).
    #[error("curve operation failed: {0}")]
    Curve(String),
}

/// Where a keyset is in its life (section 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeysetState {
    /// Published, keys served, signs nothing yet; kept so that a
    /// compromised keyset can be replaced at once.
    Standby,
    /// Signs outputs and accepts inputs; offers mark it `active`.
    Active,
    /// Accepts inputs only, until its final expiry.
    InputsOnly,
    /// Compromised: refused for inputs and outputs from now on.
    Revoked,
}

/// One keyset as the issuer's live table holds it: public data only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetInfo {
    /// The NUT-02 version-01 ID, computed from the other fields.
    pub id: KeysetIdBytes,
    /// Always `sat` for a BNAP keyset.
    pub unit: String,
    /// The NUT-02 input fee, per thousand inputs.
    pub input_fee_ppk: u64,
    /// The NUT-02 final expiry, Unix seconds; every BNAP keyset has one
    /// (P5).
    pub final_expiry: u64,
    /// The public key `A` for each amount, a power of two.
    pub keys: BTreeMap<u64, PointBytes>,
    /// Where it is in its life.
    pub state: KeysetState,
    /// When its keys were first served.
    pub published_at: u64,
    /// When it started signing, once it did.
    pub activated_at: Option<u64>,
}

/// The NUT-02 version-01 keyset ID (18.1): `01` and SHA-256 of
/// `m:hex(A)` for each amount ascending, joined by `,`, then `|unit:`,
/// `|input_fee_ppk:` when the fee is not 0, and `|final_expiry:`.
pub fn keyset_id(
    keys: &BTreeMap<u64, PointBytes>,
    unit: &str,
    input_fee_ppk: u64,
    final_expiry: u64,
) -> Result<KeysetIdBytes, KeysetError> {
    let mut map = BTreeMap::new();
    for (amount, a) in keys {
        let a = CashuPublicKey::from_slice(a).map_err(|e| KeysetError::BadKey(e.to_string()))?;
        map.insert(Amount::from(*amount), a);
    }
    let unit = CurrencyUnit::from_str(unit).map_err(|_| KeysetError::Unit(unit.into()))?;
    let id = Id::v2_from_data(&Keys::new(map), &unit, input_fee_ppk, Some(final_expiry));
    id.to_bytes()
        .try_into()
        .map_err(|_| KeysetError::BadKey("not a version-01 keyset ID".into()))
}

impl KeysetInfo {
    /// A keyset in standby, its ID computed from its keys.
    pub fn new(
        keys: BTreeMap<u64, PointBytes>,
        input_fee_ppk: u64,
        final_expiry: u64,
        published_at: u64,
    ) -> Result<Self, KeysetError> {
        if keys.keys().any(|a| !a.is_power_of_two()) {
            return Err(KeysetError::BadKey(
                "an amount is not a power of two".into(),
            ));
        }
        let id = keyset_id(&keys, UNIT, input_fee_ppk, final_expiry)?;
        Ok(Self {
            id,
            unit: UNIT.into(),
            input_fee_ppk,
            final_expiry,
            keys,
            state: KeysetState::Standby,
            published_at,
            activated_at: None,
        })
    }

    /// True when the ID matches the keys, unit, fee and final expiry, as a
    /// client MUST check (5.2).
    #[must_use]
    pub fn id_matches(&self) -> bool {
        keyset_id(
            &self.keys,
            &self.unit,
            self.input_fee_ppk,
            self.final_expiry,
        )
        .is_ok_and(|id| id == self.id)
    }

    /// The key `A` for `amount`.
    #[must_use]
    pub fn key(&self, amount: u64) -> Option<&PointBytes> {
        self.keys.get(&amount)
    }

    /// True when it was revoked.
    #[must_use]
    pub fn revoked(&self) -> bool {
        self.state == KeysetState::Revoked
    }

    /// True when its final expiry, plus the 60 s of clock skew draft-00
    /// section 2 allows on every expiry check, has passed (6.2 step 2,
    /// section 10).
    #[must_use]
    pub fn expired(&self, now: u64) -> bool {
        expired(self.final_expiry, now)
    }

    /// May an offer that expires at `expires` list it (5.2, section 10):
    /// active or inputs-only, in `sat`, and its final expiry later than the
    /// offer's `expires` plus 60 s.
    #[must_use]
    pub fn offerable(&self, expires: u64) -> bool {
        matches!(self.state, KeysetState::Active | KeysetState::InputsOnly)
            && self.unit == UNIT
            && self.final_expiry > expires.saturating_add(CLOCK_SKEW)
    }

    /// Its entry in an offer's parameters.
    #[must_use]
    pub fn entry(&self) -> KeysetEntry {
        KeysetEntry {
            id: self.id,
            input_fee_ppk: self.input_fee_ppk,
            active: self.state == KeysetState::Active,
            unknown: Vec::new(),
        }
    }

    /// The keys as cashu's NUT-01 map, for the issuer's `GET /v1/keys`.
    pub fn cashu_keys(&self) -> Result<Keys, KeysetError> {
        let mut map = BTreeMap::new();
        for (amount, a) in &self.keys {
            let a =
                CashuPublicKey::from_slice(a).map_err(|e| KeysetError::BadKey(e.to_string()))?;
            map.insert(Amount::from(*amount), a);
        }
        Ok(Keys::new(map))
    }
}

/// A blind signature and its NUT-12 DLEQ proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindSigned {
    /// `C' = a·B'`.
    pub c: PointBytes,
    /// The DLEQ challenge.
    pub e: [u8; 32],
    /// The DLEQ response.
    pub s: [u8; 32],
}

/// A keyset with its private keys: what a signer holds. Its `Debug` output
/// never shows a key.
#[derive(Clone)]
pub struct IssuerKeyset {
    info: KeysetInfo,
    secrets: BTreeMap<u64, CashuSecretKey>,
}

impl fmt::Debug for IssuerKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerKeyset")
            .field("id", &hex::encode(self.info.id))
            .field("amounts", &self.secrets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl IssuerKeyset {
    /// A keyset from its private key `a` for each amount, in standby.
    pub fn from_secrets(
        secrets: &BTreeMap<u64, [u8; 32]>,
        input_fee_ppk: u64,
        final_expiry: u64,
        published_at: u64,
    ) -> Result<Self, KeysetError> {
        let mut keys = BTreeMap::new();
        let mut sks = BTreeMap::new();
        for (amount, a) in secrets {
            let sk =
                CashuSecretKey::from_slice(a).map_err(|e| KeysetError::BadKey(e.to_string()))?;
            keys.insert(*amount, sk.public_key().to_bytes());
            sks.insert(*amount, sk);
        }
        let info = KeysetInfo::new(keys, input_fee_ppk, final_expiry, published_at)?;
        Ok(Self { info, secrets: sks })
    }

    /// The public table entry.
    #[must_use]
    pub fn info(&self) -> &KeysetInfo {
        &self.info
    }

    /// The public table entry, for a state change.
    pub fn info_mut(&mut self) -> &mut KeysetInfo {
        &mut self.info
    }

    /// Checks a note: `C = a·hash_to_curve(secret)` for the key `a` of
    /// `amount`. Returns `Y`, derived from the secret here and never taken
    /// from a caller (ERRATA N3b-28), or `None`.
    #[must_use]
    pub fn verify_note(&self, amount: u64, secret: &[u8], c: &PointBytes) -> Option<PointBytes> {
        let a = self.secrets.get(&amount)?;
        let c = CashuPublicKey::from_slice(c).ok()?;
        cashu::dhke::verify_message(a, c, secret).ok()?;
        hash_to_curve(secret)
    }

    /// Signs `B'` with the key for `amount`: `C' = a·B'` and the NUT-12 DLEQ
    /// proof with NUT-12's deterministic nonce, which 7.4 makes a MUST, so
    /// the same output always gives the same bytes.
    pub fn sign(&self, amount: u64, blinded: &PointBytes) -> Result<BlindSigned, KeysetError> {
        let a = self
            .secrets
            .get(&amount)
            .ok_or(KeysetError::NoKey(amount))?;
        let b =
            CashuPublicKey::from_slice(blinded).map_err(|e| KeysetError::BadKey(e.to_string()))?;
        let c = cashu::dhke::sign_message(a, &b).map_err(|e| KeysetError::Curve(e.to_string()))?;
        let id = Id::from_bytes(&self.info.id).map_err(|e| KeysetError::BadKey(e.to_string()))?;
        let sig = cashu::nuts::BlindSignature::new(Amount::from(amount), c, id, &b, a)
            .map_err(|e| KeysetError::Curve(e.to_string()))?;
        let dleq = sig
            .dleq
            .ok_or_else(|| KeysetError::Curve("no DLEQ proof".into()))?;
        Ok(BlindSigned {
            c: c.to_bytes(),
            e: dleq.e.to_secret_bytes(),
            s: dleq.s.to_secret_bytes(),
        })
    }
}

/// Checks a NUT-12 DLEQ proof that `C'` was made from `B'` with the key
/// whose public key is `a` (cashu's verification).
#[must_use]
pub fn verify_dleq(key: &PointBytes, blinded: &PointBytes, signed: &BlindSigned) -> bool {
    let (Ok(key), Ok(blinded), Ok(c_)) = (
        CashuPublicKey::from_slice(key),
        CashuPublicKey::from_slice(blinded),
        CashuPublicKey::from_slice(&signed.c),
    ) else {
        return false;
    };
    let (Ok(e), Ok(s)) = (
        CashuSecretKey::from_slice(&signed.e),
        CashuSecretKey::from_slice(&signed.s),
    ) else {
        return false;
    };
    // The keyset ID and amount play no part in the proof.
    let sig = cashu::nuts::BlindSignature {
        amount: Amount::from(0),
        keyset_id: Id::v1_from_keys(&Keys::new(BTreeMap::new())),
        c: c_,
        dleq: Some(BlindSignatureDleq { e, s }),
    };
    sig.verify_dleq(key, blinded).is_ok()
}

/// The lifecycle periods of section 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// A keyset is published at least this long before it signs anything
    /// (30 days).
    pub publish_lead: u64,
    /// It signs outputs for about this long (3 months), then accepts inputs
    /// only.
    pub signing_period: u64,
}

const DAY: u64 = 86_400;

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            publish_lead: 30 * DAY,
            signing_period: 91 * DAY,
        }
    }
}

/// What one rotation step does (section 10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationPlan {
    /// The standby keyset to activate.
    pub activate: Option<KeysetIdBytes>,
    /// Active keysets that move to inputs-only.
    pub retire: Vec<KeysetIdBytes>,
    /// No standby keyset would be left: publish a new one now, so that a
    /// compromised keyset can always be replaced (section 10).
    pub needs_standby: bool,
    /// No keyset signs outputs and none can be activated yet: offers cannot
    /// list `bnap:notes` until a standby keyset's publication lead passes.
    pub blocked: bool,
}

/// Plans one rotation step at `now`: when no keyset is active, or every
/// active one has signed for `signing_period`, the oldest standby keyset
/// whose publication lead has passed becomes active and the others move to
/// inputs-only. A revoked keyset is never touched.
#[must_use]
pub fn plan_rotation(keysets: &[KeysetInfo], now: u64, policy: &RotationPolicy) -> RotationPlan {
    let active: Vec<&KeysetInfo> = keysets
        .iter()
        .filter(|k| k.state == KeysetState::Active)
        .collect();
    let due = active.is_empty()
        || active.iter().all(|k| {
            k.activated_at
                .is_some_and(|t| t.saturating_add(policy.signing_period) <= now)
        });
    let mut standby: Vec<&KeysetInfo> = keysets
        .iter()
        .filter(|k| {
            k.state == KeysetState::Standby
                && k.unit == UNIT
                && !k.expired(now)
                && k.published_at.saturating_add(policy.publish_lead) <= now
        })
        .collect();
    standby.sort_by_key(|k| (k.published_at, k.id));
    let mut plan = RotationPlan::default();
    if due {
        if let Some(next) = standby.first() {
            plan.activate = Some(next.id);
            plan.retire = active.iter().map(|k| k.id).collect();
        } else if active.is_empty() {
            plan.blocked = true;
        }
    }
    let standby_left = keysets
        .iter()
        .filter(|k| k.state == KeysetState::Standby && Some(k.id) != plan.activate)
        .count();
    plan.needs_standby = standby_left == 0;
    plan
}

/// Applies a plan to the table at `now`.
pub fn apply_rotation(keysets: &mut [KeysetInfo], plan: &RotationPlan, now: u64) {
    for k in keysets.iter_mut() {
        if plan.retire.contains(&k.id) && k.state == KeysetState::Active {
            k.state = KeysetState::InputsOnly;
        }
        if plan.activate == Some(k.id) && k.state == KeysetState::Standby {
            k.state = KeysetState::Active;
            k.activated_at = Some(now);
        }
    }
}

/// Revokes a compromised keyset (section 10): from now on its inputs and
/// outputs are refused (`UNKNOWN_KEYSET`) and no offer lists it.
pub fn revoke(keyset: &mut KeysetInfo) {
    keyset.state = KeysetState::Revoked;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bnap_core::hash::sha256;

    #[test]
    fn the_nut_02_version_01_id_matches_the_published_one() {
        // The four-key keyset of cashu's NUT-02 tests, as
        // nuts/tools/notes_offer_vector.py checks it.
        let keys: BTreeMap<u64, PointBytes> = [
            (
                1,
                "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc",
            ),
            (
                2,
                "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de",
            ),
            (
                4,
                "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303",
            ),
            (
                8,
                "02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528",
            ),
        ]
        .into_iter()
        .map(|(a, k)| (a, hex::decode(k).unwrap().try_into().unwrap()))
        .collect();
        let id = keyset_id(&keys, "sat", 100, 2_059_210_353).unwrap();
        assert_eq!(
            hex::encode(id),
            "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a"
        );
    }

    fn keyset(label: &str) -> IssuerKeyset {
        let secrets: BTreeMap<u64, [u8; 32]> = (0..4)
            .map(|i| {
                let m = 1u64 << i;
                (m, sha256(format!("test {label} {m}").as_bytes()))
            })
            .collect();
        IssuerKeyset::from_secrets(&secrets, 0, 2_000_000_000, 0).unwrap()
    }

    #[test]
    fn signing_is_deterministic_and_its_dleq_verifies() {
        let k = keyset("x");
        let b = hash_to_curve(b"blinded").unwrap();
        let s1 = k.sign(4, &b).unwrap();
        assert_eq!(k.sign(4, &b).unwrap(), s1);
        assert!(verify_dleq(k.info().key(4).unwrap(), &b, &s1));
        assert!(!verify_dleq(k.info().key(2).unwrap(), &b, &s1));
        let mut bad = s1;
        bad.e[31] ^= 1;
        assert!(!verify_dleq(k.info().key(4).unwrap(), &b, &bad));
        assert_eq!(k.sign(16, &b), Err(KeysetError::NoKey(16)));
        assert!(k.info().id_matches());
        assert!(format!("{k:?}").starts_with("IssuerKeyset"));
    }

    #[test]
    fn cashu_and_bnap_core_agree_on_hash_to_curve() {
        // The signer's view derives Y with bnap-core; cashu's BDHKE derives
        // it inside blind_message and verify_message. They must agree.
        for msg in [&b""[..], b"a", &[0u8; 32], &[0xff; 64], b"bnap notes"] {
            let ours = hash_to_curve(msg).unwrap();
            let theirs = cashu::dhke::hash_to_curve(msg).unwrap().to_bytes();
            assert_eq!(ours, theirs);
        }
    }

    #[test]
    fn notes_verify_only_with_their_amount_key() {
        let k = keyset("x");
        let secret = b"note secret";
        let y = hash_to_curve(secret).unwrap();
        // With r = 0 the note is the blind signature of Y itself.
        let c = k.sign(2, &y).unwrap().c;
        assert_eq!(k.verify_note(2, secret, &c), Some(y));
        assert_eq!(k.verify_note(4, secret, &c), None);
        assert_eq!(k.verify_note(2, b"other", &c), None);
    }

    #[test]
    fn rotation_activates_a_standby_keyset_after_its_lead() {
        let policy = RotationPolicy::default();
        let mut a = keyset("a").info().clone();
        a.state = KeysetState::Active;
        a.activated_at = Some(0);
        let mut b = keyset("b").info().clone();
        b.published_at = 10 * DAY;
        let mut table = vec![a.clone(), b.clone()];
        // Not due yet.
        let p = plan_rotation(&table, 40 * DAY, &policy);
        assert_eq!(p.activate, None);
        assert!(!p.needs_standby);
        // Due, and b was published 30 days before.
        let p = plan_rotation(&table, 92 * DAY, &policy);
        assert_eq!(p.activate, Some(b.id));
        assert_eq!(p.retire, vec![a.id]);
        assert!(p.needs_standby);
        apply_rotation(&mut table, &p, 92 * DAY);
        assert_eq!(table[0].state, KeysetState::InputsOnly);
        assert_eq!(table[1].state, KeysetState::Active);
        // Revoked: no keyset signs, and a fresh standby is too young.
        revoke(&mut table[1]);
        let mut c = keyset("c").info().clone();
        c.published_at = 92 * DAY;
        table.push(c);
        let p = plan_rotation(&table, 93 * DAY, &policy);
        assert!(p.blocked);
        assert_eq!(p.activate, None);
    }
}
