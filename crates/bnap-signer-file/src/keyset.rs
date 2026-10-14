//! `bnap:notes` keysets: Cashu keysets (NUT-01, NUT-02) whose keys sign
//! notes and nothing else (`schemes/bnap-notes-draft-00.md` 2.2, 4.2).
//!
//! A keyset has unit `sat`, one key `a` per amount `2^i`, a NUT-02
//! `input_fee_ppk` and a `final_expiry`, and a version-01 keyset ID: the
//! byte `01` followed by SHA-256 of `m:hex(A)` for each amount in ascending
//! order, joined by `,`, then `|unit:sat`, `|input_fee_ppk:` and the fee
//! unless it is 0, and `|final_expiry:` and the final expiry (notes draft
//! 18.1, NUT-02). The ID is computed with the `cashu` crate
//! (`Id::v2_from_data`), and the tests check it against the notes draft's
//! keyset vectors.
//!
//! # Derivation from a seed
//!
//! The notes draft does not say how an issuer derives its keyset keys; that
//! is the issuer's own business (ERRATA candidate N4-1). This crate uses
//! BIP-32, the way Cashu mints do, under a path of its own so that a BNAP key
//! never appears in any other keyset (notes draft 4.2), even when an
//! operator reuses a seed of a Cashu mint, whose keysets live under `m/0'`:
//!
//! ```text
//! keyset key for 2^i = m / 1651401072' / 0' / index' / i'     (1651401072 = 0x626e6170, "bnap")
//! ```
//!
//! The `0'` is the unit slot (Cashu's index for `sat`). Rotating a keyset
//! means a new `index`: its keys and its ID are new.
//!
//! # Signing
//!
//! A blind signature is `C' = a·B'` with a NUT-12 DLEQ proof made with
//! NUT-12's deterministic nonce, both through the `cashu` crate, so the same
//! output always gets the same `C'` and the same proof (notes draft 7.4). A
//! note `(secret, C)` is accepted when `C = a·Y` for `Y =
//! hash_to_curve(secret)`, computed by the signer.

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::NetworkKind;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bnap_core::secp256k1::{self, Secp256k1};
use cashu::dhke::sign_message;
use cashu::nuts::{BlindSignature as CashuBlindSignature, CurrencyUnit, Id, Keys};
use cashu::{Amount, PublicKey, SecretKey};

/// The unit of every BNAP keyset (notes draft 4.2).
pub const UNIT: &str = "sat";

/// The first hardened index of the derivation path, `0x626e6170` ("bnap").
pub const DERIVATION_PURPOSE: u32 = 0x626e_6170;

/// Keys per keyset when the key file does not say: amounts `2^0` to `2^31`.
pub const DEFAULT_ORDERS: u8 = 32;

/// The most keys a keyset may have: amounts up to `2^63`.
pub const MAX_ORDERS: u8 = 64;

/// The seed lengths BIP-32 allows, in bytes.
pub const SEED_LEN: std::ops::RangeInclusive<usize> = 16..=64;

/// Why a keyset could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeysetError {
    /// The seed is not 16 to 64 bytes.
    #[error("a keyset seed is 16 to 64 bytes, not {0}")]
    SeedLength(usize),
    /// `orders` is 0 or above 64.
    #[error("orders must be 1 to 64, not {0}")]
    Orders(u8),
    /// BIP-32 failed (a derived key out of range, about 2^-127 likely).
    #[error("key derivation failed")]
    Derivation,
    /// A secret key that is zero or not below the group order.
    #[error("not a valid secp256k1 secret key (amount {0})")]
    InvalidSecret(u64),
    /// An amount that is not a power of two, or listed twice.
    #[error("amount {0} is not a power of two, or is listed twice")]
    Amount(u64),
    /// A keyset with no key.
    #[error("a keyset needs at least one key")]
    NoKeys,
    /// Every BNAP keyset publishes a final expiry (notes draft 4.2).
    #[error("a BNAP keyset needs a final_expiry above 0")]
    FinalExpiry,
    /// The `cashu` crate refused a point or a key.
    #[error("cashu: {0}")]
    Cashu(String),
}

/// A blind signature as [`NotesKeyset::sign`] makes it: `C'` and the DLEQ
/// proof's `e` and `s`.
pub(crate) type Signed = ([u8; 33], [u8; 32], [u8; 32]);

/// One amount's key: `a` and `A = a·G`.
struct AmountKey {
    secret: SecretKey,
    public: PublicKey,
}

/// A `bnap:notes` keyset with its secret keys. See the module docs.
///
/// `Debug` prints the ID and the parameters, never a key; the `cashu`
/// crate's `SecretKey` erases itself on drop.
pub struct NotesKeyset {
    id: [u8; 33],
    cashu_id: Id,
    input_fee_ppk: u64,
    final_expiry: u64,
    active: bool,
    keys: BTreeMap<u64, AmountKey>,
}

impl fmt::Debug for NotesKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotesKeyset")
            .field("id", &hex::encode(self.id))
            .field("unit", &UNIT)
            .field("input_fee_ppk", &self.input_fee_ppk)
            .field("final_expiry", &self.final_expiry)
            .field("active", &self.active)
            .field("amounts", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl NotesKeyset {
    /// Derives a keyset from `seed` under `m/1651401072'/0'/index'`, with
    /// one key per amount `2^0` to `2^(orders-1)` (see the module docs).
    pub fn derive(
        seed: &[u8],
        index: u32,
        orders: u8,
        input_fee_ppk: u64,
        final_expiry: u64,
        active: bool,
    ) -> Result<Self, KeysetError> {
        if !SEED_LEN.contains(&seed.len()) {
            return Err(KeysetError::SeedLength(seed.len()));
        }
        if orders == 0 || orders > MAX_ORDERS {
            return Err(KeysetError::Orders(orders));
        }
        let secp = Secp256k1::signing_only();
        let hardened =
            |i: u32| ChildNumber::from_hardened_idx(i).map_err(|_| KeysetError::Derivation);
        let path = [
            hardened(DERIVATION_PURPOSE)?,
            hardened(0)?,
            hardened(index)?,
        ];
        let mut master =
            Xpriv::new_master(NetworkKind::Main, seed).map_err(|_| KeysetError::Derivation)?;
        let base = master.derive_priv(&secp, &path);
        master.private_key.non_secure_erase();
        let mut base = base.map_err(|_| KeysetError::Derivation)?;
        let mut keys = Vec::with_capacity(usize::from(orders));
        let mut failed = false;
        for i in 0..u32::from(orders) {
            match hardened(i).and_then(|c| {
                base.derive_priv(&secp, &[c])
                    .map_err(|_| KeysetError::Derivation)
            }) {
                Ok(mut child) => {
                    keys.push((1u64 << i, SecretKey::from(child.private_key)));
                    child.private_key.non_secure_erase();
                }
                Err(_) => failed = true,
            }
        }
        base.private_key.non_secure_erase();
        if failed {
            return Err(KeysetError::Derivation);
        }
        Self::build(keys, input_fee_ppk, final_expiry, active)
    }

    /// A keyset from explicit secret keys, one per amount: for importing an
    /// issuer's existing keys, and for the notes draft's test keysets (18.1).
    pub fn from_secret_keys(
        keys: &[(u64, [u8; 32])],
        input_fee_ppk: u64,
        final_expiry: u64,
        active: bool,
    ) -> Result<Self, KeysetError> {
        let keys = keys
            .iter()
            .map(|(amount, sk)| {
                secp256k1::SecretKey::from_slice(sk)
                    .map(|k| (*amount, SecretKey::from(k)))
                    .map_err(|_| KeysetError::InvalidSecret(*amount))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::build(keys, input_fee_ppk, final_expiry, active)
    }

    fn build(
        keys: Vec<(u64, SecretKey)>,
        input_fee_ppk: u64,
        final_expiry: u64,
        active: bool,
    ) -> Result<Self, KeysetError> {
        if keys.is_empty() {
            return Err(KeysetError::NoKeys);
        }
        if final_expiry == 0 {
            return Err(KeysetError::FinalExpiry);
        }
        let mut map = BTreeMap::new();
        for (amount, secret) in keys {
            if !amount.is_power_of_two() || map.contains_key(&amount) {
                return Err(KeysetError::Amount(amount));
            }
            let public = secret.public_key();
            map.insert(amount, AmountKey { secret, public });
        }
        let published = Keys::new(
            map.iter()
                .map(|(amount, k)| (Amount::from(*amount), k.public))
                .collect(),
        );
        let cashu_id = Id::v2_from_data(
            &published,
            &CurrencyUnit::Sat,
            input_fee_ppk,
            Some(final_expiry),
        );
        let id: [u8; 33] = cashu_id
            .to_bytes()
            .try_into()
            .map_err(|_| KeysetError::Cashu("keyset ID is not 33 bytes".into()))?;
        Ok(Self {
            id,
            cashu_id,
            input_fee_ppk,
            final_expiry,
            active,
            keys: map,
        })
    }

    /// The full 33-byte version-01 keyset ID.
    #[must_use]
    pub fn id(&self) -> [u8; 33] {
        self.id
    }

    /// Always `sat`.
    #[must_use]
    pub fn unit(&self) -> &'static str {
        UNIT
    }

    /// The NUT-02 input fee, parts per thousand per input.
    #[must_use]
    pub fn input_fee_ppk(&self) -> u64 {
        self.input_fee_ppk
    }

    /// The NUT-02 final expiry, Unix seconds.
    #[must_use]
    pub fn final_expiry(&self) -> u64 {
        self.final_expiry
    }

    /// Whether the keyset signs outputs. An inactive keyset still accepts
    /// its notes as inputs until its final expiry (notes draft 10).
    #[must_use]
    pub fn active(&self) -> bool {
        self.active
    }

    /// The public keys `A` by amount, as NUT-01 serves them.
    #[must_use]
    pub fn public_keys(&self) -> BTreeMap<u64, [u8; 33]> {
        self.keys
            .iter()
            .map(|(amount, k)| (*amount, k.public.to_bytes()))
            .collect()
    }

    /// The public key `A` for one amount.
    #[must_use]
    pub fn public_key(&self, amount: u64) -> Option<[u8; 33]> {
        self.keys.get(&amount).map(|k| k.public.to_bytes())
    }

    /// Whether the keyset has a key for `amount`.
    #[must_use]
    pub fn has_amount(&self, amount: u64) -> bool {
        self.keys.contains_key(&amount)
    }

    /// `C = a·Y` for the key of `amount`? `y` is the point the signer
    /// derived from the note's secret, never one a caller named.
    pub(crate) fn check(&self, amount: u64, y: &[u8; 33], c: &[u8; 33]) -> bool {
        let Some(key) = self.keys.get(&amount) else {
            return false;
        };
        let Ok(y) = PublicKey::from_slice(y) else {
            return false;
        };
        sign_message(&key.secret, &y).is_ok_and(|expected| expected.to_bytes() == *c)
    }

    /// `C' = a·B'` and its deterministic NUT-12 DLEQ proof `(e, s)`.
    /// Private to the crate: [`crate::FileSigner`] signs only after the
    /// settlement's ledger took the outputs.
    pub(crate) fn sign(&self, amount: u64, blinded: &[u8; 33]) -> Result<Signed, KeysetError> {
        let key = self.keys.get(&amount).ok_or(KeysetError::Amount(amount))?;
        let b = PublicKey::from_slice(blinded).map_err(|e| KeysetError::Cashu(e.to_string()))?;
        let c = sign_message(&key.secret, &b).map_err(|e| KeysetError::Cashu(e.to_string()))?;
        let signed =
            CashuBlindSignature::new(Amount::from(amount), c, self.cashu_id, &b, &key.secret)
                .map_err(|e| KeysetError::Cashu(e.to_string()))?;
        let dleq = signed
            .dleq
            .ok_or_else(|| KeysetError::Cashu("no DLEQ proof".into()))?;
        Ok((
            signed.c.to_bytes(),
            dleq.e.to_secret_bytes(),
            dleq.s.to_secret_bytes(),
        ))
    }
}
