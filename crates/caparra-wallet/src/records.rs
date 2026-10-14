//! What the wallet keeps in its store, record by record.
//!
//! Every record is sealed by [`crate::store`]. Byte strings are hex in the
//! sealed JSON.

use std::collections::BTreeMap;

use bnap_core::manifest::{ManifestKey, Pin, SignedManifest};
use bnap_core::schnorr::Key;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::paysource::PaySourceConfig;
use crate::policy::Policy;
use crate::transport::HttpRequest;

/// Record kinds.
pub mod kind {
    /// The wallet's configuration.
    pub const CONFIG: &str = "config";
    /// The seed.
    pub const SECRET: &str = "secret";
    /// Attestation keys.
    pub const ATTEST_KEYS: &str = "attest-keys";
    /// Manifest pins, by origin.
    pub const PIN: &str = "pin";
    /// Last manifest fetch attempt, by origin.
    pub const FETCH: &str = "fetch";
    /// Notes, by `hex(K)`.
    pub const NOTE: &str = "note";
    /// Keysets with their keys, by hex ID.
    pub const KEYSET: &str = "keyset";
    /// Next counter index, by `hex(keyset)/slot`.
    pub const COUNTER: &str = "counter";
    /// Sites: origin, issuer, keysets and slots used (the backup list).
    pub const SITE: &str = "site";
    /// Fund quotes, by quote ID.
    pub const QUOTE: &str = "quote";
    /// Paid operations not yet finished, by ID.
    pub const OP: &str = "op";
    /// Receipts, by ID.
    pub const RECEIPT: &str = "receipt";
    /// Ledger entries, by ID.
    pub const LEDGER: &str = "ledger";
}

/// Hex serde for byte strings.
pub mod hexser {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes hex.
    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    /// Reads hex of the right length.
    pub fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(
        d: D,
    ) -> Result<T, D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        T::try_from(v).map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

/// Hex serde for optional byte strings.
pub mod hexopt {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes hex or null.
    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(
        v: &Option<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&hex::encode(v)),
            None => s.serialize_none(),
        }
    }

    /// Reads hex or null.
    pub fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| {
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            T::try_from(v).map_err(|_| serde::de::Error::custom("wrong length"))
        })
        .transpose()
    }
}

/// The wallet's configuration, set by a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The spend policy.
    pub policy: Policy,
    /// Where Lightning payments come from.
    pub pay_source: PaySourceConfig,
    /// This device's counter slot (bnap:notes 12.1).
    pub slot: u16,
    /// When the wallet was made.
    pub created: u64,
}

/// The seed words. Zeroized when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    /// The BIP-39 mnemonic.
    pub mnemonic: String,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Attestation keys: Web Bot Auth (`Ed25519`) and `DPoP` (`ES256`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestKeys {
    /// The Ed25519 secret of the Web Bot Auth key.
    #[serde(with = "hexser")]
    pub wba: [u8; 32],
    /// The `P-256` secret of the `DPoP` key.
    #[serde(with = "hexser")]
    pub dpop: [u8; 32],
    /// The Signature-Agent URL to name in Web Bot Auth signatures.
    #[serde(default)]
    pub agent: Option<String>,
}

impl Drop for AttestKeys {
    fn drop(&mut self) {
        self.wba.zeroize();
        self.dpop.zeroize();
    }
}

impl std::fmt::Debug for AttestKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestKeys(..)")
    }
}

/// A manifest pin (draft-00 9.3), with the manifest it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinRecord {
    /// The origin.
    pub origin: String,
    /// Pinned root.
    pub root: Key,
    /// Pinned backup.
    pub backup: Key,
    /// Highest `seq` seen.
    pub seq: u64,
    /// `H(m bytes)`.
    #[serde(with = "hexser")]
    pub hash: [u8; 32],
    /// The `bnap-required` flag.
    pub required: bool,
    /// The online keys.
    pub keys: Vec<ManifestKey>,
    /// The pin lapses after this.
    pub until: u64,
    /// The manifest bytes as fetched.
    #[serde(with = "hexser")]
    pub manifest: Vec<u8>,
    /// When it was accepted.
    pub accepted_at: u64,
}

impl PinRecord {
    /// The record of an accepted pin.
    #[must_use]
    pub fn new(origin: &str, pin: &Pin, manifest: &[u8], now: u64) -> Self {
        Self {
            origin: origin.to_owned(),
            root: pin.root,
            backup: pin.backup,
            seq: pin.seq,
            hash: pin.hash,
            required: pin.required,
            keys: pin.keys.clone(),
            until: pin.until,
            manifest: manifest.to_vec(),
            accepted_at: now,
        }
    }

    /// The core pin.
    #[must_use]
    pub fn pin(&self) -> Pin {
        Pin {
            root: self.root,
            backup: self.backup,
            seq: self.seq,
            hash: self.hash,
            required: self.required,
            keys: self.keys.clone(),
            until: self.until,
        }
    }

    /// The pinned manifest, parsed.
    #[must_use]
    pub fn manifest(&self) -> Option<SignedManifest> {
        SignedManifest::parse(&self.manifest).ok()
    }
}

/// The last manifest fetch attempt for an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchLog {
    /// When.
    pub at: u64,
}

/// Where a note is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum NoteState {
    /// Spendable.
    Unspent,
    /// Locked by an operation in flight.
    Reserved {
        /// The operation.
        op: String,
    },
    /// Spent.
    Spent,
}

/// A note the wallet holds.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteRecord {
    /// `K`, x-only, the record's name.
    #[serde(with = "hexser")]
    pub k: [u8; 32],
    /// The origin whose operator issued it.
    pub origin: String,
    /// The issuer URL.
    pub issuer: String,
    /// The keyset.
    #[serde(with = "hexser")]
    pub keyset: [u8; 33],
    /// The amount.
    pub amount: u64,
    /// `k_n`.
    #[serde(with = "hexser")]
    pub note_key: [u8; 32],
    /// `C`.
    #[serde(with = "hexser")]
    pub c: [u8; 33],
    /// Its state.
    pub state: NoteState,
}

impl std::fmt::Debug for NoteRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteRecord")
            .field("origin", &self.origin)
            .field("amount", &self.amount)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl NoteRecord {
    /// The scheme crate's note.
    #[must_use]
    pub fn note(&self) -> bnap_scheme_notes::client::Note {
        bnap_scheme_notes::client::Note {
            keyset: self.keyset,
            amount: self.amount,
            note_key: self.note_key,
            c: self.c,
        }
    }

    /// The record of a note the scheme crate unblinded.
    pub fn from_note(
        n: &bnap_scheme_notes::client::Note,
        origin: &str,
        issuer: &str,
    ) -> Result<Self, String> {
        Ok(Self {
            k: n.key().map_err(|e| e.to_string())?,
            origin: origin.to_owned(),
            issuer: issuer.to_owned(),
            keyset: n.keyset,
            amount: n.amount,
            note_key: n.note_key,
            c: n.c,
            state: NoteState::Unspent,
        })
    }
}

impl Drop for NoteRecord {
    fn drop(&mut self) {
        self.note_key.zeroize();
    }
}

/// A keyset and its keys, as fetched and checked (bnap:notes 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetRecord {
    /// The issuer URL.
    pub issuer: String,
    /// The keyset ID.
    #[serde(with = "hexser")]
    pub id: [u8; 33],
    /// `A` by amount.
    pub keys: BTreeMap<u64, String>,
    /// NUT-02 `final_expiry`.
    pub final_expiry: u64,
    /// NUT-02 `input_fee_ppk`.
    pub input_fee_ppk: u64,
}

impl KeysetRecord {
    /// The keys as points.
    #[must_use]
    pub fn points(&self) -> BTreeMap<u64, [u8; 33]> {
        self.keys
            .iter()
            .filter_map(|(a, k)| Some((*a, hex::decode(k).ok()?.try_into().ok()?)))
            .collect()
    }
}

/// The next counter index of one keyset and slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterRecord {
    /// The next unused index.
    pub next: u64,
}

/// A site the wallet holds notes at: the backup list of bnap:notes 12.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SiteRecord {
    /// The origin.
    pub origin: String,
    /// The issuer URL.
    pub issuer: String,
    /// Keyset IDs, hex.
    pub keysets: Vec<String>,
    /// Slots used.
    pub slots: Vec<u16>,
}

/// Where a fund quote is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuoteState {
    /// Saved, not paid yet.
    Unpaid,
    /// Paid; redeem or mint it.
    Paid,
    /// Redeemed in a credential.
    Redeemed,
    /// Minted into notes.
    Minted,
}

/// A fund quote (bnap:notes 8.3: saved with its key before paying).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteRecord {
    /// Quote ID.
    pub id: String,
    /// The origin.
    pub origin: String,
    /// The issuer URL.
    pub issuer: String,
    /// The NUT-20 quote key.
    #[serde(with = "hexser")]
    pub key: [u8; 32],
    /// Amount, sat.
    pub amount: u64,
    /// The invoice.
    pub invoice: String,
    /// Its payment hash.
    #[serde(with = "hexser")]
    pub payment_hash: [u8; 32],
    /// The offer that carried it, when it came in a 402.
    #[serde(with = "hexopt", default)]
    pub offer: Option<Vec<u8>>,
    /// State.
    pub state: QuoteState,
    /// Routing fee paid, sat.
    #[serde(default)]
    pub fee_sat: u64,
}

impl Drop for QuoteRecord {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for QuoteRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuoteRecord")
            .field("id", &self.id)
            .field("origin", &self.origin)
            .field("amount", &self.amount)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// An output a credential or a mint request carried, by derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputRecord {
    /// Keyset.
    #[serde(with = "hexser")]
    pub keyset: [u8; 33],
    /// Amount.
    pub amount: u64,
    /// Full counter value (slot and index).
    pub counter: u64,
}

/// Where a paid operation is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum OpState {
    /// Built and about to be sent, or sent with no answer yet.
    Sent,
    /// The server answered PENDING, UNAVAILABLE or nothing: replay it.
    Pending {
        /// When to try again.
        retry_at: u64,
    },
    /// The receipt or change failed its checks: kept as evidence.
    Disputed {
        /// What failed.
        reason: String,
    },
}

/// A paid operation the wallet has not finished: the request with its
/// credential, kept so it can be replayed (draft-00 6.4; bnap:notes 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpRecord {
    /// ID.
    pub id: String,
    /// The origin.
    pub origin: String,
    /// The task it was paid for.
    pub task: String,
    /// When it was made.
    pub created: u64,
    /// The request, credential field included.
    pub request: HttpRequest,
    /// The value scheme, or `None` for an attestation-only credential.
    pub scheme: Option<String>,
    /// The offer.
    #[serde(with = "hexser")]
    pub offer: Vec<u8>,
    /// The credential.
    #[serde(with = "hexser")]
    pub credential: Vec<u8>,
    /// The request's action scope.
    #[serde(with = "hexser")]
    pub action_scope: [u8; 32],
    /// Its Digest.
    #[serde(with = "hexser")]
    pub digest: [u8; 32],
    /// Change outputs sent.
    pub outputs: Vec<OutputRecord>,
    /// The value the wallet computed for its notes body.
    pub value: u64,
    /// Notes spent, by `hex(K)`.
    pub notes: Vec<String>,
    /// Their face value.
    pub face: u64,
    /// A fund quote redeemed.
    pub quote: Option<String>,
    /// What went out over Lightning for it, fees included.
    pub lightning_sat: u64,
    /// The ledger entry.
    pub ledger: String,
    /// The issuer, for notes.
    pub issuer: Option<String>,
    /// Where it is.
    pub state: OpState,
}

/// What a receipt is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptKind {
    /// A BNAP Response, signed by a receipt key the manifest lists.
    Bnap,
    /// A native payment: the invoice and the preimage are all the proof.
    Native,
}

/// A paid action's receipt: everything a third party needs to check it
/// (draft-00 8.1, "Using a receipt as proof").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    /// ID.
    pub id: String,
    /// What it is.
    pub kind: ReceiptKind,
    /// The origin.
    pub origin: String,
    /// The method.
    pub method: String,
    /// The URL.
    pub url: String,
    /// The value scheme.
    pub scheme: Option<String>,
    /// When it was received.
    pub at: u64,
    /// What the payment cost the wallet in the end, sat.
    pub cost_sat: u64,
    /// What the server charged, in `unit`.
    pub charged: u64,
    /// The unit.
    pub unit: Option<String>,
    /// OK or FAILED.
    pub ok: bool,
    /// The change matched the scheme's selection rule.
    pub change_ok: bool,
    /// The offer.
    #[serde(with = "hexser")]
    pub offer: Vec<u8>,
    /// The credential.
    #[serde(with = "hexser")]
    pub credential: Vec<u8>,
    /// The Response.
    #[serde(with = "hexser")]
    pub response: Vec<u8>,
    /// The manifest that listed the receipt key.
    #[serde(with = "hexser")]
    pub manifest: Vec<u8>,
    /// The request's action scope.
    #[serde(with = "hexser")]
    pub action_scope: [u8; 32],
    /// For a native payment: the invoice.
    #[serde(default)]
    pub invoice: Option<String>,
    /// For a native payment: the preimage.
    #[serde(with = "hexopt", default)]
    pub preimage: Option<[u8; 32]>,
}
