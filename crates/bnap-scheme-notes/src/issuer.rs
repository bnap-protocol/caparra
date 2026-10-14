//! The issuer's own state (operator-trusted): the keyset table, the fund
//! quote table and the signed-output table (sections 7.4, 8 and 10).
//!
//! The use store stays the authority on use: whether a note's `Y` or a
//! quote's payment is spent is decided only by the socket's commit (draft-00
//! 6.3). These tables hold what the use store does not:
//!
//! - **keysets**: the live table verification narrows the offer with
//!   (6.2 step 2), with public keys only;
//! - **quotes**: NUT-23 BOLT11 mint quotes, each locked to a NUT-20 key;
//! - **signed outputs**: every output the issuer signed, keyed by `(B',
//!   source)` and kept until 60 s after its keyset's final expiry (7.4,
//!   NUT-09), where the source is `H(body)` of the credential whose
//!   settlement signed it, or `rk_mint` for a NUT-04 mint. A settlement
//!   records its outputs before it asks the signer (with no signature yet)
//!   and completes them after, so a crash between the two still shows
//!   which outputs an outcome may have had signed.

use std::collections::BTreeMap;
#[cfg(feature = "test-support")]
use std::sync::{Mutex, PoisonError};

use crate::keyset::{BlindSigned, KeysetInfo};
use crate::wire::{KeysetIdBytes, PointBytes};

/// The issuer store failed; the gate fails closed with UNAVAILABLE.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("issuer store unavailable: {0}")]
pub struct IssuerError(pub String);

/// A NUT-23 BOLT11 mint quote for a BNAP keyset (5.3, 8.2, 8.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteRecord {
    /// The quote ID, 1 to 64 bytes.
    pub id: String,
    /// `bolt11`; a body's `fund` redeems BOLT11 quotes only (P21).
    pub method: String,
    /// `sat`.
    pub unit: String,
    /// The quote amount.
    pub amount: u64,
    /// The BOLT11 invoice.
    pub request: String,
    /// The `ln` rail's payment hash of the invoice: its `PayId` and the
    /// reference a credential's rail reference carries.
    pub payment_hash: [u8; 32],
    /// Until when the invoice can be paid.
    pub expiry: u64,
    /// The client's compressed NUT-20 key; every BNAP quote has one (P24).
    pub pubkey: Option<PointBytes>,
    /// The rail reported the invoice paid. A cache: the rail is asked again
    /// while this is false.
    pub paid: bool,
    /// The quote's `RailId` was committed, by a credential or a mint. A
    /// cache of the use store, which is the authority (8.6).
    pub issued: bool,
    /// When the quote was made.
    pub created: u64,
}

/// One output the issuer signed, or is about to sign (7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOutput {
    /// The keyset that signs it.
    pub keyset: KeysetIdBytes,
    /// Its amount.
    pub amount: u64,
    /// `B'`.
    pub blinded: PointBytes,
    /// `H(body)` of the credential whose settlement signs it, or `rk_mint`.
    pub source: [u8; 32],
    /// `C'` and the DLEQ proof, once signed; `None` while only reserved.
    pub signature: Option<BlindSigned>,
}

/// What [`IssuerStore::insert_quote`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteInsert {
    /// The quote was stored.
    Inserted,
    /// A quote with that ID exists already; it is returned unchanged.
    Exists(QuoteRecord),
}

/// The issuer's tables (operator-trusted). Every write is durable before it
/// returns, and the signed-output records of a settlement are durable
/// before the outcome write of draft-00 6.4 (7.4).
#[async_trait::async_trait]
pub trait IssuerStore: Send + Sync {
    /// Every keyset in the live table, revoked ones included.
    async fn keysets(&self) -> Result<Vec<KeysetInfo>, IssuerError>;

    /// Writes one keyset (a new one, or a state change).
    async fn put_keyset(&self, keyset: &KeysetInfo) -> Result<(), IssuerError>;

    /// The quote with this ID.
    async fn quote(&self, id: &str) -> Result<Option<QuoteRecord>, IssuerError>;

    /// Stores a new quote, unless one with its ID exists (first write wins).
    async fn insert_quote(&self, quote: &QuoteRecord) -> Result<QuoteInsert, IssuerError>;

    /// Sets the quote's `paid` and `issued` flags where the arguments are
    /// true; a flag is never cleared.
    async fn mark_quote(&self, id: &str, paid: bool, issued: bool) -> Result<(), IssuerError>;

    /// Upserts output records by `(B', source)`. A record that has a
    /// signature keeps it; one without gains the given one.
    async fn put_outputs(&self, outputs: &[SignedOutput]) -> Result<(), IssuerError>;

    /// Every record of one source, reserved or signed.
    async fn outputs_by_source(&self, source: &[u8; 32]) -> Result<Vec<SignedOutput>, IssuerError>;

    /// Every record of these `B'` values, under any source (NUT-09 restore,
    /// and the NUT-04 check that no output was signed before).
    async fn outputs_by_blinded(
        &self,
        blinded: &[PointBytes],
    ) -> Result<Vec<SignedOutput>, IssuerError>;
}

/// The keyset with this ID in a table.
#[must_use]
pub fn find_keyset<'a>(table: &'a [KeysetInfo], id: &KeysetIdBytes) -> Option<&'a KeysetInfo> {
    table.iter().find(|k| &k.id == id)
}

#[derive(Debug, Default)]
#[cfg(feature = "test-support")]
struct Tables {
    keysets: BTreeMap<KeysetIdBytes, KeysetInfo>,
    quotes: BTreeMap<String, QuoteRecord>,
    outputs: BTreeMap<(PointBytes, [u8; 32]), SignedOutput>,
}

/// An in-memory [`IssuerStore`] for tests and local development. Not
/// durable: never use it in a gate.
#[derive(Debug, Default)]
#[cfg(feature = "test-support")]
pub struct MemoryIssuerStore {
    tables: Mutex<Tables>,
    down: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "test-support")]
impl MemoryIssuerStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store holding these keysets.
    #[must_use]
    pub fn with_keysets(keysets: impl IntoIterator<Item = KeysetInfo>) -> Self {
        let s = Self::new();
        {
            let mut t = s.lock();
            for k in keysets {
                t.keysets.insert(k.id, k);
            }
        }
        s
    }

    /// Makes every call fail, as an unreachable store would.
    pub fn set_unavailable(&self, down: bool) {
        self.down.store(down, std::sync::atomic::Ordering::SeqCst);
    }

    /// Every output record, for tests.
    #[must_use]
    pub fn all_outputs(&self) -> Vec<SignedOutput> {
        self.lock().outputs.values().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn up(&self) -> Result<(), IssuerError> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            Err(IssuerError("down".into()))
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "test-support")]
#[async_trait::async_trait]
impl IssuerStore for MemoryIssuerStore {
    async fn keysets(&self) -> Result<Vec<KeysetInfo>, IssuerError> {
        self.up()?;
        Ok(self.lock().keysets.values().cloned().collect())
    }

    async fn put_keyset(&self, keyset: &KeysetInfo) -> Result<(), IssuerError> {
        self.up()?;
        self.lock().keysets.insert(keyset.id, keyset.clone());
        Ok(())
    }

    async fn quote(&self, id: &str) -> Result<Option<QuoteRecord>, IssuerError> {
        self.up()?;
        Ok(self.lock().quotes.get(id).cloned())
    }

    async fn insert_quote(&self, quote: &QuoteRecord) -> Result<QuoteInsert, IssuerError> {
        self.up()?;
        let mut t = self.lock();
        if let Some(q) = t.quotes.get(&quote.id) {
            return Ok(QuoteInsert::Exists(q.clone()));
        }
        t.quotes.insert(quote.id.clone(), quote.clone());
        Ok(QuoteInsert::Inserted)
    }

    async fn mark_quote(&self, id: &str, paid: bool, issued: bool) -> Result<(), IssuerError> {
        self.up()?;
        if let Some(q) = self.lock().quotes.get_mut(id) {
            q.paid |= paid;
            q.issued |= issued;
        }
        Ok(())
    }

    async fn put_outputs(&self, outputs: &[SignedOutput]) -> Result<(), IssuerError> {
        self.up()?;
        let mut t = self.lock();
        for o in outputs {
            let rec = t
                .outputs
                .entry((o.blinded, o.source))
                .or_insert_with(|| o.clone());
            if rec.signature.is_none() {
                rec.signature = o.signature;
            }
        }
        Ok(())
    }

    async fn outputs_by_source(&self, source: &[u8; 32]) -> Result<Vec<SignedOutput>, IssuerError> {
        self.up()?;
        Ok(self
            .lock()
            .outputs
            .values()
            .filter(|o| &o.source == source)
            .cloned()
            .collect())
    }

    async fn outputs_by_blinded(
        &self,
        blinded: &[PointBytes],
    ) -> Result<Vec<SignedOutput>, IssuerError> {
        self.up()?;
        Ok(self
            .lock()
            .outputs
            .values()
            .filter(|o| blinded.contains(&o.blinded))
            .cloned()
            .collect())
    }
}

/// Groups records by their `B'`, for NUT-09 answers.
#[must_use]
pub fn by_blinded(records: &[SignedOutput]) -> BTreeMap<PointBytes, Vec<&SignedOutput>> {
    let mut m: BTreeMap<PointBytes, Vec<&SignedOutput>> = BTreeMap::new();
    for r in records {
        m.entry(r.blinded).or_default().push(r);
    }
    m
}
