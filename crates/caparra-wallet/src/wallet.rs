//! The wallet: one encrypted store, a transport, a pay source and a clock.
//!
//! [`Wallet::fetch`] is the paid fetch (`pay` module); this module holds
//! what the wallet is and keeps: the seed, the configuration a person sets,
//! the session caps a model may narrow, manifest pins, balances, the ledger
//! and receipts.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use bnap_core::credential::Credential;
use bnap_core::hash::{Scope, sha256};
use bnap_core::manifest::{self, KeyUse, SignedManifest};
use bnap_core::offer::Offer;
use bnap_core::response::Response;
use bnap_core::secp256k1::rand::{RngCore, thread_rng};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{CapKind, Code, Refusal, Result};
use crate::invoice::Invoice;
use crate::paysource::{PaySource, PaySourceConfig};
use crate::policy::{self, Caps, LedgerEntry, Policy, Remaining, SessionCaps};
use crate::records::{
    AttestKeys, Config, FetchLog, NoteRecord, NoteState, PinRecord, ReceiptKind, ReceiptRecord,
    Secret, kind,
};
use crate::registry::Registry;
use crate::store::{KdfParams, Store};
use crate::transport::{HttpRequest, Transport};

/// The wallet's clock, Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// How often a manifest is fetched for one origin, at most (9.3).
pub const MANIFEST_INTERVAL: u64 = 300;
/// Largest manifest read, bytes.
pub const MAX_MANIFEST: usize = 64 * 1024;

/// What a wallet is opened with.
#[derive(Clone)]
pub struct Options {
    /// HTTP.
    pub transport: Arc<dyn Transport>,
    /// A pay source that overrides the configured one (tests, embedding).
    pub pay_source: Option<Arc<dyn PaySource>>,
    /// The clock.
    pub clock: Clock,
    /// The task payments count against.
    pub task: String,
    /// Key derivation cost for a new wallet.
    pub kdf: KdfParams,
}

impl Options {
    /// Options with the system clock and task `default`.
    #[must_use]
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            pay_source: None,
            clock: system_clock(),
            task: "default".into(),
            kdf: KdfParams::default(),
        }
    }
}

/// The wallet.
pub struct Wallet {
    pub(crate) store: Store,
    pub(crate) transport: Arc<dyn Transport>,
    pay_override: Option<Arc<dyn PaySource>>,
    pub(crate) clock: Clock,
    pub(crate) task: String,
    session: Mutex<SessionCaps>,
    pin_lock: tokio::sync::Mutex<()>,
    pub(crate) registry: &'static Registry,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("task", &self.task)
            .finish_non_exhaustive()
    }
}

/// A 16-byte random ID, hex.
#[must_use]
pub fn random_id() -> String {
    let mut b = [0u8; 16];
    thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// 32 random bytes.
#[must_use]
pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    thread_rng().fill_bytes(&mut b);
    b
}

fn new_attest_keys() -> AttestKeys {
    let dpop = loop {
        let k = random32();
        if bnap_scheme_dpop::client::ProofKey::es256(&k).is_some() {
            break k;
        }
    };
    AttestKeys {
        wba: random32(),
        dpop,
        agent: None,
    }
}

/// What `bnap budget` shows.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetView {
    /// The caps a person set.
    pub hard: Caps,
    /// The caps a session narrowed.
    pub session: SessionCaps,
    /// The caps in force.
    pub effective: Caps,
    /// What they leave for the origin asked about (or any origin).
    pub remaining: Remaining,
    /// The task.
    pub task: String,
    /// Spent in the last 24 hours, every origin.
    pub spent_24h: u64,
    /// The rest of the policy.
    pub policy: PolicyView,
    /// Notes held, by origin.
    pub balances: BTreeMap<String, u64>,
}

/// The policy as shown.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyView {
    /// Allowed value schemes.
    pub allowed_schemes: Vec<String>,
    /// Required properties.
    pub require: BTreeMap<String, String>,
    /// Linkability.
    pub linkable: &'static str,
    /// Linkability penalty, sat.
    pub linkable_penalty_sat: u64,
    /// Experimental schemes allowed.
    pub allow_experimental: bool,
    /// Attestations sent.
    pub attest: Vec<String>,
    /// Notes per origin, at most.
    pub max_balance_per_origin: u64,
    /// Routing fee ceiling.
    pub fee: policy::FeePolicy,
    /// The pay source, secrets hidden.
    pub pay_source: String,
}

/// A receipt as listed.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptSummary {
    /// ID.
    pub id: String,
    /// BNAP or native.
    pub kind: ReceiptKind,
    /// Origin.
    pub origin: String,
    /// Method and URL.
    pub request: String,
    /// Scheme.
    pub scheme: Option<String>,
    /// When.
    pub at: u64,
    /// What it cost, sat.
    pub cost_sat: u64,
    /// What the server charged.
    pub charged: u64,
    /// Its unit.
    pub unit: Option<String>,
    /// OK or FAILED.
    pub ok: bool,
}

impl From<&ReceiptRecord> for ReceiptSummary {
    fn from(r: &ReceiptRecord) -> Self {
        Self {
            id: r.id.clone(),
            kind: r.kind,
            origin: r.origin.clone(),
            request: format!("{} {}", r.method, r.url),
            scheme: r.scheme.clone(),
            at: r.at,
            cost_sat: r.cost_sat,
            charged: r.charged,
            unit: r.unit.clone(),
            ok: r.ok,
        }
    }
}

impl Wallet {
    fn from_store(store: Store, opts: &Options) -> Self {
        Self {
            store,
            transport: opts.transport.clone(),
            pay_override: opts.pay_source.clone(),
            clock: opts.clock.clone(),
            task: opts.task.clone(),
            session: Mutex::new(SessionCaps::default()),
            pin_lock: tokio::sync::Mutex::new(()),
            registry: Registry::embedded(),
        }
    }

    /// Creates a wallet with a new seed. Returns the mnemonic, to be shown
    /// once and never stored anywhere else.
    pub async fn create(
        path: &Path,
        passphrase: &str,
        opts: &Options,
    ) -> Result<(Self, Zeroizing<String>)> {
        let mut entropy = Zeroizing::new([0u8; 16]);
        thread_rng().fill_bytes(&mut *entropy);
        let m = bip39::Mnemonic::from_entropy(&*entropy)
            .map_err(|e| Refusal::storage(format!("cannot make a seed: {e}")))?;
        let words = Zeroizing::new(m.to_string());
        let w = Self::create_from_mnemonic(path, passphrase, &words, opts).await?;
        Ok((w, words))
    }

    /// Creates a wallet from an existing mnemonic (`bnap restore`).
    pub async fn create_from_mnemonic(
        path: &Path,
        passphrase: &str,
        mnemonic: &str,
        opts: &Options,
    ) -> Result<Self> {
        let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
            .map_err(|_| Refusal::bad_input("The mnemonic is not a valid BIP-39 phrase."))?;
        let store = Store::create(path, passphrase, opts.kdf).await?;
        let w = Self::from_store(store, opts);
        let now = (w.clock)();
        let mut tx = w.store.tx().await?;
        tx.put(
            kind::SECRET,
            "main",
            &Secret {
                mnemonic: m.to_string(),
            },
        )
        .await?;
        tx.put(kind::ATTEST_KEYS, "main", &new_attest_keys())
            .await?;
        tx.put(
            kind::CONFIG,
            "main",
            &Config {
                policy: Policy::default(),
                pay_source: PaySourceConfig::None,
                slot: 0,
                created: now,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(w)
    }

    /// Opens a wallet.
    pub async fn open(path: &Path, passphrase: &str, opts: &Options) -> Result<Self> {
        let store = Store::open(path, passphrase).await?;
        Ok(Self::from_store(store, opts))
    }

    /// The task payments count against.
    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }

    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The 64-byte BIP-39 seed.
    pub(crate) async fn seed(&self) -> Result<Zeroizing<[u8; 64]>> {
        let s: Secret = self
            .store
            .get(kind::SECRET, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no seed"))?;
        let m = bip39::Mnemonic::parse_normalized(&s.mnemonic)
            .map_err(|_| Refusal::storage("the stored seed does not parse"))?;
        Ok(Zeroizing::new(m.to_seed("")))
    }

    pub(crate) async fn attest_keys(&self) -> Result<AttestKeys> {
        self.store
            .get(kind::ATTEST_KEYS, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no attestation keys"))
    }

    /// The configuration.
    pub async fn config(&self) -> Result<Config> {
        self.store
            .get(kind::CONFIG, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no configuration"))
    }

    /// Changes the policy. For a person only: the MCP server never calls
    /// it.
    pub async fn set_policy(&self, f: impl FnOnce(&mut Policy) -> Result<()>) -> Result<Policy> {
        let mut tx = self.store.tx().await?;
        let mut c: Config = tx
            .get(kind::CONFIG, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no configuration"))?;
        f(&mut c.policy)?;
        tx.put(kind::CONFIG, "main", &c).await?;
        tx.commit().await?;
        Ok(c.policy)
    }

    /// Sets the pay source.
    pub async fn set_pay_source(&self, p: PaySourceConfig) -> Result<()> {
        let mut tx = self.store.tx().await?;
        let mut c: Config = tx
            .get(kind::CONFIG, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no configuration"))?;
        c.pay_source = p;
        tx.put(kind::CONFIG, "main", &c).await?;
        tx.commit().await
    }

    /// Sets this device's counter slot.
    pub async fn set_slot(&self, slot: u16) -> Result<()> {
        let mut tx = self.store.tx().await?;
        let mut c: Config = tx
            .get(kind::CONFIG, "main")
            .await?
            .ok_or_else(|| Refusal::storage("the wallet has no configuration"))?;
        c.slot = slot;
        tx.put(kind::CONFIG, "main", &c).await?;
        tx.commit().await
    }

    /// Sets the Signature-Agent URL named in Web Bot Auth signatures.
    pub async fn set_agent(&self, agent: Option<String>) -> Result<()> {
        let mut k = self.attest_keys().await?;
        k.agent = agent;
        self.store.put(kind::ATTEST_KEYS, "main", &k).await
    }

    /// The public Web Bot Auth key and the `DPoP` key's thumbprint, to
    /// register with an operator.
    pub async fn attest_public(&self) -> Result<(String, String)> {
        let k = self.attest_keys().await?;
        let wba = ed25519_dalek::SigningKey::from_bytes(&k.wba)
            .verifying_key()
            .to_bytes();
        let dpop = bnap_scheme_dpop::client::ProofKey::es256(&k.dpop)
            .ok_or_else(|| Refusal::storage("the DPoP key is not valid"))?
            .thumbprint()
            .to_b64u();
        Ok((hex::encode(wba), dpop))
    }

    pub(crate) fn pay_source(&self, cfg: &Config) -> Option<Arc<dyn PaySource>> {
        self.pay_override
            .clone()
            .or_else(|| cfg.pay_source.build().map(Arc::from))
    }

    /// The session's caps.
    #[must_use]
    pub fn session_caps(&self) -> SessionCaps {
        *self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Narrows a cap for this session (what the MCP `budget` tool sets).
    /// Refuses a value above the cap a person set.
    pub async fn set_session_cap(&self, cap: CapKind, sat: u64) -> Result<SessionCaps> {
        let hard = self.config().await?.policy.caps;
        let mut s = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        s.set(&hard, cap, sat)?;
        Ok(*s)
    }

    pub(crate) fn caps(&self, cfg: &Config) -> Caps {
        self.session_caps().effective(&cfg.policy.caps)
    }

    /// The ledger.
    pub async fn ledger(&self) -> Result<Vec<LedgerEntry>> {
        let mut l: Vec<LedgerEntry> = self.store.list(kind::LEDGER).await?;
        l.sort_by_key(|e| e.at);
        Ok(l)
    }

    /// Notes held, unspent, by origin.
    pub async fn balances(&self) -> Result<BTreeMap<String, u64>> {
        let notes: Vec<NoteRecord> = self.store.list(kind::NOTE).await?;
        let mut out = BTreeMap::new();
        for n in notes.iter().filter(|n| n.state == NoteState::Unspent) {
            *out.entry(n.origin.clone()).or_insert(0u64) += n.amount;
        }
        Ok(out)
    }

    /// What `bnap budget` and the MCP `budget` tool show.
    pub async fn budget(&self, origin: Option<&str>) -> Result<BudgetView> {
        let cfg = self.config().await?;
        let effective = self.caps(&cfg);
        let ledger = self.ledger().await?;
        let now = self.now();
        let remaining =
            policy::remaining(&effective, &ledger, origin.unwrap_or(""), &self.task, now);
        let since = now.saturating_sub(policy::DAY);
        let spent_24h = ledger
            .iter()
            .filter(|e| e.at > since)
            .map(LedgerEntry::counted)
            .sum();
        let p = &cfg.policy;
        Ok(BudgetView {
            hard: p.caps,
            session: self.session_caps(),
            effective,
            remaining,
            task: self.task.clone(),
            spent_24h,
            policy: PolicyView {
                allowed_schemes: p.allowed_schemes.clone(),
                require: p.require.clone(),
                linkable: p.linkable.as_str(),
                linkable_penalty_sat: p.linkable_penalty_sat,
                allow_experimental: p.allow_experimental,
                attest: p.attest.clone(),
                max_balance_per_origin: p.max_balance_per_origin,
                fee: p.fee,
                pay_source: cfg.pay_source.describe(),
            },
            balances: self.balances().await?,
        })
    }

    /// The pin for `origin`.
    pub async fn pin(&self, origin: &str) -> Result<Option<PinRecord>> {
        self.store.get(kind::PIN, origin).await
    }

    /// The live pin for `origin`, fetching the manifest when there is none
    /// or `refetch` is set (9.3): HTTPS only, at most once per five
    /// minutes. A manifest that fails the checks leaves the old pin in
    /// place until it lapses.
    pub(crate) async fn ensure_pin(
        &self,
        origin: &str,
        refetch: bool,
    ) -> Result<Option<PinRecord>> {
        let now = self.now();
        let stored: Option<PinRecord> = self.store.get(kind::PIN, origin).await?;
        let live = stored.clone().filter(|p| p.until >= now);
        if live.is_some() && !refetch {
            return Ok(live);
        }
        // One fetch at a time: a request that waited here reads the pin the
        // other one wrote.
        let _guard = self.pin_lock.lock().await;
        let seen = stored.as_ref().map(|p| p.seq);
        let stored: Option<PinRecord> = self.store.get(kind::PIN, origin).await?;
        let live = stored.clone().filter(|p| p.until >= now);
        if live.is_some() && (!refetch || live.as_ref().map(|p| p.seq) != seen) {
            return Ok(live);
        }
        if !origin.starts_with("https://") {
            return Ok(live);
        }
        let mut tx = self.store.tx().await?;
        let last: Option<FetchLog> = tx.get(kind::FETCH, origin).await?;
        if last.is_some_and(|l| now < l.at.saturating_add(MANIFEST_INTERVAL)) {
            tx.commit().await?;
            return Ok(live);
        }
        tx.put(kind::FETCH, origin, &FetchLog { at: now }).await?;
        tx.commit().await?;
        let req = HttpRequest::new("GET", format!("{origin}/.well-known/bnap"))
            .header("accept", "application/json");
        let Ok(resp) = self.transport.send(req).await else {
            return Ok(live);
        };
        if resp.status != 200 || resp.body.len() > MAX_MANIFEST {
            return Ok(live);
        }
        let old = stored.as_ref().map(PinRecord::pin);
        match manifest::accept(old.as_ref(), origin, &resp.body, now) {
            Ok((pin, _)) => {
                let rec = PinRecord::new(origin, &pin, &resp.body, now);
                self.store.put(kind::PIN, origin, &rec).await?;
                Ok(Some(rec))
            }
            Err(_) => Ok(live),
        }
    }

    /// Every receipt, oldest first.
    pub async fn receipts(&self) -> Result<Vec<ReceiptRecord>> {
        let mut r: Vec<ReceiptRecord> = self.store.list(kind::RECEIPT).await?;
        r.sort_by(|a, b| (a.at, &a.id).cmp(&(b.at, &b.id)));
        Ok(r)
    }

    /// One receipt.
    pub async fn receipt(&self, id: &str) -> Result<ReceiptRecord> {
        self.store
            .get(kind::RECEIPT, id)
            .await?
            .ok_or_else(|| Refusal::new(Code::NotFound, format!("No receipt {id}.")))
    }
}

/// Checks a stored receipt on its own, as a third party would: the
/// manifest is signed by its root and covers the origin, it lists the
/// receipt key for use `receipt` at the settlement time, the ack verifies,
/// and the Response answers the stored credential for the stored request.
/// A native receipt is checked by its preimage opening the invoice.
pub fn verify_receipt(r: &ReceiptRecord) -> std::result::Result<(), String> {
    match r.kind {
        ReceiptKind::Native => {
            let (Some(inv), Some(pre)) = (&r.invoice, &r.preimage) else {
                return Err("no invoice or preimage kept".into());
            };
            let inv = Invoice::decode(inv)?;
            if sha256(pre) == inv.payment_hash {
                Ok(())
            } else {
                Err("the preimage does not open the invoice".into())
            }
        }
        ReceiptKind::Bnap => {
            let sm = SignedManifest::parse(&r.manifest).map_err(|e| format!("manifest: {e}"))?;
            sm.verify().map_err(|e| format!("manifest: {e}"))?;
            if sm.manifest().origin != r.origin {
                return Err("the manifest is for another origin".into());
            }
            let resp = Response::parse(&r.response).map_err(|e| format!("response: {e}"))?;
            resp.verify_ack().map_err(|e| format!("response: {e}"))?;
            let f = resp.fields();
            let listed = sm.manifest().keys.iter().any(|k| {
                k.kid == f.receipt_key
                    && k.key_use == KeyUse::Receipt
                    && k.not_after >= f.settled_at
            });
            if !listed {
                return Err("the manifest does not list the receipt key".into());
            }
            let offer = Offer::parse(&r.offer).map_err(|e| format!("offer: {e}"))?;
            let cred = Credential::parse(&r.credential).map_err(|e| format!("credential: {e}"))?;
            let ctx = cred.context(&offer.offer_id(), &Scope(r.action_scope));
            if !resp.answers(&offer.offer_id(), &cred.digest(&ctx)) {
                return Err("the response answers another request".into());
            }
            Ok(())
        }
    }
}
