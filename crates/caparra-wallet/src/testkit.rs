//! A small BNAP server for tests, built from bnap-core directly (the HTTP
//! carrier crate is not built yet): a signed manifest, route-scope and
//! exact-scope offers with L402 and MPP natives, funding inside the 402,
//! the notes issuer's NUT endpoints, and the gate flow of
//! `notes/n3-core.md` on bnap-core's `process` over the in-memory use
//! store. A Lightning rail issues real regtest BOLT 11 invoices and a pay
//! source pays them. Never a gate.
//!
//! [`TestTransport`] routes the wallet's requests to the server in
//! process, so every URL is `https://api.example/...` and no socket is
//! opened.

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    clippy::unused_self,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::redundant_closure,
    missing_docs
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitcoin::hashes::Hash as _;
use bnap_core::credential::{
    Credential, CredentialParse, SchemePart, native_context, native_digest,
};
use bnap_core::error::{ErrorCode, ErrorObject};
use bnap_core::hash::{Context, Digest, OfferId, Scope, sha256};
use bnap_core::ids::rail;
use bnap_core::limits::Limits;
use bnap_core::manifest::{KeyUse, Manifest, ManifestKey, ManifestLimits, Route, RouteScopeMode};
use bnap_core::offer::{GateOfferCheck, NativeEntry, Offer, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ReceiptInput, Recorded, Request};
use bnap_core::pricing::{PayValue, Refund};
use bnap_core::response::Status;
use bnap_core::schnorr::SigningKey;
use bnap_core::secp256k1::{Secp256k1, SecretKey};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{Settlement, UseModel};
use bnap_core::test_support::MemoryStore;
use bnap_core::{BindingClass, SettleError, http};
use bnap_plug::{
    CappedSigner, ChangeCap, Confirmed, CredentialScheme, Entry, FundingRail, NativeCtx, OfferCtx,
    OfferRole, PayId, PayRequest, PayState, RailError, RailRef, SettleCtx, Verified, VerifyCtx,
    confirm_rail_id,
};
use bnap_scheme_l402::{L402, MacaroonKeys, OfferInvoices};
use bnap_scheme_mpp::lightning::Network;
use bnap_scheme_mpp::{ChallengeKeys, LightningCharge};
use bnap_scheme_notes::test_support::{KeysetSigner, MemoryIssuerStore, keyset_a, keyset_b};
use bnap_scheme_notes::wire::Body;
use bnap_scheme_notes::{
    FundRequest, IssuerStore, MintEnv, NotesConfig, NotesScheme, SCHEME_ID as NOTES,
    admission_fields, rail_error,
};
use cashu::nuts::{
    BlindSignature, BlindSignatureDleq, CheckStateRequest, CurrencyUnit, Id, KeySet, KeySetInfo,
    MintRequest, PublicKey, RestoreRequest, SecretKey as CashuSecretKey,
};

use crate::error::{Code, Refusal};
use crate::invoice::Invoice;
use crate::paysource::{Paid, PaySource};
use crate::transport::{HttpRequest, HttpResponse, Transport};
use crate::wallet::Clock;

pub const ORIGIN: &str = "https://api.example";
pub const ISSUER: &str = "https://api.example/cashu";
/// The clock the test keysets were made for (bnap:notes 18.1).
pub const START: u64 = 1_791_700_000;
pub const EXACT_LIFETIME: u64 = 600;
pub const ROUTE_LIFETIME: u64 = 3_600;
pub const PRICE: u64 = 21;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A clock tests move by hand.
#[derive(Clone, Debug)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    #[must_use]
    pub fn new(t: u64) -> Self {
        Self(Arc::new(AtomicU64::new(t)))
    }
    #[must_use]
    pub fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, s: u64) {
        self.0.fetch_add(s, Ordering::SeqCst);
    }
    #[must_use]
    pub fn clock(&self) -> Clock {
        let c = self.clone();
        Arc::new(move || c.now())
    }
}

// ------------------------------------------------------------------ rail

#[derive(Debug, Clone)]
struct Inv {
    amount: u64,
    paid: bool,
    preimage: [u8; 32],
}

/// A Lightning rail with real regtest invoices whose description hash is
/// the memo it is given.
pub struct TestRail {
    invoices: Mutex<BTreeMap<[u8; 32], Inv>>,
    next: AtomicU64,
    node: SecretKey,
    clock: TestClock,
    pub down: AtomicBool,
}

impl TestRail {
    #[must_use]
    pub fn new(clock: TestClock) -> Self {
        Self {
            invoices: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
            node: SecretKey::from_slice(&sha256(b"caparra wallet test ln node")).unwrap(),
            clock,
            down: AtomicBool::new(false),
        }
    }

    fn invoice(&self, hash: [u8; 32], memo: [u8; 32], amount: u64, at: u64) -> String {
        use bitcoin::hashes::sha256 as h;
        use cashu::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
        let secp = Secp256k1::new();
        InvoiceBuilder::new(Currency::Regtest)
            .description_hash(h::Hash::from_byte_array(memo))
            .payment_hash(h::Hash::from_byte_array(hash))
            .payment_secret(PaymentSecret(sha256(&hash)))
            .amount_milli_satoshis(amount * 1000)
            .timestamp(UNIX_EPOCH + Duration::from_secs(at))
            .expiry_time(Duration::from_secs(EXACT_LIFETIME))
            .min_final_cltv_expiry_delta(144)
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &self.node))
            .unwrap()
            .to_string()
    }

    /// Pays an invoice by its hash, as a payer's node would.
    pub fn pay(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        let mut m = lock(&self.invoices);
        let inv = m.get_mut(hash)?;
        inv.paid = true;
        Some(inv.preimage)
    }

    /// How many invoices were paid.
    #[must_use]
    pub fn paid(&self) -> usize {
        lock(&self.invoices).values().filter(|i| i.paid).count()
    }

    fn up(&self) -> Result<(), RailError> {
        if self.down.load(Ordering::SeqCst) {
            Err(RailError::Unavailable("down".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl FundingRail for TestRail {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        self.up()?;
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let preimage = sha256(&[&memo[..], &n.to_be_bytes(), b"preimage"].concat());
        let hash = sha256(&preimage);
        let now = self.clock.now();
        lock(&self.invoices).insert(
            hash,
            Inv {
                amount,
                paid: false,
                preimage,
            },
        );
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.into(),
            request: self.invoice(hash, memo, amount, now),
            amount,
            unit: unit.into(),
            expires: now + EXACT_LIFETIME,
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        self.up()?;
        let hash: [u8; 32] =
            id.0.as_slice()
                .try_into()
                .map_err(|_| RailError::NotConfirmed("id".into()))?;
        match lock(&self.invoices).get(&hash) {
            Some(i) if i.paid => Ok(PayState::Paid),
            Some(_) => Ok(PayState::Pending),
            None => Err(RailError::NotConfirmed("unknown".into())),
        }
    }

    async fn confirm(&self, r: &RailRef) -> Result<Confirmed, RailError> {
        self.up()?;
        let hash: [u8; 32] = r
            .reference
            .as_slice()
            .try_into()
            .map_err(|_| RailError::NotConfirmed("not a payment hash".into()))?;
        let inv = lock(&self.invoices)
            .get(&hash)
            .cloned()
            .ok_or_else(|| RailError::NotConfirmed("unknown".into()))?;
        Ok(Confirmed {
            canonical: rail::ln(&hash),
            state: if inv.paid {
                PayState::Paid
            } else {
                PayState::Pending
            },
            amount: inv.amount,
            unit: "sat".into(),
        })
    }
}

/// A pay source that pays the test rail's invoices.
pub struct TestPay {
    rail: Arc<TestRail>,
    pub fee_sat: AtomicU64,
    pub fail: AtomicBool,
    pub payments: Mutex<Vec<u64>>,
}

impl TestPay {
    #[must_use]
    pub fn new(rail: Arc<TestRail>) -> Self {
        Self {
            rail,
            fee_sat: AtomicU64::new(1),
            fail: AtomicBool::new(false),
            payments: Mutex::new(Vec::new()),
        }
    }

    /// Sat paid, fees included.
    #[must_use]
    pub fn total(&self) -> u64 {
        lock(&self.payments).iter().sum()
    }
}

#[async_trait::async_trait]
impl PaySource for TestPay {
    async fn pay_invoice(
        &self,
        invoice: &str,
        amount_sat: u64,
        max_fee_sat: u64,
    ) -> crate::Result<Paid> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Refusal::new(
                Code::PaymentFailed,
                "The test pay source fails.",
            ));
        }
        let inv = Invoice::decode(invoice).map_err(|e| Refusal::new(Code::PaymentFailed, e))?;
        assert_eq!(
            inv.amount_sat(),
            Some(amount_sat),
            "paid what the wallet said"
        );
        let fee = self.fee_sat.load(Ordering::SeqCst);
        // A pay source may ignore the ceiling (NIP-47 has none).
        let _ = max_fee_sat;
        let preimage = self
            .rail
            .pay(&inv.payment_hash)
            .ok_or_else(|| Refusal::new(Code::PaymentFailed, "unknown invoice"))?;
        lock(&self.payments).push(amount_sat + fee);
        Ok(Paid {
            preimage,
            fee_sat: fee,
        })
    }
}

// ---------------------------------------------------------------- server

/// What the server does differently.
#[derive(Debug, Clone, Default)]
pub struct Knobs {
    /// Serve no manifest (404).
    pub no_manifest: bool,
    /// A tier-0 server: native L402 challenges only, no BNAP offer.
    pub native_only: bool,
    /// The action fails: settle FAILED.
    pub action_fails: bool,
    /// The gate dies right after the commit (answers UNAVAILABLE).
    pub crash_after_commit: bool,
    /// Flip a byte in every receipt.
    pub tamper_receipt: bool,
    /// Sign offers with this key instead of the manifest's offer key.
    pub rogue_offer_key: Option<[u8; 32]>,
    /// Leave BNAP offers out of 402s (a stripped header).
    pub strip_bnap: bool,
    /// Funding in the 402.
    pub max_fund: Option<u64>,
    /// Flip a bit of every offer's `offer_sig`.
    pub bad_offer_sig: bool,
}

struct Keys {
    root: SigningKey,
    backup: SigningKey,
    offer: SigningKey,
    receipt: SigningKey,
    seq: u64,
    issued: u64,
    required: bool,
    manifest: Vec<u8>,
}

fn key(label: &str, n: u64) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(format!("caparra test {label} {n}").as_bytes())).unwrap()
}

/// The test server.
pub struct TestServer {
    pub clock: TestClock,
    pub store: Arc<MemoryStore>,
    signer: Arc<KeysetSigner>,
    pub rail: Arc<TestRail>,
    notes: NotesScheme,
    l402: L402,
    mpp: LightningCharge,
    issuer: Arc<MemoryIssuerStore>,
    limits: Limits,
    mac: [u8; 32],
    keys: Mutex<Keys>,
    offers: Mutex<HashMap<OfferId, Offer>>,
    route_offers: Mutex<HashMap<String, Offer>>,
    spent: Mutex<BTreeSet<[u8; 33]>>,
    pub knobs: Mutex<Knobs>,
    /// Bytes to serve as the manifest instead of the published one.
    pub manifest_override: Mutex<Option<Vec<u8>>>,
    pub requests: Mutex<Vec<HttpRequest>>,
    /// Answer PENDING to this many credential requests first.
    pub pending: AtomicU32,
    nonce: AtomicU64,
    /// Paid actions that ran.
    pub actions: AtomicU64,
    rotations: AtomicU64,
}

fn routes() -> Vec<Route> {
    let r = |id: &str, m: &str, scope, pay: &[&str], price: u64| Route {
        id: id.into(),
        match_: m.into(),
        scope,
        metered: false,
        meter: None,
        price: [("sat".to_owned(), price)].into_iter().collect(),
        pay: pay.iter().map(|s| (*s).to_owned()).collect(),
        attest: Vec::new(),
        require: None,
        headers: Vec::new(),
    };
    vec![
        r(
            "chat",
            "POST /v1/chat",
            RouteScopeMode::Route,
            &[NOTES],
            PRICE,
        ),
        r(
            "paid",
            "GET /paid",
            RouteScopeMode::Exact,
            &[
                bnap_scheme_l402::SCHEME_ID,
                NOTES,
                bnap_scheme_mpp::SCHEME_ID,
            ],
            PRICE,
        ),
        r(
            "lightning",
            "GET /ln",
            RouteScopeMode::Exact,
            &[bnap_scheme_l402::SCHEME_ID, bnap_scheme_mpp::SCHEME_ID],
            PRICE,
        ),
        r(
            "big",
            "GET /big",
            RouteScopeMode::Exact,
            &[bnap_scheme_l402::SCHEME_ID, NOTES],
            5_000,
        ),
        r(
            "notes-swap",
            "POST /bnap/notes/swap",
            RouteScopeMode::Route,
            &[NOTES],
            0,
        ),
    ]
}

fn pending_error() -> ErrorObject {
    let mut e = ErrorObject::new(ErrorCode::Pending);
    e.retry_after = Some(1);
    e
}

fn registered(s: &str) -> Option<(BindingClass, Refund)> {
    match s {
        NOTES => Some((BindingClass::S, Refund::Atomic)),
        bnap_scheme_l402::SCHEME_ID | bnap_scheme_mpp::SCHEME_ID => {
            Some((BindingClass::O, Refund::None))
        }
        _ => None,
    }
}

fn resp(status: u16, headers: Vec<(String, String)>, body: impl Into<Vec<u8>>) -> HttpResponse {
    HttpResponse {
        status,
        headers,
        body: body.into(),
    }
}

impl TestServer {
    #[must_use]
    pub fn new(clock: TestClock) -> Arc<Self> {
        let rail = Arc::new(TestRail::new(clock.clone()));
        let keysets = vec![keyset_a(), keyset_b()];
        let issuer = Arc::new(MemoryIssuerStore::with_keysets(
            keysets.iter().map(|k| k.info().clone()),
        ));
        let signer = Arc::new(KeysetSigner::new(&[7; 32], &[8; 32], keysets));
        let mut config = NotesConfig::new(ISSUER);
        config.max_fund = Some(5_000);
        let notes = NotesScheme::new(config, issuer.clone(), Some(rail.clone()));
        let shared: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(rail.clone()));
        let l402 = L402::new(
            MacaroonKeys::new(sha256(b"test l402 secret")),
            shared.clone(),
        );
        let mpp = LightningCharge::new(
            ChallengeKeys::new(sha256(b"test mpp secret").to_vec()).unwrap(),
            "api.example",
            Network::Regtest,
            shared,
        )
        .unwrap();
        let s = Self {
            clock: clock.clone(),
            store: Arc::new(MemoryStore::new()),
            signer,
            rail,
            notes,
            l402,
            mpp,
            issuer,
            limits: Limits::default(),
            mac: sha256(b"test mac key"),
            keys: Mutex::new(Keys {
                root: key("root", 0),
                backup: key("backup", 0),
                offer: key("offer", 0),
                receipt: key("receipt", 0),
                seq: 1,
                issued: clock.now(),
                required: false,
                manifest: Vec::new(),
            }),
            offers: Mutex::new(HashMap::new()),
            route_offers: Mutex::new(HashMap::new()),
            spent: Mutex::new(BTreeSet::new()),
            knobs: Mutex::new(Knobs {
                max_fund: Some(5_000),
                ..Knobs::default()
            }),
            manifest_override: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            pending: AtomicU32::new(0),
            nonce: AtomicU64::new(1),
            actions: AtomicU64::new(0),
            rotations: AtomicU64::new(0),
        };
        s.publish();
        Arc::new(s)
    }

    fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Signs and serves the manifest from the current keys.
    fn publish(&self) {
        let mut k = lock(&self.keys);
        let m = self.manifest_of(&k);
        let signer = if m.root == k.root.public_key() {
            &k.root
        } else {
            &k.backup
        };
        k.manifest = m.sign(signer, &[0; 32]).unwrap();
    }

    fn manifest_of(&self, k: &Keys) -> Manifest {
        let not_after = k.issued + 30 * 86_400;
        Manifest {
            bnap: 1,
            origin: ORIGIN.into(),
            seq: k.seq,
            issued: k.issued,
            max_age: 7 * 86_400,
            root: k.root.public_key(),
            backup: k.backup.public_key(),
            keys: vec![
                ManifestKey {
                    kid: k.offer.public_key(),
                    key_use: KeyUse::Offer,
                    not_after,
                },
                ManifestKey {
                    kid: k.receipt.public_key(),
                    key_use: KeyUse::Receipt,
                    not_after,
                },
            ],
            required: k.required,
            limits: ManifestLimits::default(),
            carriers: vec!["http".into()],
            routes: routes(),
        }
    }

    /// The manifest bytes served now.
    #[must_use]
    pub fn manifest(&self) -> Vec<u8> {
        lock(&self.keys).manifest.clone()
    }

    /// A manifest signed by `signer` with `f` applied, without serving it.
    #[must_use]
    pub fn forge_manifest(&self, signer: &SigningKey, f: impl FnOnce(&mut Manifest)) -> Vec<u8> {
        let k = lock(&self.keys);
        let mut m = self.manifest_of(&k);
        f(&mut m);
        m.sign(signer, &[0; 32]).unwrap()
    }

    /// The root and backup signing keys.
    #[must_use]
    pub fn root_keys(&self) -> (SigningKey, SigningKey) {
        let k = lock(&self.keys);
        (k.root.clone(), k.backup.clone())
    }

    /// The current offer key.
    #[must_use]
    pub fn offer_key(&self) -> SigningKey {
        lock(&self.keys).offer.clone()
    }

    /// A new offer key, published under the same root with a higher `seq`.
    pub fn rotate_offer_key(&self) {
        let n = self.rotations.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut k = lock(&self.keys);
            k.offer = key("offer", n);
            k.seq += 1;
            k.issued = self.now();
        }
        lock(&self.route_offers).clear();
        self.publish();
    }

    /// Retires the root: the backup signs a manifest naming itself as root
    /// and a fresh backup, with a new offer key.
    pub fn rotate_root(&self) {
        let n = self.rotations.fetch_add(1, Ordering::SeqCst) + 1;
        {
            let mut k = lock(&self.keys);
            k.root = k.backup.clone();
            k.backup = key("backup", n);
            k.offer = key("offer", n);
            k.seq += 1;
            k.issued = self.now();
        }
        lock(&self.route_offers).clear();
        self.publish();
    }

    /// Sets `bnap-required` and publishes.
    pub fn set_required(&self, required: bool) {
        {
            let mut k = lock(&self.keys);
            k.required = required;
            k.seq += 1;
            k.issued = self.now();
        }
        self.publish();
    }

    /// Every request the server saw.
    #[must_use]
    pub fn seen(&self) -> Vec<HttpRequest> {
        lock(&self.requests).clone()
    }

    fn knobs(&self) -> Knobs {
        lock(&self.knobs).clone()
    }

    fn next_nonce(&self) -> [u8; 16] {
        let n = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&sha256(&n.to_be_bytes())[..8]);
        b[8..].copy_from_slice(&n.to_be_bytes());
        b
    }

    fn scheme(&self, id: &str) -> Option<&dyn CredentialScheme> {
        match id {
            NOTES => Some(&self.notes),
            bnap_scheme_l402::SCHEME_ID => Some(&self.l402),
            bnap_scheme_mpp::SCHEME_ID => Some(&self.mpp),
            _ => None,
        }
    }

    async fn make_offer(
        &self,
        route: &Route,
        scope: Scope,
        route_scope: bool,
        schemes: &[&str],
        fund: Option<&FundRequest>,
    ) -> Result<Offer, ErrorObject> {
        let now = self.now();
        let expires = now
            + if route_scope {
                ROUTE_LIFETIME
            } else {
                EXACT_LIFETIME
            };
        let (offer_pub, offer_sk) = {
            let k = lock(&self.keys);
            match self.knobs().rogue_offer_key {
                Some(r) => {
                    let sk = SigningKey::from_secret_bytes(&r).unwrap();
                    (sk.public_key(), sk)
                }
                None => (k.offer.public_key(), k.offer.clone()),
            }
        };
        let nonce = self.next_nonce();
        let mut f = OfferFields::new(scope, expires, offer_pub, nonce);
        f.route_scope = route_scope;
        f.info = Some(format!("{ORIGIN}/.well-known/bnap"));
        f.headers.clone_from(&route.headers);
        f.unknown = vec![(3_000_000_001, vec![0x0a, 0x0a])];
        let amount = route.price.get("sat").copied().unwrap_or(0);
        let unavailable = |_| ErrorObject::new(ErrorCode::Unavailable);
        for s in schemes {
            let scheme = self
                .scheme(s)
                .ok_or_else(|| ErrorObject::new(ErrorCode::NotOffered))?;
            let cx = OfferCtx {
                now,
                route_id: &route.id,
                scope: &scope,
                route_scope,
                metered: false,
                expires,
                role: OfferRole::Pay {
                    amount,
                    unit: "sat",
                },
            };
            let params = match fund.filter(|_| *s == NOTES) {
                Some(req) => {
                    let q = self
                        .notes
                        .create_fund_quote(req, &route.id, &nonce, now)
                        .await
                        .map_err(|e| e.to_error_object())?
                        .ok_or_else(|| ErrorObject::new(ErrorCode::Unavailable))?;
                    self.notes
                        .offer_with_quote(&cx, &q)
                        .await
                        .map_err(|e| e.to_error_object())?
                }
                None => scheme.offer(&cx).await.map_err(|e| e.to_error_object())?,
            };
            let mut e = PayEntry::new(*s, amount, "sat");
            e.params = params.params;
            f.pay.push(e);
        }
        let offer_id = f
            .offer_id()
            .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))?;
        if !route_scope {
            for (i, entry) in f.pay.clone().iter().enumerate() {
                let scheme = self.scheme(&entry.scheme).unwrap();
                if let Some(n) = scheme
                    .native(&NativeCtx {
                        now,
                        offer_id: &offer_id,
                        entry,
                        pay_index: i,
                        expires,
                    })
                    .await
                    .map_err(|e| e.to_error_object())?
                {
                    f.native.push(NativeEntry::new(i as u64, n.kind, n.data));
                }
            }
        }
        let u = UnsignedOffer::new(&f, Some(&self.mac)).map_err(unavailable)?;
        let sig = u
            .message()
            .sign_with(&offer_sk, &[0; 32])
            .map_err(unavailable)?;
        let offer = u.finish(&sig).map_err(unavailable)?;
        if fund.is_none() {
            lock(&self.offers).insert(offer.offer_id(), offer.clone());
        }
        Ok(offer)
    }

    fn route_for(&self, method: &str, path: &str) -> Option<Route> {
        routes().into_iter().find(|r| r.matches(method, path))
    }

    fn action_scope(req: &HttpRequest, route: &Route) -> Scope {
        let url = url::Url::parse(&req.url).unwrap();
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let vals: Vec<(String, Vec<u8>)> = route
            .headers
            .iter()
            .map(|n| (n.clone(), req.field(n).unwrap_or_default().into_bytes()))
            .collect();
        let pairs: Vec<(&str, &[u8])> = vals
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        http::action_scope(
            &req.method,
            &http::target(ORIGIN, &target),
            &req.body,
            &pairs,
        )
    }

    /// The 402 for `route`: its offers, the natives of its exact offer, and
    /// `err` (REQUIRED for a request without a credential).
    async fn challenge(&self, req: &HttpRequest, route: &Route, err: ErrorObject) -> HttpResponse {
        let knobs = self.knobs();
        let now = self.now();
        let scope = Self::action_scope(req, route);
        let mut offers = Vec::new();
        let pay: Vec<&str> = route.pay.iter().map(String::as_str).collect();
        let class = |s: &&str| registered(s).is_some_and(|r| r.0.route_scope_allowed());
        let made: Result<(), ErrorObject> = async {
            if route.scope == RouteScopeMode::Route {
                let route_pay: Vec<&str> = pay.iter().copied().filter(class).collect();
                if !route_pay.is_empty() {
                    let cached = lock(&self.route_offers)
                        .get(&route.id)
                        .filter(|o| o.fields().expires > now + 600)
                        .cloned();
                    let o = match cached {
                        Some(o) => o,
                        None => {
                            let o = self
                                .make_offer(
                                    route,
                                    http::route_scope(ORIGIN, &route.id),
                                    true,
                                    &route_pay,
                                    None,
                                )
                                .await?;
                            lock(&self.route_offers).insert(route.id.clone(), o.clone());
                            o
                        }
                    };
                    offers.push(o);
                }
                let exact: Vec<&str> = pay.iter().copied().filter(|s| !class(s)).collect();
                if !exact.is_empty() {
                    offers.push(self.make_offer(route, scope, false, &exact, None).await?);
                }
            } else {
                offers.push(self.make_offer(route, scope, false, &pay, None).await?);
            }
            if knobs.max_fund.is_some()
                && pay.contains(&NOTES)
                && let Some(v) = req.field(crate::pay::FUND_FIELD)
                && let Ok(fr) = FundRequest::parse_header(&v)
            {
                offers.push(
                    self.make_offer(route, scope, false, &[NOTES], Some(&fr))
                        .await?,
                );
            }
            Ok(())
        }
        .await;
        if let Err(e) = made {
            return self.error(&e);
        }
        let mut headers = Vec::new();
        if !knobs.strip_bnap {
            for o in &offers {
                let mut b = o.bytes().to_vec();
                if knobs.bad_offer_sig {
                    let sig = o.offer_sig().0;
                    if let Some(i) = b.windows(64).position(|w| w == sig) {
                        b[i] ^= 1;
                    }
                }
                headers.push((
                    "WWW-Authenticate".into(),
                    format!("BNAP offer=\"{}\"", URL_SAFE_NO_PAD.encode(b)),
                ));
            }
        }
        for o in &offers {
            for n in &o.fields().native {
                headers.push((
                    "WWW-Authenticate".into(),
                    String::from_utf8_lossy(&n.data).into_owned(),
                ));
            }
        }
        headers.push((
            crate::pay::ERROR_FIELD.into(),
            URL_SAFE_NO_PAD.encode(err.to_bytes().unwrap_or_default()),
        ));
        headers.push(("Cache-Control".into(), "no-store".into()));
        resp(402, headers, Vec::new())
    }

    fn error(&self, e: &ErrorObject) -> HttpResponse {
        let status = e.socket_code().map_or(503, ErrorCode::http_status);
        resp(
            status,
            vec![(
                crate::pay::ERROR_FIELD.into(),
                URL_SAFE_NO_PAD.encode(e.to_bytes().unwrap_or_default()),
            )],
            Vec::new(),
        )
    }

    /// Handles one request.
    pub async fn handle(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        lock(&self.requests).push(req.clone());
        let url = url::Url::parse(&req.url).map_err(|e| e.to_string())?;
        if url.origin().ascii_serialization() != ORIGIN {
            return Err(format!(
                "no route to {}",
                url.origin().ascii_serialization()
            ));
        }
        let knobs = self.knobs();
        let path = url.path().to_owned();
        if req.method == "GET" && path == "/.well-known/bnap" {
            if knobs.no_manifest || knobs.native_only {
                return Ok(resp(404, Vec::new(), Vec::new()));
            }
            let body = lock(&self.manifest_override)
                .clone()
                .unwrap_or_else(|| self.manifest());
            return Ok(resp(
                200,
                vec![("content-type".into(), "application/json".into())],
                body,
            ));
        }
        if req.method == "GET" && path == "/free" {
            return Ok(resp(200, Vec::new(), "free"));
        }
        if let Some(rest) = path.strip_prefix("/cashu") {
            return Ok(self.issuer_endpoint(&req, rest).await);
        }
        let Some(route) = self.route_for(&req.method, &path) else {
            return Ok(resp(404, Vec::new(), Vec::new()));
        };
        if knobs.native_only {
            return Ok(self.native(&req, &route).await);
        }
        if let Some(c) = req.field(crate::pay::CREDENTIAL_FIELD) {
            return Ok(self.paid(&req, &route, &c).await);
        }
        Ok(self
            .challenge(&req, &route, ErrorObject::new(ErrorCode::Required))
            .await)
    }

    async fn native(&self, req: &HttpRequest, route: &Route) -> HttpResponse {
        let Some(auth) = req.field("authorization") else {
            let scope = Self::action_scope(req, route);
            let o = match self
                .make_offer(route, scope, false, &[bnap_scheme_l402::SCHEME_ID], None)
                .await
            {
                Ok(o) => o,
                Err(e) => return self.error(&e),
            };
            let headers = o
                .fields()
                .native
                .iter()
                .map(|n| {
                    (
                        "WWW-Authenticate".to_owned(),
                        String::from_utf8_lossy(&n.data).into_owned(),
                    )
                })
                .collect();
            return resp(402, headers, Vec::new());
        };
        let Some(token) = bnap_scheme_l402::credential_from_authorization(&auth) else {
            return self.error(&ErrorObject::new(ErrorCode::Malformed));
        };
        let now = self.now();
        let rec = match self.l402.recover_native(token.as_bytes(), now).await {
            Ok(r) => r,
            Err(e) => return self.error(&e.to_error_object()),
        };
        let Some(offer) = lock(&self.offers).get(&rec.offer_id).cloned() else {
            return self.error(&ErrorObject::new(ErrorCode::BadOffer));
        };
        let scope = Self::action_scope(req, route);
        let check = self.check(scope, None);
        if let Err(e) = check.check_native(&offer, bnap_scheme_l402::SCHEME_ID) {
            return self.error(&ErrorObject::from(&e));
        }
        let ctx = native_context(&offer.offer_id(), &scope, bnap_scheme_l402::SCHEME_ID);
        let digest = native_digest(&ctx, token.as_bytes());
        self.run(req, &offer, scope, ctx, digest, Some(&rec.part))
            .await
    }

    fn take_pending(&self) -> bool {
        let mut cur = self.pending.load(Ordering::SeqCst);
        while cur > 0 {
            match self
                .pending
                .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(now) => cur = now,
            }
        }
        false
    }

    fn check(&self, action_scope: Scope, route_scope: Option<Scope>) -> GateOfferCheck<'_> {
        GateOfferCheck {
            now: self.now(),
            max_offer: self.limits.max_offer,
            mac_keys: std::slice::from_ref(&self.mac),
            offer_keys: &[],
            action_scope,
            route_scope,
        }
    }

    async fn paid(&self, req: &HttpRequest, route: &Route, b64: &str) -> HttpResponse {
        let Some(bytes) = URL_SAFE_NO_PAD.decode(b64.trim()).ok() else {
            return self.error(&ErrorObject::new(ErrorCode::Malformed));
        };
        let cred = match Credential::parse_with(
            &bytes,
            &CredentialParse {
                max_credential: http::HTTP_MAX_CREDENTIAL,
                known_ext_types: &[],
            },
        ) {
            Ok(c) => c,
            Err(e) => return self.error(&ErrorObject::from(&e)),
        };
        let scope = Self::action_scope(req, route);
        let route_scope =
            (route.scope == RouteScopeMode::Route).then(|| http::route_scope(ORIGIN, &route.id));
        let offers = lock(&self.offers).clone();
        let offer = match self
            .check(scope, route_scope)
            .check_credential(&cred, |id| offers.get(id).cloned())
        {
            Ok(o) => o,
            Err(e) => {
                let eo = ErrorObject::from(&e);
                if e.code().sends_fresh_offer() {
                    return self.challenge(req, route, eo).await;
                }
                return self.error(&eo);
            }
        };
        if let Err(e) = cred
            .check_binding_classes(|s| registered(s).map(|r| r.0))
            .and_then(|()| cred.check_tls_binding(None))
        {
            return self.error(&ErrorObject::from(&e));
        }
        if self.take_pending() {
            return self.error(&pending_error());
        }
        let ctx = cred.context(&offer.offer_id(), &scope);
        let digest = cred.digest(&ctx);
        self.run(req, &offer, scope, ctx, digest, cred.pay.as_ref())
            .await
    }

    async fn run(
        &self,
        req: &HttpRequest,
        offer: &Offer,
        scope: Scope,
        ctx: Context,
        digest: Digest,
        part: Option<&SchemePart>,
    ) -> HttpResponse {
        match self.run_inner(offer, scope, ctx, digest, part).await {
            Ok((status, receipt)) => {
                let mut bytes = receipt;
                if self.knobs().tamper_receipt {
                    let i = bytes.len() / 2;
                    bytes[i] ^= 1;
                }
                let (code, body) = if status == Status::Ok {
                    (200, format!("paid content for {}", req.url))
                } else {
                    (500, "the action failed".to_owned())
                };
                resp(
                    code,
                    vec![
                        (
                            crate::pay::RECEIPT_FIELD.into(),
                            URL_SAFE_NO_PAD.encode(bytes),
                        ),
                        ("Cache-Control".into(), "private, no-store".into()),
                    ],
                    body,
                )
            }
            Err(e) => self.error(&e),
        }
    }

    async fn run_inner(
        &self,
        offer: &Offer,
        scope: Scope,
        ctx: Context,
        digest: Digest,
        part: Option<&SchemePart>,
    ) -> Result<(Status, Vec<u8>), ErrorObject> {
        let now = self.now();
        let knobs = self.knobs();
        let part = part.ok_or_else(|| ErrorObject::new(ErrorCode::Underpaid))?;
        let id = part.scheme.as_str();
        let scheme = self
            .scheme(id)
            .ok_or_else(|| ErrorObject::new(ErrorCode::NotOffered))?;
        let (_, refund) = registered(id).ok_or_else(|| ErrorObject::new(ErrorCode::NotOffered))?;
        let (_, entry) = offer
            .fields()
            .pay_entry(id)
            .ok_or_else(|| ErrorObject::new(ErrorCode::NotOffered))?;
        let view = CappedSigner::verify_only(self.signer.clone(), &entry.unit);
        let verified: Verified = scheme
            .verify(
                part,
                &VerifyCtx {
                    now,
                    offer,
                    entry: Entry::Pay(entry),
                    action_scope: &scope,
                    context: &ctx,
                    digest: &digest,
                    signer: &view,
                },
            )
            .await
            .map_err(|e| e.to_error_object())?;
        let mut payments = Vec::new();
        for r in &verified.rail_ids {
            let p = confirm_rail_id(&*self.rail, r)
                .await
                .map_err(|e| rail_error(&e).to_error_object())?;
            payments.push(p);
        }
        let rail_ids: Vec<_> = payments.iter().map(|p| p.rail_id).collect();
        let mut backing: Vec<_> = payments
            .iter()
            .map(bnap_plug::RailPayment::backing)
            .collect();
        backing.extend(view.notes());
        let fields = if id == NOTES {
            admission_fields(offer.fields(), self.limits.pending_timeout)
        } else {
            offer.fields().clone()
        };
        let schemes = [verified.uses(id, UseModel::Single)];
        let store: &dyn bnap_core::store::UseStore = &*self.store;
        let admitted = outcome::process(
            store,
            &Request {
                offer: &fields,
                context: &ctx,
                pay_body: &part.body,
                attest_bodies: &[],
                schemes: &schemes,
                rail_ids: &rail_ids,
                pay: Some(PayValue {
                    scheme: id,
                    claimed: verified.value,
                    backing,
                    refund,
                }),
                attest: &[],
                now,
            },
            &self.limits,
        )
        .await
        .map_err(|e| e.to_error_object())?;
        let receipt_key = lock(&self.keys).receipt.clone();
        let input = ReceiptInput {
            offer_id: offer.offer_id(),
            digest,
            unit: Some("sat".into()),
            metered: false,
            receipt_key: receipt_key.public_key(),
        };
        let settle_with = |cap: ChangeCap, charged: u64| {
            let (capped, guard) =
                CappedSigner::for_change(self.signer.clone(), self.store.clone(), &cap);
            let verified = verified.clone();
            async move {
                let r = scheme
                    .settle(
                        part,
                        &verified,
                        &SettleCtx {
                            now,
                            status: cap.status(),
                            charged,
                            entry,
                            context: &ctx,
                            digest: &digest,
                        },
                        &capped,
                    )
                    .await;
                guard.close();
                r.map_err(|e| e.to_error_object())
            }
        };
        let refund_of = |r: Recorded| async move {
            let cap = r.refund_cap().unwrap();
            let result = settle_with(cap, 0).await?;
            outcome::record_refund(store, &r, result.as_deref())
                .await
                .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))
        };
        let recorded = match admitted {
            Admitted::Replay(r) if r.needs_refund() => refund_of(r).await?,
            Admitted::Replay(r) => r,
            Admitted::New(pending) => {
                if id == NOTES
                    && let Ok(body) = Body::parse(&part.body)
                {
                    let mut s = lock(&self.spent);
                    for i in &body.inputs {
                        if let Some(y) = bnap_core::note::hash_to_curve(i.secret().as_bytes()) {
                            s.insert(y);
                        }
                    }
                }
                if knobs.crash_after_commit {
                    return Err(ErrorObject::new(ErrorCode::Unavailable));
                }
                self.actions.fetch_add(1, Ordering::SeqCst);
                let status = if knobs.action_fails {
                    Status::Failed
                } else {
                    Status::Ok
                };
                let charge = pending.charge(status, 0);
                let result = settle_with(charge.cap().clone(), charge.charged()).await?;
                let s = Settlement::new(&charge, now).with_scheme_result(result);
                match outcome::settle(store, &pending, &s, &self.limits).await {
                    Ok(r) => r,
                    Err(SettleError::AlreadySettled(r)) if r.needs_refund() => {
                        refund_of(*r).await?
                    }
                    Err(SettleError::AlreadySettled(r)) => *r,
                    Err(_) => return Err(ErrorObject::new(ErrorCode::Unavailable)),
                }
            }
        };
        let status = recorded.record().status;
        let u = recorded
            .unsigned_receipt(&input)
            .ok_or_else(pending_error)?
            .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))?;
        let sig = u
            .message()
            .sign_with(&receipt_key, &[0; 32])
            .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))?;
        let r = u
            .finish(&sig)
            .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))?;
        let st = match status {
            bnap_core::store::OutcomeStatus::Failed => Status::Failed,
            _ => Status::Ok,
        };
        Ok((st, r.bytes().to_vec()))
    }

    // -------------------------------------------------------- the issuer

    async fn issuer_endpoint(&self, req: &HttpRequest, path: &str) -> HttpResponse {
        let json = |v: serde_json::Value| {
            resp(
                200,
                vec![("content-type".into(), "application/json".into())],
                v.to_string(),
            )
        };
        let bad = |m: String| resp(400, Vec::new(), m);
        let now = self.now();
        let keysets = match self.issuer.keysets().await {
            Ok(k) => k,
            Err(e) => return resp(503, Vec::new(), e.to_string()),
        };
        match (req.method.as_str(), path) {
            ("GET", "/v1/keysets") => {
                let infos: Vec<KeySetInfo> = keysets
                    .iter()
                    .map(|k| KeySetInfo {
                        id: Id::from_bytes(&k.id).unwrap(),
                        unit: CurrencyUnit::Sat,
                        active: k.state == bnap_scheme_notes::KeysetState::Active,
                        input_fee_ppk: k.input_fee_ppk,
                        final_expiry: Some(k.final_expiry),
                    })
                    .collect();
                json(serde_json::json!({ "keysets": infos }))
            }
            ("GET", p) if p.starts_with("/v1/keys/") => {
                let want = &p["/v1/keys/".len()..];
                let Some(k) = keysets.iter().find(|k| hex::encode(k.id) == want) else {
                    return resp(404, Vec::new(), Vec::new());
                };
                let ks = KeySet {
                    id: Id::from_bytes(&k.id).unwrap(),
                    unit: CurrencyUnit::Sat,
                    active: Some(k.state == bnap_scheme_notes::KeysetState::Active),
                    keys: k.cashu_keys().unwrap(),
                    input_fee_ppk: k.input_fee_ppk,
                    final_expiry: Some(k.final_expiry),
                };
                json(serde_json::json!({ "keysets": [ks] }))
            }
            ("POST", "/v1/mint/quote/bolt11") => {
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
                    return bad("json".into());
                };
                let amount = v["amount"].as_u64().unwrap_or(0);
                let Some(pk) = v["pubkey"]
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 33]>::try_from(b).ok())
                else {
                    return bad("pubkey".into());
                };
                let nonce = self.next_nonce();
                let q = match self
                    .notes
                    .create_fund_quote(&FundRequest { amount, pubkey: pk }, "fund", &nonce, now)
                    .await
                {
                    Ok(Some(q)) => q,
                    Ok(None) => return bad("no funding".into()),
                    Err(e) => return resp(503, Vec::new(), e.to_string()),
                };
                json(serde_json::json!({
                    "quote": q.quote, "request": q.request, "amount": q.amount, "unit": "sat",
                    "state": "UNPAID", "expiry": q.expiry, "pubkey": hex::encode(q.pubkey),
                }))
            }
            ("POST", "/v1/mint/bolt11") => {
                let Ok(m) = serde_json::from_slice::<MintRequest<String>>(&req.body) else {
                    return bad("json".into());
                };
                let env = MintEnv {
                    store: self.store.clone(),
                    signer: self.signer.clone(),
                    limits: &self.limits,
                    now,
                };
                match self.notes.mint(&env, &m).await {
                    Ok(sigs) => json(serde_json::json!({ "signatures": sigs })),
                    Err(e) => bad(e.to_string()),
                }
            }
            ("POST", "/v1/restore") => {
                // NUT-09 finds outputs by B' alone: a restoring wallet does
                // not know the amounts.
                let Ok(r) = serde_json::from_slice::<RestoreRequest>(&req.body) else {
                    return bad("json".into());
                };
                let blinded: Vec<[u8; 33]> = r
                    .outputs
                    .iter()
                    .map(|o| o.blinded_secret.to_bytes())
                    .collect();
                let Ok(records) = self.issuer.outputs_by_blinded(&blinded).await else {
                    return resp(503, Vec::new(), Vec::new());
                };
                let mut outs = Vec::new();
                let mut sigs = Vec::new();
                for o in &r.outputs {
                    let b = o.blinded_secret.to_bytes();
                    let Some(rec) = records.iter().find(|x| x.blinded == b) else {
                        continue;
                    };
                    let signed = rec.signature;
                    let mut echo = o.clone();
                    echo.amount = rec.amount.into();
                    echo.keyset_id = Id::from_bytes(&rec.keyset).unwrap();
                    outs.push(echo);
                    sigs.push(BlindSignature {
                        amount: rec.amount.into(),
                        keyset_id: Id::from_bytes(&rec.keyset).unwrap(),
                        c: PublicKey::from_slice(&signed.c).unwrap(),
                        dleq: Some(BlindSignatureDleq {
                            e: CashuSecretKey::from_slice(&signed.e).unwrap(),
                            s: CashuSecretKey::from_slice(&signed.s).unwrap(),
                        }),
                    });
                }
                json(serde_json::json!({ "outputs": outs, "signatures": sigs }))
            }
            ("POST", "/v1/checkstate") => {
                let Ok(r) = serde_json::from_slice::<CheckStateRequest>(&req.body) else {
                    return bad("json".into());
                };
                let spent = lock(&self.spent).clone();
                let states: Vec<serde_json::Value> =
                    r.ys.iter()
                        .map(|y| {
                            let s = if spent.contains(&y.to_bytes()) {
                                "SPENT"
                            } else {
                                "UNSPENT"
                            };
                            serde_json::json!({ "Y": y.to_hex(), "state": s, "witness": null })
                        })
                        .collect();
                json(serde_json::json!({ "states": states }))
            }
            _ => resp(404, Vec::new(), Vec::new()),
        }
    }
}

/// Routes the wallet's requests to a [`TestServer`] in process.
pub struct TestTransport {
    pub server: Arc<TestServer>,
}

#[async_trait::async_trait]
impl Transport for TestTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        if !req.url.starts_with("https://") {
            return Err("only https URLs are fetched".into());
        }
        self.server.handle(req).await
    }
}

/// A server, its clock, its pay source and a transport to it.
pub struct Kit {
    pub clock: TestClock,
    pub server: Arc<TestServer>,
    pub pay: Arc<TestPay>,
    pub transport: Arc<TestTransport>,
}

impl Kit {
    #[must_use]
    pub fn new() -> Self {
        let clock = TestClock::new(START);
        let server = TestServer::new(clock.clone());
        let pay = Arc::new(TestPay::new(server.rail.clone()));
        let transport = Arc::new(TestTransport {
            server: server.clone(),
        });
        Self {
            clock,
            server,
            pay,
            transport,
        }
    }

    /// Wallet options on this kit, for `task`.
    #[must_use]
    pub fn options(&self, task: &str) -> crate::wallet::Options {
        crate::wallet::Options {
            transport: self.transport.clone(),
            pay_source: Some(self.pay.clone()),
            clock: self.clock.clock(),
            task: task.into(),
            kdf: crate::store::KdfParams::insecure_for_tests(),
        }
    }
}

impl Default for Kit {
    fn default() -> Self {
        Self::new()
    }
}

/// A wallet on a kit, with the policy tests start from: experimental
/// schemes allowed (every value scheme in the registry is experimental).
pub async fn wallet(kit: &Kit, dir: &std::path::Path, task: &str) -> crate::wallet::Wallet {
    let (w, _) = crate::wallet::Wallet::create(
        &dir.join("wallet.db"),
        "test passphrase",
        &kit.options(task),
    )
    .await
    .unwrap();
    w.set_policy(|p| {
        p.allow_experimental = true;
        Ok(())
    })
    .await
    .unwrap();
    w
}
