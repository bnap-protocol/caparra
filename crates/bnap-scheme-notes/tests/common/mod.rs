//! A gate and a wallet for the integration tests: bnap-core's `process`
//! over the in-memory use store, the keyset-holding test signer, the
//! in-memory issuer tables, a fake Lightning rail that issues real regtest
//! BOLT11 invoices, and `NotesScheme` as the `bnap:notes` plug, run in the
//! order of `notes/n3-core.md`.

#![allow(
    dead_code,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::unused_self,
    clippy::many_single_char_names
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::error::ErrorObject;
use bnap_core::hash::{Context, Digest, OfferId, RailId, Scope, sha256};
use bnap_core::ids::rail;
use bnap_core::limits::Limits;
use bnap_core::offer::{AttestEntry, GateOfferCheck, Offer, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ReceiptInput, Recorded, Request, SettleError};
use bnap_core::pricing::{PayValue, Refund, VerifiedAttest};
use bnap_core::response::{Response, Status};
use bnap_core::secp256k1::{Secp256k1, SecretKey};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{SchemeUses, Settlement, UseModel, UseStore};
use bnap_core::test_support::{MemoryStore, block_on};
use bnap_core::{BindingClass, ErrorCode, http};
use bnap_plug::{
    CappedSigner, ChangeCap, Confirmed, CredentialScheme, Entry, FundingRail, OfferCtx, OfferRole,
    PayId, PayRequest, PayState, RailError, RailRef, SchemeError, SettleCtx, Signer, Verified,
    VerifyCtx, confirm_rail_id,
};
use bnap_scheme_notes::client::{self, Note, PendingOutput};
use bnap_scheme_notes::keyset::IssuerKeyset;
use bnap_scheme_notes::test_support::{KeysetSigner, MemoryIssuerStore, keyset_a, keyset_b};
use bnap_scheme_notes::wire::{FundQuote, KeysetIdBytes, Params};
use bnap_scheme_notes::{
    NotesConfig, NotesScheme, SCHEME_ID, admission_fields, funded, rail_error,
};

pub const NOW: u64 = 1_791_700_000;
pub const AUX0: [u8; 32] = [0; 32];
pub const ORIGIN: &str = "https://api.example";
pub const ISSUER: &str = "https://api.example/cashu";
pub const BODY: &[u8] =
    br#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;
/// The placeholder Web Bot Auth body of draft-00 section 14 (P37).
pub const WBA_BODY: &[u8] = b"sig1=:...placeholder web bot auth signature over the Context...:";
pub const WBA: &str = "httpsig:web-bot-auth";

pub fn offer_sk() -> [u8; 32] {
    sha256(b"bnap test offer key")
}

pub fn receipt_sk() -> [u8; 32] {
    sha256(b"bnap test receipt key")
}

pub fn mac_key() -> [u8; 32] {
    sha256(b"bnap test mac key")
}

pub fn act() -> Scope {
    http::action_scope(
        "POST",
        &http::target(ORIGIN, "/v1/chat/completions"),
        BODY,
        &[],
    )
}

pub fn route() -> Scope {
    http::route_scope(ORIGIN, "chat")
}

// ------------------------------------------------------------------ rail

#[derive(Debug, Clone)]
struct Invoice {
    amount: u64,
    paid: bool,
}

/// A Lightning rail that issues real regtest BOLT11 invoices (so clients
/// can check them, 8.3), knows which are paid, and can go down.
pub struct FakeLn {
    invoices: Mutex<BTreeMap<[u8; 32], Invoice>>,
    next: AtomicU64,
    down: AtomicBool,
    node: SecretKey,
    /// Reported amount override, for an under-paying rail.
    pub report: Mutex<Option<u64>>,
}

impl FakeLn {
    pub fn new() -> Self {
        Self {
            invoices: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(0),
            down: AtomicBool::new(false),
            node: SecretKey::from_slice(&sha256(b"bnap notes test ln node")).unwrap(),
            report: Mutex::new(None),
        }
    }

    pub fn pay(&self, hash: &[u8; 32]) {
        self.invoices.lock().unwrap().get_mut(hash).unwrap().paid = true;
    }

    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    fn up(&self) -> Result<(), RailError> {
        if self.down.load(Ordering::SeqCst) {
            Err(RailError::Unavailable("the node is down".into()))
        } else {
            Ok(())
        }
    }

    /// A deterministic regtest invoice for `amount` sat with this hash.
    pub fn invoice(&self, hash: [u8; 32], memo: [u8; 32], amount: u64, at: u64) -> String {
        use bitcoin::hashes::sha256 as h;
        use cashu::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
        let secp = Secp256k1::new();
        InvoiceBuilder::new(Currency::Regtest)
            .description_hash(h::Hash::from_byte_array(memo))
            .payment_hash(h::Hash::from_byte_array(hash))
            .payment_secret(PaymentSecret(sha256(&hash)))
            .amount_milli_satoshis(amount * 1000)
            .timestamp(UNIX_EPOCH + Duration::from_secs(at))
            .expiry_time(Duration::from_secs(600))
            .min_final_cltv_expiry_delta(144)
            .build_signed(|m| secp.sign_ecdsa_recoverable(m, &self.node))
            .unwrap()
            .to_string()
    }
}

#[async_trait::async_trait]
impl FundingRail for FakeLn {
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
        let preimage = sha256(&[&memo[..], &n.to_be_bytes()].concat());
        let hash = sha256(&preimage);
        self.invoices.lock().unwrap().insert(
            hash,
            Invoice {
                amount,
                paid: false,
            },
        );
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.into(),
            request: self.invoice(hash, memo, amount, NOW),
            amount,
            unit: unit.into(),
            expires: NOW + 600,
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        self.up()?;
        let hash: [u8; 32] =
            id.0.as_slice()
                .try_into()
                .map_err(|_| RailError::NotConfirmed("id".into()))?;
        match self.invoices.lock().unwrap().get(&hash) {
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
        let inv = self
            .invoices
            .lock()
            .unwrap()
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
            amount: self.report.lock().unwrap().unwrap_or(inv.amount),
            unit: "sat".into(),
        })
    }
}

// ------------------------------------------------------------------ gate

/// What a request runs into, besides the credential.
#[derive(Debug, Clone)]
pub struct Opts {
    pub now: u64,
    /// The action's result.
    pub status: Status,
    /// Meter units, for metered offers.
    pub units: u64,
    pub action_scope: Scope,
    /// The gate crashes right after the commit.
    pub crash_after_commit: bool,
    /// The action outlives `pending_timeout`: the sweep runs meanwhile.
    pub slow_action: bool,
    /// The action settles after `pending_timeout`, and no sweep ran.
    pub late_settle: bool,
    /// The route requires `link-payment = unlinkable`.
    pub unlinkable: bool,
    /// The TLS exporter of the connection.
    pub binding: Option<[u8; 32]>,
}

impl Opts {
    pub fn at(now: u64) -> Self {
        Self {
            now,
            status: Status::Ok,
            units: 0,
            action_scope: act(),
            crash_after_commit: false,
            slow_action: false,
            late_settle: false,
            unlinkable: false,
            binding: None,
        }
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self::at(NOW)
    }
}

/// A refusal: the 8.2 Error object's socket code and scheme code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: ErrorCode,
    pub scheme_code: Option<String>,
    pub retry_after: Option<u64>,
}

impl From<ErrorObject> for Refusal {
    fn from(e: ErrorObject) -> Self {
        Self {
            code: e.socket_code().expect("a socket code"),
            scheme_code: e.scheme_code,
            retry_after: e.retry_after,
        }
    }
}

pub fn code(e: &Refusal) -> (ErrorCode, Option<String>) {
    (e.code, e.scheme_code.clone())
}

pub fn notes_code(c: &str) -> (ErrorCode, Option<String>) {
    (ErrorCode::BadCredential, Some(format!("bnap:notes/{c}")))
}

pub struct Gate {
    pub store: Arc<MemoryStore>,
    pub signer: Arc<KeysetSigner>,
    pub issuer: Arc<MemoryIssuerStore>,
    pub rail: Arc<FakeLn>,
    pub scheme: NotesScheme,
    pub limits: Limits,
    offers: Mutex<BTreeMap<OfferId, Offer>>,
}

impl Gate {
    /// Keysets A (active) and B (inputs only), funding up to 5,000 sat.
    pub fn new() -> Self {
        Self::with_keysets(vec![keyset_a(), keyset_b()])
    }

    pub fn with_keysets(keysets: Vec<IssuerKeyset>) -> Self {
        let issuer = Arc::new(MemoryIssuerStore::with_keysets(
            keysets.iter().map(|k| k.info().clone()),
        ));
        let signer = Arc::new(KeysetSigner::new(&offer_sk(), &receipt_sk(), keysets));
        let rail = Arc::new(FakeLn::new());
        let mut config = NotesConfig::new(ISSUER);
        config.max_fund = Some(5000);
        config.unlinkable_routes.insert("private".into());
        let scheme = NotesScheme::new(config, issuer.clone(), Some(rail.clone()));
        Self {
            store: Arc::new(MemoryStore::new()),
            signer,
            issuer,
            rail,
            scheme,
            limits: Limits::default(),
            offers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The scheme's parameters for an offer.
    pub fn params(
        &self,
        expires: u64,
        route_scope: bool,
        amount: u64,
        quote: Option<&FundQuote>,
    ) -> Vec<u8> {
        let scope = if route_scope { route() } else { act() };
        let cx = OfferCtx {
            now: NOW,
            route_id: "chat",
            scope: &scope,
            route_scope,
            metered: false,
            expires,
            role: OfferRole::Pay {
                amount,
                unit: "sat",
            },
        };
        match quote {
            None => block_on(self.scheme.offer(&cx)).unwrap().params.unwrap(),
            Some(q) => block_on(self.scheme.offer_with_quote(&cx, q))
                .unwrap()
                .params
                .unwrap(),
        }
    }

    /// Signs and caches an offer.
    pub fn sign(&self, f: &OfferFields) -> Offer {
        let u = UnsignedOffer::new(f, Some(&mac_key())).unwrap();
        let sig = block_on(self.signer.schnorr(u.message())).unwrap();
        let offer = u.finish(&sig).unwrap();
        self.offers
            .lock()
            .unwrap()
            .insert(offer.offer_id(), offer.clone());
        offer
    }

    /// An exact-scope offer of `amount` sat for the chat action.
    pub fn exact_offer(&self, amount: u64, expires: u64) -> Offer {
        let mut f = OfferFields::new(
            act(),
            expires,
            self.signer.offer_key(),
            nonce(amount ^ expires),
        );
        let mut e = PayEntry::new(SCHEME_ID, amount, "sat");
        e.params = Some(self.params(expires, false, amount, None));
        f.pay = vec![e];
        self.sign(&f)
    }

    /// The route offer: metered, up to `amount` at `rate` per 1,000 units,
    /// a 20% Web Bot Auth discount.
    pub fn route_offer(&self, amount: u64, rate: u64, expires: u64) -> Offer {
        let n: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let mut f = OfferFields::new(route(), expires, self.signer.offer_key(), n);
        f.route_scope = true;
        f.metered = true;
        f.info = Some("https://api.example/.well-known/bnap".into());
        let mut e = PayEntry::new(SCHEME_ID, amount, "sat");
        e.rate = Some(rate);
        e.params = Some(self.params(expires, true, amount, None));
        f.pay = vec![e];
        f.attest = vec![AttestEntry::discount(WBA, 2000)];
        f.unknown = vec![(3_000_000_001, vec![0x0a, 0x0a])];
        self.sign(&f)
    }

    /// An exact-scope offer carrying a fund quote made for `pubkey`.
    pub fn funded_offer(&self, amount: u64, asked: u64, pubkey: [u8; 33]) -> (Offer, FundQuote) {
        let nonce = nonce(asked + 7);
        let q = block_on(self.scheme.create_fund_quote(
            &bnap_scheme_notes::FundRequest {
                amount: asked,
                pubkey,
            },
            "chat",
            &nonce,
            NOW,
        ))
        .unwrap()
        .unwrap();
        let expires = NOW + 900;
        let mut f = OfferFields::new(act(), expires, self.signer.offer_key(), nonce);
        let mut e = PayEntry::new(SCHEME_ID, amount, "sat");
        e.params = Some(self.params(expires, false, amount, Some(&q)));
        f.pay = vec![e];
        (self.sign(&f), q)
    }

    /// The gate's whole flow for one request.
    pub fn handle(&self, cred: &Credential, o: &Opts) -> Result<Response, Refusal> {
        self.handle_raw(cred, o).map_err(Refusal::from)
    }

    fn handle_raw(&self, cred: &Credential, o: &Opts) -> Result<Response, ErrorObject> {
        let check = GateOfferCheck {
            now: o.now,
            max_offer: bnap_core::limits::MAX_OFFER,
            mac_keys: &[mac_key()],
            offer_keys: &[],
            action_scope: o.action_scope,
            route_scope: Some(route()),
        };
        let offers = self.offers.lock().unwrap().clone();
        let offer = check
            .check_credential(cred, |id| offers.get(id).cloned())
            .map_err(|e| ErrorObject::from(&e))?;
        cred.check_tls_binding(o.binding.as_ref())
            .map_err(|e| ErrorObject::from(&e))?;
        let offer_id = offer.offer_id();
        let ctx = cred.context(&offer_id, &o.action_scope);
        let digest = cred.digest(&ctx);
        let part = cred.pay.as_ref().expect("a notes credential");
        let (_, entry) = offer.fields().pay_entry(SCHEME_ID).unwrap();
        let (verified, rail_ids, backing) = self.verify(&offer, entry, part, &ctx, &digest, o)?;
        // The Web Bot Auth stub of 18.2 item 3 (P37).
        let wba_ok = cred
            .attest
            .iter()
            .any(|a| a.scheme == WBA && a.body == WBA_BODY);
        let attest: Vec<VerifiedAttest> = if wba_ok {
            vec![VerifiedAttest::new(WBA, BindingClass::A)]
        } else {
            Vec::new()
        };
        let wba_id = vec![sha256(b"bot key thumbprint").to_vec()];
        let mut schemes = vec![verified.uses(SCHEME_ID, UseModel::Single)];
        if wba_ok {
            schemes.push(SchemeUses {
                scheme: WBA,
                model: UseModel::Reusable,
                local_ids: &wba_id,
            });
        }
        let attest_bodies: Vec<&[u8]> = cred.attest.iter().map(|a| a.body.as_slice()).collect();
        let fields = admission_fields(offer.fields(), self.limits.pending_timeout);
        let store: &dyn UseStore = &*self.store;
        let admitted = block_on(outcome::process(
            store,
            &Request {
                offer: &fields,
                context: &ctx,
                pay_body: &part.body,
                attest_bodies: &attest_bodies,
                schemes: &schemes,
                rail_ids: &rail_ids,
                pay: Some(PayValue {
                    scheme: SCHEME_ID,
                    claimed: verified.value,
                    backing,
                    refund: Refund::Atomic,
                }),
                attest: &attest,
                now: o.now,
            },
            &self.limits,
        ))
        .map_err(|e| e.to_error_object())?;
        let receipt_input = ReceiptInput {
            offer_id,
            digest,
            unit: Some("sat".into()),
            metered: offer.fields().metered,
            receipt_key: self.signer.receipt_key(),
        };
        let run_settle = |cap: &ChangeCap, charged: u64, now: u64| {
            let (capped, guard) =
                CappedSigner::for_change(self.signer.clone(), self.store.clone(), cap);
            let r = block_on(self.scheme.settle(
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
            ));
            guard.close();
            r.map_err(|e| e.to_error_object())
        };
        let refund = |r: &Recorded, now: u64| -> Result<Recorded, ErrorObject> {
            let cap = r.refund_cap().unwrap();
            let result = run_settle(&cap, 0, now)?;
            block_on(outcome::record_refund(store, r, result.as_deref()))
                .map_err(|_| ErrorObject::new(ErrorCode::Unavailable))
        };
        let answer = match admitted {
            Admitted::Replay(r) if r.needs_refund() => refund(&r, o.now)?,
            Admitted::Replay(r) => r,
            Admitted::New(pending) => {
                if o.crash_after_commit {
                    return Err(ErrorObject::new(ErrorCode::Unavailable));
                }
                let mut settled_at = o.now;
                if o.slow_action || o.late_settle {
                    settled_at = o.now + self.limits.pending_timeout + 1;
                }
                if o.slow_action {
                    block_on(outcome::sweep(store, settled_at, &self.limits)).unwrap();
                }
                let charge = pending.charge(o.status, o.units);
                // A scheme whose OK settle fails (here: the sweep already
                // timed the outcome out, so no fresh change is reserved)
                // is settled FAILED instead, charge 0, with its refund.
                let (charge, result) = match run_settle(charge.cap(), charge.charged(), settled_at)
                {
                    Ok(r) => (charge, r),
                    Err(_) if o.status == Status::Ok => {
                        let failed = pending.charge(Status::Failed, 0);
                        let r = run_settle(failed.cap(), 0, settled_at)?;
                        (failed, r)
                    }
                    Err(e) => return Err(e),
                };
                let s = Settlement::new(&charge, settled_at).with_scheme_result(result);
                match block_on(outcome::settle(store, &pending, &s, &self.limits)) {
                    Ok(rec) => rec,
                    Err(SettleError::AlreadySettled(rec)) if rec.needs_refund() => {
                        refund(&rec, settled_at)?
                    }
                    Err(SettleError::AlreadySettled(rec)) => *rec,
                    Err(_) => return Err(ErrorObject::new(ErrorCode::Unavailable)),
                }
            }
        };
        let unsigned = answer.unsigned_receipt(&receipt_input).unwrap().unwrap();
        let ack = block_on(self.signer.schnorr(unsigned.message())).unwrap();
        Ok(unsigned.finish(&ack).unwrap())
    }

    /// Verify the part and confirm its rail references: the verified part,
    /// the `RailId`s, and the backing the rail and the signer confirmed.
    fn verify(
        &self,
        offer: &Offer,
        entry: &PayEntry,
        part: &SchemePart,
        ctx: &Context,
        digest: &Digest,
        o: &Opts,
    ) -> Result<(Verified, Vec<RailId>, Vec<bnap_core::pricing::Backing>), ErrorObject> {
        let view = CappedSigner::verify_only(self.signer.clone(), "sat");
        let verified = block_on(self.scheme.verify(
            part,
            &VerifyCtx {
                now: o.now,
                offer,
                entry: Entry::Pay(entry),
                action_scope: &o.action_scope,
                context: ctx,
                digest,
                signer: &view,
            },
        ))
        .map_err(|e| e.to_error_object())?;
        if o.unlinkable && funded(&verified) {
            return Err(ErrorObject::new(ErrorCode::Policy));
        }
        let rail: &dyn FundingRail = &*self.rail;
        let payments = verified
            .rail_ids
            .iter()
            .map(|r| block_on(confirm_rail_id(rail, r)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| rail_error(&e).to_error_object())?;
        let rail_ids = payments.iter().map(|p| p.rail_id).collect();
        let mut backing: Vec<_> = payments
            .iter()
            .map(bnap_plug::RailPayment::backing)
            .collect();
        backing.extend(view.notes());
        Ok((verified, rail_ids, backing))
    }

    /// The verify step alone, as a scheme error.
    pub fn verify_only(&self, cred: &Credential, o: &Opts) -> Result<Verified, SchemeError> {
        let offers = self.offers.lock().unwrap().clone();
        let offer = match &cred.offer {
            OfferRef::Inline(b) => Offer::parse(b).unwrap(),
            OfferRef::Id(id) => offers[id].clone(),
        };
        let ctx = cred.context(&offer.offer_id(), &o.action_scope);
        let digest = cred.digest(&ctx);
        let (_, entry) = offer.fields().pay_entry(SCHEME_ID).unwrap();
        let view = CappedSigner::verify_only(self.signer.clone(), "sat");
        block_on(self.scheme.verify(
            cred.pay.as_ref().unwrap(),
            &VerifyCtx {
                now: o.now,
                offer: &offer,
                entry: Entry::Pay(entry),
                action_scope: &o.action_scope,
                context: &ctx,
                digest: &digest,
                signer: &view,
            },
        ))
    }

    /// What the store reserved for the outcome of `rk`.
    pub fn reserved(&self, rk: &bnap_core::ReplayKey) -> u64 {
        block_on(self.store.outcome(rk))
            .unwrap()
            .map_or(0, |r| r.change_total)
    }

    /// Every keyset's public keys, as a wallet fetched them.
    pub fn keys(&self) -> client::KeyTable {
        block_on(bnap_scheme_notes::IssuerStore::keysets(&*self.issuer))
            .unwrap()
            .into_iter()
            .map(|k| (k.id, k.keys))
            .collect()
    }
}

pub fn nonce(n: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[8..].copy_from_slice(&n.to_be_bytes());
    b
}

// ---------------------------------------------------------------- wallet

/// A wallet: a seed, a counter per keyset, and the notes it holds.
pub struct Wallet {
    pub seed: [u8; 64],
    pub counters: BTreeMap<KeysetIdBytes, u64>,
}

/// A credential as the wallet built it, with what it needs afterwards.
pub struct Paid {
    pub credential: Credential,
    pub outputs: Vec<PendingOutput>,
    pub value: u64,
    pub notes: Vec<Note>,
}

impl Wallet {
    pub fn new(tag: &str) -> Self {
        let a = sha256(format!("bnap notes test seed {tag} 0").as_bytes());
        let b = sha256(format!("bnap notes test seed {tag} 1").as_bytes());
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&a);
        seed[32..].copy_from_slice(&b);
        Self {
            seed,
            counters: BTreeMap::new(),
        }
    }

    fn next(&mut self, ks: &KeysetIdBytes) -> u64 {
        *self.counters.entry(*ks).or_insert(0)
    }

    pub fn outputs(&mut self, ks: &KeysetIdBytes, amounts: &[u64]) -> Vec<PendingOutput> {
        let start = self.next(ks);
        let (out, next) = client::derive_outputs(&self.seed, ks, amounts, start);
        self.counters.insert(*ks, next);
        out
    }

    /// Notes of these amounts on `keyset`, as a mint earlier gave them:
    /// outputs from the seed, signed with the keyset's keys, unblinded.
    pub fn notes(&mut self, keyset: &IssuerKeyset, amounts: &[u64]) -> Vec<Note> {
        let ks = keyset.info().id;
        self.outputs(&ks, amounts)
            .into_iter()
            .map(|p| {
                let s = keyset.sign(p.output.amount, &p.output.blinded).unwrap();
                let a = keyset.info().key(p.output.amount).unwrap();
                Note {
                    keyset: ks,
                    amount: p.output.amount,
                    note_key: p.derived.note_key,
                    c: client::unblind(&s.c, &p.derived.r, a).unwrap(),
                }
            })
            .collect()
    }

    /// A credential for `offer` spending `notes` (and a fund quote), with
    /// the canonical ladder on `out_keyset` covering its value.
    pub fn pay(
        &mut self,
        offer: &Offer,
        notes: &[Note],
        fund: Option<(&FundQuote, &[u8; 32])>,
        out_keyset: &KeysetIdBytes,
        o: &Opts,
    ) -> Paid {
        let (_, entry) = offer.fields().pay_entry(SCHEME_ID).unwrap();
        let params = Params::parse(entry.params.as_ref().unwrap()).unwrap();
        let fee = |ks: &KeysetIdBytes| params.keyset(ks).map(|k| k.input_fee_ppk);
        let value = bnap_scheme_notes::amount::value(
            notes
                .iter()
                .map(|n| (n.amount, fee(&n.keyset).unwrap_or(0))),
            fund.map_or(0, |(q, _)| q.amount),
        )
        .unwrap();
        let outputs = {
            let start = self.next(out_keyset);
            let (out, next) = client::ladder_outputs(&self.seed, out_keyset, value, start);
            self.counters.insert(*out_keyset, next);
            out
        };
        let outs: Vec<_> = outputs.iter().map(|p| p.output).collect();
        self.build(offer, notes, &outs, fund, o, outputs, value)
    }

    /// A credential with exactly these outputs.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        offer: &Offer,
        notes: &[Note],
        outs: &[bnap_scheme_notes::Output],
        fund: Option<(&FundQuote, &[u8; 32])>,
        o: &Opts,
        outputs: Vec<PendingOutput>,
        value: u64,
    ) -> Paid {
        let (body, ordered) =
            client::build_body(notes, outs, fund.map(|(q, _)| q.quote.as_str())).unwrap();
        let mut c = Credential::new(OfferRef::Inline(offer.bytes().to_vec()));
        c.pay = Some(SchemePart::new(SCHEME_ID, body.to_bytes().unwrap()));
        c.binding = o.binding;
        let ctx = c.context(&offer.offer_id(), &o.action_scope);
        let digest = c.digest(&ctx);
        let w =
            client::sign_witness(&body, &ordered, fund.map(|(_, k)| k), &digest, &AUX0).unwrap();
        c.pay.as_mut().unwrap().witness = w.to_bytes();
        Paid {
            credential: c,
            outputs,
            value,
            notes: ordered,
        }
    }
}

/// The change in a Response, checked and unblinded.
pub fn change(gate: &Gate, paid: &Paid, resp: &Response) -> client::Recovered {
    let f = resp.fields();
    let keys = gate.keys();
    client::recover_change(
        &paid.outputs,
        client::key_lookup(&keys),
        paid.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap()
}

pub fn total(notes: &[Note]) -> u64 {
    notes.iter().map(|n| n.amount).sum()
}

/// The keyset ID of a test keyset.
pub fn id(k: &IssuerKeyset) -> KeysetIdBytes {
    k.info().id
}
