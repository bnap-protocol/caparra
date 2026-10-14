//! The paid fetch: send, read the 402, check the offers against the pinned
//! manifest, choose one value credential (and the attestations the policy
//! allows), reserve its cost against every cap, pay, and keep the receipt.
//!
//! The order is the overview's "client choice" (Negotiation): verify
//! `offer_sig` with an offer key the pinned root signed, refetching the
//! manifest once for an unknown key; keep what the wallet can use; drop
//! what the policy forbids; rank by cost; send exactly one value
//! credential. The wallet never says which schemes it supports.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::error::{BadOffer, Error as CoreError, ErrorCode, ErrorObject};
use bnap_core::hash::{Context, Scope, sha256};
use bnap_core::http;
use bnap_core::limits::Limits;
use bnap_core::offer::{ClientOfferCheck, Effect, Offer};
use bnap_core::response::{Response, Status};
use bnap_scheme_notes::client::{self as notes, PendingOutput};
use bnap_scheme_notes::wire::{FundQuote, Params};
use bnap_scheme_notes::{FundRequest, SCHEME_ID as NOTES};
use serde::Serialize;

use crate::error::{Code, Refusal, Result};
use crate::invoice::Invoice;
use crate::policy::{self, Caps};
use crate::rank::{self, Candidate, to_sat};
use crate::records::{
    Config, NoteRecord, NoteState, OpRecord, OpState, OutputRecord, PinRecord, QuoteRecord,
    QuoteState, ReceiptKind, ReceiptRecord, kind,
};
use crate::transport::{HttpRequest, HttpResponse};
use crate::wallet::{Wallet, random_id, random32};

/// The credential field.
pub const CREDENTIAL_FIELD: &str = "BNAP-Credential";
/// The receipt field.
pub const RECEIPT_FIELD: &str = "BNAP-Receipt";
/// The error field.
pub const ERROR_FIELD: &str = "BNAP-Error";
/// The funding request field (bnap:notes 8.1).
pub const FUND_FIELD: &str = "BNAP-Fund";

/// A request to fetch, maybe paying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    /// Method.
    pub method: String,
    /// Absolute `https` URL.
    pub url: String,
    /// Extra header fields.
    pub headers: Vec<(String, String)>,
    /// Content.
    pub body: Vec<u8>,
    /// The most this one request may cost, sat; never above the per-request
    /// cap a person set.
    pub max_sat: Option<u64>,
}

impl FetchRequest {
    /// A GET.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".into(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            max_sat: None,
        }
    }

    /// A POST with content.
    #[must_use]
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body: body.into(),
            max_sat: None,
        }
    }
}

/// What a paid request cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Payment {
    /// The origin paid.
    pub origin: String,
    /// The value scheme, `None` when attestations alone admitted it.
    pub scheme: Option<String>,
    /// What it cost the wallet, routing fees included, change deducted.
    pub cost_sat: u64,
    /// What the server charged.
    pub charged: u64,
    /// In this unit.
    pub unit: Option<String>,
    /// The action's status: OK or FAILED.
    pub ok: bool,
    /// The receipt kept for it.
    pub receipt: String,
    /// The answer is a replay of an earlier settlement.
    pub replayed: bool,
}

/// The answer to a fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FetchResult {
    /// HTTP status.
    pub status: u16,
    /// Header fields.
    pub headers: Vec<(String, String)>,
    /// Content.
    #[serde(skip)]
    pub body: Vec<u8>,
    /// What was paid, if anything.
    pub payment: Option<Payment>,
}

impl FetchResult {
    fn plain(r: HttpResponse) -> Self {
        Self {
            status: r.status,
            headers: r.headers,
            body: r.body,
            payment: None,
        }
    }
}

enum Step {
    Done(FetchResult),
    Retry(HttpResponse),
}

/// The challenges in a 402.
#[derive(Debug, Default)]
pub(crate) struct Challenges {
    pub offers: Vec<Vec<u8>>,
    pub natives: Vec<String>,
    pub error: Option<ErrorObject>,
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim()).ok()
}

impl Challenges {
    pub(crate) fn parse(r: &HttpResponse) -> Self {
        let mut c = Self::default();
        for v in r.headers_all("www-authenticate") {
            let t = v.trim_start();
            let scheme = t.split([' ', ',']).next().unwrap_or("");
            if scheme.eq_ignore_ascii_case("BNAP") {
                // One or more `offer="…"` parameters; base64url holds no quote.
                let mut rest = t;
                while let Some(i) = rest.find("offer=\"") {
                    rest = &rest[i + 7..];
                    let Some(end) = rest.find('"') else { break };
                    if let Some(b) = b64d(&rest[..end]) {
                        c.offers.push(b);
                    }
                    rest = &rest[end..];
                }
            } else if scheme.eq_ignore_ascii_case("L402")
                || scheme.eq_ignore_ascii_case("LSAT")
                || scheme.eq_ignore_ascii_case("Payment")
            {
                c.natives.push(t.to_owned());
            }
        }
        c.error = r
            .header(ERROR_FIELD)
            .and_then(b64d)
            .and_then(|b| ErrorObject::parse(&b).ok());
        c
    }
}

/// The receipt in a response: the `BNAP-Receipt` field, or the final
/// `bnap-receipt` event of an event stream (draft-00 10.2).
pub(crate) fn receipt_bytes(r: &HttpResponse) -> Option<Vec<u8>> {
    if let Some(v) = r.header(RECEIPT_FIELD) {
        return b64d(v);
    }
    let ct = r.header("content-type").unwrap_or("");
    if !ct.starts_with("text/event-stream") {
        return None;
    }
    let text = String::from_utf8_lossy(&r.body);
    let mut event = "";
    let mut found = None;
    for line in text.lines() {
        if let Some(e) = line.strip_prefix("event:") {
            event = e.trim();
        } else if let Some(d) = line.strip_prefix("data:")
            && event == "bnap-receipt"
        {
            found = b64d(d);
        } else if line.is_empty() {
            event = "";
        }
    }
    found
}

/// The request-target in origin form: path and query as sent.
pub(crate) fn request_target(url: &url::Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    }
}

fn action_scope(req: &HttpRequest, origin: &str, target: &str, names: &[String]) -> Scope {
    let values: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| (n.clone(), req.field(n).unwrap_or_default().into_bytes()))
        .collect();
    let pairs: Vec<(&str, &[u8])> = values
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_slice()))
        .collect();
    http::action_scope(
        &req.method,
        &http::target(origin, target),
        &req.body,
        &pairs,
    )
}

/// The price of a pay entry after the attestations the wallet sends, as
/// draft-00 7 computes it, assuming they verify. Quotas are not counted
/// on: the wallet cannot see their counters.
fn price(offer: &Offer, base: u64, sending: &[String]) -> u64 {
    let f = offer.fields();
    let ours = |s: &str| sending.iter().any(|x| x == s);
    if f.attest
        .iter()
        .any(|a| a.effect == Effect::Waive && ours(&a.scheme))
    {
        return 0;
    }
    let mut p = base;
    for a in f
        .attest
        .iter()
        .filter(|a| a.effect == Effect::Discount && ours(&a.scheme))
    {
        let v = a.value.unwrap_or(0).min(10_000);
        let off = u64::try_from(u128::from(p) * u128::from(v) / 10_000).unwrap_or(p);
        p -= off;
    }
    p
}

fn offer_refusal(e: &CoreError) -> Refusal {
    match e {
        CoreError::BadOffer(BadOffer::Signature) => Refusal::bad_offer_sig(),
        CoreError::BadOffer(BadOffer::NotPinned) => Refusal::unknown_key(),
        CoreError::Stale(_) => Refusal::new(
            Code::Stale,
            "Every offer in the 402 has expired. Nothing was paid; retry the request.",
        ),
        CoreError::WrongScope => Refusal::new(
            Code::WrongScope,
            "The offer is for another request. Nothing was paid.",
        ),
        other => Refusal::new(
            Code::BadOffer,
            format!("The offer failed its checks ({other}). Nothing was paid."),
        ),
    }
}

/// How a chosen candidate is paid.
#[derive(Debug, Clone)]
enum How {
    /// Notes already held at this origin.
    Notes { notes: Vec<NoteRecord>, value: u64 },
    /// A fund quote inside the 402 (bnap:notes 8).
    Fund,
    /// A Lightning invoice through the scheme's native artifact.
    Lightning { challenge: String, invoice: Invoice },
    /// Attestations alone: the price after them is 0.
    AttestOnly,
}

#[derive(Debug, Clone)]
struct Plan {
    offer: Offer,
    scope: Scope,
    entry: usize,
    scheme: String,
    price: u64,
    how: How,
    attest: Vec<String>,
    cand: Candidate,
    /// The most this plan puts at risk, reserved against the caps: the
    /// face value of the notes sent (an operator that kept the change
    /// would keep it all), the quote and its routing fee, or the invoice
    /// and its routing fee.
    risk: u64,
}

struct Ctx<'a> {
    cfg: &'a Config,
    caps: Caps,
    base: &'a HttpRequest,
    origin: String,
    target: String,
    pin: PinRecord,
    limits: Limits,
}

impl Wallet {
    /// Fetches `req`, paying the 402 if the policy and the caps allow.
    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResult> {
        let cfg = self.config().await?;
        let url = url::Url::parse(&req.url)
            .map_err(|e| Refusal::bad_input(format!("Not a URL: {e}.")))?;
        if url.scheme() != "https" {
            return Err(Refusal::bad_input(
                "Paid requests go over https only. Use an https:// URL.",
            ));
        }
        let mut caps = self.caps(&cfg);
        if let Some(m) = req.max_sat {
            let hard = cfg.policy.caps.per_request;
            if m > hard {
                return Err(Refusal::above_hard_cap(
                    crate::error::CapKind::PerRequest,
                    m,
                    hard,
                ));
            }
            caps.per_request = caps.per_request.min(m);
        }
        let base = HttpRequest {
            method: req.method.clone(),
            url: url.to_string(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };
        let resp = self
            .transport
            .send(base.clone())
            .await
            .map_err(Refusal::network)?;
        if resp.status != 402 {
            return Ok(FetchResult::plain(resp));
        }
        let mut resp = resp;
        for attempt in 0..2 {
            match self
                .pay_402(&cfg, caps, &base, &url, &resp, attempt)
                .await?
            {
                Step::Done(r) => return Ok(r),
                Step::Retry(fresh) => resp = fresh,
            }
        }
        let e = Challenges::parse(&resp).error.map_or_else(
            || {
                Refusal::new(
                    Code::NoOffer,
                    "The server kept refusing fresh offers. Nothing was paid.",
                )
            },
            |e| Refusal::from_server(&e),
        );
        Err(e)
    }

    async fn pay_402(
        &self,
        cfg: &Config,
        caps: Caps,
        base: &HttpRequest,
        url: &url::Url,
        resp: &HttpResponse,
        attempt: u32,
    ) -> Result<Step> {
        let origin = url.origin().ascii_serialization();
        let ch = Challenges::parse(resp);
        let pin = self.ensure_pin(&origin, false).await?;
        if ch.offers.is_empty() {
            return match &pin {
                Some(p) if p.required => Err(Refusal::bnap_required()),
                Some(_) => Err(Refusal::new(
                    Code::NoOffer,
                    "The 402 carried no BNAP offer, and this origin is pinned: a native challenge no signed offer lists is never paid.",
                )),
                None if !ch.natives.is_empty() => self
                    .pay_native(cfg, caps, base, &origin, &ch.natives)
                    .await
                    .map(Step::Done),
                None => Err(Refusal::new(
                    Code::NoOffer,
                    "The server asked for payment but sent nothing this wallet can pay.",
                )),
            };
        }
        let Some(pin) = pin else {
            return Err(Refusal::new(
                Code::Manifest,
                format!(
                    "Could not fetch a valid manifest from {origin}/.well-known/bnap. The wallet pays BNAP offers only from an origin whose manifest it pinned over HTTPS."
                ),
            ));
        };
        let limits = pin
            .manifest()
            .and_then(|m| Limits::from_manifest(&m.manifest().limits).ok())
            .unwrap_or_default();
        let mut cx = Ctx {
            cfg,
            caps,
            base,
            origin,
            target: request_target(url),
            pin,
            limits,
        };
        let offers = self.check_offers(&mut cx, &ch.offers).await?;
        let plan = self.choose(&cx, &offers).await?;
        let step = match plan.how.clone() {
            How::Fund => self.pay_funded(&cx, &plan).await?,
            How::Lightning { challenge, invoice } => {
                self.pay_lightning(&cx, &plan, &challenge, &invoice).await?
            }
            How::Notes { notes, value } => {
                self.pay_notes(&cx, &plan, notes, value, None, None).await?
            }
            How::AttestOnly => self.pay_attest_only(&cx, &plan).await?,
        };
        match step {
            Step::Retry(r) if attempt > 0 => {
                let e = Challenges::parse(&r).error;
                Err(e.map_or_else(
                    || {
                        Refusal::new(
                            Code::NoOffer,
                            "The server refused the fresh offer too. Nothing was paid.",
                        )
                    },
                    |e| Refusal::from_server(&e),
                ))
            }
            s => Ok(s),
        }
    }

    /// The offers that pass draft-00 4.4 for this request, in server order.
    async fn check_offers(&self, cx: &mut Ctx<'_>, raw: &[Vec<u8>]) -> Result<Vec<(Offer, Scope)>> {
        let now = self.now();
        let route = cx.pin.manifest().and_then(|m| {
            let path = cx.target.split('?').next().unwrap_or("");
            m.manifest()
                .routes
                .iter()
                .find(|r| r.matches(&cx.base.method, path))
                .map(|r| http::route_scope(&cx.origin, &r.id))
        });
        let mut valid = Vec::new();
        let mut first: Option<Refusal> = None;
        let mut refetched = false;
        for bytes in raw {
            let offer = match Offer::parse_with_limit(bytes, cx.limits.max_offer) {
                Ok(o) => o,
                Err(e) => {
                    first.get_or_insert_with(|| offer_refusal(&e));
                    continue;
                }
            };
            let scope = action_scope(cx.base, &cx.origin, &cx.target, &offer.fields().headers);
            loop {
                let r = offer.check_client(&ClientOfferCheck {
                    now,
                    origin: &cx.origin,
                    pinned_keys: Some(&cx.pin.keys),
                    action_scope: scope,
                    route_scope: route,
                });
                match r {
                    Ok(()) => {
                        valid.push((offer.clone(), scope));
                        break;
                    }
                    Err(CoreError::BadOffer(BadOffer::NotPinned)) if !refetched => {
                        // An unknown offer key: refetch the manifest once.
                        refetched = true;
                        match self.ensure_pin(&cx.origin, true).await? {
                            Some(p) if p.seq != cx.pin.seq || p.keys != cx.pin.keys => cx.pin = p,
                            _ => {
                                first.get_or_insert_with(|| {
                                    offer_refusal(&CoreError::BadOffer(BadOffer::NotPinned))
                                });
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        first.get_or_insert_with(|| offer_refusal(&e));
                        break;
                    }
                }
            }
        }
        if valid.is_empty() {
            if cx.pin.required && first.is_none() {
                return Err(Refusal::bnap_required());
            }
            return Err(first.unwrap_or_else(|| Refusal::new(Code::NoOffer, "No usable offer.")));
        }
        Ok(valid)
    }

    /// Builds every candidate, applies the policy, ranks, and returns the
    /// best one that fits the caps.
    #[allow(clippy::too_many_lines)]
    async fn choose(&self, cx: &Ctx<'_>, offers: &[(Offer, Scope)]) -> Result<Plan> {
        let p = &cx.cfg.policy;
        let notes: Vec<NoteRecord> = self.store.list(kind::NOTE).await?;
        let balance: u64 = notes
            .iter()
            .filter(|n| n.origin == cx.origin && n.state == NoteState::Unspent)
            .map(|n| n.amount)
            .sum();
        let keys_ok = self.attest_keys().await.is_ok();
        let room = policy::remaining(
            &cx.caps,
            &self.ledger().await?,
            &cx.origin,
            &self.task,
            self.now(),
        )
        .min();
        let has_pay = self.pay_source(cx.cfg).is_some();
        let mut plans = Vec::new();
        let mut refusal: Option<Refusal> = None;
        for (oi, (offer, scope)) in offers.iter().enumerate() {
            let f = offer.fields();
            let attest: Vec<String> = f
                .attest
                .iter()
                .filter(|a| keys_ok && p.may_attest(&a.scheme))
                .map(|a| a.scheme.clone())
                .collect();
            let required_missing = f
                .attest
                .iter()
                .find(|a| a.effect == Effect::Required && !attest.contains(&a.scheme));
            if let Some(a) = required_missing {
                refusal.get_or_insert_with(|| {
                    Refusal::new(
                        Code::Policy,
                        format!(
                            "The offer requires the attestation {}, which the policy does not send. A person can allow it with `bnap budget set --attest {}`.",
                            a.scheme, a.scheme
                        ),
                    )
                });
                continue;
            }
            for (ei, e) in f.pay.iter().enumerate() {
                let v = match p.admit_scheme(self.registry, &e.scheme) {
                    Ok(v) => v,
                    Err(r) => {
                        refusal.get_or_insert(r);
                        continue;
                    }
                };
                let Some(amount) = to_sat(e.amount, &e.unit) else {
                    continue;
                };
                let pr = price(offer, amount, &attest);
                let mk = |value: u64, fee: u64, linkable: bool| Candidate {
                    offer: oi,
                    entry: ei,
                    scheme: e.scheme.clone(),
                    value_sat: value,
                    fee_sat: fee,
                    linkable,
                };
                let plan = |how: How, cand: Candidate, risk: u64| Plan {
                    offer: offer.clone(),
                    scope: *scope,
                    entry: ei,
                    scheme: e.scheme.clone(),
                    price: pr,
                    how,
                    attest: attest.clone(),
                    cand,
                    risk,
                };
                if pr == 0 && e.scheme == NOTES {
                    plans.push(plan(How::AttestOnly, mk(0, 0, false), 0));
                    continue;
                }
                if e.scheme == NOTES {
                    if e.unit != "sat" {
                        continue;
                    }
                    let Some(params) = e.params.as_deref().and_then(|b| Params::parse(b).ok())
                    else {
                        continue;
                    };
                    // Only notes the caps could lose whole: the face value is
                    // what a payment puts at risk.
                    let mine: Vec<NoteRecord> = notes
                        .iter()
                        .filter(|n| {
                            n.origin == cx.origin
                                && n.issuer == params.issuer
                                && n.state == NoteState::Unspent
                                && n.amount <= room
                        })
                        .cloned()
                        .collect();
                    let held_notes: Vec<_> = mine.iter().map(NoteRecord::note).collect();
                    let fee = |ks: &[u8; 33]| params.keyset(ks).map(|k| k.input_fee_ppk);
                    let max_in = usize::try_from(params.max_inputs()).unwrap_or(usize::MAX);
                    if let Some(sel) = notes::select_notes(&held_notes, fee, pr, max_in) {
                        let chosen: Vec<NoteRecord> =
                            sel.notes.iter().map(|&i| mine[i].clone()).collect();
                        let face: u64 = chosen.iter().map(|n| n.amount).sum();
                        let input_fee = face - sel.value;
                        plans.push(plan(
                            How::Notes {
                                notes: chosen,
                                value: sel.value,
                            },
                            mk(pr, input_fee, false),
                            face,
                        ));
                    } else if has_pay
                        && params.max_fund.is_some_and(|m| m >= pr)
                        && balance.saturating_add(pr) <= p.max_balance_per_origin
                    {
                        // Funding in the 402 links this action to the payment.
                        let fee = p.fee.max_fee(pr);
                        plans.push(plan(How::Fund, mk(pr, fee, true), pr.saturating_add(fee)));
                    } else {
                        refusal.get_or_insert_with(|| {
                            Refusal::new(
                                Code::InsufficientNotes,
                                format!(
                                    "Not enough notes at {} to pay {pr} sat. Buy credit with `bnap fund {} <sat>`, or configure a pay source.",
                                    cx.origin, cx.origin
                                ),
                            )
                        });
                    }
                    continue;
                }
                // Class O Lightning schemes: the native entry of this pay
                // entry holds the challenge, signed with the offer.
                let Some(n) = f.native.iter().find(|n| n.pay_index == ei as u64) else {
                    continue;
                };
                let Ok(text) = String::from_utf8(n.data.clone()) else {
                    continue;
                };
                let Some(invoice) = lightning_invoice(&e.scheme, &text) else {
                    continue;
                };
                let now = self.now();
                if invoice.amount_sat() != Some(amount)
                    || invoice.description_hash != Some(offer.offer_id().0)
                    || invoice.expires_at <= now
                {
                    refusal.get_or_insert_with(|| {
                        Refusal::new(
                            Code::BadInvoice,
                            format!(
                                "The {} invoice does not match its offer. Nothing was paid.",
                                e.scheme
                            ),
                        )
                    });
                    continue;
                }
                if !has_pay {
                    refusal.get_or_insert_with(|| {
                        Refusal::new(
                            Code::NoPaySource,
                            "No pay source is configured. A person can set one with `bnap paysource nwc <uri>`.",
                        )
                    });
                    continue;
                }
                plans.push(plan(
                    How::Lightning {
                        challenge: text,
                        invoice,
                    },
                    mk(amount, p.fee.max_fee(amount), crate::registry::linkable(&v)),
                    amount.saturating_add(p.fee.max_fee(amount)),
                ));
            }
        }
        let ranked = rank::rank(plans.iter().map(|p| p.cand.clone()).collect(), p);
        if ranked.is_empty() {
            return Err(refusal.unwrap_or_else(|| {
                Refusal::new(
                    Code::NoOffer,
                    "No offer lists a scheme this wallet can pay with.",
                )
            }));
        }
        // The best ranked plan whose risk fits every cap.
        let ledger = self.ledger().await?;
        let now = self.now();
        let mut first_refusal = None;
        let mut best = None;
        for c in &ranked {
            let plan = plans
                .iter()
                .find(|p| p.cand == *c)
                .expect("the ranked candidate is one of the plans");
            match policy::check(&cx.caps, &ledger, &cx.origin, &self.task, plan.risk, now) {
                Ok(()) => {
                    best = Some(c.clone());
                    break;
                }
                Err(r) => {
                    first_refusal.get_or_insert(r);
                }
            }
        }
        let Some(best) = best else {
            return Err(first_refusal.expect("a refusal for every candidate"));
        };
        Ok(plans
            .into_iter()
            .find(|p| p.cand == best)
            .expect("the ranked candidate is one of the plans"))
    }

    /// The keys of the active keyset of a notes entry, fetched and checked
    /// once, then kept.
    pub(crate) async fn keyset_keys(
        &self,
        origin: &str,
        issuer: &str,
        id: &[u8; 33],
    ) -> Result<crate::records::KeysetRecord> {
        let name = hex::encode(id);
        if let Some(k) = self
            .store
            .get::<crate::records::KeysetRecord>(kind::KEYSET, &name)
            .await?
            .filter(|k| k.issuer == issuer)
        {
            return Ok(k);
        }
        let k = crate::issuer::Issuer::new(issuer, origin, &*self.transport)?
            .keyset(id)
            .await?;
        self.store.put(kind::KEYSET, &name, &k).await?;
        Ok(k)
    }

    /// Builds the credential for a plan: attestation bodies over the
    /// Context, the pay part's body, then (through `witness`) the class S
    /// witness over the Digest.
    async fn build_credential(
        &self,
        cx: &Ctx<'_>,
        plan: &Plan,
        offer_ref: OfferRef,
        pay: Option<SchemePart>,
        witness: impl FnOnce(&bnap_core::hash::Digest) -> Result<Vec<u8>>,
    ) -> Result<(Credential, Context, bnap_core::hash::Digest)> {
        let mut c = Credential::new(offer_ref);
        c.pay = pay;
        c.attest = plan
            .attest
            .iter()
            .map(|s| SchemePart::new(s.clone(), Vec::new()))
            .collect();
        c.sort_attest();
        let ctx = c.context(&plan.offer.offer_id(), &plan.scope);
        if !c.attest.is_empty() {
            let keys = self.attest_keys().await?;
            let now = self.now();
            let url =
                url::Url::parse(&cx.base.url).map_err(|e| Refusal::bad_input(e.to_string()))?;
            for a in &mut c.attest {
                a.body = crate::attest::body(
                    &a.scheme,
                    &keys,
                    &ctx,
                    &url,
                    &cx.base.method,
                    now,
                    plan.offer.fields().expires,
                    cx.limits.pending_timeout,
                )?;
            }
        }
        let digest = c.digest(&ctx);
        if let Some(p) = c.pay.as_mut() {
            p.witness = witness(&digest)?;
        }
        c.to_bytes().map_err(|e| {
            Refusal::new(Code::BadInput, format!("cannot encode the credential: {e}"))
        })?;
        Ok((c, ctx, digest))
    }

    fn offer_ref(plan: &Plan) -> OfferRef {
        // Route-scope offers are cached by the gate: name them by ID.
        if plan.offer.fields().route_scope {
            OfferRef::Id(plan.offer.offer_id())
        } else {
            OfferRef::Inline(plan.offer.bytes().to_vec())
        }
    }

    fn request_with(base: &HttpRequest, cred: &Credential) -> Result<HttpRequest> {
        let bytes = cred.to_bytes().map_err(|e| {
            Refusal::new(Code::BadInput, format!("cannot encode the credential: {e}"))
        })?;
        let mut r = base.clone();
        r.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case(CREDENTIAL_FIELD));
        r.headers
            .push((CREDENTIAL_FIELD.into(), URL_SAFE_NO_PAD.encode(bytes)));
        Ok(r)
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn pay_notes(
        &self,
        cx: &Ctx<'_>,
        plan: &Plan,
        chosen: Vec<NoteRecord>,
        value: u64,
        fund: Option<(&FundQuote, &[u8; 32])>,
        reserved: Option<String>,
    ) -> Result<Step> {
        let e = &plan.offer.fields().pay[plan.entry];
        let params = Params::parse(e.params.as_deref().unwrap_or_default())
            .map_err(|_| Refusal::new(Code::BadOffer, "The notes parameters do not parse."))?;
        let active = params
            .keysets
            .iter()
            .find(|k| k.active)
            .ok_or_else(|| Refusal::new(Code::BadOffer, "The offer names no active keyset."))?;
        let ks = self
            .keyset_keys(&cx.origin, &params.issuer, &active.id)
            .await?;
        if ks.input_fee_ppk != active.input_fee_ppk {
            return Err(Refusal::new(
                Code::Issuer,
                "The issuer's keyset fee differs from the offer's. Nothing was paid.",
            ));
        }
        let seed = self.seed().await?;
        let mut tx = self.store.tx().await?;
        let id = if let Some(r) = reserved {
            // A funded payment reserved its cost before paying the quote.
            r
        } else {
            let id = random_id();
            self.reserve_entry(
                &mut tx,
                &cx.caps,
                &cx.origin,
                &id,
                plan.risk,
                &format!("{} {}", cx.base.method, cx.base.url),
            )
            .await?;
            id
        };
        // The notes again, under the write lock: another request may have
        // taken one since they were chosen.
        let mut held = Vec::new();
        for n in &chosen {
            let name = hex::encode(n.k);
            match tx.get::<NoteRecord>(kind::NOTE, &name).await? {
                Some(mut cur) if cur.state == NoteState::Unspent => {
                    cur.state = NoteState::Reserved { op: id.clone() };
                    tx.put(kind::NOTE, &name, &cur).await?;
                    held.push(cur);
                }
                _ => {
                    return Err(Refusal::new(
                        Code::InsufficientNotes,
                        "Another request took these notes first. Retry.",
                    ));
                }
            }
        }
        let outputs = self
            .take_ladder(&mut tx, &seed, cx.cfg.slot, &active.id, value)
            .await?;
        if outputs.len() as u64 > params.max_outputs() {
            return Err(Refusal::new(
                Code::Policy,
                "The change ladder needs more outputs than the offer allows. Nothing was paid.",
            ));
        }
        self.record_site(&mut tx, &cx.origin, &params.issuer, &active.id, cx.cfg.slot)
            .await?;
        let inputs: Vec<_> = held.iter().map(NoteRecord::note).collect();
        let outs: Vec<_> = outputs.iter().map(|p| p.output).collect();
        let (body, ordered) =
            notes::build_body(&inputs, &outs, fund.map(|(q, _)| q.quote.as_str())).map_err(
                |e| Refusal::new(Code::BadInput, format!("cannot build the notes body: {e}")),
            )?;
        let body_bytes = body.to_bytes().map_err(|e| {
            Refusal::new(Code::BadInput, format!("cannot build the notes body: {e}"))
        })?;
        let aux = random32();
        let offer_ref = if fund.is_some() {
            // An offer with a fund quote is never cached (bnap:notes 5.4).
            OfferRef::Inline(plan.offer.bytes().to_vec())
        } else {
            Self::offer_ref(plan)
        };
        let (cred, _ctx, digest) = self
            .build_credential(
                cx,
                plan,
                offer_ref,
                Some(SchemePart::new(NOTES, body_bytes)),
                |d| {
                    Ok(
                        notes::sign_witness(&body, &ordered, fund.map(|(_, k)| k), d, &aux)
                            .map_err(|e| Refusal::new(Code::BadInput, format!("cannot sign: {e}")))?
                            .to_bytes(),
                    )
                },
            )
            .await?;
        let request = Self::request_with(cx.base, &cred)?;
        let face: u64 = held.iter().map(|n| n.amount).sum();
        let op = OpRecord {
            id: id.clone(),
            origin: cx.origin.clone(),
            task: self.task.clone(),
            created: self.now(),
            request,
            scheme: Some(NOTES.into()),
            offer: plan.offer.bytes().to_vec(),
            credential: cred.to_bytes().unwrap_or_default(),
            action_scope: plan.scope.0,
            digest: digest.0,
            outputs: outputs
                .iter()
                .map(|p| OutputRecord {
                    keyset: p.output.keyset,
                    amount: p.output.amount,
                    counter: p.derived.counter,
                })
                .collect(),
            value,
            notes: held.iter().map(|n| hex::encode(n.k)).collect(),
            face,
            quote: fund.map(|(q, _)| q.quote.clone()),
            lightning_sat: 0,
            invoice: None,
            preimage: None,
            ledger: id.clone(),
            issuer: Some(params.issuer.clone()),
            state: OpState::Sent,
        };
        tx.put(kind::OP, &id, &op).await?;
        tx.commit().await?;
        self.send_op(cx, op).await
    }

    async fn pay_attest_only(&self, cx: &Ctx<'_>, plan: &Plan) -> Result<Step> {
        let id = random_id();
        let (cred, _ctx, digest) = self
            .build_credential(cx, plan, Self::offer_ref(plan), None, |_| Ok(Vec::new()))
            .await?;
        let mut tx = self.store.tx().await?;
        self.reserve_entry(
            &mut tx,
            &cx.caps,
            &cx.origin,
            &id,
            0,
            &format!("{} {}", cx.base.method, cx.base.url),
        )
        .await?;
        let op = OpRecord {
            id: id.clone(),
            origin: cx.origin.clone(),
            task: self.task.clone(),
            created: self.now(),
            request: Self::request_with(cx.base, &cred)?,
            scheme: None,
            offer: plan.offer.bytes().to_vec(),
            credential: cred.to_bytes().unwrap_or_default(),
            action_scope: plan.scope.0,
            digest: digest.0,
            outputs: Vec::new(),
            value: 0,
            notes: Vec::new(),
            face: 0,
            quote: None,
            lightning_sat: 0,
            invoice: None,
            preimage: None,
            ledger: id.clone(),
            issuer: None,
            state: OpState::Sent,
        };
        tx.put(kind::OP, &id, &op).await?;
        tx.commit().await?;
        self.send_op(cx, op).await
    }

    async fn pay_lightning(
        &self,
        cx: &Ctx<'_>,
        plan: &Plan,
        challenge: &str,
        invoice: &Invoice,
    ) -> Result<Step> {
        let pay = self
            .pay_source(cx.cfg)
            .ok_or_else(|| Refusal::new(Code::NoPaySource, "No pay source is configured."))?;
        let id = random_id();
        let amount = plan.cand.value_sat;
        let max_fee = plan.cand.fee_sat;
        let mut tx = self.store.tx().await?;
        self.reserve_entry(
            &mut tx,
            &cx.caps,
            &cx.origin,
            &id,
            plan.risk,
            &format!("{} {}", cx.base.method, cx.base.url),
        )
        .await?;
        tx.commit().await?;
        let invoice_text = lightning_invoice_text(&plan.scheme, challenge).unwrap_or_default();
        let paid = match pay.pay_invoice(&invoice_text, amount, max_fee).await {
            Ok(p) if sha256(&p.preimage) == invoice.payment_hash => p,
            Ok(_) => {
                // The pay source says it paid but its preimage does not open
                // the invoice: count the payment as spent.
                self.true_up(&id, Some(amount + max_fee)).await?;
                return Err(Refusal::new(
                    Code::PaymentFailed,
                    "The pay source returned a preimage that does not open the invoice. The payment is counted as spent.",
                ));
            }
            Err(e) => return Err(uncertain(e)),
        };
        // The fee the pay source reports counts in full, ceiling or not.
        let fee = paid.fee_sat;
        // Proof first: the invoice and its preimage are kept before anything
        // else can fail; the receipt of the answer replaces this record.
        let proof = ReceiptRecord {
            id: id.clone(),
            kind: ReceiptKind::Native,
            origin: cx.origin.clone(),
            method: cx.base.method.clone(),
            url: cx.base.url.clone(),
            scheme: Some(plan.scheme.clone()),
            at: self.now(),
            cost_sat: amount + fee,
            charged: 0,
            unit: Some("sat".into()),
            ok: false,
            change_ok: true,
            offer: plan.offer.bytes().to_vec(),
            credential: Vec::new(),
            response: Vec::new(),
            manifest: Vec::new(),
            action_scope: plan.scope.0,
            invoice: Some(invoice_text.clone()),
            preimage: Some(paid.preimage),
        };
        self.store.put(kind::RECEIPT, &id, &proof).await?;
        let body = lightning_body(&plan.scheme, challenge, paid.preimage)?;
        let (cred, _ctx, digest) = self
            .build_credential(
                cx,
                plan,
                OfferRef::Inline(plan.offer.bytes().to_vec()),
                Some(SchemePart::new(plan.scheme.clone(), body)),
                |_| Ok(Vec::new()),
            )
            .await?;
        let op = OpRecord {
            id: id.clone(),
            origin: cx.origin.clone(),
            task: self.task.clone(),
            created: self.now(),
            request: Self::request_with(cx.base, &cred)?,
            scheme: Some(plan.scheme.clone()),
            offer: plan.offer.bytes().to_vec(),
            credential: cred.to_bytes().unwrap_or_default(),
            action_scope: plan.scope.0,
            digest: digest.0,
            outputs: Vec::new(),
            value: amount,
            notes: Vec::new(),
            face: 0,
            quote: None,
            lightning_sat: amount + fee,
            invoice: Some(invoice_text.clone()),
            preimage: Some(paid.preimage),
            ledger: id.clone(),
            issuer: None,
            state: OpState::Sent,
        };
        self.store.put(kind::OP, &id, &op).await?;
        self.send_op(cx, op).await
    }

    /// Funds inside the 402 (bnap:notes 8): asks again with `BNAP-Fund`,
    /// checks the quote in the offer, saves it with its key and the offer,
    /// pays it, and redeems it in the credential.
    #[allow(clippy::too_many_lines)]
    async fn pay_funded(&self, cx: &Ctx<'_>, plan: &Plan) -> Result<Step> {
        let pay = self
            .pay_source(cx.cfg)
            .ok_or_else(|| Refusal::new(Code::NoPaySource, "No pay source is configured."))?;
        let amount = plan.price;
        let max_fee = plan.cand.fee_sat;
        let key = random32();
        let pubkey = notes::quote_pubkey(&key)
            .map_err(|e| Refusal::storage(format!("cannot make a quote key: {e}")))?;
        let mut ask = cx.base.clone();
        ask.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case(FUND_FIELD));
        ask.headers.push((
            FUND_FIELD.into(),
            FundRequest { amount, pubkey }.to_header(),
        ));
        let resp = self.transport.send(ask).await.map_err(Refusal::network)?;
        let ch = Challenges::parse(&resp);
        let now = self.now();
        let mut found = None;
        for b in &ch.offers {
            let Ok(o) = Offer::parse_with_limit(b, cx.limits.max_offer) else {
                continue;
            };
            let scope = action_scope(cx.base, &cx.origin, &cx.target, &o.fields().headers);
            if o.check_client(&ClientOfferCheck {
                now,
                origin: &cx.origin,
                pinned_keys: Some(&cx.pin.keys),
                action_scope: scope,
                route_scope: None,
            })
            .is_err()
            {
                continue;
            }
            let Some((ei, e)) = o
                .fields()
                .pay
                .iter()
                .enumerate()
                .find(|(_, e)| e.scheme == NOTES)
            else {
                continue;
            };
            let Some(params) = e.params.as_deref().and_then(|b| Params::parse(b).ok()) else {
                continue;
            };
            if let Some(q) = params.fund_quote.clone().filter(|q| q.pubkey == pubkey) {
                found = Some((o.clone(), scope, ei, q, params));
                break;
            }
        }
        let Some((offer, scope, ei, q, params)) = found else {
            return Err(Refusal::new(
                Code::NoOffer,
                "The server offered no fund quote. Buy credit with `bnap fund`, then retry.",
            ));
        };
        notes::check_fund_quote(&q, &pubkey, amount, now).map_err(|e| {
            Refusal::new(
                Code::BadInvoice,
                format!("The fund quote fails its checks: {e}. Nothing was paid."),
            )
        })?;
        let e = &offer.fields().pay[ei];
        let fresh_price = price(&offer, e.amount, &plan.attest);
        if q.amount < fresh_price {
            return Err(Refusal::new(
                Code::BadInvoice,
                "The fund quote is below the offer's price. Nothing was paid.",
            ));
        }
        let payment_hash = notes::invoice_payment_hash(&q)
            .map_err(|e| Refusal::new(Code::BadInvoice, e.to_string()))?;
        // Reserve, then save the quote, its key and the offer before paying
        // (bnap:notes 8.3).
        let reserve_id = random_id();
        let mut tx = self.store.tx().await?;
        self.reserve_entry(
            &mut tx,
            &cx.caps,
            &cx.origin,
            &reserve_id,
            q.amount + max_fee,
            &format!("{} {}", cx.base.method, cx.base.url),
        )
        .await?;
        let rec = QuoteRecord {
            id: q.quote.clone(),
            origin: cx.origin.clone(),
            issuer: params.issuer.clone(),
            key,
            amount: q.amount,
            invoice: q.request.clone(),
            payment_hash,
            offer: Some(offer.bytes().to_vec()),
            state: QuoteState::Unpaid,
            fee_sat: 0,
            ledger: Some(reserve_id.clone()),
        };
        tx.put(kind::QUOTE, &q.quote, &rec).await?;
        tx.commit().await?;
        let paid = match pay.pay_invoice(&q.request, q.amount, max_fee).await {
            Ok(p) if sha256(&p.preimage) == payment_hash => p,
            Ok(_) => {
                self.true_up(&reserve_id, Some(q.amount + max_fee)).await?;
                return Err(Refusal::new(
                    Code::PaymentFailed,
                    "The pay source returned a preimage that does not open the invoice. The payment is counted as spent.",
                ));
            }
            Err(e) => return Err(uncertain(e)),
        };
        let mut rec = rec;
        rec.state = QuoteState::Paid;
        rec.fee_sat = paid.fee_sat;
        self.store.put(kind::QUOTE, &q.quote, &rec).await?;
        let fplan = Plan {
            offer: offer.clone(),
            scope,
            entry: ei,
            scheme: NOTES.into(),
            price: fresh_price,
            how: How::Fund,
            attest: plan.attest.clone(),
            cand: Candidate {
                offer: 0,
                entry: ei,
                scheme: NOTES.into(),
                value_sat: q.amount,
                fee_sat: rec.fee_sat,
                linkable: true,
            },
            risk: q.amount + max_fee,
        };
        let step = self
            .pay_notes(
                cx,
                &fplan,
                Vec::new(),
                q.amount,
                Some((&q, &key)),
                Some(reserve_id.clone()),
            )
            .await;
        if step.is_err()
            && self
                .store
                .get::<OpRecord>(kind::OP, &reserve_id)
                .await?
                .is_none()
        {
            // Nothing was sent: the paid quote is still mintable, and only
            // its routing fee was spent.
            // The quote counts in full until the mint returns notes.
            self.true_up(&reserve_id, Some(rec.amount + rec.fee_sat))
                .await?;
            let _ = self.mint_quote(&q.quote).await;
        }
        step
    }

    /// Sends an operation's request and settles it from the answer.
    async fn send_op(&self, cx: &Ctx<'_>, op: OpRecord) -> Result<Step> {
        let mut op = op;
        let mut waited = 0u64;
        loop {
            let sent = self.transport.send(op.request.clone()).await;
            let resp = match sent {
                Ok(r) => r,
                Err(e) => {
                    self.set_op_state(
                        &mut op,
                        OpState::Pending {
                            retry_at: self.now() + 30,
                        },
                    )
                    .await?;
                    return Err(Refusal::new(
                        Code::Network,
                        format!(
                            "The paid request may not have arrived ({e}). Run `bnap resume` to replay it; it is never paid twice."
                        ),
                    ));
                }
            };
            match self.settle_op(&mut op, &resp, Some(&cx.limits)).await {
                Err(r)
                    if r.code == Code::Pending
                        && r.retry_after.is_some_and(|s| s <= 5)
                        && waited < 10 =>
                {
                    let s = r.retry_after.unwrap_or(1).max(1);
                    waited += s;
                    tokio::time::sleep(std::time::Duration::from_secs(s)).await;
                }
                other => return other,
            }
        }
    }

    async fn set_op_state(&self, op: &mut OpRecord, s: OpState) -> Result<()> {
        op.state = s;
        self.store.put(kind::OP, &op.id, op).await
    }

    /// Sets a ledger entry's final cost.
    pub(crate) async fn true_up(&self, id: &str, actual: Option<u64>) -> Result<()> {
        let mut tx = self.store.tx().await?;
        if let Some(mut e) = tx.get::<policy::LedgerEntry>(kind::LEDGER, id).await? {
            e.actual = actual;
            tx.put(kind::LEDGER, id, &e).await?;
        }
        tx.commit().await
    }

    /// Settles an operation from the server's answer: the receipt (checked
    /// against the pin), the change (every DLEQ checked), the notes, the
    /// ledger and the receipt record, in one transaction.
    async fn settle_op(
        &self,
        op: &mut OpRecord,
        resp: &HttpResponse,
        limits: Option<&Limits>,
    ) -> Result<Step> {
        let now = self.now();
        let limits = limits.copied().unwrap_or_default();
        if let Some(bytes) = receipt_bytes(resp) {
            return self.settle_receipt(op, resp, &bytes, &limits, now).await;
        }
        let Some(err) = Challenges::parse(resp).error else {
            self.set_op_state(op, OpState::Pending { retry_at: now + 30 })
                .await?;
            return Err(Refusal::new(
                Code::BadReceipt,
                format!(
                    "The server answered {} with no receipt and no error. Run `bnap resume` to fetch the receipt.",
                    resp.status
                ),
            ));
        };
        let refusal = Refusal::from_server(&err);
        match err.socket_code() {
            Some(ErrorCode::Pending) => {
                let wait = err.retry_after.unwrap_or(5);
                self.set_op_state(
                    op,
                    OpState::Pending {
                        retry_at: now + wait,
                    },
                )
                .await?;
                Err(refusal)
            }
            Some(ErrorCode::Unavailable) | None => {
                // Maybe committed, maybe not: keep it for a replay.
                self.set_op_state(op, OpState::Pending { retry_at: now + 30 })
                    .await?;
                Err(refusal)
            }
            Some(ErrorCode::Spent) => {
                self.close_op(op, true).await?;
                Err(refusal.with_paid(op.lightning_sat))
            }
            Some(code) => {
                // Refused before the commit: nothing was consumed.
                self.close_op(op, false).await?;
                let mut refusal = refusal;
                if let Some(q) = op.quote.clone() {
                    let minted = self.mint_quote(&q).await.unwrap_or(0);
                    let _ = write!(
                        refusal.message,
                        " The fund quote was paid over Lightning; {}",
                        if minted > 0 {
                            "it was minted into notes."
                        } else {
                            "it could not be minted yet and counts against the caps; `bnap resume` retries."
                        }
                    );
                }
                // A fresh offer is tried again only when nothing went out
                // over Lightning for this one.
                let retry = matches!(
                    code,
                    ErrorCode::BadOffer | ErrorCode::Stale | ErrorCode::WrongScope
                ) && op.lightning_sat == 0
                    && op.quote.is_none();
                if retry && resp.status == 402 {
                    return Ok(Step::Retry(resp.clone()));
                }
                Err(refusal.with_paid(op.lightning_sat))
            }
        }
    }

    /// Ends an operation that got no receipt: its notes are spent (`spent`)
    /// or back to unspent, and its cost is what went out over Lightning,
    /// plus the notes when they are lost.
    async fn close_op(&self, op: &OpRecord, spent: bool) -> Result<()> {
        let mut tx = self.store.tx().await?;
        for k in &op.notes {
            if let Some(mut n) = tx.get::<NoteRecord>(kind::NOTE, k).await? {
                n.state = if spent {
                    NoteState::Spent
                } else {
                    NoteState::Unspent
                };
                tx.put(kind::NOTE, k, &n).await?;
            }
        }
        // A paid quote counts in full until it is minted into notes
        // (`mint_quote` takes its amount off this entry then): an issuer
        // that refuses the mint keeps the payment.
        let (quote_value, quote_fee) = match &op.quote {
            Some(q) => tx
                .get::<QuoteRecord>(kind::QUOTE, q)
                .await?
                .map_or((0, 0), |q| (q.amount, q.fee_sat)),
            None => (0, 0),
        };
        let actual = op.lightning_sat + quote_fee + quote_value + if spent { op.face } else { 0 };
        if let Some(mut e) = tx
            .get::<policy::LedgerEntry>(kind::LEDGER, &op.ledger)
            .await?
        {
            e.actual = Some(actual);
            tx.put(kind::LEDGER, &op.ledger, &e).await?;
        }
        // A Lightning payment the server refused stays provable: the
        // invoice and its preimage are kept as a receipt.
        if let (Some(invoice), Some(preimage)) = (&op.invoice, op.preimage) {
            let rec = ReceiptRecord {
                id: op.id.clone(),
                kind: ReceiptKind::Native,
                origin: op.origin.clone(),
                method: op.request.method.clone(),
                url: op.request.url.clone(),
                scheme: op.scheme.clone(),
                at: self.now(),
                cost_sat: actual,
                charged: 0,
                unit: Some("sat".into()),
                ok: false,
                change_ok: true,
                offer: op.offer.clone(),
                credential: op.credential.clone(),
                response: Vec::new(),
                manifest: Vec::new(),
                action_scope: op.action_scope,
                invoice: Some(invoice.clone()),
                preimage: Some(preimage),
            };
            tx.put(kind::RECEIPT, &rec.id, &rec).await?;
        }
        tx.delete(kind::OP, &op.id).await?;
        tx.commit().await
    }

    #[allow(clippy::too_many_lines)]
    async fn settle_receipt(
        &self,
        op: &mut OpRecord,
        resp: &HttpResponse,
        bytes: &[u8],
        limits: &Limits,
        now: u64,
    ) -> Result<Step> {
        let pin = self
            .store
            .get::<PinRecord>(kind::PIN, &op.origin)
            .await?
            .ok_or_else(|| Refusal::storage("the origin's pin is gone"))?;
        let offer = Offer::parse_with_limit(&op.offer, limits.max_offer)
            .map_err(|e| Refusal::storage(format!("a stored offer does not parse: {e}")))?;
        let response = match Response::parse_with_limit(bytes, limits.max_response) {
            Ok(r) => r,
            Err(e) => {
                return self
                    .dispute(op, format!("the receipt does not parse: {e}"))
                    .await;
            }
        };
        let digest = bnap_core::hash::Digest(op.digest);
        if let Err(e) = response.check_client(&pin.keys, now, &offer.offer_id(), &digest) {
            return self
                .dispute(op, format!("the receipt fails its checks: {e}"))
                .await;
        }
        let f = response.fields();
        let charged = f.charged;
        let mut change = Vec::new();
        let mut change_ok = true;
        if !op.outputs.is_empty() {
            let seed = self.seed().await?;
            let pending: Vec<PendingOutput> = op
                .outputs
                .iter()
                .filter_map(|o| {
                    let d = notes::derive(&*seed, &o.keyset, o.counter)?;
                    Some(PendingOutput {
                        output: bnap_scheme_notes::Output {
                            keyset: o.keyset,
                            amount: o.amount,
                            blinded: d.blinded,
                        },
                        derived: d,
                    })
                })
                .collect();
            let issuer = op.issuer.clone().unwrap_or_default();
            let mut table = notes::KeyTable::new();
            for o in &op.outputs {
                if let std::collections::btree_map::Entry::Vacant(e) = table.entry(o.keyset) {
                    let k = self.keyset_keys(&op.origin, &issuer, &o.keyset).await?;
                    e.insert(k.points());
                }
            }
            let charged_value = if f.status == Status::Ok { charged } else { 0 };
            match notes::recover_change(
                &pending,
                notes::key_lookup(&table),
                op.value,
                charged_value,
                f.scheme_result.as_deref(),
            ) {
                Ok(r) => {
                    change_ok = r.matches_rule;
                    for n in &r.notes {
                        change.push(
                            NoteRecord::from_note(n, &op.origin, &issuer)
                                .map_err(Refusal::storage)?,
                        );
                    }
                }
                Err(e) => {
                    return self
                        .dispute(op, format!("the change fails its checks: {e}"))
                        .await;
                }
            }
        }
        let change_sat: u64 = change.iter().map(|n| n.amount).sum();
        let mut tx = self.store.tx().await?;
        for k in &op.notes {
            if let Some(mut n) = tx.get::<NoteRecord>(kind::NOTE, k).await? {
                n.state = NoteState::Spent;
                tx.put(kind::NOTE, k, &n).await?;
            }
        }
        for n in &change {
            tx.put(kind::NOTE, &hex::encode(n.k), n).await?;
        }
        let mut quote_value = 0;
        let mut quote_fee = 0;
        if let Some(qid) = &op.quote
            && let Some(mut q) = tx.get::<QuoteRecord>(kind::QUOTE, qid).await?
        {
            quote_value = q.amount;
            quote_fee = q.fee_sat;
            q.state = QuoteState::Redeemed;
            tx.put(kind::QUOTE, qid, &q).await?;
        }
        // Change and refunds are notes of this operator, its IOU. They give
        // back only the face of the notes this request spent; what went out
        // over Lightning (a quote funded in the 402, a fee) counts in full,
        // or an operator could hand the value back as notes again and again
        // and take sats past the caps.
        let cost = op.face.saturating_sub(change_sat) + quote_value + quote_fee + op.lightning_sat;
        if let Some(mut e) = tx
            .get::<policy::LedgerEntry>(kind::LEDGER, &op.ledger)
            .await?
        {
            e.actual = Some(cost);
            tx.put(kind::LEDGER, &op.ledger, &e).await?;
        }
        let url = op.request.url.clone();
        let rec = ReceiptRecord {
            id: op.id.clone(),
            kind: ReceiptKind::Bnap,
            origin: op.origin.clone(),
            method: op.request.method.clone(),
            url,
            scheme: op.scheme.clone(),
            at: now,
            cost_sat: cost,
            charged,
            unit: f.unit.clone(),
            ok: f.status == Status::Ok,
            change_ok,
            offer: op.offer.clone(),
            credential: op.credential.clone(),
            response: bytes.to_vec(),
            manifest: pin.manifest.clone(),
            action_scope: op.action_scope,
            invoice: op.invoice.clone(),
            preimage: op.preimage,
        };
        tx.put(kind::RECEIPT, &rec.id, &rec).await?;
        tx.delete(kind::OP, &op.id).await?;
        tx.commit().await?;
        Ok(Step::Done(FetchResult {
            status: resp.status,
            headers: resp.headers.clone(),
            body: resp.body.clone(),
            payment: Some(Payment {
                origin: op.origin.clone(),
                scheme: op.scheme.clone(),
                cost_sat: cost,
                charged,
                unit: f.unit.clone(),
                ok: f.status == Status::Ok,
                receipt: rec.id,
                replayed: f.replayed,
            }),
        }))
    }

    async fn dispute(&self, op: &mut OpRecord, reason: String) -> Result<Step> {
        self.set_op_state(
            op,
            OpState::Disputed {
                reason: reason.clone(),
            },
        )
        .await?;
        Err(Refusal::new(
            Code::BadReceipt,
            format!(
                "{reason}. The credential and the answer are kept as evidence; the notes stay locked."
            ),
        ))
    }

    /// Pays a native challenge of an origin the wallet has no pin for
    /// (draft-00 9.3 "always"): the client has no signed offer to compare
    /// it with, so it pays exactly what the invoice asks, within the
    /// policy and the caps.
    #[allow(clippy::too_many_lines)]
    async fn pay_native(
        &self,
        cfg: &Config,
        caps: Caps,
        base: &HttpRequest,
        origin: &str,
        natives: &[String],
    ) -> Result<FetchResult> {
        let p = &cfg.policy;
        let now = self.now();
        let mut cands = Vec::new();
        let mut refusal = None;
        for (i, text) in natives.iter().enumerate() {
            let scheme = if bnap_scheme_l402::Challenge::parse(text).is_ok() {
                bnap_scheme_l402::SCHEME_ID
            } else if bnap_scheme_mpp::challenge::Challenge::parse(text).is_ok() {
                bnap_scheme_mpp::SCHEME_ID
            } else {
                continue;
            };
            let v = match p.admit_scheme(self.registry, scheme) {
                Ok(v) => v,
                Err(r) => {
                    refusal.get_or_insert(r);
                    continue;
                }
            };
            let Some(inv) = lightning_invoice(scheme, text) else {
                continue;
            };
            let Some(amount) = inv.amount_sat() else {
                continue;
            };
            if inv.expires_at <= now {
                continue;
            }
            cands.push((
                Candidate {
                    offer: i,
                    entry: 0,
                    scheme: scheme.into(),
                    value_sat: amount,
                    fee_sat: p.fee.max_fee(amount),
                    linkable: crate::registry::linkable(&v),
                },
                text.clone(),
                inv,
            ));
        }
        let ranked = rank::rank(cands.iter().map(|c| c.0.clone()).collect(), p);
        let Some(best) = ranked.first() else {
            return Err(refusal.unwrap_or_else(|| {
                Refusal::new(
                    Code::NoOffer,
                    "The server sent no challenge this wallet can pay.",
                )
            }));
        };
        let (cand, text, inv) = cands
            .into_iter()
            .find(|c| c.0 == *best)
            .expect("the ranked candidate is one of them");
        let pay = self
            .pay_source(cfg)
            .ok_or_else(|| Refusal::new(Code::NoPaySource, "No pay source is configured. A person can set one with `bnap paysource nwc <uri>`."))?;
        let id = random_id();
        let cx_caps = caps;
        let mut tx = self.store.tx().await?;
        let ledger: Vec<policy::LedgerEntry> = tx.list(kind::LEDGER).await?;
        policy::check(&cx_caps, &ledger, origin, &self.task, cand.cost(), now)?;
        tx.put(
            kind::LEDGER,
            &id,
            &policy::LedgerEntry {
                id: id.clone(),
                origin: origin.to_owned(),
                task: self.task.clone(),
                at: now,
                reserved: cand.cost(),
                actual: None,
                what: format!("{} {} (native)", base.method, base.url),
            },
        )
        .await?;
        tx.commit().await?;
        let invoice_text = lightning_invoice_text(&cand.scheme, &text).unwrap_or_default();
        let paid = match pay
            .pay_invoice(&invoice_text, cand.value_sat, cand.fee_sat)
            .await
        {
            Ok(p) if sha256(&p.preimage) == inv.payment_hash => p,
            Ok(_) => {
                self.true_up(&id, Some(cand.cost())).await?;
                return Err(Refusal::new(
                    Code::PaymentFailed,
                    "The pay source returned a preimage that does not open the invoice. The payment is counted as spent.",
                ));
            }
            Err(e) => return Err(uncertain(e)),
        };
        let cost = cand.value_sat + paid.fee_sat;
        self.true_up(&id, Some(cost)).await?;
        // The invoice and its preimage are kept before the paid request
        // goes out: they prove the payment whatever happens next.
        let mut rec = ReceiptRecord {
            id: id.clone(),
            kind: ReceiptKind::Native,
            origin: origin.to_owned(),
            method: base.method.clone(),
            url: base.url.clone(),
            scheme: Some(cand.scheme.clone()),
            at: self.now(),
            cost_sat: cost,
            charged: cand.value_sat,
            unit: Some("sat".into()),
            ok: false,
            change_ok: true,
            offer: Vec::new(),
            credential: Vec::new(),
            response: Vec::new(),
            manifest: Vec::new(),
            action_scope: [0; 32],
            invoice: Some(invoice_text),
            preimage: Some(paid.preimage),
        };
        self.store.put(kind::RECEIPT, &id, &rec).await?;
        let auth = native_authorization(&cand.scheme, &text, paid.preimage)?;
        let mut req = base.clone();
        req.headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("authorization"));
        req.headers.push(("Authorization".into(), auth));
        let resp = self.transport.send(req).await.map_err(|e| {
            let mut r = Refusal::network(e).with_paid(cost);
            let _ = write!(r.message, " The payment's proof is kept as receipt {id}.");
            r
        })?;
        rec.ok = (200..300).contains(&resp.status);
        rec.response = receipt_bytes(&resp).unwrap_or_default();
        self.store.put(kind::RECEIPT, &id, &rec).await?;
        Ok(FetchResult {
            status: resp.status,
            headers: resp.headers.clone(),
            body: resp.body,
            payment: Some(Payment {
                origin: origin.to_owned(),
                scheme: Some(cand.scheme),
                cost_sat: cost,
                charged: cand.value_sat,
                unit: Some("sat".into()),
                ok: rec.ok,
                receipt: id,
                replayed: false,
            }),
        })
    }

    /// Replays every operation without a final answer (draft-00 6.4;
    /// bnap:notes 15), and mints every paid quote not yet used.
    pub async fn resume(&self) -> Result<Vec<ResumeOutcome>> {
        let ops: Vec<OpRecord> = self.store.list(kind::OP).await?;
        let mut out = Vec::new();
        for mut op in ops {
            if matches!(op.state, OpState::Disputed { .. }) {
                out.push(ResumeOutcome {
                    id: op.id.clone(),
                    result: Err(Refusal::new(
                        Code::BadReceipt,
                        "Disputed: kept as evidence.",
                    )),
                });
                continue;
            }
            let r = match self.transport.send(op.request.clone()).await {
                Ok(resp) => self.settle_op(&mut op, &resp, None).await.map(|s| match s {
                    Step::Done(r) => r.payment,
                    Step::Retry(_) => None,
                }),
                Err(e) => Err(Refusal::network(e)),
            };
            out.push(ResumeOutcome {
                id: op.id,
                result: r,
            });
        }
        let quotes: Vec<QuoteRecord> = self.store.list(kind::QUOTE).await?;
        for q in &quotes {
            if q.state == QuoteState::Unpaid {
                // Paid late, perhaps: mint it if the issuer says so.
                let _ = self.mint_quote(&q.id).await;
                continue;
            }
            if q.state != QuoteState::Paid {
                continue;
            }
            let r = self.mint_quote(&q.id).await.map(|_| None);
            out.push(ResumeOutcome {
                id: q.id.clone(),
                result: r,
            });
        }
        Ok(out)
    }
}

/// A pay source error: the payment may still settle (a timeout, a hold
/// invoice), so its reservation stays counted against the caps.
fn uncertain(mut e: Refusal) -> Refusal {
    e.message.push_str(
        " It may still settle, so its reservation stays counted against the caps; `bnap resume` collects a late payment.",
    );
    e
}

/// What resuming one operation gave.
#[derive(Debug, Clone, Serialize)]
pub struct ResumeOutcome {
    /// Operation or quote ID.
    pub id: String,
    /// What came of it.
    pub result: std::result::Result<Option<Payment>, Refusal>,
}

fn lightning_invoice_text(scheme: &str, challenge: &str) -> Option<String> {
    match scheme {
        bnap_scheme_l402::SCHEME_ID => bnap_scheme_l402::Challenge::parse(challenge)
            .ok()
            .map(|c| c.invoice),
        bnap_scheme_mpp::SCHEME_ID => {
            let c = bnap_scheme_mpp::challenge::Challenge::parse(challenge).ok()?;
            let r = bnap_scheme_mpp::lightning::ChargeRequest::decode(&c.request).ok()?;
            Some(r.invoice)
        }
        _ => None,
    }
}

/// The invoice of a Lightning challenge, decoded and checked against the
/// challenge's own statement of it (MPP's request repeats the amount and
/// the payment hash).
fn lightning_invoice(scheme: &str, challenge: &str) -> Option<Invoice> {
    let text = lightning_invoice_text(scheme, challenge)?;
    let inv = Invoice::decode(&text).ok()?;
    if scheme == bnap_scheme_mpp::SCHEME_ID {
        let c = bnap_scheme_mpp::challenge::Challenge::parse(challenge).ok()?;
        let r = bnap_scheme_mpp::lightning::ChargeRequest::decode(&c.request).ok()?;
        if inv.amount_sat() != Some(r.amount) || inv.payment_hash != r.payment_hash {
            return None;
        }
    }
    Some(inv)
}

fn lightning_body(scheme: &str, challenge: &str, preimage: [u8; 32]) -> Result<Vec<u8>> {
    let bad = |e: &dyn std::fmt::Display| {
        Refusal::new(Code::BadOffer, format!("cannot answer the challenge: {e}"))
    };
    match scheme {
        bnap_scheme_l402::SCHEME_ID => {
            let c = bnap_scheme_l402::Challenge::parse(challenge).map_err(|e| bad(&e))?;
            let t = bnap_scheme_l402::Token::new(&c.token, preimage).map_err(|e| bad(&e))?;
            Ok(t.to_string().into_bytes())
        }
        bnap_scheme_mpp::SCHEME_ID => {
            let c = bnap_scheme_mpp::challenge::Challenge::parse(challenge).map_err(|e| bad(&e))?;
            Ok(bnap_scheme_mpp::lightning::Credential::new(c, preimage)
                .encode()
                .into_bytes())
        }
        other => Err(bad(&format!("unknown scheme {other}"))),
    }
}

fn native_authorization(scheme: &str, challenge: &str, preimage: [u8; 32]) -> Result<String> {
    let bad = |e: &dyn std::fmt::Display| {
        Refusal::new(Code::BadOffer, format!("cannot answer the challenge: {e}"))
    };
    if scheme == bnap_scheme_l402::SCHEME_ID {
        let c = bnap_scheme_l402::Challenge::parse(challenge).map_err(|e| bad(&e))?;
        let t = bnap_scheme_l402::Token::new(&c.token, preimage).map_err(|e| bad(&e))?;
        return Ok(bnap_scheme_l402::authorization(&t));
    }
    let body = lightning_body(scheme, challenge, preimage)?;
    let token = String::from_utf8(body).map_err(|e| bad(&e))?;
    Ok(bnap_scheme_mpp::challenge::authorization(&token))
}
