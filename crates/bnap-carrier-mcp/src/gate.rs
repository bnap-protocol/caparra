//! The gate behind [`crate::PricedTools`]: offers, the 4.4 checks, scheme
//! verification, rail confirmation, `bnap_core::outcome::process`, the
//! tool call, settlement and the receipt, for one `tools/call`.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bnap_core::credential::{CredentialParse, SchemePart, native_context, native_digest};
use bnap_core::hash::{Context, Digest, OfferId, RailId, Scope};
use bnap_core::limits::Limits;
use bnap_core::offer::{AttestEntry, Effect, GateOfferCheck, NativeEntry, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ReceiptInput, Recorded, Request};
use bnap_core::pricing::{ChangeCap, PayValue, VerifiedAttest};
use bnap_core::response::{Response, Status};
use bnap_core::secp256k1::rand::{RngCore, thread_rng};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{SchemeUses, Settlement};
use bnap_core::{Credential, ErrorCode, ErrorObject, Offer, SettleError};
use bnap_plug::{
    CappedSigner, Entry, NativeCtx, OfferCtx, OfferRole, RailPayment, SchemeError, SettleCtx,
    Verified, VerifyCtx, confirm_rail_id,
};
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ErrorCode as RpcCode};
use serde_json::{Map, Value, json};

use crate::config::{
    ConfigError, DEFAULT_MAX_KEPT, DEFAULT_OFFER_CACHE, DEFAULT_OFFER_LIFETIME, GateConfig,
    SchemeConfig, ToolPrice, system_clock,
};
use crate::scope::{ScopeError, action_scope, arguments_jcs};
use crate::wire::{self, ErrorData, b64u, from_b64u};
use crate::{Clock, mpp};

/// What a call carried in `params._meta`, taken out before the tool runs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Presented {
    /// The value of [`wire::CREDENTIAL`], if present.
    pub bnap: Option<Value>,
    /// The value of [`wire::MPP_CREDENTIAL`], if present.
    pub mpp: Option<Value>,
}

/// Why a call is refused: the Error object, and whether a fresh offer may
/// go with it.
#[derive(Debug, Clone)]
struct Refusal(ErrorObject);

impl Refusal {
    fn code(code: ErrorCode) -> Self {
        Self(ErrorObject::new(code))
    }

    fn detail(code: ErrorCode, detail: &str) -> Self {
        Self(ErrorObject::new(code).with_detail(detail))
    }

    fn socket(&self) -> ErrorCode {
        self.0.socket_code().unwrap_or(ErrorCode::Unavailable)
    }
}

impl From<&bnap_core::Error> for Refusal {
    fn from(e: &bnap_core::Error) -> Self {
        Self::code(e.code())
    }
}

impl From<&SchemeError> for Refusal {
    fn from(e: &SchemeError) -> Self {
        Self(e.to_error_object())
    }
}

/// What the action and its settlement produced, before the receipt.
enum Answer {
    Result(CallToolResult),
    Error(McpError),
    /// A replay of an outcome whose answer was not kept: the receipt alone.
    ReceiptOnly,
}

/// What a kept answer looks like in the outcome record.
fn keep(answer: &Answer, max: usize) -> Option<Vec<u8>> {
    let v = match answer {
        Answer::Result(r) => json!({ "result": r }),
        Answer::Error(e) => json!({ "error": e }),
        Answer::ReceiptOnly => return None,
    };
    let bytes = serde_json::to_vec(&v).ok()?;
    (bytes.len() <= max).then_some(bytes)
}

fn kept(bytes: Option<&[u8]>) -> Answer {
    let Some(v) = bytes.and_then(|b| serde_json::from_slice::<Value>(b).ok()) else {
        return Answer::ReceiptOnly;
    };
    if let Some(r) = v
        .get("result")
        .and_then(|r| serde_json::from_value::<CallToolResult>(r.clone()).ok())
    {
        return Answer::Result(r);
    }
    if let Some(e) = v
        .get("error")
        .and_then(|e| serde_json::from_value::<McpError>(e.clone()).ok())
    {
        return Answer::Error(e);
    }
    Answer::ReceiptOnly
}

/// Issued offers, by `OfferID`, until they expire (5.1).
#[derive(Debug, Default)]
struct OfferCache {
    offers: HashMap<OfferId, Offer>,
}

impl OfferCache {
    fn insert(&mut self, offer: Offer, now: u64, cap: usize) {
        let skew = bnap_core::limits::CLOCK_SKEW;
        self.offers
            .retain(|_, o| o.fields().expires.saturating_add(skew) >= now);
        while self.offers.len() >= cap.max(1) {
            let Some(oldest) = self
                .offers
                .iter()
                .min_by_key(|(_, o)| o.fields().expires)
                .map(|(id, _)| *id)
            else {
                break;
            };
            self.offers.remove(&oldest);
        }
        self.offers.insert(offer.offer_id(), offer);
    }

    fn get(&self, id: &OfferId) -> Option<Offer> {
        self.offers.get(id).cloned()
    }
}

/// The gate: one per server, shared by every session's [`crate::PricedTools`].
pub struct Gate {
    cfg: GateConfig,
    offers: Mutex<OfferCache>,
    denied_tasks: Mutex<std::collections::VecDeque<String>>,
}

/// How many task IDs of priced calls the gate remembers to deny.
const DENIED_TASKS: usize = 4096;

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("server_uri", &self.cfg.server_uri)
            .field("schemes", &self.cfg.schemes.keys().collect::<Vec<_>>())
            .field("tools", &self.cfg.tools.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Builds a [`Gate`].
pub struct GateBuilder {
    cfg: GateConfig,
}

impl std::fmt::Debug for GateBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateBuilder")
            .field("server_uri", &self.cfg.server_uri)
            .finish_non_exhaustive()
    }
}

impl GateBuilder {
    /// Adds a scheme, under its plug's ID.
    #[must_use]
    pub fn scheme(mut self, s: SchemeConfig) -> Self {
        self.cfg.schemes.insert(s.plug.id().to_owned(), s);
        self
    }

    /// Adds a rail, under its kind.
    #[must_use]
    pub fn rail(mut self, rail: Arc<dyn bnap_plug::FundingRail>) -> Self {
        self.cfg.rails.insert(rail.kind().to_owned(), rail);
        self
    }

    /// Prices a tool.
    #[must_use]
    pub fn tool(mut self, name: &str, price: ToolPrice) -> Self {
        self.cfg.tools.insert(name.to_owned(), price);
        self
    }

    /// Sets the limits (from the manifest).
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.cfg.limits = limits;
        self
    }

    /// Adds a retained `K_mac`, accepted but no longer used for new offers.
    #[must_use]
    pub fn retained_mac_key(mut self, key: [u8; 32]) -> Self {
        self.cfg.mac_keys.push(key);
        self
    }

    /// Sets the exact-scope offer lifetime.
    #[must_use]
    pub fn offer_lifetime(mut self, secs: u64) -> Self {
        self.cfg.offer_lifetime = secs;
        self
    }

    /// Sets the clock.
    #[must_use]
    pub fn clock(mut self, clock: Clock) -> Self {
        self.cfg.clock = clock;
        self
    }

    /// Sets the largest tool result kept for replays (0 keeps none).
    #[must_use]
    pub fn max_kept(mut self, bytes: usize) -> Self {
        self.cfg.max_kept = bytes;
        self
    }

    /// Sets the offer cache size.
    #[must_use]
    pub fn offer_cache(mut self, n: usize) -> Self {
        self.cfg.offer_cache = n;
        self
    }

    /// Checks the configuration and builds the gate.
    pub fn build(self) -> Result<Gate, ConfigError> {
        let cfg = self.cfg;
        if cfg.mac_keys.is_empty() {
            return Err(ConfigError::NoMacKey);
        }
        cfg.limits.validate()?;
        cfg.limits.check_offer_lifetime(cfg.offer_lifetime)?;
        for (tool, price) in &cfg.tools {
            let names = price
                .pay
                .iter()
                .map(|p| &p.scheme)
                .chain(price.attest.iter().map(|a| &a.scheme));
            for scheme in names {
                if !cfg.schemes.contains_key(scheme) {
                    return Err(ConfigError::UnknownScheme {
                        tool: tool.clone(),
                        scheme: scheme.clone(),
                    });
                }
            }
            if price.pay.is_empty() && !price.attest.iter().any(|a| a.effect == Effect::Waive) {
                return Err(ConfigError::NoPay(tool.clone()));
            }
        }
        Ok(Gate {
            cfg,
            offers: Mutex::new(OfferCache::default()),
            denied_tasks: Mutex::new(std::collections::VecDeque::new()),
        })
    }
}

/// A verified value scheme: its entry, what it verified, and what the
/// rails confirmed.
struct PayChecked<'a> {
    entry: &'a PayEntry,
    verified: Verified,
    rail_ids: Vec<RailId>,
    backing: Vec<bnap_core::pricing::Backing>,
}

/// One credential on its way through the socket.
struct Call<'a> {
    tool: &'a str,
    price: &'a ToolPrice,
    scope: Scope,
    offer: Offer,
    context: Context,
    digest: Digest,
    pay: Option<(&'a SchemeConfig, SchemePart)>,
    attest: Vec<(Option<&'a SchemeConfig>, SchemePart)>,
    /// The credential came in the MPP key: an MPP receipt goes back too.
    native_mpp: bool,
    now: u64,
}

impl Gate {
    /// A builder with the required parts: the server URI, the store, the
    /// signer with its offer and receipt keys, and the current `K_mac`.
    #[must_use]
    pub fn builder(
        server_uri: &str,
        store: Arc<dyn bnap_core::store::UseStore>,
        signer: Arc<dyn bnap_plug::Signer>,
        offer_key: bnap_core::schnorr::Key,
        receipt_key: bnap_core::schnorr::Key,
        mac_key: [u8; 32],
    ) -> GateBuilder {
        GateBuilder {
            cfg: GateConfig {
                server_uri: server_uri.to_owned(),
                store,
                signer,
                offer_key,
                receipt_key,
                mac_keys: vec![mac_key],
                limits: Limits::default(),
                offer_lifetime: DEFAULT_OFFER_LIFETIME,
                schemes: BTreeMap::new(),
                rails: BTreeMap::new(),
                tools: BTreeMap::new(),
                clock: system_clock(),
                max_kept: DEFAULT_MAX_KEPT,
                offer_cache: DEFAULT_OFFER_CACHE,
            },
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &GateConfig {
        &self.cfg
    }

    /// The price of `tool`, or `None` for a free tool.
    #[must_use]
    pub fn price(&self, tool: &str) -> Option<&ToolPrice> {
        self.cfg.tools.get(tool)
    }

    /// The action scope of a call to `tool` with `arguments` on this server.
    pub fn scope(
        &self,
        tool: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> Result<Scope, ScopeError> {
        action_scope(&self.cfg.server_uri, tool, arguments)
    }

    /// Records the task a priced tool answered with: the call settled
    /// FAILED, so the task is cancelled and its ID never served (`tasks/*`
    /// are not priced).
    pub fn deny_task(&self, task_id: &str) {
        let mut d = self
            .denied_tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if d.len() >= DENIED_TASKS {
            d.pop_front();
        }
        d.push_back(task_id.to_owned());
    }

    /// True for the task of a priced call ([`Self::deny_task`]).
    #[must_use]
    pub fn task_denied(&self, task_id: &str) -> bool {
        self.denied_tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|t| t == task_id)
    }

    fn cached(&self, id: &OfferId) -> Option<Offer> {
        self.offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
    }

    fn check(&self, now: u64, scope: Scope) -> GateOfferCheck<'_> {
        GateOfferCheck {
            now,
            max_offer: self.cfg.limits.max_offer,
            mac_keys: &self.cfg.mac_keys,
            offer_keys: &[],
            action_scope: scope,
            route_scope: None,
        }
    }

    /// Runs one priced `tools/call`. `strict` says the message was read by
    /// [`crate::strict`]; `presented` is what `_meta` carried; `action`
    /// runs the tool. The action runs at most once, and only after the
    /// commit.
    pub async fn call<F, Fut>(
        &self,
        params: CallToolRequestParams,
        presented: Presented,
        strict: bool,
        action: F,
    ) -> Result<CallToolResponse, McpError>
    where
        F: FnOnce(CallToolRequestParams) -> Fut,
        Fut: Future<Output = Result<CallToolResponse, McpError>>,
    {
        let now = (self.cfg.clock)();
        let tool = params.name.to_string();
        let Some(price) = self.cfg.tools.get(&tool) else {
            return action(params).await;
        };
        if !strict {
            tracing::error!(
                tool,
                "a priced call was not read by the strict JSON layer; refused"
            );
            return Err(bare(&Refusal::detail(
                ErrorCode::Unavailable,
                "the server does not read calls strictly",
            )));
        }
        // The tool reads inputResponses and requestState, and neither is
        // in the scope: a priced call must complete in one round.
        if params.input_responses.is_some() || params.request_state.is_some() {
            return Err(bare(&Refusal::detail(
                ErrorCode::Malformed,
                "a priced call carries no inputResponses or requestState",
            )));
        }
        let scope = match self.scope(&tool, params.arguments.as_ref()) {
            Ok(s) => s,
            Err(e) => {
                return Err(bare(&Refusal::detail(ErrorCode::Malformed, &e.to_string())));
            }
        };
        // The tool gets the arguments as the scope hashed them: re-read
        // from their JCS bytes, so `2.0` reaches it as `2`.
        let mut params = params;
        {
            let canonical = arguments_jcs(params.arguments.as_ref())
                .ok()
                .and_then(|b| serde_json::from_slice::<Map<String, Value>>(&b).ok());
            let Some(canonical) = canonical else {
                return Err(bare(&Refusal::code(ErrorCode::Malformed)));
            };
            params.arguments = Some(canonical);
        }
        let call = match presented {
            Presented {
                bnap: None,
                mpp: None,
            } => {
                return Err(self
                    .refuse(Refusal::code(ErrorCode::Required), &tool, price, scope, now)
                    .await);
            }
            Presented {
                bnap: Some(_),
                mpp: Some(_),
            } => Err(Refusal::detail(
                ErrorCode::Malformed,
                "more than one credential",
            )),
            Presented {
                bnap: Some(v),
                mpp: None,
            } => self.open_bnap(&v, &tool, price, scope, now),
            Presented {
                bnap: None,
                mpp: Some(v),
            } => self.open_mpp(&v, &tool, price, scope, now).await,
        };
        let call = match call {
            Ok(c) => c,
            Err(r) => return Err(self.refuse(r, &tool, price, scope, now).await),
        };
        match self.run(&call, params, action).await {
            Ok(r) => r,
            Err(r) => Err(self.refuse(r, &tool, price, scope, now).await),
        }
    }

    /// A BNAP Credential: decode, parse, the 4.4 checks, binding.
    fn open_bnap<'a>(
        &'a self,
        v: &Value,
        tool: &'a str,
        price: &'a ToolPrice,
        scope: Scope,
        now: u64,
    ) -> Result<Call<'a>, Refusal> {
        let text = v.as_str().ok_or(Refusal::detail(
            ErrorCode::Malformed,
            "the credential is not a string",
        ))?;
        let max = self.cfg.limits.max_credential;
        let bytes = from_b64u(text, max).map_err(|e| match e {
            wire::B64Error::TooLarge => Refusal::code(ErrorCode::TooLarge),
            _ => Refusal::detail(ErrorCode::Malformed, "the credential is not base64url"),
        })?;
        let cred = Credential::parse_with(
            &bytes,
            &CredentialParse {
                max_credential: max,
                known_ext_types: &[],
            },
        )
        .map_err(|e| Refusal::from(&e))?;
        let offer = self
            .check(now, scope)
            .check_credential(&cred, |id| self.cached(id))
            .map_err(|e| Refusal::from(&e))?;
        // MCP carries no TLS exporter: a bound credential cannot be checked
        // (5.3).
        cred.check_tls_binding(None)
            .map_err(|e| Refusal::from(&e))?;
        cred.check_binding_classes(|s| self.cfg.schemes.get(s).map(|c| c.class))
            .map_err(|e| Refusal::from(&e))?;
        let context = cred.context(&offer.offer_id(), &scope);
        let digest = cred.digest(&context);
        let pay = match &cred.pay {
            Some(p) => Some((
                self.cfg
                    .schemes
                    .get(&p.scheme)
                    .ok_or(Refusal::code(ErrorCode::NotOffered))?,
                p.clone(),
            )),
            None => None,
        };
        let attest = cred
            .attest
            .iter()
            .map(|p| (self.cfg.schemes.get(&p.scheme), p.clone()))
            .collect();
        Ok(Call {
            tool,
            price,
            scope,
            offer,
            context,
            digest,
            pay,
            attest,
            native_mpp: false,
            now,
        })
    }

    /// An MPP credential in the MPP key: the native path of 5.4.
    async fn open_mpp<'a>(
        &'a self,
        v: &Value,
        tool: &'a str,
        price: &'a ToolPrice,
        scope: Scope,
        now: u64,
    ) -> Result<Call<'a>, Refusal> {
        let id = bnap_scheme_mpp::SCHEME_ID;
        let token = mpp::credential_token(v)
            .map_err(|e| Refusal::detail(ErrorCode::Malformed, &e.to_string()))?;
        if token.len() > self.cfg.limits.max_credential {
            return Err(Refusal::code(ErrorCode::TooLarge));
        }
        let cfg = self
            .cfg
            .schemes
            .get(id)
            .ok_or(Refusal::code(ErrorCode::NotOffered))?;
        let recovered = cfg
            .plug
            .recover_native(token.as_bytes(), now)
            .await
            .map_err(|e| Refusal::from(&e))?;
        let offer = self
            .cached(&recovered.offer_id)
            .ok_or(Refusal::code(ErrorCode::BadOffer))?;
        self.check(now, scope)
            .check_native(&offer, id)
            .map_err(|e| Refusal::from(&e))?;
        let context = native_context(&offer.offer_id(), &scope, id);
        let digest = native_digest(&context, token.as_bytes());
        Ok(Call {
            tool,
            price,
            scope,
            offer,
            context,
            digest,
            pay: Some((cfg, recovered.part)),
            attest: Vec::new(),
            native_mpp: true,
            now,
        })
    }

    /// The value scheme: the tool's require, verify, and every rail
    /// confirmed. `None` for a credential without pay.
    async fn verify_pay<'c>(&self, c: &'c Call<'_>) -> Result<Option<PayChecked<'c>>, Refusal> {
        let Some((cfg, part)) = &c.pay else {
            return Ok(None);
        };
        let (_, entry) = c
            .offer
            .fields()
            .pay_entry(cfg.plug.id())
            .ok_or(Refusal::code(ErrorCode::NotOffered))?;
        if !c.price.require.satisfied_by(&cfg.properties) {
            return Err(Refusal::detail(
                ErrorCode::Policy,
                "the scheme does not meet the tool's require",
            ));
        }
        let view = CappedSigner::verify_only(self.cfg.signer.clone(), &entry.unit);
        let verified = cfg
            .plug
            .verify(
                part,
                &VerifyCtx {
                    now: c.now,
                    offer: &c.offer,
                    entry: Entry::Pay(entry),
                    action_scope: &c.scope,
                    context: &c.context,
                    digest: &c.digest,
                    signer: &view,
                },
            )
            .await
            .map_err(|e| Refusal::from(&e))?;
        // The rails confirm every payment the scheme named: the RailId
        // comes from their bytes, the value from what they saw paid.
        let mut payments: Vec<RailPayment> = Vec::new();
        for r in &verified.rail_ids {
            let rail = self.cfg.rails.get(&r.kind).ok_or(Refusal::detail(
                ErrorCode::Unavailable,
                "no rail of that kind",
            ))?;
            payments.push(
                confirm_rail_id(&**rail, r)
                    .await
                    .map_err(|e| Refusal::code(e.code()))?,
            );
        }
        let rail_ids = payments.iter().map(|p| p.rail_id).collect();
        let mut backing: Vec<_> = payments.iter().map(RailPayment::backing).collect();
        backing.extend(view.notes());
        Ok(Some(PayChecked {
            entry,
            verified,
            rail_ids,
            backing,
        }))
    }

    /// The attestations that verify. One that does not has no effect (7);
    /// one whose verifier is down fails the call closed.
    async fn verify_attest<'c>(
        &self,
        c: &'c Call<'_>,
    ) -> Result<Vec<(&'c SchemeConfig, Verified)>, Refusal> {
        let mut attested = Vec::new();
        for (cfg, part) in &c.attest {
            let Some(cfg) = *cfg else { continue };
            let Some(entry) = c.offer.fields().attest_entry(cfg.plug.id()) else {
                continue;
            };
            let view = CappedSigner::verify_only(self.cfg.signer.clone(), "");
            match cfg
                .plug
                .verify(
                    part,
                    &VerifyCtx {
                        now: c.now,
                        offer: &c.offer,
                        entry: Entry::Attest(entry),
                        action_scope: &c.scope,
                        context: &c.context,
                        digest: &c.digest,
                        signer: &view,
                    },
                )
                .await
            {
                Ok(v) => attested.push((cfg, v)),
                Err(SchemeError::Unavailable(d)) => {
                    return Err(Refusal::detail(ErrorCode::Unavailable, &d));
                }
                Err(_) => {}
            }
        }
        Ok(attested)
    }

    /// Verify, confirm, `process`, run, settle and answer with a receipt.
    async fn run<F, Fut>(
        &self,
        c: &Call<'_>,
        params: CallToolRequestParams,
        action: F,
    ) -> Result<Result<CallToolResponse, McpError>, Refusal>
    where
        F: FnOnce(CallToolRequestParams) -> Fut,
        Fut: Future<Output = Result<CallToolResponse, McpError>>,
    {
        let pay = self.verify_pay(c).await?;
        let attested = self.verify_attest(c).await?;
        let attest_bodies: Vec<&[u8]> = c.attest.iter().map(|(_, p)| p.body.as_slice()).collect();
        let verified_attest: Vec<VerifiedAttest> = attested
            .iter()
            .map(|(cfg, v)| {
                let id = cfg.plug.id();
                let a = VerifiedAttest::new(id, cfg.class);
                match v.quota_use_id(id) {
                    Some(q) => a.with_quota_id(q),
                    None => a,
                }
            })
            .collect();
        let mut schemes: Vec<SchemeUses<'_>> = Vec::new();
        let mut pay_value = None;
        if let (Some((cfg, _)), Some(p)) = (&c.pay, &pay) {
            schemes.push(p.verified.uses(cfg.plug.id(), cfg.model));
            pay_value = Some(PayValue {
                scheme: cfg.plug.id(),
                claimed: p.verified.value,
                backing: p.backing.clone(),
                refund: cfg.refund,
            });
        }
        for (cfg, v) in &attested {
            schemes.push(v.uses(cfg.plug.id(), cfg.model));
        }
        let admitted = outcome::process(
            &*self.cfg.store,
            &Request {
                offer: c.offer.fields(),
                context: &c.context,
                pay_body: c.pay.as_ref().map_or(&[][..], |(_, p)| p.body.as_slice()),
                attest_bodies: &attest_bodies,
                schemes: &schemes,
                rail_ids: pay.as_ref().map_or(&[][..], |p| p.rail_ids.as_slice()),
                pay: pay_value,
                attest: &verified_attest,
                now: c.now,
            },
            &self.cfg.limits,
        )
        .await
        .map_err(|e| Refusal(e.to_error_object()))?;
        let verified = pay.as_ref().map(|p| &p.verified);
        // From here the credential is committed: a failure is never
        // answered with a fresh offer, so no client pays twice for it.
        let committed = |r: Refusal| {
            tracing::warn!(error = ?r.0, "a committed call failed to settle or sign");
            Refusal::detail(
                ErrorCode::Unavailable,
                "the committed call could not be answered",
            )
        };
        let (recorded, answer) = self
            .conclude(c, verified, admitted, params, action)
            .await
            .map_err(committed)?;
        let receipt = self
            .sign_receipt(c, pay.as_ref().map(|p| p.entry), &recorded)
            .await
            .map_err(committed)?;
        Ok(Self::answer(c, &recorded, &receipt, answer))
    }

    /// From `process`'s answer to a recorded outcome: a replay answers
    /// from the record (its refund first, if due); a new commit runs the
    /// action and settles it.
    async fn conclude<F, Fut>(
        &self,
        c: &Call<'_>,
        verified: Option<&Verified>,
        admitted: Admitted,
        params: CallToolRequestParams,
        action: F,
    ) -> Result<(Recorded, Answer), Refusal>
    where
        F: FnOnce(CallToolRequestParams) -> Fut,
        Fut: Future<Output = Result<CallToolResponse, McpError>>,
    {
        let pending = match admitted {
            Admitted::Replay(r) => {
                let r = if r.needs_refund() {
                    self.refund(c, verified, &r).await?
                } else {
                    r
                };
                let answer = kept(r.record().response.as_deref());
                return Ok((r, answer));
            }
            Admitted::New(pending) => pending,
        };
        let answer = self.act(c, params, action).await;
        let status = match &answer {
            Answer::Result(r) if r.is_error != Some(true) => Status::Ok,
            _ => Status::Failed,
        };
        let charge = pending.charge(status, 0);
        let result = self
            .settle_scheme(c, verified, charge.cap(), charge.charged())
            .await?;
        let s = Settlement::new(&charge, (self.cfg.clock)())
            .with_scheme_result(result)
            .with_response(keep(&answer, self.cfg.max_kept));
        match outcome::settle(&*self.cfg.store, &pending, &s, &self.cfg.limits).await {
            Ok(r) => Ok((r, answer)),
            // The timeout won: the OK result is discarded, the answer is
            // the FAILED record.
            Err(SettleError::AlreadySettled(r)) => {
                let r = if r.needs_refund() {
                    self.refund(c, verified, &r).await?
                } else {
                    *r
                };
                Ok((r, Answer::ReceiptOnly))
            }
            Err(_) => Err(Refusal::code(ErrorCode::Unavailable)),
        }
    }

    /// Runs the tool, at most until `pending_timeout` after the commit's
    /// clock (6.4: an action still running then is discarded).
    async fn act<F, Fut>(&self, c: &Call<'_>, params: CallToolRequestParams, action: F) -> Answer
    where
        F: FnOnce(CallToolRequestParams) -> Fut,
        Fut: Future<Output = Result<CallToolResponse, McpError>>,
    {
        let elapsed = (self.cfg.clock)().saturating_sub(c.now);
        let limit = Duration::from_secs(self.cfg.limits.pending_timeout.saturating_sub(elapsed));
        match tokio::time::timeout(limit, action(params)).await {
            Ok(Ok(CallToolResponse::Complete(r))) => Answer::Result(r),
            Ok(Ok(_)) => Answer::Error(McpError::new(
                RpcCode::INTERNAL_ERROR,
                "a priced tool must complete in one call",
                None,
            )),
            Ok(Err(e)) => Answer::Error(e),
            Err(_) => Answer::Error(McpError::new(
                RpcCode::INTERNAL_ERROR,
                "the tool did not finish within the pending timeout",
                None,
            )),
        }
    }

    /// The value scheme's settle inside one change budget, closed when it
    /// returns. A credential without pay has nothing to settle.
    async fn settle_scheme(
        &self,
        c: &Call<'_>,
        verified: Option<&Verified>,
        cap: &ChangeCap,
        charged: u64,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let (Some((cfg, part)), Some(verified)) = (&c.pay, verified) else {
            return Ok(None);
        };
        let (_, entry) = c
            .offer
            .fields()
            .pay_entry(cfg.plug.id())
            .ok_or(Refusal::code(ErrorCode::NotOffered))?;
        let (capped, guard) =
            CappedSigner::for_change(self.cfg.signer.clone(), self.cfg.store.clone(), cap);
        let result = cfg
            .plug
            .settle(
                part,
                verified,
                &SettleCtx {
                    now: c.now,
                    status: cap.status(),
                    charged,
                    entry,
                    context: &c.context,
                    digest: &c.digest,
                },
                &capped,
            )
            .await;
        guard.close();
        result.map_err(|e| Refusal::from(&e))
    }

    /// A timed-out outcome's refund: settle FAILED under the recorded cap,
    /// then record it once.
    async fn refund(
        &self,
        c: &Call<'_>,
        verified: Option<&Verified>,
        r: &Recorded,
    ) -> Result<Recorded, Refusal> {
        let cap = r
            .refund_cap()
            .ok_or(Refusal::code(ErrorCode::Unavailable))?;
        let result = self.settle_scheme(c, verified, &cap, 0).await?;
        outcome::record_refund(&*self.cfg.store, r, result.as_deref())
            .await
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))
    }

    async fn sign_receipt(
        &self,
        c: &Call<'_>,
        entry: Option<&PayEntry>,
        recorded: &Recorded,
    ) -> Result<Response, Refusal> {
        let unsigned = recorded
            .unsigned_receipt(&ReceiptInput {
                offer_id: c.offer.offer_id(),
                digest: c.digest,
                unit: entry.map(|e| e.unit.clone()),
                metered: false,
                receipt_key: self.cfg.receipt_key,
            })
            .ok_or(Refusal::code(ErrorCode::Unavailable))?
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))?;
        let ack = self
            .cfg
            .signer
            .schnorr(unsigned.message())
            .await
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))?;
        unsigned
            .finish(&ack)
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))
    }

    /// The answer with its receipt in `_meta` (or in `error.data`).
    fn answer(
        c: &Call<'_>,
        recorded: &Recorded,
        receipt: &Response,
        answer: Answer,
    ) -> Result<CallToolResponse, McpError> {
        let mut meta = Map::new();
        meta.insert(wire::RECEIPT.into(), Value::String(b64u(receipt.bytes())));
        let rec = recorded.record();
        if c.native_mpp
            && rec.status.settled() == Some(Status::Ok)
            && let Some(v) = rec.scheme_result.as_deref().and_then(mpp::receipt_value)
        {
            meta.insert(wire::MPP_RECEIPT.into(), v);
        }
        let failed = || {
            McpError::new(
                RpcCode::INTERNAL_ERROR,
                "The tool call failed. The receipt in error.data records the outcome.",
                None,
            )
        };
        match answer {
            Answer::Result(mut r) => {
                let m = r.meta.get_or_insert_with(rmcp::model::MetaObject::new);
                m.0.extend(meta);
                Ok(CallToolResponse::Complete(r))
            }
            Answer::Error(e) => Err(with_data(e, meta)),
            Answer::ReceiptOnly if rec.status.settled() == Some(Status::Ok) => {
                let mut r = CallToolResult::success(Vec::new());
                r.meta = Some(rmcp::model::MetaObject(meta));
                Ok(CallToolResponse::Complete(r))
            }
            Answer::ReceiptOnly => Err(with_data(failed(), meta)),
        }
        .inspect(|_| tracing::debug!(tool = c.tool, "answered a priced call"))
    }

    /// The JSON-RPC error for a refusal, with a fresh offer when a new
    /// payment can answer it.
    async fn refuse(
        &self,
        r: Refusal,
        tool: &str,
        price: &ToolPrice,
        scope: Scope,
        now: u64,
    ) -> McpError {
        let code = r.socket();
        if !wire::carries_offer(code) {
            return error_of(&r, Vec::new(), Vec::new());
        }
        match self.issue(tool, price, scope, now).await {
            Ok(offer) => {
                let challenges = offer
                    .fields()
                    .native
                    .iter()
                    .filter(|n| n.kind == bnap_scheme_mpp::NATIVE_KIND)
                    .filter_map(|n| std::str::from_utf8(&n.data).ok())
                    .filter_map(mpp::challenge_value)
                    .collect();
                error_of(&r, vec![b64u(offer.bytes())], challenges)
            }
            Err(e) => {
                tracing::warn!(tool, error = ?e.0, "could not issue an offer");
                error_of(&e, Vec::new(), Vec::new())
            }
        }
    }

    /// Issues an exact-scope offer for one call (4.2), with each class O
    /// scheme's native artifact, and caches it when it carries natives
    /// (5.1).
    async fn issue(
        &self,
        tool: &str,
        price: &ToolPrice,
        scope: Scope,
        now: u64,
    ) -> Result<Offer, Refusal> {
        let expires = now + self.cfg.offer_lifetime;
        let mut nonce = [0u8; 16];
        thread_rng().fill_bytes(&mut nonce);
        let mut f = OfferFields::new(scope, expires, self.cfg.offer_key, nonce);
        let unavailable = |e: &SchemeError| Refusal::from(e);
        for p in &price.pay {
            let Some(cfg) = self.offerable(&p.scheme, price) else {
                continue;
            };
            let params = cfg
                .plug
                .offer(&OfferCtx {
                    now,
                    route_id: tool,
                    scope: &scope,
                    route_scope: false,
                    metered: false,
                    expires,
                    role: OfferRole::Pay {
                        amount: p.amount,
                        unit: &p.unit,
                    },
                })
                .await
                .map_err(|e| unavailable(&e))?;
            let mut entry = PayEntry::new(&p.scheme, p.amount, &p.unit);
            entry.params = params.params;
            f.pay.push(entry);
        }
        for a in &price.attest {
            let Some(cfg) = self.offerable(&a.scheme, price) else {
                continue;
            };
            let params = cfg
                .plug
                .offer(&OfferCtx {
                    now,
                    route_id: tool,
                    scope: &scope,
                    route_scope: false,
                    metered: false,
                    expires,
                    role: OfferRole::Attest { effect: a.effect },
                })
                .await
                .map_err(|e| unavailable(&e))?;
            let mut entry: AttestEntry = a.clone();
            entry.params = params.params;
            f.attest.push(entry);
        }
        if f.pay.is_empty() && !f.attest.iter().any(|a| a.effect == Effect::Waive) {
            return Err(Refusal::detail(
                ErrorCode::Unavailable,
                "no scheme can be offered",
            ));
        }
        let offer_id = f.offer_id().map_err(|e| Refusal::from(&e))?;
        for (i, entry) in f.pay.clone().iter().enumerate() {
            let Some(cfg) = self.cfg.schemes.get(&entry.scheme) else {
                continue;
            };
            let natives = cfg
                .plug
                .natives(&NativeCtx {
                    now,
                    offer_id: &offer_id,
                    entry,
                    pay_index: i,
                    expires,
                })
                .await
                .map_err(|e| unavailable(&e))?;
            for n in natives {
                f.native.push(NativeEntry::new(i as u64, n.kind, n.data));
            }
        }
        let unsigned = UnsignedOffer::new(&f, Some(&self.cfg.mac_keys[0]))
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))?;
        let sig = self
            .cfg
            .signer
            .schnorr(unsigned.message())
            .await
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))?;
        let offer = unsigned
            .finish_with_limit(&sig, self.cfg.limits.max_offer)
            .map_err(|_| Refusal::code(ErrorCode::Unavailable))?;
        if !offer.fields().native.is_empty() {
            self.offers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(offer.clone(), now, self.cfg.offer_cache);
        }
        Ok(offer)
    }

    /// The scheme, if it is configured and meets the tool's require.
    fn offerable(&self, id: &str, price: &ToolPrice) -> Option<&SchemeConfig> {
        self.cfg
            .schemes
            .get(id)
            .filter(|c| price.require.satisfied_by(&c.properties))
    }
}

/// An error with no offer.
fn bare(r: &Refusal) -> McpError {
    error_of(r, Vec::new(), Vec::new())
}

/// The JSON-RPC error of a refusal (module [`wire`]).
fn error_of(r: &Refusal, offers: Vec<String>, challenges: Vec<Value>) -> McpError {
    let code = r.socket();
    let data = ErrorData {
        http_status: code.http_status(),
        challenges,
        offers,
        error: Some(r.0.clone()),
        receipt: None,
    };
    McpError::new(
        RpcCode(wire::jsonrpc_code(code)),
        wire::message(code),
        Some(data.to_value()),
    )
}

/// `e` with `meta` merged into its `data` object (a non-object `data` is
/// kept under `data`).
fn with_data(mut e: McpError, meta: Map<String, Value>) -> McpError {
    let mut data = match e.data.take() {
        Some(Value::Object(m)) => m,
        None => Map::new(),
        Some(other) => {
            let mut m = Map::new();
            m.insert("data".into(), other);
            m
        }
    };
    data.extend(meta);
    e.data = Some(Value::Object(data));
    e
}
