//! The gate: the [`Gatekeeper`] that runs the socket for every request.
//!
//! For a request on a manifest route it computes the action scope (10.1),
//! takes the credential (10.2), runs the offer checks of 4.4 before any
//! plug sees the bytes, verifies every scheme part, has the operator's
//! rails confirm every payment, and hands the rest to bnap-core's
//! `outcome::process`. A new outcome becomes a [`Ticket`]: the layer runs
//! the action and the ticket settles it (6.4) before the answer leaves with
//! its receipt. A replay is answered from the recorded outcome. Requests
//! off every route are forwarded untouched.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bnap_carrier_http::carrier::{challenge_response, error_response};
use bnap_carrier_http::fields::{self, BNAP_FUND, BNAP_RECEIPT, NO_STORE, PAYMENT_RECEIPT};
use bnap_carrier_http::{
    Admit, ClientAddr, Done, GateRequest, Gatekeeper, HttpCarrier, HttpRequest, Kept, NativeAuth,
    Run, Ticket, b64u,
};
use bnap_core::credential::{CredentialParse, SchemePart, native_context, native_digest};
use bnap_core::hash::{Context, Digest, OfferId, RailId, Scope};
use bnap_core::limits::{CLOCK_SKEW, Limits};
use bnap_core::manifest::ManifestKey;
use bnap_core::offer::{AttestEntry, GateOfferCheck, NativeEntry, Offer, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, Pending, ReceiptInput, Recorded, Request, SettleError};
use bnap_core::pricing::{Backing, ChangeCap, PayValue, VerifiedAttest};
use bnap_core::response::Status;
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{SchemeUses, Settlement, UseModel, UseStore};
use bnap_core::{BindingClass, Credential, ErrorCode, ErrorObject};
use bnap_plug::carrier::{Carrier as _, Challenge, NativeChallenge, RawCredential};
use bnap_plug::{
    CappedSigner, CredentialScheme, Entry, NativeCtx, OfferCtx, OfferRole, RailPayment,
    SchemeError, SettleCtx, Signer, Verified, VerifyCtx, confirm_rail_id,
};
use bnap_scheme_notes::{FundQuote, FundRequest, NotesScheme};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method, Request as HttpReq, Response, StatusCode};

use crate::config::{Front, RoutePlan, Slot, Upstream};
use crate::limiter::Limiter;
use crate::plugs::{Clock, OutputBound, Plugs, ValuePlug};
use crate::registry::Registry;

/// The well-known path of the manifest.
pub const WELL_KNOWN: &str = "/.well-known/bnap";

/// Margin kept between an action's deadline and `pending_timeout`, so the
/// gate's own settle comes before the sweep's timeout.
pub const SETTLE_MARGIN: u64 = 5;

/// Most offers kept in the cache of offers issued (route offers and
/// exact-scope offers with natives, draft-00 5.1).
pub const MAX_CACHED_OFFERS: usize = 50_000;

/// The lifetime of an exact-scope offer that carries `bnap:notes`.
#[must_use]
pub fn notes_exact_lifetime(exact: u64, pending_timeout: u64) -> u64 {
    exact + pending_timeout + CLOCK_SKEW
}

/// A route, resolved, with its route scope.
#[derive(Debug, Clone)]
pub struct GateRoute {
    /// The plan.
    pub plan: RoutePlan,
    /// `H_"bnap/route/http"(origin, id)`.
    pub route_scope: Scope,
}

/// Everything the gate holds. Shared by every request and ticket.
pub struct Inner {
    front: Front,
    origin: String,
    routes: Vec<GateRoute>,
    registry: Registry,
    carrier: HttpCarrier,
    signer: Arc<dyn Signer>,
    store: Arc<dyn UseStore>,
    values: std::collections::BTreeMap<String, ValuePlug>,
    attests: std::collections::BTreeMap<String, Arc<dyn CredentialScheme>>,
    notes: Option<Arc<NotesScheme>>,
    mac_keys: Vec<[u8; 32]>,
    offer_key: ManifestKey,
    receipt_key: ManifestKey,
    manifest: Bytes,
    limits: Limits,
    clock: Clock,
    exact_lifetime: u64,
    route_lifetime: u64,
    keep_response: usize,
    max_outputs: usize,
    trust_forwarded_for: bool,
    route_offers: tokio::sync::Mutex<HashMap<String, Offer>>,
    cache: Mutex<HashMap<OfferId, Offer>>,
    mint_limit: Limiter<IpAddr>,
    verify_limit: Limiter<IpAddr>,
    offer_limit: Limiter<OfferId>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("origin", &self.origin)
            .field("front", &self.front)
            .finish_non_exhaustive()
    }
}

/// What the gate needs besides its plugs.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The front.
    pub front: Front,
    /// The manifest origin.
    pub origin: String,
    /// Resolved routes.
    pub plans: Vec<RoutePlan>,
    /// The manifest bytes, the keys and limits taken from it.
    pub manifest: crate::manifest::Loaded,
    /// Exact-offer lifetime, seconds.
    pub exact_lifetime: u64,
    /// Route-offer lifetime, seconds.
    pub route_lifetime: u64,
    /// Largest answer kept for replays.
    pub keep_response: usize,
    /// `[limits]`.
    pub limits: crate::config::LimitSection,
    /// Read `X-Forwarded-For`.
    pub trust_forwarded_for: bool,
}

/// The gatekeeper the layer runs.
#[derive(Debug, Clone)]
pub struct Gate(pub Arc<Inner>);

impl Gate {
    /// A gate over these plugs.
    #[must_use]
    pub fn new(s: Settings, plugs: &Plugs, registry: Registry, clock: Clock) -> Self {
        let max_credential = s
            .manifest
            .limits
            .max_credential
            .min(bnap_core::http::HTTP_MAX_CREDENTIAL);
        let mut natives = Vec::new();
        for (id, parse) in [
            (
                bnap_scheme_l402::SCHEME_ID,
                bnap_scheme_l402::credential_from_authorization as fn(&str) -> Option<&str>,
            ),
            (
                bnap_scheme_mpp::SCHEME_ID,
                bnap_scheme_mpp::credential_from_authorization,
            ),
        ] {
            if plugs.values.contains_key(id) {
                natives.push(NativeAuth {
                    scheme: id.into(),
                    parse,
                });
            }
        }
        let carrier = HttpCarrier::new(s.origin.clone(), max_credential).with_natives(natives);
        let routes = s
            .plans
            .into_iter()
            .map(|plan| GateRoute {
                route_scope: carrier.route_scope_of(&plan.section.id),
                plan,
            })
            .collect();
        Self(Arc::new(Inner {
            front: s.front,
            origin: s.origin,
            routes,
            registry,
            carrier,
            signer: plugs.signer.clone(),
            store: plugs.store.clone(),
            values: plugs.values.clone(),
            attests: plugs.attests.clone(),
            notes: plugs.notes.clone(),
            mac_keys: plugs.mac_keys.clone(),
            offer_key: s.manifest.offer_key.clone(),
            receipt_key: s.manifest.receipt_key.clone(),
            manifest: Bytes::from(s.manifest.bytes.clone()),
            limits: s.manifest.limits,
            clock,
            exact_lifetime: s.exact_lifetime,
            route_lifetime: s.route_lifetime,
            keep_response: s.keep_response,
            max_outputs: s.limits.max_change_outputs,
            trust_forwarded_for: s.trust_forwarded_for || s.front.is_auth(),
            route_offers: tokio::sync::Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            mint_limit: Limiter::new(s.limits.mints_per_minute),
            verify_limit: Limiter::new(s.limits.verifies_per_minute),
            offer_limit: Limiter::new(s.limits.verifies_per_offer_per_minute),
        }))
    }

    /// The shared state.
    #[must_use]
    pub fn inner(&self) -> &Arc<Inner> {
        &self.0
    }
}

trait RouteScopeOf {
    fn route_scope_of(&self, id: &str) -> Scope;
}

impl RouteScopeOf for HttpCarrier {
    fn route_scope_of(&self, id: &str) -> Scope {
        self.route_scope(id)
    }
}

#[async_trait::async_trait]
impl Gatekeeper for Gate {
    async fn admit(&self, req: GateRequest) -> Admit {
        self.0.clone().admit(req).await
    }
}

/// An answer the gate sends itself.
type Answer = Response<Bytes>;

fn err(code: ErrorCode) -> ErrorObject {
    ErrorObject::new(code)
}

fn scheme_err(e: &SchemeError) -> ErrorObject {
    e.to_error_object()
}

/// A plain JSON answer for a refusal that is not a socket error.
fn plain(status: StatusCode, code: &str, message: &str) -> Answer {
    let body =
        serde_json::json!({ "error": { "type": "gateway", "code": code, "message": message } });
    let mut r = Response::new(Bytes::from(body.to_string()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    r
}

/// One part of a credential on its way through the socket.
struct PayPart {
    plug: ValuePlug,
    part: SchemePart,
    entry: PayEntry,
}

/// What `run_socket` needs from the request.
struct SocketInput {
    offer: Offer,
    context: Context,
    digest: Digest,
    action_scope: Scope,
    pay: Option<PayPart>,
    attest: Vec<SchemePart>,
    route: usize,
    forward: HttpReq<Bytes>,
    sent_context: Option<[u8; 32]>,
}

impl Inner {
    /// The socket limits from the manifest.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn client(&self, parts: &http::request::Parts) -> Option<IpAddr> {
        if self.trust_forwarded_for
            && let Some(ip) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse().ok())
        {
            return Some(ip);
        }
        parts.extensions.get::<ClientAddr>().map(|c| c.0)
    }

    fn manifest_answer(&self) -> Answer {
        let mut r = Response::new(self.manifest.clone());
        r.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        r.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        r
    }

    #[allow(clippy::too_many_lines)]
    async fn admit(self: Arc<Self>, req: GateRequest) -> Admit {
        let GateRequest { mut parts, body } = req;
        tracing::trace!(uri = %parts.uri, len = body.len(), "gate: admit");
        let now = self.now();
        // Auth fronts send a subrequest; the action is named by the
        // forwarded method and URI, and its content is never seen.
        if self.front.is_auth() {
            let method = parts
                .headers
                .get("x-forwarded-method")
                .and_then(|v| Method::from_bytes(v.as_bytes()).ok());
            let uri = parts
                .headers
                .get("x-forwarded-uri")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<http::Uri>().ok());
            match (method, uri) {
                (Some(m), Some(u)) => {
                    parts.method = m;
                    parts.uri = u;
                }
                _ => {
                    return Admit::Answer(self.auth_status(plain(
                        StatusCode::BAD_REQUEST,
                        "NO_FORWARDED_REQUEST",
                        "The front sent no X-Forwarded-Method and X-Forwarded-Uri.",
                    )));
                }
            }
        }
        if parts.method == Method::GET && parts.uri.path() == WELL_KNOWN {
            return Admit::Answer(self.auth_status(self.manifest_answer()));
        }
        // Routes match the path as an application would route it
        // (percent-decoded, dot-segments removed, empty segments
        // collapsed), so an encoded variant of a paid path is still that
        // route; the scope still hashes, and the proxy still forwards, the
        // target exactly as received (10.1).
        let path = route_path(parts.uri.path());
        let Some(ri) = self
            .routes
            .iter()
            .position(|r| r.plan.manifest.matches(parts.method.as_str(), &path))
        else {
            if self.front.is_auth() {
                return Admit::Answer(Response::new(Bytes::new()));
            }
            return Admit::Forward(HttpReq::from_parts(parts, body));
        };
        let route = &self.routes[ri];
        // The request-target is hashed and forwarded as received; only the
        // origin form names an action of this origin.
        if !parts
            .uri
            .path_and_query()
            .is_some_and(|pq| pq.as_str().starts_with('/'))
            || parts.uri.authority().is_some() && !self.front.is_auth()
        {
            return Admit::Answer(
                self.answer_error(ri, &err(ErrorCode::Malformed), None, None, now)
                    .await,
            );
        }
        let has_content = if self.front.is_auth() {
            // The subrequest carries no content; the front states the
            // original request's length (empty or 0 when it had none).
            !body.is_empty()
                || match parts.headers.get("x-original-content-length") {
                    None => true,
                    Some(v) => {
                        !(v.as_bytes().is_empty() || v.as_bytes() == b"0")
                            || parts
                                .headers
                                .get("x-original-transfer-encoding")
                                .is_some_and(|t| !t.as_bytes().is_empty())
                    }
                }
        } else {
            false
        };
        if has_content {
            return Admit::Answer(self.auth_status(plain(
                StatusCode::BAD_REQUEST,
                "CONTENT_NOT_VISIBLE",
                "This gate runs behind an auth front, which never shows it the request content, so a paid request cannot carry any.",
            )));
        }
        if route.plan.section.upstream == Upstream::Openai
            && route.plan.section.metered
            && crate::meter::asks_for_stream(&body)
        {
            return Admit::Answer(plain(
                StatusCode::BAD_REQUEST,
                "STREAM_NOT_METERED",
                "Streaming is not available on this metered route. Send the request without \"stream\": true.",
            ));
        }
        let http_req = HttpRequest::new(&parts, body.clone(), route.plan.section.headers.clone());
        let action_scope = match self.carrier.action_scope(&http_req) {
            Ok(s) => s,
            Err(e) => {
                return Admit::Answer(
                    self.answer_error(ri, &ErrorObject::from(&e), None, None, now)
                        .await,
                );
            }
        };
        let addr = self.client(&parts);
        let extracted = match self.carrier.extract(&http_req) {
            Ok(c) => c,
            Err(e) => {
                return Admit::Answer(
                    self.answer_error(ri, &ErrorObject::from(&e), Some(action_scope), addr, now)
                        .await,
                );
            }
        };
        let sent_context = match fields::context(&http_req.headers) {
            Ok(c) => c,
            Err(e) => {
                return Admit::Answer(
                    self.answer_error(ri, &ErrorObject::from(&e), None, None, now)
                        .await,
                );
            }
        };
        let fund = http_req
            .headers
            .get(BNAP_FUND)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // The application gets the request without the BNAP fields.
        let mut forward = HttpReq::from_parts(parts, body);
        for f in fields::REQUEST_FIELDS {
            forward.headers_mut().remove(f);
        }
        let result = match extracted {
            None => {
                return Admit::Answer(
                    self.challenge(ri, action_scope, addr, fund.as_deref(), now)
                        .await,
                );
            }
            Some(RawCredential::Bnap(bytes)) => {
                self.bnap_input(ri, &bytes, action_scope, addr, now)
            }
            Some(RawCredential::Native { scheme, bytes }) => {
                // The native credential travelled in Authorization; it is
                // the payment, not the application's credential.
                forward.headers_mut().remove(AUTHORIZATION);
                self.native_input(ri, &scheme, &bytes, action_scope, addr, now)
                    .await
            }
        };
        let input = match result {
            Ok((offer, context, digest, pay, attest)) => SocketInput {
                offer,
                context,
                digest,
                action_scope,
                pay,
                attest,
                route: ri,
                forward,
                sent_context,
            },
            Err(e) => {
                return Admit::Answer(
                    self.answer_error(ri, &e, Some(action_scope), addr, now)
                        .await,
                );
            }
        };
        match self.clone().run_socket(input, now).await {
            Ok(a) => a,
            Err(e) => Admit::Answer(
                self.answer_error(ri, &e, Some(action_scope), addr, now)
                    .await,
            ),
        }
    }

    /// An answer through nginx's `auth_request`, which passes 2xx, 401 and
    /// 403 only: any other status goes as 401 with the real one in
    /// `BNAP-Status` (the nginx snippet in the book maps it back).
    fn auth_status(&self, mut r: Answer) -> Answer {
        if self.front == Front::AuthRequest
            && !r.status().is_success()
            && r.status() != StatusCode::UNAUTHORIZED
            && r.status() != StatusCode::FORBIDDEN
        {
            let real = r.status().as_u16();
            r.headers_mut()
                .insert("bnap-status", HeaderValue::from(real));
            *r.status_mut() = StatusCode::UNAUTHORIZED;
        }
        r
    }

    /// An error answer: with fresh offers for the codes that send one (8.2).
    async fn answer_error(
        &self,
        ri: usize,
        e: &ErrorObject,
        action_scope: Option<Scope>,
        addr: Option<IpAddr>,
        now: u64,
    ) -> Answer {
        let fresh = e.socket_code().is_some_and(ErrorCode::sends_fresh_offer);
        let r = match (fresh, action_scope) {
            (true, Some(scope)) => {
                // Offers with natives count against the address's mint
                // limit, as in a 402 for a request without a credential.
                let offers = self.offers(ri, scope, addr, None, now, true).await;
                let (offers, natives) = match offers {
                    Ok(o) => o,
                    Err(e2) => return self.auth_status(error_response(&self.carrier, &e2)),
                };
                if offers.is_empty() {
                    // Every offer of the route mints an invoice and the
                    // address used up its mint limit: a 402 without a fresh
                    // offer would mislead, so say when to come back.
                    let mut limited = err(ErrorCode::RateLimited);
                    limited.retry_after = Some(crate::limiter::WINDOW);
                    return self.auth_status(error_response(&self.carrier, &limited));
                }
                challenge_response(
                    &self.carrier,
                    &Challenge {
                        offers: &offers,
                        natives: &natives,
                        error: Some(e),
                    },
                )
            }
            _ => error_response(&self.carrier, e),
        };
        self.auth_status(r)
    }

    /// The 402 for a request without a credential.
    async fn challenge(
        &self,
        ri: usize,
        scope: Scope,
        addr: Option<IpAddr>,
        fund: Option<&str>,
        now: u64,
    ) -> Answer {
        let required = err(ErrorCode::Required);
        let fund = match fund.map(FundRequest::parse_header) {
            Some(Ok(f)) => Some(f),
            Some(Err(_)) => {
                return self.auth_status(error_response(&self.carrier, &err(ErrorCode::Malformed)));
            }
            None => None,
        };
        match self.offers(ri, scope, addr, fund.as_ref(), now, true).await {
            Ok((offers, natives)) if !offers.is_empty() => self.auth_status(challenge_response(
                &self.carrier,
                &Challenge {
                    offers: &offers,
                    natives: &natives,
                    error: Some(&required),
                },
            )),
            Ok(_) => {
                let mut e = err(ErrorCode::RateLimited);
                e.retry_after = Some(crate::limiter::WINDOW);
                self.auth_status(error_response(&self.carrier, &e))
            }
            Err(e) => self.auth_status(error_response(&self.carrier, &e)),
        }
    }

    fn cached(&self, id: &OfferId) -> Option<Offer> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn remember(&self, offer: &Offer, now: u64) {
        let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if c.len() >= MAX_CACHED_OFFERS {
            c.retain(|_, o| o.fields().expires + CLOCK_SKEW >= now);
        }
        if c.len() < MAX_CACHED_OFFERS {
            c.insert(offer.offer_id(), offer.clone());
        } else {
            tracing::warn!("offer cache full; an offer was issued uncached");
        }
    }

    /// Every offer for a request on route `ri`: the shared route-scope
    /// offer, and the exact-scope offers. Offers with natives or a fund
    /// quote mint an invoice each, so they are made only when `mint` is
    /// set and the client's address is under its mint limit (DECISIONS row
    /// 24); otherwise they are left out.
    #[allow(clippy::too_many_lines)]
    async fn offers(
        &self,
        ri: usize,
        action_scope: Scope,
        addr: Option<IpAddr>,
        fund: Option<&FundRequest>,
        now: u64,
        mint: bool,
    ) -> Result<(Vec<Offer>, Vec<NativeChallenge>), ErrorObject> {
        let route = &self.routes[ri];
        let plan = &route.plan;
        if now + CLOCK_SKEW > self.offer_key.not_after {
            tracing::error!("the manifest's offer key has expired: sign a new manifest");
            return Err(err(ErrorCode::Unavailable));
        }
        let mut offers = Vec::new();
        let mut natives = Vec::new();
        if plan.section.scope == bnap_core::manifest::RouteScopeMode::Route
            && let Some(o) = self.route_offer(ri, now).await?
        {
            offers.push(o);
        }
        let may_mint = |limiter: &Limiter<IpAddr>| match addr {
            Some(a) => limiter.hit(&a, now).is_ok(),
            None => true,
        };
        for slot in [Slot::ExactMetered, Slot::ExactPlain] {
            let entries: Vec<_> = plan.pay.iter().filter(|p| p.slot == slot).collect();
            let waives = slot == Slot::ExactPlain
                && plan
                    .attest
                    .iter()
                    .any(|a| a.attest.effect == bnap_core::Effect::Waive);
            if entries.is_empty() && !waives {
                continue;
            }
            let with_natives = entries.iter().any(|e| {
                e.class == BindingClass::O
                    && matches!(
                        e.scheme.as_str(),
                        bnap_scheme_l402::SCHEME_ID | bnap_scheme_mpp::SCHEME_ID
                    )
            });
            if with_natives && !(mint && may_mint(&self.mint_limit)) {
                continue;
            }
            let o = self
                .build_offer(
                    ri,
                    action_scope,
                    false,
                    slot == Slot::ExactMetered,
                    &entries,
                    None,
                    now,
                )
                .await?;
            if let Some(o) = o {
                if !o.fields().native.is_empty() {
                    self.remember(&o, now);
                    for n in &o.fields().native {
                        let scheme = &o.fields().pay
                            [usize::try_from(n.pay_index).unwrap_or(usize::MAX)]
                        .scheme;
                        if let Ok(v) = String::from_utf8(n.data.clone()) {
                            natives.push(NativeChallenge {
                                scheme: scheme.clone(),
                                value: v,
                            });
                        }
                    }
                }
                offers.push(o);
            }
        }
        // A fund quote (bnap:notes 8.2): an exact-scope notes offer made for
        // this request only, never cached (5.4), and never made without
        // BNAP-Fund.
        if let (Some(req), Some(notes)) = (fund, &self.notes)
            && let Some(entry) = plan
                .pay
                .iter()
                .find(|p| p.scheme == bnap_scheme_notes::SCHEME_ID)
            && mint
            && may_mint(&self.mint_limit)
        {
            let nonce: [u8; 16] = rand::random();
            let q = notes
                .create_fund_quote(req, &plan.section.id, &nonce, now)
                .await
                .map_err(|e| scheme_err(&e))?;
            if let Some(q) = q {
                let o = self
                    .build_offer_with(
                        ri,
                        action_scope,
                        false,
                        false,
                        &[entry],
                        Some((&q, nonce)),
                        now,
                    )
                    .await?;
                if let Some(o) = o {
                    offers.push(o);
                }
            }
        }
        Ok((offers, natives))
    }

    /// The route's current route-scope offer: one per route per issuing
    /// interval, the same for every client (5.1), replaced once half its
    /// lifetime is gone.
    async fn route_offer(&self, ri: usize, now: u64) -> Result<Option<Offer>, ErrorObject> {
        let plan = &self.routes[ri].plan;
        let entries: Vec<_> = plan.pay.iter().filter(|p| p.slot == Slot::Route).collect();
        let waives = plan
            .attest
            .iter()
            .any(|a| a.attest.effect == bnap_core::Effect::Waive && a.class.route_scope_allowed());
        if entries.is_empty() && !waives {
            return Ok(None);
        }
        let mut current = self.route_offers.lock().await;
        if let Some(o) = current.get(&plan.section.id)
            && o.fields().expires >= now + self.route_lifetime / 2
        {
            return Ok(Some(o.clone()));
        }
        let o = self
            .build_offer(
                ri,
                self.routes[ri].route_scope,
                true,
                plan.section.metered,
                &entries,
                None,
                now,
            )
            .await?;
        if let Some(o) = &o {
            self.remember(o, now);
            current.insert(plan.section.id.clone(), o.clone());
        }
        Ok(o)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_offer(
        &self,
        ri: usize,
        scope: Scope,
        route_scope: bool,
        metered: bool,
        entries: &[&crate::config::PayPlan],
        fund: Option<(&FundQuote, [u8; 16])>,
        now: u64,
    ) -> Result<Option<Offer>, ErrorObject> {
        self.build_offer_with(ri, scope, route_scope, metered, entries, fund, now)
            .await
    }

    /// Builds and signs one offer (4.2): every record but the signatures
    /// and natives, the `OfferID`, each class O scheme's native artifact,
    /// then `offer_sig` and the MAC.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn build_offer_with(
        &self,
        ri: usize,
        scope: Scope,
        route_scope: bool,
        metered: bool,
        entries: &[&crate::config::PayPlan],
        fund: Option<(&FundQuote, [u8; 16])>,
        now: u64,
    ) -> Result<Option<Offer>, ErrorObject> {
        let plan = &self.routes[ri].plan;
        let has_notes = entries
            .iter()
            .any(|e| e.scheme == bnap_scheme_notes::SCHEME_ID);
        let lifetime = if route_scope {
            self.route_lifetime
        } else if has_notes {
            // A notes entry admits nothing after expires - pending_timeout
            // - 60 s (notes 5.4): give the client the same usable window
            // as any exact offer.
            notes_exact_lifetime(self.exact_lifetime, self.limits.pending_timeout)
        } else {
            self.exact_lifetime
        };
        let expires = (now + lifetime).min(self.offer_key.not_after);
        let nonce = fund.map_or_else(rand::random, |(_, n)| n);
        let mut f = OfferFields::new(scope, expires, self.offer_key.kid, nonce);
        f.route_scope = route_scope;
        f.metered = metered;
        f.info = Some(format!("{}{WELL_KNOWN}", self.origin));
        f.headers.clone_from(&plan.section.headers);
        for e in entries {
            let Some(plug) = self.values.get(&e.scheme) else {
                continue;
            };
            let cx = OfferCtx {
                now,
                route_id: &plan.section.id,
                scope: &scope,
                route_scope,
                metered,
                expires,
                role: OfferRole::Pay {
                    amount: e.amount,
                    unit: &e.unit,
                },
            };
            let params = match (fund, &self.notes) {
                (Some((q, _)), Some(n)) if e.scheme == bnap_scheme_notes::SCHEME_ID => {
                    n.offer_with_quote(&cx, q).await
                }
                _ => plug.scheme.offer(&cx).await,
            };
            let params = match params {
                Ok(p) => p,
                Err(SchemeError::Unavailable(m)) => {
                    tracing::warn!(scheme = %e.scheme, "left out of the offer: {m}");
                    continue;
                }
                Err(_) => continue,
            };
            let mut p = PayEntry::new(e.scheme.clone(), e.amount, e.unit.clone());
            p.params = params.params;
            if metered {
                p.rate = e.rate;
            }
            f.pay.push(p);
        }
        for a in &plan.attest {
            if route_scope && !a.class.route_scope_allowed() {
                continue;
            }
            let mut entry = AttestEntry::new(a.attest.scheme.clone(), a.attest.effect);
            entry.value = a.attest.value;
            entry.epoch = a.attest.epoch;
            f.attest.push(entry);
        }
        let waives = f
            .attest
            .iter()
            .any(|a| a.effect == bnap_core::Effect::Waive);
        if f.pay.is_empty() && !waives {
            return Ok(None);
        }
        // GREASE (draft-00 2): one record of random odd type and value.
        let g: [u8; 3] = rand::random();
        f.unknown = vec![(
            bnap_core::tlv::grease_type(u16::from_be_bytes([g[0], g[1]])),
            vec![g[2]],
        )];
        f.check_binding_classes(|s| Some(self.registry.class(s)))
            .map_err(|e| {
                tracing::error!("refusing to build an offer that breaks a class rule: {e}");
                err(ErrorCode::Unavailable)
            })?;
        let offer_id = f.offer_id().map_err(|_| err(ErrorCode::Unavailable))?;
        if !route_scope {
            for (i, entry) in f.pay.clone().iter().enumerate() {
                if self.registry.class(&entry.scheme) != BindingClass::O {
                    continue;
                }
                let Some(plug) = self.values.get(&entry.scheme) else {
                    continue;
                };
                let native = plug
                    .scheme
                    .native(&NativeCtx {
                        now,
                        offer_id: &offer_id,
                        entry,
                        pay_index: i,
                        expires,
                    })
                    .await
                    .map_err(|e| {
                        tracing::error!(scheme = %entry.scheme, "no native challenge: {e}");
                        scheme_err(&e)
                    })?;
                if let Some(n) = native {
                    f.native.push(NativeEntry::new(i as u64, n.kind, n.data));
                }
            }
        }
        let unsigned = UnsignedOffer::new(&f, Some(&self.mac_keys[0]))
            .map_err(|_| err(ErrorCode::Unavailable))?;
        let sig = self.signer.schnorr(unsigned.message()).await.map_err(|e| {
            tracing::error!("the signer refused an offer: {e}");
            err(ErrorCode::Unavailable)
        })?;
        let offer = unsigned
            .finish(&sig)
            .map_err(|_| err(ErrorCode::Unavailable))?;
        Ok(Some(offer))
    }

    fn check(&self, now: u64, ri: usize, action_scope: Scope) -> GateOfferCheck<'_> {
        GateOfferCheck {
            now,
            max_offer: self.limits.max_offer,
            mac_keys: &self.mac_keys,
            // Offers published in advance are not issued by this gate.
            offer_keys: &[],
            action_scope,
            route_scope: Some(self.routes[ri].route_scope),
        }
    }

    /// Bounds the plug work one client address and one offer can cause
    /// (draft-00 12).
    fn bound_work(
        &self,
        addr: Option<IpAddr>,
        offer: &OfferId,
        now: u64,
    ) -> Result<(), ErrorObject> {
        let limited = |retry| {
            let mut e = err(ErrorCode::RateLimited);
            e.retry_after = Some(retry);
            e
        };
        if let Some(a) = addr {
            self.verify_limit.hit(&a, now).map_err(limited)?;
        }
        self.offer_limit.hit(offer, now).map_err(limited)
    }

    #[allow(clippy::type_complexity)]
    fn bnap_input(
        &self,
        ri: usize,
        bytes: &[u8],
        action_scope: Scope,
        addr: Option<IpAddr>,
        now: u64,
    ) -> Result<(Offer, Context, Digest, Option<PayPart>, Vec<SchemePart>), ErrorObject> {
        let cred = Credential::parse_with(
            bytes,
            &CredentialParse {
                max_credential: self.carrier.max_credential(),
                known_ext_types: &[],
            },
        )
        .map_err(|e| ErrorObject::from(&e))?;
        // Record rules first (5.1: a binding with no class S scheme is
        // MALFORMED), before the offer's checks reach NOT_OFFERED (4.4).
        cred.check_binding_classes(|s| Some(self.registry.class(s)))
            .map_err(|e| ErrorObject::from(&e))?;
        // This gate never sees the client's TLS session (5.3).
        cred.check_tls_binding(None)
            .map_err(|e| ErrorObject::from(&e))?;
        let offer = self
            .check(now, ri, action_scope)
            .check_credential(&cred, |id| self.cached(id))
            .map_err(|e| ErrorObject::from(&e))?;
        let context = cred.context(&offer.offer_id(), &action_scope);
        let digest = cred.digest(&context);
        self.bound_work(addr, &offer.offer_id(), now)?;
        let pay = match &cred.pay {
            None => None,
            Some(part) => {
                let plug = self
                    .values
                    .get(&part.scheme)
                    .cloned()
                    .ok_or_else(|| err(ErrorCode::NotOffered))?;
                let (_, entry) = offer
                    .fields()
                    .pay_entry(&part.scheme)
                    .ok_or_else(|| err(ErrorCode::NotOffered))?;
                Some(PayPart {
                    plug,
                    part: part.clone(),
                    entry: entry.clone(),
                })
            }
        };
        Ok((offer, context, digest, pay, cred.attest.clone()))
    }

    #[allow(clippy::type_complexity)]
    async fn native_input(
        &self,
        ri: usize,
        scheme: &str,
        bytes: &[u8],
        action_scope: Scope,
        addr: Option<IpAddr>,
        now: u64,
    ) -> Result<(Offer, Context, Digest, Option<PayPart>, Vec<SchemePart>), ErrorObject> {
        if !self.routes[ri].plan.pay.iter().any(|p| p.scheme == scheme) {
            return Err(err(ErrorCode::NotOffered));
        }
        let plug = self
            .values
            .get(scheme)
            .cloned()
            .ok_or_else(|| err(ErrorCode::NotOffered))?;
        if let Some(a) = addr {
            self.verify_limit.hit(&a, now).map_err(|retry| {
                let mut e = err(ErrorCode::RateLimited);
                e.retry_after = Some(retry);
                e
            })?;
        }
        let recovered = plug
            .scheme
            .recover_native(bytes, now)
            .await
            .map_err(|e| scheme_err(&e))?;
        let offer = match &recovered.offer {
            Some(b) => Offer::parse_with_limit(b, self.limits.max_offer)
                .map_err(|e| ErrorObject::from(&e))?,
            None => self
                .cached(&recovered.offer_id)
                .ok_or_else(|| err(ErrorCode::BadOffer))?,
        };
        if offer.offer_id() != recovered.offer_id {
            return Err(err(ErrorCode::BadOffer));
        }
        self.check(now, ri, action_scope)
            .check_native(&offer, scheme)
            .map_err(|e| ErrorObject::from(&e))?;
        self.offer_limit
            .hit(&offer.offer_id(), now)
            .map_err(|retry| {
                let mut e = err(ErrorCode::RateLimited);
                e.retry_after = Some(retry);
                e
            })?;
        let context = native_context(&offer.offer_id(), &action_scope, scheme);
        let digest = native_digest(&context, bytes);
        let (_, entry) = offer
            .fields()
            .pay_entry(scheme)
            .ok_or_else(|| err(ErrorCode::NotOffered))?;
        let entry = entry.clone();
        Ok((
            offer,
            context,
            digest,
            Some(PayPart {
                plug,
                part: recovered.part,
                entry,
            }),
            Vec::new(),
        ))
    }

    /// Confirms each rail reference with the scheme's rails of that kind
    /// (operator-trusted, draft-00 6.1).
    async fn confirm(
        &self,
        pay: &PayPart,
        verified: &Verified,
    ) -> Result<Vec<RailPayment>, ErrorObject> {
        let notes = pay.part.scheme == bnap_scheme_notes::SCHEME_ID;
        let mut out = Vec::new();
        for r in &verified.rail_ids {
            let mut last = None;
            let mut found = None;
            for rail in pay.plug.rails.iter().filter(|x| x.kind() == r.kind) {
                match confirm_rail_id(&**rail, r).await {
                    Ok(p) => {
                        found = Some(p);
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            match (found, last) {
                (Some(p), _) => out.push(p),
                (None, Some(e)) if notes => {
                    return Err(bnap_scheme_notes::rail_error(&e).to_error_object());
                }
                (None, Some(e)) => return Err(err(e.code())),
                (None, None) => return Err(err(ErrorCode::BadCredential)),
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_lines)]
    async fn run_socket(
        self: Arc<Self>,
        input: SocketInput,
        now: u64,
    ) -> Result<Admit, ErrorObject> {
        let route = &self.routes[input.route];
        // BNAP-Context (10.2) is compared before any plug runs.
        if input.sent_context.is_some_and(|c| c != input.context.0) {
            return Err(err(ErrorCode::Malformed));
        }
        let mut verified_pay = None;
        let mut backing: Vec<Backing> = Vec::new();
        let mut rail_ids: Vec<RailId> = Vec::new();
        if let Some(pay) = &input.pay {
            let view = CappedSigner::verify_only(self.signer.clone(), &pay.entry.unit);
            let v = pay
                .plug
                .scheme
                .verify(
                    &pay.part,
                    &VerifyCtx {
                        now,
                        offer: &input.offer,
                        entry: Entry::Pay(&pay.entry),
                        action_scope: &input.action_scope,
                        context: &input.context,
                        digest: &input.digest,
                        signer: &view,
                    },
                )
                .await
                .map_err(|e| scheme_err(&e))?;
            if pay.part.scheme == bnap_scheme_notes::SCHEME_ID
                && route
                    .plan
                    .section
                    .require
                    .get("link-payment")
                    .map(String::as_str)
                    == Some("unlinkable")
                && bnap_scheme_notes::funded(&v)
            {
                return Err(err(ErrorCode::Policy));
            }
            let payments = self.confirm(pay, &v).await?;
            rail_ids = payments.iter().map(|p| p.rail_id).collect();
            backing = payments.iter().map(RailPayment::backing).collect();
            backing.extend(view.notes());
            verified_pay = Some(v);
        }
        let mut attested: Vec<(String, Verified)> = Vec::new();
        for part in &input.attest {
            let Some(scheme) = self.attests.get(&part.scheme) else {
                // Offered but not run here: no effect (a required one fails
                // admission with POLICY).
                continue;
            };
            let Some(entry) = input.offer.fields().attest_entry(&part.scheme) else {
                return Err(err(ErrorCode::NotOffered));
            };
            let view = CappedSigner::verify_only(self.signer.clone(), "sat");
            match scheme
                .verify(
                    part,
                    &VerifyCtx {
                        now,
                        offer: &input.offer,
                        entry: Entry::Attest(entry),
                        action_scope: &input.action_scope,
                        context: &input.context,
                        digest: &input.digest,
                        signer: &view,
                    },
                )
                .await
            {
                Ok(v) => attested.push((part.scheme.clone(), v)),
                Err(SchemeError::Unavailable(m)) => {
                    tracing::warn!(scheme = %part.scheme, "attestation verifier unavailable: {m}");
                    return Err(err(ErrorCode::Unavailable));
                }
                Err(e) => tracing::debug!(scheme = %part.scheme, "attestation not verified: {e}"),
            }
        }
        let attest: Vec<VerifiedAttest> = attested
            .iter()
            .map(|(id, v)| {
                let a = VerifiedAttest::new(id.clone(), self.registry.class(id));
                match v.quota_use_id(id) {
                    Some(q) => a.with_quota_id(q),
                    None => a,
                }
            })
            .collect();
        let mut schemes: Vec<SchemeUses<'_>> = Vec::new();
        if let (Some(pay), Some(v)) = (&input.pay, &verified_pay) {
            let model = self
                .registry
                .scheme(&pay.part.scheme)
                .and_then(crate::registry::SchemeEntry::model)
                .ok_or_else(|| err(ErrorCode::Unavailable))?;
            schemes.push(v.uses(&pay.part.scheme, model));
        }
        for (id, v) in &attested {
            schemes.push(v.uses(id, UseModel::Reusable));
        }
        let attest_bodies: Vec<&[u8]> = input.attest.iter().map(|a| a.body.as_slice()).collect();
        let notes_pay = input
            .pay
            .as_ref()
            .is_some_and(|p| p.part.scheme == bnap_scheme_notes::SCHEME_ID);
        let fields = if notes_pay {
            bnap_scheme_notes::admission_fields(input.offer.fields(), self.limits.pending_timeout)
        } else {
            input.offer.fields().clone()
        };
        let pay_value = match (&input.pay, &verified_pay) {
            (Some(p), Some(v)) => Some(PayValue {
                scheme: &p.part.scheme,
                claimed: v.value,
                backing: backing.clone(),
                refund: self.registry.scheme(&p.part.scheme).map_or(
                    bnap_core::pricing::Refund::None,
                    crate::registry::SchemeEntry::refund,
                ),
            }),
            _ => None,
        };
        let empty: &[u8] = &[];
        let admitted = outcome::process(
            &*self.store,
            &Request {
                offer: &fields,
                context: &input.context,
                pay_body: input.pay.as_ref().map_or(empty, |p| p.part.body.as_slice()),
                attest_bodies: &attest_bodies,
                schemes: &schemes,
                rail_ids: &rail_ids,
                pay: pay_value,
                attest: &attest,
                now,
            },
            &self.limits,
        )
        .await;
        drop(schemes);
        let admitted = admitted.map_err(|e| {
            if matches!(e, bnap_core::ProcessError::Store(_)) {
                tracing::error!("use store: {e}");
            }
            e.to_error_object()
        })?;
        let settle = SettleState {
            gate: self.clone(),
            offer: input.offer,
            context: input.context,
            digest: input.digest,
            pay: input.pay.map(|p| (p, verified_pay.unwrap_or_default())),
            route: input.route,
        };
        match admitted {
            Admitted::Replay(r) => {
                let r = if r.needs_refund() {
                    settle.refund(&r, now).await?
                } else {
                    r
                };
                let receipt = settle.receipt_fields(&r).await?;
                let mut answer = self.replay_answer(&r, receipt);
                if self.front.is_auth() {
                    // A 2xx would let the front run the action again: a
                    // replay never runs it twice (6.4).
                    *answer.status_mut() = StatusCode::CONFLICT;
                    answer = self.auth_status(answer);
                }
                Ok(Admit::Answer(answer))
            }
            Admitted::New(pending) => {
                let ticket = GateTicket {
                    state: settle,
                    pending,
                    created: now,
                };
                if self.front.is_auth() {
                    // The gate never sees the action: it is admitted, and
                    // settled OK, now.
                    let fields = match Box::new(ticket).settle(Done::Ok { units: 0 }, None).await {
                        Ok(f) => f,
                        Err(r) => return Ok(Admit::Answer(self.auth_status(r))),
                    };
                    let mut r = Response::new(Bytes::new());
                    r.headers_mut().extend(fields);
                    r.headers_mut()
                        .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
                    return Ok(Admit::Answer(r));
                }
                Ok(Admit::Run(Run {
                    request: input.forward,
                    ticket: Box::new(ticket),
                }))
            }
        }
    }

    /// The answer to a replay: the kept answer if there is one, otherwise
    /// the receipt alone (6.4).
    fn replay_answer(&self, r: &Recorded, receipt: HeaderMap) -> Answer {
        let mut resp = if let Some(k) = r.record().response.as_deref().and_then(decode_kept) {
            let mut resp = Response::new(k.body);
            *resp.status_mut() = k.status;
            if let Some(ct) = k.content_type {
                resp.headers_mut().insert(CONTENT_TYPE, ct);
            }
            resp
        } else {
            let body = serde_json::json!({ "bnap": { "replayed": true, "response_kept": false } });
            let mut resp = Response::new(Bytes::from(body.to_string()));
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            resp
        };
        resp.headers_mut().extend(receipt);
        resp.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
        self.auth_status(resp)
    }
}

/// The path a route is matched on: percent-decoded once, dot-segments
/// removed (RFC 3986 5.2.4), empty segments collapsed.
#[must_use]
pub fn route_path(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut dec = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2]))
        {
            dec.push(h * 16 + l);
            i += 3;
        } else {
            dec.push(b[i]);
            i += 1;
        }
    }
    let dec = String::from_utf8_lossy(&dec);
    let mut out: Vec<&str> = Vec::new();
    for seg in dec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let trailing = dec.ends_with('/') && !out.is_empty();
    let mut p = format!("/{}", out.join("/"));
    if trailing {
        p.push('/');
    }
    p
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `status (2 bytes) ‖ lp(content type) ‖ body`, the kept answer.
fn encode_kept(k: &Kept) -> Vec<u8> {
    let mut out = k.status.as_u16().to_be_bytes().to_vec();
    let ct = k
        .content_type
        .as_ref()
        .map_or(&[][..], HeaderValue::as_bytes);
    out.extend_from_slice(&bnap_core::encoding::lp(ct));
    out.extend_from_slice(&k.body);
    out
}

fn decode_kept(b: &[u8]) -> Option<Kept> {
    let status = StatusCode::from_u16(u16::from_be_bytes([*b.first()?, *b.get(1)?])).ok()?;
    let (ct, used) = bnap_core::encoding::read_lp(&b[2..]).ok()?;
    let rest = &b[2 + used..];
    let content_type = if ct.is_empty() {
        None
    } else {
        Some(HeaderValue::from_bytes(ct).ok()?)
    };
    Some(Kept {
        status,
        content_type,
        body: Bytes::copy_from_slice(rest),
    })
}

/// What settling an outcome needs.
struct SettleState {
    gate: Arc<Inner>,
    offer: Offer,
    context: Context,
    digest: Digest,
    pay: Option<(PayPart, Verified)>,
    route: usize,
}

impl SettleState {
    /// The value scheme's settle inside one change budget, closed when it
    /// returns. No pay part settles nothing.
    async fn settle_scheme(
        &self,
        cap: &ChangeCap,
        charged: u64,
        now: u64,
    ) -> Result<Option<Vec<u8>>, ErrorObject> {
        let Some((pay, verified)) = &self.pay else {
            return Ok(None);
        };
        let bounded: Arc<dyn Signer> = Arc::new(OutputBound {
            inner: self.gate.signer.clone(),
            store: self.gate.store.clone(),
            max: self.gate.max_outputs,
        });
        let (capped, guard) = CappedSigner::for_change(bounded, self.gate.store.clone(), cap);
        let r = pay
            .plug
            .scheme
            .settle(
                &pay.part,
                verified,
                &SettleCtx {
                    now,
                    status: cap.status(),
                    charged,
                    entry: &pay.entry,
                    context: &self.context,
                    digest: &self.digest,
                },
                &capped,
            )
            .await;
        guard.close();
        r.map_err(|e| scheme_err(&e))
    }

    /// The refund of a timed-out outcome: the scheme's FAILED settle under
    /// the recorded cap, then recorded once.
    async fn refund(&self, r: &Recorded, now: u64) -> Result<Recorded, ErrorObject> {
        let cap = r.refund_cap().ok_or_else(|| err(ErrorCode::Unavailable))?;
        let result = self.settle_scheme(&cap, 0, now).await?;
        outcome::record_refund(&*self.gate.store, r, result.as_deref())
            .await
            .map_err(|_| err(ErrorCode::Unavailable))
    }

    /// Signs the receipt of a recorded outcome and returns the fields that
    /// carry it.
    async fn receipt_fields(&self, r: &Recorded) -> Result<HeaderMap, ErrorObject> {
        let gate = &self.gate;
        let now = gate.now();
        if gate.receipt_key.not_after < now {
            tracing::error!("the manifest's receipt key has expired: sign a new manifest");
            return Err(err(ErrorCode::Unavailable));
        }
        let unsigned = r
            .unsigned_receipt(&ReceiptInput {
                offer_id: self.offer.offer_id(),
                digest: self.digest,
                unit: self.pay.as_ref().map(|(p, _)| p.entry.unit.clone()),
                metered: self.offer.fields().metered,
                receipt_key: gate.receipt_key.kid,
            })
            .ok_or_else(|| err(ErrorCode::Unavailable))?
            .map_err(|_| err(ErrorCode::Unavailable))?;
        let sig = gate.signer.schnorr(unsigned.message()).await.map_err(|e| {
            tracing::error!("the signer refused a receipt: {e}");
            err(ErrorCode::Unavailable)
        })?;
        let receipt = unsigned
            .finish(&sig)
            .map_err(|_| err(ErrorCode::Unavailable))?;
        let mut h = HeaderMap::new();
        h.insert(
            BNAP_RECEIPT,
            HeaderValue::from_str(&b64u(receipt.bytes()))
                .map_err(|_| err(ErrorCode::Unavailable))?,
        );
        // MPP's own receipt goes next to BNAP's (ERRATA row 33).
        if let Some((p, _)) = &self.pay
            && p.part.scheme == bnap_scheme_mpp::SCHEME_ID
            && receipt.fields().status == Status::Ok
            && let Some(sr) = &receipt.fields().scheme_result
            && let Ok(v) = HeaderValue::from_bytes(sr)
        {
            h.insert(PAYMENT_RECEIPT, v);
        }
        let _ = self.route;
        Ok(h)
    }
}

/// Settles one committed outcome after the action.
struct GateTicket {
    state: SettleState,
    pending: Pending,
    created: u64,
}

#[async_trait::async_trait]
impl Ticket for GateTicket {
    fn timeout(&self) -> Duration {
        let gate = &self.state.gate;
        let deadline = self.created + gate.limits.pending_timeout.saturating_sub(SETTLE_MARGIN);
        Duration::from_secs(deadline.saturating_sub(gate.now()).max(1))
    }

    fn metered(&self) -> bool {
        self.state.offer.fields().metered
    }

    fn meter(&self, head: &http::response::Parts, body: &[u8]) -> Result<u64, String> {
        let plan = &self.state.gate.routes[self.state.route].plan;
        let pointer = plan
            .meter_path()
            .ok_or_else(|| "the route has no meter".to_owned())?;
        let ct = head.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok());
        crate::meter::count(&pointer, ct, body)
    }

    async fn settle(
        self: Box<Self>,
        done: Done,
        answer: Option<Kept>,
    ) -> Result<HeaderMap, Response<Bytes>> {
        let gate = self.state.gate.clone();
        let refuse = |e: ErrorObject| error_response(&gate.carrier, &e);
        let now = gate.now();
        let (status, units) = match done {
            Done::Ok { units } => (Status::Ok, units),
            Done::Failed { .. } => (Status::Failed, 0),
        };
        let mut charge = self.pending.charge(status, units);
        let result = match self
            .state
            .settle_scheme(charge.cap(), charge.charged(), now)
            .await
        {
            Ok(r) => r,
            Err(e) if status == Status::Ok => {
                // The OK settle failed (for example the sweep already timed
                // the outcome out): settle FAILED instead, with the refund.
                tracing::warn!("OK settle failed ({:?}); settling FAILED", e.socket_code());
                charge = self.pending.charge(Status::Failed, 0);
                self.state
                    .settle_scheme(charge.cap(), 0, now)
                    .await
                    .map_err(refuse)?
            }
            Err(e) => return Err(refuse(e)),
        };
        let kept = answer
            .filter(|k| gate.keep_response > 0 && k.body.len() <= gate.keep_response)
            .map(|k| encode_kept(&k));
        let s = Settlement::new(&charge, now)
            .with_scheme_result(result)
            .with_response(kept.clone());
        let recorded = match outcome::settle(&*gate.store, &self.pending, &s, &gate.limits).await {
            Ok(r) => r,
            Err(SettleError::AlreadySettled(r)) if r.needs_refund() => {
                self.state.refund(&r, now).await.map_err(refuse)?
            }
            Err(SettleError::AlreadySettled(r)) => *r,
            Err(SettleError::ChangeOverCap { .. }) => {
                let failed = self.pending.charge(Status::Failed, 0);
                let r = self
                    .state
                    .settle_scheme(failed.cap(), 0, now)
                    .await
                    .map_err(refuse)?;
                let s = Settlement::new(&failed, now)
                    .with_scheme_result(r)
                    .with_response(kept);
                match outcome::settle(&*gate.store, &self.pending, &s, &gate.limits).await {
                    Ok(r) => r,
                    Err(SettleError::AlreadySettled(r)) if r.needs_refund() => {
                        self.state.refund(&r, now).await.map_err(refuse)?
                    }
                    Err(SettleError::AlreadySettled(r)) => *r,
                    Err(_) => return Err(refuse(err(ErrorCode::Unavailable))),
                }
            }
            Err(e) => {
                tracing::error!("settle: {e:?}");
                return Err(refuse(err(ErrorCode::Unavailable)));
            }
        };
        self.state.receipt_fields(&recorded).await.map_err(refuse)
    }
}

#[cfg(test)]
mod tests {
    use super::route_path;

    #[test]
    fn route_paths_are_what_an_application_routes() {
        for (raw, want) in [
            ("/v1/chat/completions", "/v1/chat/completions"),
            ("/v1/chat/%63ompletions", "/v1/chat/completions"),
            ("/v1%2Fchat%2fcompletions", "/v1/chat/completions"),
            ("//v1///chat/./completions", "/v1/chat/completions"),
            ("/v1/x/../chat/completions", "/v1/chat/completions"),
            ("/../../v1", "/v1"),
            ("/files/", "/files/"),
            ("/", "/"),
            ("/%zz", "/%zz"),
            ("/%2", "/%2"),
        ] {
            assert_eq!(route_path(raw), want, "{raw}");
        }
    }
}
