//! End to end over rmcp's streamable HTTP transport: an rmcp server with a
//! free and priced tools behind `PricedTools`, and rmcp's own client.
//!
//! Payments go through the fake Lightning rail (L402 as a BNAP Credential,
//! `payment:lightning/charge` natively in the MPP key) or a `DPoP`
//! attestation that waives the price.

// Test bodies name the world, the arguments and the error with one letter.
#![allow(clippy::many_single_char_names)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bnap_carrier_mcp::client::{PaymentError, bnap_meta, mpp_meta, receipt};
use bnap_carrier_mcp::{
    Gate, PricedTools, SchemeConfig, StrictConfig, ToolPrice, router, scope, wire,
};
use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::hash::sha256;
use bnap_core::offer::{AttestEntry, Effect};
use bnap_core::pricing::Refund;
use bnap_core::response::Status;
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::CoreMessage;
use bnap_core::store::UseModel;
use bnap_core::test_support::MemoryStore;
use bnap_core::{BindingClass, Credential, ErrorCode, Offer, Response};
use bnap_plug::{
    BlindSignature, BlindedOutput, ChangeLimit, FundingRail, KeysetId, Point, Signer, SignerError,
};
use bnap_rail_fake::FakeRail;
use bnap_scheme_dpop::client::{ProofClaims, ProofKey, body, sign_proof};
use bnap_scheme_dpop::{DpopScheme, StaticAuthority};
use bnap_scheme_l402::{L402, MacaroonKeys, OfferInvoices, Token};
use bnap_scheme_mpp::{ChallengeKeys, ChargeRequest, LightningCharge, Network};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, JsonObject, MetaObject,
    RequestMetaObject, ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleClient, RoleServer, ServerHandler, ServiceError, ServiceExt};
use serde_json::{Map, Value, json};

const NOW: u64 = 1_791_700_000;
const L402_ID: &str = bnap_scheme_l402::SCHEME_ID;
const MPP_ID: &str = bnap_scheme_mpp::SCHEME_ID;
const DPOP: &str = bnap_scheme_dpop::DPOP;

/// The tools: `echo` is free, `weather` and `forecast` cost 21 sat,
/// `fails` costs 21 sat and reports an error, `agent` is waived for a
/// registered `DPoP` key.
#[derive(Clone)]
struct Tools {
    runs: Arc<AtomicUsize>,
    saw_secret: Arc<AtomicUsize>,
}

impl ServerHandler for Tools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if context.meta.0.0.contains_key(wire::CREDENTIAL)
            || context.meta.0.0.contains_key(wire::MPP_CREDENTIAL)
        {
            self.saw_secret.fetch_add(1, Ordering::SeqCst);
        }
        let n = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
        let args = Value::Object(request.arguments.clone().unwrap_or_default());
        let text = format!("{} #{n} {args}", request.name);
        match &*request.name {
            "fails" => Ok(CallToolResult::error(vec![ContentBlock::text(text)]).into()),
            _ => Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into()),
        }
    }
}

/// A signer with one offer key and one receipt key.
#[derive(Debug)]
struct TestSigner {
    offer: SigningKey,
    receipt: SigningKey,
}

impl TestSigner {
    fn new() -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(&sha256(b"mcp offer key")).unwrap(),
            receipt: SigningKey::from_secret_bytes(&sha256(b"mcp receipt key")).unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let key = if *msg.key() == self.offer.public_key() {
            &self.offer
        } else if *msg.key() == self.receipt.public_key() {
            &self.receipt
        } else {
            return Err(SignerError::Refused("key not held".into()));
        };
        msg.sign_with(key, &[0; 32])
            .map_err(|e| SignerError::Refused(e.to_string()))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        _unit: &str,
        _amount: u64,
        _secret: &[u8],
        _c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        Ok(None)
    }

    async fn blind_sign(
        &self,
        _keyset: &KeysetId,
        _outputs: &[BlindedOutput],
        _limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        Err(SignerError::Refused("no change".into()))
    }
}

struct World {
    url: String,
    fake: Arc<FakeRail>,
    runs: Arc<AtomicUsize>,
    saw_secret: Arc<AtomicUsize>,
    receipt_key: Key,
    dpop_key: ProofKey,
    clock: Arc<AtomicU64>,
    client: RunningService<RoleClient, ()>,
}

fn gate(fake: &Arc<FakeRail>, uri: &str, dpop_key: &ProofKey, clock: &Arc<AtomicU64>) -> Gate {
    let invoices: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(fake.clone()));
    let l402 = Arc::new(L402::new(MacaroonKeys::new([0x21; 32]), invoices.clone()));
    let mpp = Arc::new(
        LightningCharge::new(
            ChallengeKeys::new([0x22; 32]).unwrap(),
            "127.0.0.1",
            Network::Regtest,
            invoices,
        )
        .unwrap(),
    );
    let dpop = Arc::new(DpopScheme::new(Arc::new(
        StaticAuthority::new().with_key(dpop_key.thumbprint()),
    )));
    let signer = TestSigner::new();
    let (offer_key, receipt_key) = (signer.offer.public_key(), signer.receipt.public_key());
    let price = ToolPrice::new()
        .pay(L402_ID, 21, "sat")
        .pay(MPP_ID, 21, "sat");
    let c = clock.clone();
    Gate::builder(
        uri,
        Arc::new(MemoryStore::new()),
        Arc::new(signer),
        offer_key,
        receipt_key,
        [0x6b; 32],
    )
    .scheme(SchemeConfig::new(
        l402,
        BindingClass::O,
        UseModel::Single,
        Refund::None,
    ))
    .scheme(SchemeConfig::new(
        mpp,
        BindingClass::O,
        UseModel::Single,
        Refund::None,
    ))
    .scheme(SchemeConfig::new(
        dpop,
        BindingClass::A,
        UseModel::Reusable,
        Refund::None,
    ))
    .rail(fake.clone())
    .tool("weather", price.clone())
    .tool("forecast", price.clone())
    .tool("fails", price)
    .tool(
        "agent",
        ToolPrice::new().attest(AttestEntry::new(DPOP, Effect::Waive)),
    )
    .clock(Arc::new(move || c.load(Ordering::SeqCst)))
    .build()
    .unwrap()
}

async fn world() -> World {
    world_with(true).await
}

/// A server on a free port; `strict` puts the strict JSON layer in front.
async fn world_with(strict: bool) -> World {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let fake = Arc::new(FakeRail::new([0x11; 32]).with_ttl(300));
    fake.set_now(NOW);
    let clock = Arc::new(AtomicU64::new(NOW));
    let dpop_key = ProofKey::es256(&[0x33; 32]).unwrap();
    let gate = Arc::new(gate(&fake, &url, &dpop_key, &clock));
    let receipt_key = gate.config().receipt_key;
    let runs = Arc::new(AtomicUsize::new(0));
    let saw_secret = Arc::new(AtomicUsize::new(0));
    let tools = Tools {
        runs: runs.clone(),
        saw_secret: saw_secret.clone(),
    };
    let app = if strict {
        router(
            "/mcp",
            gate,
            StreamableHttpServerConfig::default(),
            StrictConfig::default(),
            move || tools.clone(),
        )
    } else {
        let mut config = StreamableHttpServerConfig::default();
        config.legacy_session_mode = false;
        config.json_response = true;
        let service: StreamableHttpService<PricedTools<Tools>, LocalSessionManager> =
            StreamableHttpService::new(
                move || Ok(PricedTools::new(tools.clone(), gate.clone())),
                Arc::default(),
                config,
            );
        axum::Router::new().nest_service("/mcp", service)
    };
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = ().serve(StreamableHttpClientTransport::from_uri(url.as_str())).await.unwrap();
    World {
        url,
        fake,
        runs,
        saw_secret,
        receipt_key,
        dpop_key,
        clock,
        client,
    }
}

fn args(v: &Value) -> JsonObject {
    v.as_object().unwrap().clone()
}

fn params(
    tool: &'static str,
    a: &Value,
    meta: Option<Map<String, Value>>,
) -> CallToolRequestParams {
    let mut p = CallToolRequestParams::new(tool).with_arguments(args(a));
    p.meta = meta.map(|m| RequestMetaObject(MetaObject(m)));
    p
}

/// A call's outcome: the result, or the error's code and data.
enum Outcome {
    Ok(CallToolResult),
    Err(i32, Option<Value>),
}

impl Outcome {
    fn ok(self) -> CallToolResult {
        match self {
            Self::Ok(r) => r,
            Self::Err(code, data) => panic!("expected a result, got {code} {data:?}"),
        }
    }

    fn err(self) -> (i32, PaymentError) {
        match self {
            Self::Ok(r) => panic!("expected an error, got {r:?}"),
            Self::Err(code, data) => (code, PaymentError::read(code, data.as_ref())),
        }
    }
}

impl World {
    async fn call(&self, p: CallToolRequestParams) -> Outcome {
        match self.client.call_tool_once(p).await {
            Ok(CallToolResponse::Complete(r)) => Outcome::Ok(r),
            Ok(other) => panic!("unexpected response {other:?}"),
            Err(ServiceError::McpError(e)) => Outcome::Err(e.code.0, e.data),
            Err(e) => panic!("transport error {e}"),
        }
    }

    /// Calls without a credential and returns the one BNAP offer.
    async fn offer(&self, tool: &'static str, a: &Value) -> (PaymentError, Offer) {
        let (code, e) = self.call(params(tool, a, None)).await.err();
        assert_eq!(code, wire::PAYMENT_REQUIRED);
        assert_eq!(e.offers.len(), 1);
        let offer = e.offers[0].clone();
        (e, offer)
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }

    /// Checks a receipt: signed by the receipt key, answering this offer,
    /// with this status and replay flag.
    fn check_receipt(&self, r: &Response, offer: &Offer, status: Status, replayed: bool) {
        r.verify_ack().unwrap();
        let f = r.fields();
        assert_eq!(f.receipt_key, self.receipt_key);
        assert_eq!(f.offer_id, offer.offer_id());
        assert_eq!(f.status, status);
        assert_eq!(f.replayed, replayed);
    }
}

fn native(offer: &Offer, kind: &str) -> String {
    let n = offer
        .fields()
        .native
        .iter()
        .find(|n| n.kind == kind)
        .unwrap();
    String::from_utf8(n.data.clone()).unwrap()
}

/// Pays the offer's invoice on the fake rail and returns the L402 token.
fn pay_l402(w: &World, offer: &Offer) -> String {
    let c = bnap_scheme_l402::Challenge::parse(&native(offer, "l402-macaroon")).unwrap();
    let mpp = bnap_scheme_mpp::Challenge::parse(&native(offer, "mpp-challenge")).unwrap();
    let hash = ChargeRequest::decode(&mpp.request).unwrap().payment_hash;
    let preimage = w.fake.pay(&hash).unwrap();
    Token::new(&c.token, preimage).unwrap().to_string()
}

/// Pays the offer's invoice and returns the MPP token (HTTP form).
fn pay_mpp(w: &World, offer: &Offer) -> String {
    let c = bnap_scheme_mpp::Challenge::parse(&native(offer, "mpp-challenge")).unwrap();
    let hash = ChargeRequest::decode(&c.request).unwrap().payment_hash;
    let preimage = w.fake.pay(&hash).unwrap();
    bnap_scheme_mpp::Credential::new(c, preimage).encode()
}

/// A BNAP Credential naming `offer` by ID, with an L402 pay part.
fn l402_credential(offer: &Offer, token: &str) -> Vec<u8> {
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(L402_ID, token.as_bytes().to_vec()));
    c.to_bytes().unwrap()
}

#[tokio::test]
async fn a_free_tool_runs_without_payment() {
    let w = world().await;
    let r = w.call(params("echo", &json!({"x": 1}), None)).await.ok();
    assert_eq!(w.runs(), 1);
    assert!(receipt(r.meta.as_ref().map(|m| &m.0)).is_none());
}

#[tokio::test]
async fn a_priced_tool_without_credential_gets_an_offer_and_does_not_run() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (e, offer) = w.offer("weather", &a).await;
    assert_eq!(w.runs(), 0);
    // The MPP MCP shape: -32042, httpStatus 402, challenges with the MPP
    // challenge (request as JSON) and the BNAP offer entry.
    assert_eq!(e.http_status, 402);
    assert_eq!(e.error.as_ref().unwrap().code, ErrorCode::Required.code());
    assert_eq!(e.challenges.len(), 1);
    let ch = &e.challenges[0];
    assert_eq!(ch["method"], "lightning");
    assert_eq!(ch["intent"], "charge");
    assert!(ch["request"].is_object());
    assert!(e.receipt.is_none());
    // The offer is for exactly this call.
    let s = scope::action_scope(&w.url, "weather", Some(&args(&a))).unwrap();
    assert_eq!(offer.fields().scope, s);
    assert!(!offer.fields().route_scope);
    let names: Vec<_> = offer
        .fields()
        .pay
        .iter()
        .map(|p| p.scheme.as_str())
        .collect();
    assert_eq!(names, [L402_ID, MPP_ID]);
}

#[tokio::test]
async fn an_l402_credential_pays_once_and_its_replay_returns_the_kept_result() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    let first = w
        .call(params("weather", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    assert_eq!(
        w.saw_secret.load(Ordering::SeqCst),
        0,
        "the tool never sees a credential"
    );
    let r = receipt(first.meta.as_ref().map(|m| &m.0)).unwrap();
    w.check_receipt(&r, &offer, Status::Ok, false);
    assert_eq!(r.fields().charged, 21);
    assert_eq!(r.fields().unit.as_deref(), Some("sat"));
    // No MPP receipt for a BNAP credential.
    assert!(
        !first
            .meta
            .as_ref()
            .unwrap()
            .0
            .contains_key(wire::MPP_RECEIPT)
    );

    // The same credential again: the action does not run twice, the kept
    // result comes back with a fresh receipt marked replayed (6.4).
    let again = w
        .call(params("weather", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    assert_eq!(again.content, first.content);
    let r2 = receipt(again.meta.as_ref().map(|m| &m.0)).unwrap();
    w.check_receipt(&r2, &offer, Status::Ok, true);
    assert_eq!(r2.fields().settled_at, r.fields().settled_at);
    assert_eq!(r2.fields().charged, 21);
}

#[tokio::test]
async fn altered_arguments_are_wrong_scope_with_a_fresh_offer() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    for altered in [
        json!({"city": "Zug"}),
        json!({"city": "Bern", "days": 1}),
        json!({}),
        json!({"City": "Bern"}),
    ] {
        let (code, e) = w
            .call(params("weather", &altered, Some(bnap_meta(&cred))))
            .await
            .err();
        assert_eq!(code, wire::VERIFICATION_FAILED, "{altered}");
        assert_eq!(e.error.unwrap().code, ErrorCode::WrongScope.code());
        assert_eq!(e.http_status, 402);
        assert_eq!(e.offers.len(), 1, "a fresh offer for the altered call");
        assert!(e.receipt.is_none());
    }
    assert_eq!(w.runs(), 0);
    // The credential still works for the call it was made for.
    w.call(params("weather", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
}

#[tokio::test]
async fn equivalent_json_has_one_scope() {
    let w = world().await;
    let a = json!({"city": "Bern", "days": 2, "opts": {"b": true, "a": [1, "x"]}});
    let (_, offer) = w.offer("weather", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    // Other member order and another spelling of the number 2.
    let same = json!({"opts": {"a": [1.0, "x"], "b": true}, "days": 2.0, "city": "Bern"});
    w.call(params("weather", &same, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
}

#[tokio::test]
async fn a_credential_for_one_tool_is_refused_on_another() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let token = pay_l402(&w, &offer);
    let cred = l402_credential(&offer, &token);
    let (code, e) = w
        .call(params("forecast", &a, Some(bnap_meta(&cred))))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::WrongScope.code());
    // The MPP form of the same payment, on the other tool, too.
    let mpp_token = {
        let c = bnap_scheme_mpp::Challenge::parse(&native(&offer, "mpp-challenge")).unwrap();
        let t = bnap_scheme_l402::Token::parse(token.as_bytes()).unwrap();
        bnap_scheme_mpp::Credential::new(c, *t.preimage()).encode()
    };
    let (code, e) = w
        .call(params("forecast", &a, Some(mpp_meta(&mpp_token).unwrap())))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::WrongScope.code());
    assert_eq!(w.runs(), 0);
}

#[tokio::test]
async fn an_mpp_native_credential_pays_and_gets_both_receipts() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let token = pay_mpp(&w, &offer);
    let r = w
        .call(params("weather", &a, Some(mpp_meta(&token).unwrap())))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    let meta = &r.meta.as_ref().unwrap().0;
    let bnap = receipt(Some(meta)).unwrap();
    w.check_receipt(&bnap, &offer, Status::Ok, false);
    let mpp = &meta[wire::MPP_RECEIPT];
    assert_eq!(mpp["status"], "success");
    assert_eq!(mpp["method"], "lightning");
    assert!(mpp["challengeId"].is_string());
    // Replay: no second run, the same MPP receipt, the BNAP one replayed.
    let again = w
        .call(params("weather", &a, Some(mpp_meta(&token).unwrap())))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    let meta2 = &again.meta.as_ref().unwrap().0;
    w.check_receipt(&receipt(Some(meta2)).unwrap(), &offer, Status::Ok, true);
    assert_eq!(meta2[wire::MPP_RECEIPT], *mpp);
}

#[tokio::test]
async fn one_payment_under_two_schemes_admits_one_call() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let token = pay_l402(&w, &offer);
    w.call(params(
        "weather",
        &a,
        Some(bnap_meta(&l402_credential(&offer, &token))),
    ))
    .await
    .ok();
    let c = bnap_scheme_mpp::Challenge::parse(&native(&offer, "mpp-challenge")).unwrap();
    let preimage = *Token::parse(token.as_bytes()).unwrap().preimage();
    let mpp_token = bnap_scheme_mpp::Credential::new(c, preimage).encode();
    let (code, e) = w
        .call(params("weather", &a, Some(mpp_meta(&mpp_token).unwrap())))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::Spent.code());
    assert_eq!(e.http_status, 409);
    assert!(e.receipt.is_none());
    assert_eq!(w.runs(), 1);
}

#[tokio::test]
async fn an_unpaid_invoice_never_runs_the_tool() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let c = bnap_scheme_l402::Challenge::parse(&native(&offer, "l402-macaroon")).unwrap();
    let token = Token::new(&c.token, [9; 32]).unwrap().to_string();
    let (code, e) = w
        .call(params(
            "weather",
            &a,
            Some(bnap_meta(&l402_credential(&offer, &token))),
        ))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::BadCredential.code());
    assert_eq!(w.runs(), 0);
}

#[tokio::test]
async fn a_dpop_attestation_waives_the_price() {
    let w = world().await;
    let a = json!({"task": "summarize"});
    let (_, offer) = w.offer("agent", &a).await;
    assert_eq!(offer.fields().pay, []);
    // Not cached (no natives): the credential carries the offer inline.
    let mut c = Credential::new(OfferRef::Inline(offer.bytes().to_vec()));
    let s = scope::action_scope(&w.url, "agent", Some(&args(&a))).unwrap();
    let ctx = {
        let mut probe = c.clone();
        probe.attest = vec![SchemePart::new(DPOP, Vec::new())];
        probe.context(&offer.offer_id(), &s)
    };
    let proof = sign_proof(
        &w.dpop_key,
        &ProofClaims {
            context: &ctx,
            htm: "POST",
            htu: &w.url,
            iat: NOW,
            jti: "j1",
            access_token: None,
        },
    );
    c.attest = vec![SchemePart::new(DPOP, body(&proof, None))];
    let cred = c.to_bytes().unwrap();
    let r = w
        .call(params("agent", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    let rec = receipt(r.meta.as_ref().map(|m| &m.0)).unwrap();
    w.check_receipt(&rec, &offer, Status::Ok, false);
    assert_eq!(rec.fields().charged, 0);
    assert_eq!(rec.fields().unit, None);
    // Replay of the same proof: answered from the record.
    w.call(params("agent", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(w.runs(), 1);
    // An unregistered key: the waive has no effect, and without pay the
    // price is not met.
    let other = ProofKey::es256(&[0x44; 32]).unwrap();
    let proof = sign_proof(
        &other,
        &ProofClaims {
            context: &ctx,
            htm: "POST",
            htu: &w.url,
            iat: NOW,
            jti: "j2",
            access_token: None,
        },
    );
    c.attest = vec![SchemePart::new(DPOP, body(&proof, None))];
    let (code, e) = w
        .call(params("agent", &a, Some(bnap_meta(&c.to_bytes().unwrap()))))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::Underpaid.code());
    assert_eq!(w.runs(), 1);
}

#[tokio::test]
async fn a_failed_tool_settles_failed_with_its_receipt() {
    let w = world().await;
    let a = json!({"q": 1});
    let (_, offer) = w.offer("fails", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    let r = w
        .call(params("fails", &a, Some(bnap_meta(&cred))))
        .await
        .ok();
    assert_eq!(r.is_error, Some(true));
    let rec = receipt(r.meta.as_ref().map(|m| &m.0)).unwrap();
    w.check_receipt(&rec, &offer, Status::Failed, false);
    assert_eq!(rec.fields().charged, 0);
}

#[tokio::test]
async fn an_expired_offer_is_stale() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    w.clock.store(NOW + 300 + 61, Ordering::SeqCst);
    let (code, e) = w
        .call(params("weather", &a, Some(bnap_meta(&cred))))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::Stale.code());
    assert_eq!(e.offers.len(), 1);
    assert_eq!(w.runs(), 0);
}

#[tokio::test]
async fn bad_credentials_are_refused_before_anything_runs() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let token = pay_mpp(&w, &offer);
    // Two value credentials.
    let mut both = mpp_meta(&token).unwrap();
    both.extend(bnap_meta(b"x"));
    let (code, e) = w.call(params("weather", &a, Some(both))).await.err();
    assert_eq!(code, wire::INVALID_PARAMS);
    assert_eq!(e.error.unwrap().code, ErrorCode::Malformed.code());
    // Not base64url, not a string, not a credential.
    for v in [json!("+++"), json!(7), json!("AAAA")] {
        let mut m = Map::new();
        m.insert(wire::CREDENTIAL.into(), v.clone());
        let (code, e) = w.call(params("weather", &a, Some(m))).await.err();
        assert_eq!(code, wire::INVALID_PARAMS, "{v}");
        assert_eq!(e.error.unwrap().code, ErrorCode::Malformed.code());
    }
    // Over the credential limit.
    let mut m = Map::new();
    m.insert(wire::CREDENTIAL.into(), json!("A".repeat(30_000)));
    let (_, e) = w.call(params("weather", &a, Some(m))).await.err();
    assert_eq!(e.error.unwrap().code, ErrorCode::TooLarge.code());
    // A TLS binding cannot be checked over MCP.
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(L402_ID, b"x".to_vec()));
    c.binding = Some([1; 32]);
    let (_, e) = w
        .call(params(
            "weather",
            &a,
            Some(bnap_meta(&c.to_bytes().unwrap())),
        ))
        .await
        .err();
    assert_eq!(e.error.unwrap().code, ErrorCode::Binding.code());
    // An unknown OfferID.
    let mut c = Credential::new(OfferRef::Id(bnap_core::OfferId([5; 32])));
    c.pay = Some(SchemePart::new(L402_ID, b"x".to_vec()));
    let (code, e) = w
        .call(params(
            "weather",
            &a,
            Some(bnap_meta(&c.to_bytes().unwrap())),
        ))
        .await
        .err();
    assert_eq!(code, wire::VERIFICATION_FAILED);
    assert_eq!(e.error.unwrap().code, ErrorCode::BadOffer.code());
    assert_eq!(e.offers.len(), 1);
    assert_eq!(w.runs(), 0);
}

/// A raw JSON-RPC POST, for bodies rmcp's client cannot produce.
async fn post(url: &str, tool: &str, body: &str) -> Value {
    let res = reqwest::Client::new()
        .post(url)
        .header("mcp-method", "tools/call")
        .header("mcp-name", tool)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .body(body.to_owned())
        .send()
        .await
        .unwrap();
    let text = res.text().await.unwrap();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("not JSON: {text}"))
}

fn call_body(tool: &str, arguments: &str, meta: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{{"name":"t","version":"1"}},"io.modelcontextprotocol/clientCapabilities":{{}}{meta}}}}}}}"#
    )
}

#[tokio::test]
async fn duplicate_json_members_are_refused_before_rmcp() {
    let w = world().await;
    for (arguments, meta) in [
        (r#"{"city":"Bern","city":"Zug"}"#, ""),
        (r#"{"a":{"b":1,"b":2}}"#, ""),
        (r#"{"a":[{"b":1,"\u0062":2}]}"#, ""),
        (
            r#"{"city":"Bern"}"#,
            r#","org.bnap/credential":"x","org.bnap/credential":"y""#,
        ),
    ] {
        for tool in ["weather", "echo"] {
            let v = post(&w.url, tool, &call_body(tool, arguments, meta)).await;
            assert_eq!(v["id"], 7);
            assert_eq!(v["error"]["code"], wire::INVALID_PARAMS, "{arguments}");
            let d = PaymentError::read(wire::INVALID_PARAMS, v["error"].get("data"));
            assert_eq!(d.error.unwrap().code, ErrorCode::Malformed.code());
            assert_eq!(d.http_status, 400);
        }
    }
    assert_eq!(w.runs(), 0);
    // The same call without the duplicate reaches the gate: an offer.
    let v = post(
        &w.url,
        "weather",
        &call_body("weather", r#"{"city":"Bern"}"#, ""),
    )
    .await;
    assert_eq!(v["error"]["code"], wire::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn a_unicode_escape_is_the_same_argument() {
    let w = world().await;
    let a = json!({"city": "Bern"});
    let (_, offer) = w.offer("weather", &a).await;
    let cred = l402_credential(&offer, &pay_l402(&w, &offer));
    let meta = format!(r#","org.bnap/credential":"{}""#, wire::b64u(&cred));
    let v = post(
        &w.url,
        "weather",
        &call_body("weather", r#"{"c\u0069ty":"B\u0065rn"}"#, &meta),
    )
    .await;
    assert!(v.get("error").is_none(), "{v}");
    assert!(v["result"]["_meta"][wire::RECEIPT].is_string());
    assert_eq!(w.runs(), 1);
}

#[tokio::test]
async fn without_the_strict_layer_a_priced_tool_never_runs() {
    let w = world_with(false).await;
    let a = json!({"city": "Bern"});
    let (code, e) = w.call(params("weather", &a, None)).await.err();
    assert_eq!(code, wire::INTERNAL_ERROR);
    assert_eq!(e.error.unwrap().code, ErrorCode::Unavailable.code());
    assert_eq!(e.offers, []);
    // Free tools still work.
    w.call(params("echo", &a, None)).await.ok();
    assert_eq!(w.runs(), 1);
}
