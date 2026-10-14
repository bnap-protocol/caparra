//! The world of the gate's integration tests: a mock OpenAI-compatible
//! upstream (axum), keys and a signed manifest in a temporary directory,
//! the gate started in-process on 127.0.0.1 with the fake rail, the file
//! signer and the SQLite use store, and a clock the tests move.

#![allow(dead_code, clippy::missing_panics_doc, clippy::too_many_lines)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::routing::{get, post};
use bnap_carrier_http::{b64u, client};
use bnap_core::hash::Scope;
use bnap_core::manifest::{KeyUse, ManifestKey};
use bnap_core::schnorr::SigningKey;
use bnap_core::{Offer, Response};
use caparra_gate::config::Config;
use caparra_gate::manifest::SignInput;
use caparra_gate::plugs::Clock;
use caparra_gate::server::Running;

pub const NOW: u64 = 1_791_700_000;
pub const ORIGIN: &str = "https://api.example";
pub const CHAT: &str = "/v1/chat/completions";
pub const OFFER_SECRET: &str = "bda3aea2a2aae7f8373847fa9ea2937fa8befc1da0d83a3071da3c458f13a6b6";
pub const RECEIPT_SECRET: &str = "03cd229c5c5926c3fba5ce72f70d3ac6d632506b9a461c12201b4e8849d9b494";
pub const SEED: &str = "4a7627233f8531b73f6cd8d2b708fede917ebf29f7a518537cc7e0ac5a77c998";
pub const NOT_AFTER: u64 = 4_102_444_800;
pub const DPOP_SECRET: [u8; 32] = [0x44; 32];

/// What the mock upstream saw.
#[derive(Debug, Default)]
pub struct Seen {
    pub calls: AtomicUsize,
    pub last: Mutex<Option<(String, String, http::HeaderMap)>>,
}

pub struct World {
    pub dir: tempfile::TempDir,
    pub clock: Arc<AtomicU64>,
    pub gate: Option<Running>,
    pub base: String,
    pub seen: Arc<Seen>,
    pub http: reqwest::Client,
    pub cfg: Config,
}

pub fn key_file() -> String {
    format!(
        r#"[[key]]
use = "offer"
secret = "{OFFER_SECRET}"
not_after = {NOT_AFTER}

[[key]]
use = "receipt"
secret = "{RECEIPT_SECRET}"
not_after = {NOT_AFTER}

[[keyset]]
seed = "{SEED}"
index = 0
input_fee_ppk = 100
final_expiry = {NOT_AFTER}
active = true
orders = 16
"#
    )
}

fn write_private(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub fn root_key() -> SigningKey {
    SigningKey::from_secret_bytes(&[0x52; 32]).unwrap()
}

pub fn dpop_thumbprint() -> String {
    bnap_scheme_dpop::client::ProofKey::ed25519(&DPOP_SECRET)
        .thumbprint()
        .to_b64u()
}

/// The default configuration; `extra` is appended (more routes).
pub fn config_text(dir: &std::path::Path, upstream: &str, extra: &str) -> String {
    let d = dir.display();
    let root = root_key().public_key();
    let thumb = dpop_thumbprint();
    format!(
        r#"
[gate]
origin = "{ORIGIN}"
listen = "127.0.0.1:0"
upstream = "http://{upstream}"
mac_key_file = "{d}/mac.key"
offer_lifetime_s = 300
route_offer_lifetime_s = 3600

[manifest]
file = "{d}/manifest.json"
root = "{root}"

[store]
kind = "sqlite"
path = "{d}/use.db"

[signer]
kind = "file"
keys = "{d}/keys.toml"

[[rail]]
id = "ln"
kind = "fake"
registry = "ln:lnd"
seed = "{fake}"
invoice_expiry_s = 300

[[scheme]]
id = "bnap:notes"
rail = "ln"
max_fund_sat = 10000

[[scheme]]
id = "httpauth:L402"
rail = "ln"
secret_file = "{d}/l402.key"

[[scheme]]
id = "payment:lightning/charge"
rail = "ln"
secret_file = "{d}/mpp.key"
network = "regtest"

[[attest]]
id = "httpauth:DPoP"
keys = ["{thumb}"]

[[route]]
id = "chat"
match = "POST {CHAT}"
scope = "route"
price = {{ sat = 2100 }}
metered = true
meter = "tokens"
rate = 500
accept = ["bnap:notes", "httpauth:L402", "payment:lightning/charge"]
attest = [{{ scheme = "httpauth:DPoP", effect = "discount", value = 2000 }}]
allow_experimental = true
upstream = "openai"

[[route]]
id = "status"
match = "GET /v1/status"
scope = "route"
price = {{ sat = 10 }}
accept = ["bnap:notes"]
attest = [{{ scheme = "httpauth:DPoP", effect = "waive" }}]
allow_experimental = true

[[route]]
id = "fixed"
match = "POST /v1/fixed"
scope = "exact"
price = {{ sat = 21 }}
accept = ["httpauth:L402", "payment:lightning/charge"]
allow_experimental = true
{extra}
"#,
        fake = "11".repeat(32),
    )
}

/// Writes keys, secrets and a manifest signed for `cfg` into `dir`.
pub fn write_material(dir: &std::path::Path, cfg: &Config, now: u64) {
    write_private(&dir.join("keys.toml"), &key_file());
    write_private(&dir.join("mac.key"), &hex::encode([0x6b; 32]));
    write_private(&dir.join("l402.key"), &hex::encode([0x21; 32]));
    write_private(&dir.join("mpp.key"), &hex::encode([0x22; 32]));
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plans = cfg.plan(&registry).unwrap();
    let pk = |s: &str| {
        SigningKey::from_secret_bytes(&hex::decode(s).unwrap().try_into().unwrap())
            .unwrap()
            .public_key()
    };
    let bytes = caparra_gate::manifest::sign(
        cfg,
        &plans,
        &SignInput {
            root: root_key(),
            backup: SigningKey::from_secret_bytes(&[0x53; 32])
                .unwrap()
                .public_key(),
            seq: 1,
            keys: vec![
                ManifestKey {
                    kid: pk(OFFER_SECRET),
                    key_use: KeyUse::Offer,
                    not_after: NOT_AFTER,
                },
                ManifestKey {
                    kid: pk(RECEIPT_SECRET),
                    key_use: KeyUse::Receipt,
                    not_after: NOT_AFTER,
                },
            ],
            issued: now,
            aux: [0; 32],
        },
    )
    .unwrap();
    std::fs::write(dir.join("manifest.json"), bytes).unwrap();
}

async fn upstream(seen: Arc<Seen>) -> String {
    let s1 = seen.clone();
    let s2 = seen.clone();
    let s3 = seen.clone();
    let app = axum::Router::new()
        .route(
            CHAT,
            post(move |req: axum::extract::Request| {
                let seen = s1.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                    seen.calls.fetch_add(1, Ordering::SeqCst);
                    *seen.last.lock().unwrap() = Some((
                        parts.method.to_string(),
                        parts.uri.to_string(),
                        parts.headers.clone(),
                    ));
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let mode = v["mock"].as_str().unwrap_or("ok").to_owned();
                    let tokens = v["mock_tokens"].as_u64().unwrap_or(850);
                    match mode.as_str() {
                        "sse" => axum::response::Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(axum::body::Body::from("data: {\"usage\":{\"total_tokens\":5}}\n\n"))
                            .unwrap(),
                        "fail" => axum::response::Response::builder()
                            .status(500)
                            .body(axum::body::Body::from("boom"))
                            .unwrap(),
                        "inject" => axum::response::Response::builder()
                            .header("content-type", "application/json")
                            .header("bnap-receipt", "Zm9yZ2Vk")
                            .header("bnap-error", "AAEB")
                            .header("payment-receipt", "forged")
                            .header("www-authenticate", "BNAP offer=\"AAEB\"")
                            .body(axum::body::Body::from(format!(
                                r#"{{"choices":[],"usage":{{"total_tokens":{tokens}}}}}"#
                            )))
                            .unwrap(),
                        _ => axum::response::Response::builder()
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(format!(
                                r#"{{"id":"c-1","choices":[{{"message":{{"content":"Hello"}}}}],"usage":{{"prompt_tokens":10,"completion_tokens":{},"total_tokens":{tokens}}}}}"#,
                                tokens.saturating_sub(10)
                            )))
                            .unwrap(),
                    }
                }
            }),
        )
        .route(
            "/v1/status",
            get(move || {
                let seen = s2.clone();
                async move {
                    seen.calls.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({"status": "up"}))
                }
            }),
        )
        .route(
            "/v1/fixed",
            post(move || {
                let seen = s3.clone();
                async move {
                    seen.calls.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({"fixed": true}))
                }
            }),
        )
        .route("/free", get(|| async { "free" }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    addr.to_string()
}

impl World {
    pub async fn new() -> Self {
        Self::with_extra("").await
    }

    pub async fn with_extra(extra: &str) -> Self {
        let extra = extra.to_owned();
        Self::with_text(move |dir, up| config_text(dir, up, &extra)).await
    }

    /// A world whose configuration `text(dir, upstream)` writes.
    pub async fn with_text(text: impl FnOnce(&std::path::Path, &str) -> String) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .try_init();
        let dir = tempfile::tempdir().unwrap();
        let seen = Arc::new(Seen::default());
        let up = upstream(seen.clone()).await;
        let cfg = Config::parse(&text(dir.path(), &up)).unwrap();
        write_material(dir.path(), &cfg, NOW);
        let clock = Arc::new(AtomicU64::new(NOW));
        let c = clock.clone();
        let clk: Clock = Arc::new(move || c.load(Ordering::SeqCst));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate = caparra_gate::server::start(&cfg, clk, Some(listener))
            .await
            .unwrap();
        if let Some(f) = gate.plugs.fakes.get("ln") {
            f.set_now(NOW);
        }
        let base = format!("http://{}", gate.addr);
        Self {
            dir,
            clock,
            gate: Some(gate),
            base,
            seen,
            http: reqwest::Client::new(),
            cfg,
        }
    }

    pub fn running(&self) -> &Running {
        self.gate.as_ref().unwrap()
    }

    pub fn fake(&self) -> &bnap_rail_fake::FakeRail {
        &self.running().plugs.fakes["ln"]
    }

    pub fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn advance(&self, s: u64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
        self.fake().set_now(self.now());
    }

    pub fn calls(&self) -> usize {
        self.seen.calls.load(Ordering::SeqCst)
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: &str,
        headers: &[(&str, String)],
    ) -> reqwest::Response {
        let mut r = self
            .http
            .request(method.parse().unwrap(), format!("{}{path}", self.base));
        for (k, v) in headers {
            r = r.header(*k, v);
        }
        if !body.is_empty() {
            r = r
                .header("content-type", "application/json")
                .body(body.to_owned());
        }
        r.send().await.unwrap()
    }
}

/// The action scope a client computes for a request.
pub fn scope(method: &str, path: &str, body: &str) -> Scope {
    bnap_core::http::action_scope(
        method,
        &bnap_core::http::target(ORIGIN, path),
        body.as_bytes(),
        &[],
    )
}

/// What a client reads from an answer's fields.
pub struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: String,
}

pub async fn read(r: reqwest::Response) -> Answer {
    let status = r.status().as_u16();
    let mut headers = http::HeaderMap::new();
    for (k, v) in r.headers() {
        headers.append(
            http::HeaderName::from_bytes(k.as_str().as_bytes()).unwrap(),
            http::HeaderValue::from_bytes(v.as_bytes()).unwrap(),
        );
    }
    let body = r.text().await.unwrap();
    Answer {
        status,
        headers,
        body,
    }
}

impl Answer {
    pub fn offers(&self) -> Vec<Offer> {
        client::offers(&self.headers)
    }

    pub fn natives(&self) -> Vec<String> {
        client::native_challenges(&self.headers)
    }

    pub fn receipt(&self) -> Option<Response> {
        client::receipt(&self.headers)
    }

    pub fn error(&self) -> Option<bnap_core::ErrorCode> {
        client::error(&self.headers).and_then(|e| e.socket_code())
    }

    pub fn route_offer(&self) -> Offer {
        self.offers()
            .into_iter()
            .find(|o| o.fields().route_scope)
            .expect("a route offer")
    }

    pub fn exact_offer(&self) -> Offer {
        self.offers()
            .into_iter()
            .find(|o| !o.fields().route_scope)
            .expect("an exact offer")
    }

    pub fn cache_control(&self) -> Option<&str> {
        self.headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
    }
}

pub fn cred_header(c: &bnap_core::Credential) -> (&'static str, String) {
    ("bnap-credential", b64u(&c.to_bytes().unwrap()))
}
