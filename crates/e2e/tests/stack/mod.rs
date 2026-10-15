//! The real gate on the regtest network: `bnap-signer --store` and
//! `caparra-gate run` started as processes from this workspace's binaries,
//! with the LND rail on the payee node, the SQLite use store, a mock
//! OpenAI-compatible upstream, and a TLS front (the test CA in
//! `tests/fixtures`) for clients that fetch HTTPS only, such as `bnap`.
//!
//! Payments are made from the payer node with `lncli` (devenv/regtest).

#![allow(dead_code, clippy::missing_panics_doc, clippy::too_many_lines)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use axum::routing::{get, post};
use bnap_carrier_http::{b64u, client};
use bnap_core::manifest::{ManifestKey, Pin};
use bnap_core::schnorr::SigningKey;
use bnap_core::{Offer, Response};

/// The metered route.
pub const CHAT: &str = "/v1/chat/completions";
/// A chat request the mock upstream answers with 850 tokens.
pub const CHAT_BODY: &str =
    r#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;
/// The passphrase of every test wallet.
pub const PASS: &str = "e2e regtest passphrase";

pub fn devenv() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devenv/regtest")
}

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The payee node's gRPC address, TLS cert and invoice macaroon, from the
/// environment or from `devenv/regtest/up.sh`.
pub fn lnd() -> (String, String, String) {
    if let (Ok(a), Ok(c), Ok(m)) = (
        std::env::var("BNAP_REGTEST_LND_ADDRESS"),
        std::env::var("BNAP_REGTEST_LND_CERT"),
        std::env::var("BNAP_REGTEST_LND_MACAROON"),
    ) {
        return (a, c, m);
    }
    let up = Command::new("sh")
        .arg(devenv().join("up.sh"))
        .status()
        .expect("run devenv/regtest/up.sh");
    assert!(up.success(), "devenv/regtest/up.sh failed");
    let env = std::fs::read_to_string(devenv().join(".state/env")).expect("read .state/env");
    let get = |key: &str| {
        env.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} missing from .state/env"))
            .to_owned()
    };
    (
        get("BNAP_REGTEST_LND_ADDRESS"),
        get("BNAP_REGTEST_LND_CERT"),
        get("BNAP_REGTEST_LND_MACAROON"),
    )
}

/// The argv that pays an invoice from the payer node: `lncli payinvoice`
/// in the payer container. `{invoice}` and `{max_fee}` are the `bnap
/// paysource command` placeholders.
pub fn payer_argv() -> Vec<String> {
    let compose = devenv().join("compose.yml");
    [
        "docker",
        "compose",
        "-f",
        compose.to_str().unwrap(),
        "exec",
        "-T",
        "payer",
        "lncli",
        "--network=regtest",
        "payinvoice",
        "--force",
        "--json",
        "--fee_limit",
        "{max_fee}",
        "{invoice}",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// Pays `invoice` from the payer node and returns the preimage. Retried a
/// few times: right after the channel opens the router can briefly report
/// no balance.
pub fn payer_pays(invoice: &str) -> [u8; 32] {
    let mut last = String::new();
    for _ in 0..10 {
        let out = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(devenv().join("compose.yml"))
            .args(["exec", "-T", "payer", "lncli", "--network=regtest"])
            .args(["payinvoice", "--force", "--json", invoice])
            .output()
            .expect("run lncli payinvoice");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success()
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout)
            && v["status"] == "SUCCEEDED"
        {
            let mut preimage = [0; 32];
            hex::decode_to_slice(v["payment_preimage"].as_str().unwrap(), &mut preimage).unwrap();
            return preimage;
        }
        last = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("payinvoice did not succeed: {last}");
}

/// Where cargo puts this workspace's binaries.
fn bin_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    target.join("debug")
}

/// The path of one of this workspace's binaries, built once per test
/// process (`cargo build` serializes concurrent builds itself).
pub fn bin(name: &str) -> PathBuf {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let ok = Command::new(cargo)
            .args(["build", "--locked", "--bins"])
            .args([
                "-p",
                "caparra-gate",
                "-p",
                "bnap-signer-process",
                "-p",
                "bnap-cli",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run cargo build");
        assert!(ok.success(), "cargo build of the binaries failed");
    });
    bin_dir().join(name)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn random_hex() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// What the mock upstream saw.
#[derive(Debug, Default)]
pub struct Seen {
    pub calls: AtomicUsize,
}

async fn upstream(seen: Arc<Seen>) -> SocketAddr {
    let (s1, s2, s3) = (seen.clone(), seen.clone(), seen.clone());
    let app = axum::Router::new()
        .route(
            CHAT,
            post(move |body: axum::body::Bytes| {
                let seen = s1.clone();
                async move {
                    seen.calls.fetch_add(1, Ordering::SeqCst);
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let tokens = v["mock_tokens"].as_u64().unwrap_or(850);
                    axum::response::Response::builder()
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(format!(
                            r#"{{"id":"c-1","choices":[{{"message":{{"content":"Hello"}}}}],"usage":{{"prompt_tokens":10,"completion_tokens":{},"total_tokens":{tokens}}}}}"#,
                            tokens.saturating_sub(10)
                        )))
                        .unwrap()
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
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    addr
}

/// Terminates TLS with the fixture certificate (`localhost`, signed by
/// the fixture CA) and passes the bytes on to `to`.
async fn tls_front(listener: tokio::net::TcpListener, to: SocketAddr) {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(fixtures().join("localhost.pem"))
            .unwrap()
            .map(Result::unwrap)
            .collect();
    let key = PrivateKeyDer::from_pem_file(fixtures().join("localhost.key")).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let Ok(mut up) = tokio::net::TcpStream::connect(to).await else {
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
        });
    }
}

/// Child processes killed when the stack goes.
struct Procs(Vec<Child>);

impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// One gate, its signer and its upstream.
pub struct Stack {
    pub dir: tempfile::TempDir,
    /// `https://localhost:<port>`: the manifest origin, served by the TLS
    /// front.
    pub origin: String,
    /// `http://127.0.0.1:<port>`: the gate itself.
    pub base: String,
    pub seen: Arc<Seen>,
    pub http: reqwest::Client,
    /// The keys of the manifest, accepted as a client pins them (9.3).
    pub pin: Pin,
    procs: Procs,
}

impl Stack {
    pub async fn start() -> Self {
        let (address, cert, macaroon) = lnd();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let seen = Arc::new(Seen::default());
        let up = upstream(seen.clone()).await;
        let gate_port = free_port();
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://localhost:{}", front.local_addr().unwrap().port());
        tokio::spawn(tls_front(front, ([127, 0, 0, 1], gate_port).into()));

        // Keys: online keys for 20 days (a manifest key may not outlive 30
        // days, MAN-KEY-LIFETIME), a notes keyset for a year.
        let t = now();
        write_private(
            &d.join("keys.toml"),
            &format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{}\"\nnot_after = {}\n\n\
                 [[key]]\nuse = \"receipt\"\nsecret = \"{}\"\nnot_after = {}\n\n\
                 [[keyset]]\nseed = \"{}\"\nindex = 0\ninput_fee_ppk = 100\n\
                 final_expiry = {}\nactive = true\norders = 16\n",
                random_hex(),
                t + 20 * 86_400,
                random_hex(),
                t + 20 * 86_400,
                random_hex(),
                t + 365 * 86_400,
            ),
        );
        for f in ["mac.key", "l402.key", "mpp.key", "root.key"] {
            write_private(&d.join(f), &random_hex());
        }
        let root_secret: [u8; 32] =
            hex::decode(std::fs::read_to_string(d.join("root.key")).unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let root = SigningKey::from_secret_bytes(&root_secret)
            .unwrap()
            .public_key();
        let backup = SigningKey::from_secret_bytes(&rand::random::<[u8; 32]>())
            .unwrap()
            .public_key();
        let dd = d.display();
        let config = format!(
            r#"
[gate]
origin = "{origin}"
listen = "127.0.0.1:{gate_port}"
upstream = "http://{up}"
mac_key_file = "{dd}/mac.key"
offer_lifetime_s = 300
route_offer_lifetime_s = 3600

[manifest]
file = "{dd}/manifest.json"
root = "{root}"

[store]
kind = "sqlite"
path = "{dd}/use.db"

[signer]
kind = "process"
socket = "{dd}/signer/s.sock"

[[rail]]
id = "ln"
kind = "lnd"
address = "{address}"
cert = "{cert}"
macaroon = "{macaroon}"
invoice_expiry_s = 300

[[scheme]]
id = "bnap:notes"
rail = "ln"
max_fund_sat = 10000

[[scheme]]
id = "httpauth:L402"
rail = "ln"
secret_file = "{dd}/l402.key"

[[scheme]]
id = "payment:lightning/charge"
rail = "ln"
secret_file = "{dd}/mpp.key"
network = "regtest"

[[route]]
id = "chat"
match = "POST {CHAT}"
scope = "route"
price = {{ sat = 2100 }}
metered = true
meter = "tokens"
rate = 500
accept = ["bnap:notes", "httpauth:L402", "payment:lightning/charge"]
allow_experimental = true
upstream = "openai"

[[route]]
id = "status"
match = "GET /v1/status"
scope = "route"
price = {{ sat = 10 }}
accept = ["bnap:notes"]
allow_experimental = true

[[route]]
id = "fixed"
match = "POST /v1/fixed"
scope = "exact"
price = {{ sat = 21 }}
accept = ["httpauth:L402", "payment:lightning/charge"]
allow_experimental = true

[limits]
mints_per_minute = 600
"#
        );
        std::fs::write(d.join("gate.toml"), config).unwrap();

        let sign = Command::new(bin("caparra-gate"))
            .args(["manifest", "sign", "--config"])
            .arg(d.join("gate.toml"))
            .arg("--root-key")
            .arg(d.join("root.key"))
            .args(["--backup", &backup.to_string(), "--seq", "1"])
            .arg("--keys-from")
            .arg(d.join("keys.toml"))
            .arg("--out")
            .arg(d.join("manifest.json"))
            .output()
            .unwrap();
        assert!(
            sign.status.success(),
            "manifest sign: {}",
            String::from_utf8_lossy(&sign.stderr)
        );

        let log = |name: &str| std::fs::File::create(d.join(name)).unwrap();
        std::fs::create_dir(d.join("signer")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(d.join("signer"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut procs = Procs(Vec::new());
        procs.0.push(
            Command::new(bin("bnap-signer"))
                .arg("--keys")
                .arg(d.join("keys.toml"))
                .arg("--socket")
                .arg(d.join("signer/s.sock"))
                .arg("--store")
                .arg(d.join("use.db"))
                .stdout(Stdio::null())
                .stderr(log("signer.log"))
                .spawn()
                .unwrap(),
        );
        wait_for(|| d.join("signer/s.sock").exists(), "the signer socket");
        procs.0.push(
            Command::new(bin("caparra-gate"))
                .arg("run")
                .arg("--config")
                .arg(d.join("gate.toml"))
                .stdout(Stdio::null())
                .stderr(log("gate.log"))
                .spawn()
                .unwrap(),
        );
        let base = format!("http://127.0.0.1:{gate_port}");
        let http = reqwest::Client::new();
        let started = Instant::now();
        let manifest = loop {
            if let Ok(r) = http.get(format!("{base}/.well-known/bnap")).send().await
                && r.status() == 200
            {
                break r.bytes().await.unwrap();
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the gate did not start: {}",
                std::fs::read_to_string(d.join("gate.log")).unwrap_or_default()
            );
            if let Some(c) = procs.0.last_mut()
                && let Ok(Some(status)) = c.try_wait()
            {
                panic!(
                    "the gate exited ({status}): {}",
                    std::fs::read_to_string(d.join("gate.log")).unwrap_or_default()
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let (pin, _) = bnap_core::manifest::accept(None, &origin, &manifest, now()).unwrap();
        Self {
            dir,
            origin,
            base,
            seen,
            http,
            pin,
            procs,
        }
    }

    pub fn calls(&self) -> usize {
        self.seen.calls.load(Ordering::SeqCst)
    }

    /// The manifest's receipt keys.
    pub fn keys(&self) -> &[ManifestKey] {
        &self.pin.keys
    }

    pub fn gate_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("gate.log")).unwrap_or_default()
    }

    /// Sends a request to the gate directly (plain HTTP; the scope's
    /// target is the origin's, as the gate computes it).
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: &str,
        headers: &[(&str, String)],
    ) -> Answer {
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
        read(r.send().await.unwrap()).await
    }

    /// The action scope a client computes for a request to this origin.
    pub fn scope(&self, method: &str, path: &str, body: &str) -> bnap_core::hash::Scope {
        bnap_core::http::action_scope(
            method,
            &bnap_core::http::target(&self.origin, path),
            body.as_bytes(),
            &[],
        )
    }

    /// The `bnap` CLI with a wallet in this stack's directory, trusting the
    /// fixture CA.
    pub fn bnap(&self, args: &[&str]) -> (bool, serde_json::Value, String) {
        let out = Command::new(bin("bnap"))
            .arg("--wallet")
            .arg(self.dir.path().join("wallet.db"))
            .arg("--json")
            .args(args)
            .env("BNAP_PASSPHRASE", PASS)
            .env("SSL_CERT_FILE", fixtures().join("ca.pem"))
            .env_remove("SSL_CERT_DIR")
            .env_remove("BNAP_WALLET")
            .env_remove("BNAP_TASK")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let v = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
        (out.status.success(), v, text)
    }
}

fn wait_for(cond: impl Fn() -> bool, what: &str) {
    let started = Instant::now();
    while !cond() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What a client reads from an answer.
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
            .find(|o| !o.fields().route_scope && !o.fields().native.is_empty())
            .expect("an exact offer with natives")
    }
}

pub fn cred_header(c: &bnap_core::Credential) -> (&'static str, String) {
    ("bnap-credential", b64u(&c.to_bytes().unwrap()))
}
