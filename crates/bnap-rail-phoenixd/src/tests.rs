//! The rail against a small stand-in for phoenixd's HTTP API.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use bnap_core::hash::hmac_sha256;
use bnap_plug::confirm_rail_id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// One request the stand-in received.
#[derive(Debug, Clone)]
struct Seen {
    head: String,
    body: String,
}

/// An HTTP/1.1 server on a random local port that answers each request
/// with `answer(method and path)` and records it.
struct Phoenixd {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

type Answer = fn(&str) -> (u16, String);

async fn phoenixd(answer: Answer) -> Phoenixd {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            break (head.to_owned(), body.to_owned());
                        }
                    }
                };
                let line = head.lines().next().unwrap_or_default().to_owned();
                log.lock().unwrap().push(Seen { head, body });
                let (status, json) = answer(&line);
                let reason = if status == 200 { "OK" } else { "X" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                    json.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    Phoenixd { url, seen }
}

const HASH: [u8; 32] = [0xab; 32];

fn hash_hex() -> String {
    hex::encode(HASH)
}

fn incoming(paid: bool, expired: bool, requested: u64, received: u64, fees: u64) -> String {
    format!(
        r#"{{"subType":"lightning","paymentHash":"{}","preimage":"{}","externalId":null,"description":null,"invoice":"lnbcrt1x","isPaid":{paid},"isExpired":{expired},"requestedSat":{requested},"receivedSat":{received},"fees":{fees},"payerNote":null,"payerKey":null,"expiresAt":1,"completedAt":2,"createdAt":0}}"#,
        hash_hex(),
        "00".repeat(32)
    )
}

fn rail(url: &str) -> PhoenixdRail {
    let mut c = PhoenixdConfig::new(url, "secret-pw");
    c.webhook_secret = Some("hook".into());
    PhoenixdRail::new(&c).unwrap()
}

fn ln(hash: [u8; 32]) -> RailRef {
    RailRef {
        kind: "ln".into(),
        reference: hash.to_vec(),
    }
}

#[tokio::test]
async fn an_invoice_is_created_with_the_memo_as_description_hash() {
    let p = phoenixd(|line| {
        assert!(line.starts_with("POST /createinvoice "), "{line}");
        (
            200,
            format!(
                r#"{{"amountSat":21,"paymentHash":"{}","serialized":"lnbcrt210n1fake"}}"#,
                hex::encode(HASH)
            ),
        )
    })
    .await;
    let r = rail(&p.url).request(21, "sat", [7; 32]).await.unwrap();
    assert_eq!(r.id, PayId(HASH.to_vec()));
    assert_eq!(
        (r.rail_kind.as_str(), r.request.as_str()),
        ("ln", "lnbcrt210n1fake")
    );
    assert_eq!((r.amount, r.unit.as_str()), (21, "sat"));
    let seen = p.seen.lock().unwrap()[0].clone();
    assert_eq!(
        seen.body,
        format!(
            "amountSat=21&descriptionHash={}&expirySeconds=3600",
            hex::encode([7; 32])
        )
    );
    let auth = base64::engine::general_purpose::STANDARD.encode(":secret-pw");
    assert!(
        seen.head
            .lines()
            .any(|l| l.eq_ignore_ascii_case(&format!("authorization: Basic {auth}"))),
        "{}",
        seen.head
    );
    // msat converts when whole; otherwise the rail refuses before any call.
    assert!(rail(&p.url).request(21_000, "msat", [7; 32]).await.is_ok());
    assert!(rail(&p.url).request(21_001, "msat", [7; 32]).await.is_err());
    assert!(rail(&p.url).request(21, "USD", [7; 32]).await.is_err());
}

#[tokio::test]
async fn a_paid_invoice_confirms_with_at_least_its_amount() {
    // 21 sat requested, 19 sat net after 1,500 msat of liquidity fees.
    let p = phoenixd(|_| (200, incoming(true, false, 21, 19, 1_500))).await;
    let r = rail(&p.url);
    let c = r.confirm(&ln(HASH)).await.unwrap();
    assert_eq!(c.canonical, HASH.to_vec());
    assert_eq!(
        (c.state, c.amount, c.unit.as_str()),
        (PayState::Paid, 21_000, "msat")
    );
    let paid = confirm_rail_id(&r, &ln(HASH)).await.unwrap();
    assert_eq!(paid.amount, 21_000);
    assert_eq!(
        r.status(&PayId(HASH.to_vec())).await.unwrap(),
        PayState::Paid
    );
    let seen = p.seen.lock().unwrap()[0].clone();
    assert!(
        seen.head
            .starts_with(&format!("GET /payments/incoming/{} ", hash_hex())),
        "{}",
        seen.head
    );
}

#[test]
fn amounts_states_and_hashes_are_read_from_the_answer() {
    let p = |paid, expired, req, rec, fees| {
        serde_json::from_str::<IncomingPayment>(&incoming(paid, expired, req, rec, fees)).unwrap()
    };
    let c = confirmed(&HASH, &p(false, false, 21, 0, 0)).unwrap();
    assert_eq!((c.state, c.amount), (PayState::Pending, 0));
    let c = confirmed(&HASH, &p(false, true, 21, 0, 0)).unwrap();
    assert_eq!((c.state, c.amount), (PayState::Expired, 0));
    // An overpayment counts in full.
    let c = confirmed(&HASH, &p(true, false, 21, 30, 0)).unwrap();
    assert_eq!(c.amount, 30_000);
    // An amountless invoice counts what arrived plus fees.
    let mut free = p(true, false, 0, 19, 1_500);
    free.requested_sat = None;
    assert_eq!(confirmed(&HASH, &free).unwrap().amount, 20_500);
    // An answer about another payment is refused.
    assert!(matches!(
        confirmed(&[1; 32], &p(true, false, 21, 21, 0)),
        Err(RailError::Unavailable(_))
    ));
}

#[tokio::test]
async fn unknown_payments_errors_and_outages_never_confirm() {
    let none = phoenixd(|_| (204, String::new())).await;
    assert!(matches!(
        rail(&none.url).confirm(&ln(HASH)).await,
        Err(RailError::NotConfirmed(_))
    ));
    let unauthorized = phoenixd(|_| (401, "{}".into())).await;
    assert!(matches!(
        rail(&unauthorized.url).confirm(&ln(HASH)).await,
        Err(RailError::Unavailable(_))
    ));
    let garbage = phoenixd(|_| (200, "not json".into())).await;
    assert!(matches!(
        rail(&garbage.url).confirm(&ln(HASH)).await,
        Err(RailError::Unavailable(_))
    ));
    let unpaid = phoenixd(|_| (200, incoming(false, false, 21, 0, 0))).await;
    let e = confirm_rail_id(&rail(&unpaid.url), &ln(HASH))
        .await
        .unwrap_err();
    assert_eq!(e.code(), bnap_core::ErrorCode::BadCredential);
    // Nothing listens on port 9 of localhost.
    let down = rail("http://127.0.0.1:9");
    assert!(matches!(
        down.confirm(&ln(HASH)).await,
        Err(RailError::Unavailable(_))
    ));
    assert!(down.request(1, "sat", [0; 32]).await.is_err());
    // Another rail kind and a short reference.
    let r = rail(&none.url);
    let onchain = RailRef {
        kind: "onchain".into(),
        reference: HASH.to_vec(),
    };
    assert!(matches!(
        r.confirm(&onchain).await,
        Err(RailError::WrongKind { .. })
    ));
    let short = RailRef {
        kind: "ln".into(),
        reference: vec![1; 31],
    };
    assert!(matches!(
        r.confirm(&short).await,
        Err(RailError::NotConfirmed(_))
    ));
}

#[test]
fn webhooks_are_checked_before_they_are_read() {
    let r = rail("http://127.0.0.1:9");
    let body = format!(
        r#"{{"type":"payment_received","timestamp":1,"amountSat":21,"paymentHash":"{}","externalId":"order-7","payerNote":null,"payerKey":null}}"#,
        hash_hex()
    );
    let sig = hex::encode(hmac_sha256(b"hook", body.as_bytes()));
    assert_eq!(
        r.verify_webhook(body.as_bytes(), &sig),
        Ok(WebhookEvent::PaymentReceived {
            payment_hash: HASH,
            amount_sat: 21,
            external_id: Some("order-7".into()),
        })
    );
    assert!(
        r.verify_webhook(body.as_bytes(), &sig.to_uppercase())
            .is_ok()
    );
    let mut tampered = body.clone().into_bytes();
    tampered[40] ^= 1;
    assert_eq!(
        r.verify_webhook(&tampered, &sig),
        Err(WebhookError::BadSignature)
    );
    assert_eq!(
        r.verify_webhook(body.as_bytes(), "zz"),
        Err(WebhookError::BadSignature)
    );
    let other = br#"{"type":"payment_sent","timestamp":1}"#;
    let osig = hex::encode(hmac_sha256(b"hook", other));
    assert_eq!(
        r.verify_webhook(other, &osig),
        Ok(WebhookEvent::Other("payment_sent".into()))
    );
    let no_secret = PhoenixdRail::new(&PhoenixdConfig::new("http://x", "pw")).unwrap();
    assert_eq!(
        no_secret.verify_webhook(body.as_bytes(), &sig),
        Err(WebhookError::NoSecret)
    );
}

#[test]
fn passwords_come_from_phoenix_conf_or_a_bare_file() {
    let dir = std::env::temp_dir().join(format!("bnap-phoenixd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("phoenix.conf");
    std::fs::write(
        &conf,
        "chain=testnet\nhttp-password=abc123\nhttp-password-limited-access=xyz\nwebhook-secret=hook\n",
    )
    .unwrap();
    assert_eq!(read_secret_file(&conf, "http-password").unwrap(), "abc123");
    assert_eq!(read_secret_file(&conf, "webhook-secret").unwrap(), "hook");
    let bare = dir.join("pw");
    std::fs::write(&bare, "  s3cret\n").unwrap();
    assert_eq!(read_secret_file(&bare, "http-password").unwrap(), "s3cret");
    std::fs::write(&bare, "two words\n").unwrap();
    assert!(read_secret_file(&bare, "http-password").is_err());
    assert!(read_secret_file(&dir.join("missing"), "http-password").is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    // The configuration never prints its secrets.
    let mut c = PhoenixdConfig::new("http://x", "abc123");
    c.webhook_secret = Some("hook".into());
    let shown = format!("{c:?}");
    assert!(!shown.contains("abc123") && !shown.contains("hook"));
}
