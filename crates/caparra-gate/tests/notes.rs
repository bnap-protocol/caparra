//! `bnap:notes` through the gate, with the N6 client module as the wallet:
//! funded inside the 402, spent on the metered route offer with a DPoP
//! discount, replayed, refused as SPENT on reuse, refunded when the answer
//! cannot be metered; DPoP waive on its own.

#![allow(
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod common;

use bnap_core::Credential;
use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::response::Status;
use bnap_core::{ErrorCode, Offer};
use bnap_scheme_notes::FundRequest;
use bnap_scheme_notes::client::{self, KeyTable, Note, PendingOutput};
use bnap_scheme_notes::wire::{FundQuote, KeysetIdBytes, Params};
use common::*;

const CHAT_BODY: &str =
    r#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;

struct Wallet {
    seed: [u8; 64],
    next: u64,
    keyset: KeysetIdBytes,
    keys: KeyTable,
}

impl Wallet {
    fn new() -> Self {
        let signer = bnap_signer_file::FileSigner::from_toml(&key_file()).unwrap();
        let ks = &signer.keysets()[0];
        let mut keys = KeyTable::new();
        keys.insert(ks.id(), ks.public_keys());
        Self {
            seed: [0x5e; 64],
            next: 0,
            keyset: ks.id(),
            keys,
        }
    }

    fn outputs(&mut self, value: u64) -> Vec<PendingOutput> {
        let (out, next) = client::ladder_outputs(&self.seed, &self.keyset, value, self.next);
        self.next = next;
        out
    }
}

/// A credential for `offer` spending `notes` (plus a fund quote), with a
/// DPoP proof when `dpop` is set, and the outputs it asks change for.
struct Paid {
    credential: Credential,
    outputs: Vec<PendingOutput>,
    value: u64,
}

fn pay(
    w: &mut Wallet,
    offer: &Offer,
    by_id: bool,
    notes: &[Note],
    fund: Option<(&FundQuote, &[u8; 32])>,
    dpop: bool,
    method: &str,
    path: &str,
    body: &str,
) -> Paid {
    let (_, entry) = offer.fields().pay_entry("bnap:notes").unwrap();
    let params = Params::parse(entry.params.as_ref().unwrap()).unwrap();
    let fee = |ks: &KeysetIdBytes| params.keyset(ks).map_or(0, |k| k.input_fee_ppk);
    let value = bnap_scheme_notes::amount::value(
        notes.iter().map(|n| (n.amount, fee(&n.keyset))),
        fund.map_or(0, |(q, _)| q.amount),
    )
    .unwrap();
    let outputs = w.outputs(value);
    let outs: Vec<_> = outputs.iter().map(|p| p.output).collect();
    let (b, ordered) =
        client::build_body(notes, &outs, fund.map(|(q, _)| q.quote.as_str())).unwrap();
    let mut c = Credential::new(if by_id {
        OfferRef::Id(offer.offer_id())
    } else {
        OfferRef::Inline(offer.bytes().to_vec())
    });
    c.pay = Some(SchemePart::new("bnap:notes", b.to_bytes().unwrap()));
    let act = scope(method, path, body);
    if dpop {
        c.attest = vec![SchemePart::new("httpauth:DPoP", Vec::new())];
        let ctx = c.context(&offer.offer_id(), &act);
        let key = bnap_scheme_dpop::client::ProofKey::ed25519(&DPOP_SECRET);
        let proof = bnap_scheme_dpop::client::sign_proof(
            &key,
            &bnap_scheme_dpop::client::ProofClaims {
                context: &ctx,
                htm: method,
                htu: &format!("{ORIGIN}{path}"),
                iat: NOW,
                jti: &hex::encode(rand_bytes()),
                access_token: None,
            },
        );
        c.attest[0].body = bnap_scheme_dpop::client::body(&proof, None);
    }
    let ctx = c.context(&offer.offer_id(), &act);
    let digest = c.digest(&ctx);
    let wit = client::sign_witness(&b, &ordered, fund.map(|(_, k)| k), &digest, &[0; 32]).unwrap();
    c.pay.as_mut().unwrap().witness = wit.to_bytes();
    Paid {
        credential: c,
        outputs,
        value,
    }
}

fn rand_bytes() -> [u8; 8] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::SeqCst).to_be_bytes()
}

fn fund_quote_of(offer: &Offer) -> Option<FundQuote> {
    let (_, e) = offer.fields().pay_entry("bnap:notes")?;
    Params::parse(e.params.as_ref()?).ok()?.fund_quote
}

/// The fake rail's invoice string ends in the payment hash.
fn fake_hash(invoice: &str) -> [u8; 32] {
    let hex_part = &invoice[invoice.len() - 64..];
    hex::decode(hex_part).unwrap().try_into().unwrap()
}

/// Funds the wallet with `amount` sat through the 402 of the chat route,
/// paying `CHAT_BODY` on the way, and returns the change notes.
async fn fund(w: &World, wallet: &mut Wallet, amount: u64, tag: u8) -> Vec<Note> {
    let quote_key = [tag; 32];
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    let header = FundRequest { amount, pubkey }.to_header();
    let a = read(
        w.send("POST", CHAT, CHAT_BODY, &[("bnap-fund", header)])
            .await,
    )
    .await;
    assert_eq!(a.status, 402);
    let offer = a
        .offers()
        .into_iter()
        .find(|o| fund_quote_of(o).is_some())
        .expect("an offer with a fund quote");
    assert!(!offer.fields().route_scope);
    let q = fund_quote_of(&offer).unwrap();
    assert_eq!(q.amount, amount);
    assert_eq!(q.pubkey, pubkey);
    // Unpaid: refused, nothing consumed.
    let unpaid = pay(
        wallet,
        &offer,
        false,
        &[],
        Some((&q, &quote_key)),
        false,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&unpaid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.error(), Some(ErrorCode::BadCredential), "{}", r.body);
    w.fake().pay(&fake_hash(&q.request)).unwrap();
    let paid = pay(
        wallet,
        &offer,
        false,
        &[],
        Some((&q, &quote_key)),
        false,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let receipt = r.receipt().unwrap();
    receipt.verify_ack().unwrap();
    let f = receipt.fields();
    assert!(offer.fields().metered, "metered, as the route offer is");
    assert_eq!(f.metered_units, Some(850));
    assert_eq!(
        f.charged, 425,
        "a fund offer on a metered route is metered, not priced at the ceiling"
    );
    let got = client::recover_change(
        &paid.outputs,
        client::key_lookup(&wallet.keys),
        paid.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert!(got.matches_rule);
    assert_eq!(
        got.notes.iter().map(|n| n.amount).sum::<u64>(),
        amount - 425
    );
    got.notes
}

#[tokio::test]
async fn notes_fund_then_spend_metered_with_a_dpop_discount_replay_and_spent() {
    let w = World::new().await;
    let mut wallet = Wallet::new();
    let notes = fund(&w, &mut wallet, 5000, 1).await;
    assert_eq!(w.calls(), 1);

    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    let route = a.route_offer();
    let paid = pay(
        &mut wallet,
        &route,
        true,
        &notes,
        None,
        true,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    // At least price(amount) = 2,100 less 20% = 1,680 sat.
    assert!(paid.value >= 1680);
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.cache_control(), Some("private, no-store"));
    let receipt = r.receipt().unwrap();
    receipt.verify_ack().unwrap();
    let f = receipt.fields().clone();
    assert_eq!(f.status, Status::Ok);
    assert_eq!(f.metered_units, Some(850));
    // ceil(850 x 500 / 1000) = 425, less 20% = 340 (draft-00 10.3).
    assert_eq!(f.charged, 340);
    assert_eq!(f.unit.as_deref(), Some("sat"));
    let change = client::recover_change(
        &paid.outputs,
        client::key_lookup(&wallet.keys),
        paid.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert_eq!(
        change.notes.iter().map(|n| n.amount).sum::<u64>(),
        paid.value - 340
    );
    assert_eq!(w.calls(), 2);

    // The same credential again: replayed, same charge and change, the
    // kept answer, and the action does not run twice.
    let again = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(again.status, 200);
    let rf = again.receipt().unwrap();
    assert!(rf.fields().replayed);
    assert_eq!(rf.fields().charged, 340);
    assert_eq!(rf.fields().scheme_result, f.scheme_result);
    assert_eq!(again.body, r.body);
    assert_eq!(w.calls(), 2);

    // The same notes in a new credential (other outputs): SPENT.
    let reuse = pay(
        &mut wallet,
        &route,
        true,
        &notes,
        None,
        false,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let s = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&reuse.credential)])
            .await,
    )
    .await;
    assert_eq!(s.status, 409, "{}", s.body);
    assert_eq!(s.error(), Some(ErrorCode::Spent));

    // The change spends; a credential bound to another request is
    // WRONG_SCOPE... no: the route offer covers the route, and the Context
    // binds the request, so a body swap fails the witness.
    let next = pay(
        &mut wallet,
        &route,
        true,
        &change.notes,
        None,
        false,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let other_body = r#"{"model":"m-1","messages":[],"max_tokens":1}"#;
    let swapped = read(
        w.send("POST", CHAT, other_body, &[cred_header(&next.credential)])
            .await,
    )
    .await;
    assert_eq!(
        swapped.error(),
        Some(ErrorCode::BadCredential),
        "{}",
        swapped.body
    );
    let ok = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&next.credential)])
            .await,
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    // Without the discount: 425.
    assert_eq!(ok.receipt().unwrap().fields().charged, 425);
}

#[tokio::test]
async fn an_answer_that_cannot_be_metered_settles_failed_and_refunds() {
    let w = World::new().await;
    let mut wallet = Wallet::new();
    let notes = fund(&w, &mut wallet, 5000, 2).await;
    let body = r#"{"model":"m-1","messages":[],"mock":"sse"}"#;
    let a = read(w.send("POST", CHAT, body, &[]).await).await;
    let route = a.route_offer();
    let paid = pay(
        &mut wallet,
        &route,
        true,
        &notes,
        None,
        false,
        "POST",
        CHAT,
        body,
    );
    let r = read(
        w.send("POST", CHAT, body, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.status, 502, "an unmetered answer is withheld: {}", r.body);
    let f = r.receipt().unwrap().fields().clone();
    assert_eq!(f.status, Status::Failed);
    assert_eq!(f.charged, 0);
    let change = client::recover_change(
        &paid.outputs,
        client::key_lookup(&wallet.keys),
        paid.value,
        0,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert_eq!(
        change.notes.iter().map(|n| n.amount).sum::<u64>(),
        paid.value,
        "a whole refund"
    );
}

#[tokio::test]
async fn upstream_bnap_fields_are_scrubbed() {
    let w = World::new().await;
    let mut wallet = Wallet::new();
    let notes = fund(&w, &mut wallet, 5000, 3).await;
    let body = r#"{"model":"m-1","messages":[],"mock":"inject"}"#;
    let route = read(w.send("POST", CHAT, body, &[]).await)
        .await
        .route_offer();
    let paid = pay(
        &mut wallet,
        &route,
        true,
        &notes,
        None,
        false,
        "POST",
        CHAT,
        body,
    );
    let r = read(
        w.send("POST", CHAT, body, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.headers.get("bnap-error").is_none());
    assert!(r.headers.get("payment-receipt").is_none());
    assert!(r.headers.get("www-authenticate").is_none());
    let receipt = r.receipt().expect("the gate's receipt, not the forged one");
    receipt.verify_ack().unwrap();
    assert_eq!(receipt.fields().charged, 425);
    // The upstream never saw the credential.
    let seen = w.seen.last.lock().unwrap().clone().unwrap();
    assert!(seen.2.get("bnap-credential").is_none());
}

#[tokio::test]
async fn a_dpop_waive_admits_without_payment_and_context_must_match() {
    let w = World::new().await;
    let a = read(w.send("GET", "/v1/status", "", &[]).await).await;
    assert_eq!(a.status, 402);
    let route = a.route_offer();
    let mut c = Credential::new(OfferRef::Id(route.offer_id()));
    c.attest = vec![SchemePart::new("httpauth:DPoP", Vec::new())];
    let act = scope("GET", "/v1/status", "");
    let ctx = c.context(&route.offer_id(), &act);
    let key = bnap_scheme_dpop::client::ProofKey::ed25519(&DPOP_SECRET);
    let proof = bnap_scheme_dpop::client::sign_proof(
        &key,
        &bnap_scheme_dpop::client::ProofClaims {
            context: &ctx,
            htm: "GET",
            htu: &format!("{ORIGIN}/v1/status"),
            iat: NOW,
            jti: "j1",
            access_token: None,
        },
    );
    c.attest[0].body = bnap_scheme_dpop::client::body(&proof, None);
    // A BNAP-Context that is not the gate's Context: MALFORMED.
    let wrong = ("bnap-context", bnap_carrier_http::b64u(&[1; 32]));
    let r = read(
        w.send("GET", "/v1/status", "", &[cred_header(&c), wrong])
            .await,
    )
    .await;
    assert_eq!(r.error(), Some(ErrorCode::Malformed));
    let right = ("bnap-context", bnap_carrier_http::b64u(&ctx.0));
    let r = read(
        w.send("GET", "/v1/status", "", &[cred_header(&c), right])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let f = r.receipt().unwrap().fields().clone();
    assert_eq!(f.charged, 0);
    assert_eq!(f.unit, None);
    // A proof by a key the operator does not honour: no effect, and no pay
    // part, so UNDERPAID.
    let mut c2 = c.clone();
    let other = bnap_scheme_dpop::client::ProofKey::ed25519(&[0x45; 32]);
    let p2 = bnap_scheme_dpop::client::sign_proof(
        &other,
        &bnap_scheme_dpop::client::ProofClaims {
            context: &ctx,
            htm: "GET",
            htu: &format!("{ORIGIN}/v1/status"),
            iat: NOW,
            jti: "j2",
            access_token: None,
        },
    );
    c2.attest[0].body = bnap_scheme_dpop::client::body(&p2, None);
    let r = read(w.send("GET", "/v1/status", "", &[cred_header(&c2)]).await).await;
    assert_eq!(r.error(), Some(ErrorCode::Underpaid), "{}", r.body);
}

/// With the process signer (`bnap-signer --store` on the gate's use
/// store) the gate reads the keyset table from the signer process, so
/// `bnap:notes` starts, funds inside the 402 and spends with change. Before
/// the signer served its keysets the gate refused to start.
#[tokio::test]
async fn notes_work_with_the_process_signer_and_its_store() {
    let w = World::with_process_signer().await;
    let mut wallet = Wallet::new();
    let notes = fund(&w, &mut wallet, 5000, 7).await;
    assert_eq!(notes.iter().map(|n| n.amount).sum::<u64>(), 4575);

    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    let route = a.route_offer();
    let paid = pay(
        &mut wallet,
        &route,
        true,
        &notes,
        None,
        false,
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let f = r.receipt().unwrap().fields().clone();
    assert_eq!(f.charged, 425);
    let change = client::recover_change(
        &paid.outputs,
        client::key_lookup(&wallet.keys),
        paid.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert!(change.matches_rule);
    assert_eq!(
        change.notes.iter().map(|n| n.amount).sum::<u64>(),
        paid.value - 425
    );
}

/// The issuer's NUT-02 keysets and NUT-01 keys are served under the
/// issuer URL (`{origin}/cashu` by default): a wallet that funds inside the
/// 402 fetches the keyset's keys there to unblind its change. Before, the
/// gate forwarded these paths to the application.
#[tokio::test]
async fn the_issuer_serves_its_keysets_and_keys() {
    let w = World::new().await;
    let wallet = Wallet::new();
    let id = hex::encode(wallet.keyset);
    let a = read(w.send("GET", "/cashu/v1/keysets", "", &[]).await).await;
    assert_eq!(a.status, 200, "{}", a.body);
    let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
    assert_eq!(v["keysets"][0]["id"], id);
    assert_eq!(v["keysets"][0]["unit"], "sat");
    assert_eq!(v["keysets"][0]["active"], true);
    assert_eq!(v["keysets"][0]["input_fee_ppk"], 100);

    let a = read(
        w.send("GET", &format!("/cashu/v1/keys/{id}"), "", &[])
            .await,
    )
    .await;
    assert_eq!(a.status, 200, "{}", a.body);
    let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
    let keys = v["keysets"][0]["keys"].as_object().unwrap();
    let want = &wallet.keys[&wallet.keyset];
    assert_eq!(keys.len(), want.len());
    for (amount, k) in want {
        assert_eq!(keys[&amount.to_string()], hex::encode(k));
    }
    let a = read(w.send("GET", "/cashu/v1/keys", "", &[]).await).await;
    assert_eq!(a.status, 200);
    let a = read(
        w.send(
            "GET",
            &format!("/cashu/v1/keys/01{}", "00".repeat(32)),
            "",
            &[],
        )
        .await,
    )
    .await;
    assert_eq!(a.status, 404);
    assert_eq!(w.calls(), 0, "never forwarded to the application");
}

#[tokio::test]
async fn the_issuer_endpoints_match_the_normalized_path_and_serve_head() {
    let w = World::new().await;
    // Encoded, doubled-slash, dot-segment and trailing-slash variants are
    // the same endpoints, as the router would see them (L4).
    for path in [
        "/cashu/v1/%6Beysets",
        "/cashu//v1/keysets",
        "/cashu/x/../v1/keysets",
        "/cashu/v1/keysets/",
        "/cashu/v1/keys/",
    ] {
        let a = read(w.send("GET", path, "", &[]).await).await;
        assert_eq!(a.status, 200, "{path}: {}", a.body);
        let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
        assert!(v["keysets"].is_array(), "{path}: {}", a.body);
    }
    // HEAD is served like GET, without a body.
    for path in ["/cashu/v1/keysets", "/cashu/v1/keys"] {
        let a = read(w.send("HEAD", path, "", &[]).await).await;
        assert_eq!(a.status, 200, "{path}");
        assert_eq!(
            a.headers.get("content-type").unwrap(),
            "application/json",
            "{path}"
        );
        assert!(a.body.is_empty(), "{path}");
    }
    assert_eq!(w.calls(), 0, "never forwarded to the application");
}

#[tokio::test]
async fn the_gate_refuses_an_issuer_path_that_is_empty_or_shadowed() {
    let dir = tempfile::tempdir().unwrap();
    let base = config_text(dir.path(), "127.0.0.1:9", "");
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plan = |text: &str| {
        caparra_gate::config::Config::parse(text)
            .unwrap()
            .plan(&registry)
    };
    assert!(plan(&base).is_ok());
    let fund = "max_fund_sat = 10000";
    // The issuer URL is the origin itself: its endpoints would take
    // /v1/keys and /v1/keysets of the whole origin.
    for url in [ORIGIN.to_owned(), format!("{ORIGIN}/")] {
        let t = base.replace(fund, &format!("{fund}\nissuer_url = \"{url}\""));
        assert_ne!(t, base);
        let e = plan(&t).unwrap_err().to_string();
        assert!(e.contains("issuer"), "{url}: {e}");
    }
    // A route under the issuer's key endpoints would never be reached.
    for m in [
        "GET /cashu/v1/keys",
        "GET /cashu/v1/keys/00ab",
        "POST /cashu/v1/keysets",
        "GET /cashu/v1/keys/*",
    ] {
        let t = format!(
            "{base}\n[[route]]\nid = \"shadow\"\nmatch = \"{m}\"\nscope = \"exact\"\nprice = {{ sat = 1 }}\naccept = [\"httpauth:L402\"]\nallow_experimental = true\n"
        );
        let e = plan(&t).unwrap_err().to_string();
        assert!(e.contains("issuer"), "{m}: {e}");
    }
    // Routes beside or above them are fine (the issuer answers its own key
    // endpoints first), and so is an issuer off this origin.
    for m in [
        "GET /cashu/v1/mint/quote/bolt11",
        "GET /cashu/v1/keysetsx",
        "GET /cashu/*",
    ] {
        let t = format!(
            "{base}\n[[route]]\nid = \"beside\"\nmatch = \"{m}\"\nscope = \"exact\"\nprice = {{ sat = 1 }}\naccept = [\"httpauth:L402\"]\nallow_experimental = true\n"
        );
        assert!(plan(&t).is_ok(), "{m}: {:?}", plan(&t).err());
    }
    let off = base.replace(
        fund,
        &format!("{fund}\nissuer_url = \"https://mint.example\""),
    );
    assert!(plan(&off).is_ok());
}
