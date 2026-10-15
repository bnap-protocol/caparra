//! End to end against the real gate: `caparra-gate run` with the LND rail
//! on the regtest payee node, the SQLite use store and `bnap-signer
//! --store`, every payment made from the payer node over Lightning.
//!
//! - `bnap:notes` funded inside the 402, the quote's invoice paid from the
//!   payer node, redeemed on the metered route offer, the change spent on
//!   a second metered call: receipts verify against the manifest's receipt
//!   key, a replay returns `replayed` with the same outcome, and every reuse
//!   (the quote, the spent notes) is SPENT.
//! - One Lightning payment presented via L402 and via MPP admits exactly
//!   one action.
//! - The `bnap` CLI does the same through the TLS front: it funds inside
//!   the 402, pays a metered call and an L402 / MPP route, and its receipts
//!   verify.
//!
//! Needs the `regtest` feature and Docker (see `tests/regtest.rs`):
//!
//! ```text
//! cargo nextest run -p e2e --features regtest
//! ```

#![cfg(feature = "regtest")]
#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::many_single_char_names
)]

mod stack;

use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::response::Status;
use bnap_core::{Credential, ErrorCode, Offer};
use bnap_scheme_notes::FundRequest;
use bnap_scheme_notes::client::{self, KeyTable, Note, PendingOutput};
use bnap_scheme_notes::wire::{FundQuote, KeysetIdBytes, Params};
use stack::{Answer, CHAT, CHAT_BODY, Stack, cred_header, now, payer_pays};

/// A notes wallet built from the N6 client module: the keyset's keys come
/// from the key file (the `bnap` CLI test fetches them from the gate's
/// NUT-01 endpoint instead).
struct Wallet {
    seed: [u8; 64],
    next: u64,
    keyset: KeysetIdBytes,
    keys: KeyTable,
}

impl Wallet {
    fn new(s: &Stack) -> Self {
        let signer = bnap_signer_file::FileSigner::load(s.dir.path().join("keys.toml")).unwrap();
        let ks = &signer.keysets()[0];
        let mut keys = KeyTable::new();
        keys.insert(ks.id(), ks.public_keys());
        Self {
            seed: rand::random::<[u8; 32]>().repeat(2).try_into().unwrap(),
            next: 0,
            keyset: ks.id(),
            keys,
        }
    }
}

/// A notes credential and what it needs to recover its change.
struct Paid {
    credential: Credential,
    outputs: Vec<PendingOutput>,
    value: u64,
}

fn pay(
    s: &Stack,
    w: &mut Wallet,
    offer: &Offer,
    notes: &[Note],
    fund: Option<(&FundQuote, &[u8; 32])>,
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
    let (outputs, next) = client::ladder_outputs(&w.seed, &w.keyset, value, w.next);
    w.next = next;
    let outs: Vec<_> = outputs.iter().map(|p| p.output).collect();
    let (b, ordered) =
        client::build_body(notes, &outs, fund.map(|(q, _)| q.quote.as_str())).unwrap();
    let mut c = Credential::new(if offer.fields().route_scope {
        OfferRef::Id(offer.offer_id())
    } else {
        OfferRef::Inline(offer.bytes().to_vec())
    });
    c.pay = Some(SchemePart::new("bnap:notes", b.to_bytes().unwrap()));
    let ctx = c.context(&offer.offer_id(), &s.scope(method, path, body));
    let digest = c.digest(&ctx);
    let wit = client::sign_witness(&b, &ordered, fund.map(|(_, k)| k), &digest, &[0; 32]).unwrap();
    c.pay.as_mut().unwrap().witness = wit.to_bytes();
    Paid {
        credential: c,
        outputs,
        value,
    }
}

fn fund_quote_of(offer: &Offer) -> Option<FundQuote> {
    let (_, e) = offer.fields().pay_entry("bnap:notes")?;
    Params::parse(e.params.as_ref()?).ok()?.fund_quote
}

/// The receipt of `a`, checked as a client checks it (8.1, 9.3): the ack
/// verifies under a receipt key of the pinned manifest and answers this
/// offer and Digest.
fn checked_receipt(
    s: &Stack,
    a: &Answer,
    offer: &Offer,
    c: &Credential,
    scope: bnap_core::hash::Scope,
) -> bnap_core::Response {
    let r = a.receipt().expect("a receipt");
    let ctx = c.context(&offer.offer_id(), &scope);
    r.check_client(s.keys(), now(), &offer.offer_id(), &c.digest(&ctx))
        .expect("the receipt verifies against the manifest");
    r
}

#[tokio::test(flavor = "multi_thread")]
async fn notes_funded_in_the_402_metered_replayed_and_spent() {
    let s = Stack::start().await;
    let mut w = Wallet::new(&s);
    let chat = s.scope("POST", CHAT, CHAT_BODY);

    // The 402 with BNAP-Fund: an exact-scope offer carrying a NUT-23 quote
    // locked to a fresh key, next to the route's metered offer.
    let quote_key: [u8; 32] = rand::random();
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    let header = FundRequest {
        amount: 5000,
        pubkey,
    }
    .to_header();
    let a = s
        .send("POST", CHAT, CHAT_BODY, &[("bnap-fund", header)])
        .await;
    assert_eq!(a.status, 402, "{}", a.body);
    assert_eq!(a.error(), Some(ErrorCode::Required));
    let route = a.route_offer();
    assert!(route.fields().metered);
    let fund_offer = a
        .offers()
        .into_iter()
        .find(|o| fund_quote_of(o).is_some())
        .expect("an offer with a fund quote");
    let q = fund_quote_of(&fund_offer).unwrap();
    assert_eq!(q.amount, 5000);
    assert!(
        q.request.starts_with("lnbcrt50u"),
        "a regtest invoice for 5,000 sat"
    );

    // Unpaid, the quote is refused and nothing is consumed.
    let unpaid = pay(
        &s,
        &mut w,
        &route,
        &[],
        Some((&q, &quote_key)),
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let r = s
        .send("POST", CHAT, CHAT_BODY, &[cred_header(&unpaid.credential)])
        .await;
    assert_eq!(r.error(), Some(ErrorCode::BadCredential), "{}", r.body);
    assert_eq!(s.calls(), 0);

    // Paid from the payer node, then redeemed on the metered route offer
    // (bnap:notes 8.4: any offer that lists bnap:notes).
    payer_pays(&q.request);
    let paid = pay(
        &s,
        &mut w,
        &route,
        &[],
        Some((&q, &quote_key)),
        "POST",
        CHAT,
        CHAT_BODY,
    );
    let first = s
        .send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
        .await;
    assert_eq!(first.status, 200, "{}\n{}", first.body, s.gate_log());
    assert_eq!(s.calls(), 1);
    assert!(first.body.contains("\"total_tokens\":850"));
    let receipt = checked_receipt(&s, &first, &route, &paid.credential, chat);
    let f = receipt.fields().clone();
    assert_eq!(f.status, Status::Ok);
    assert!(!f.replayed);
    assert_eq!(f.metered_units, Some(850));
    // ceil(850 x 500 / 1000) = 425 sat, under the 2,100 sat ceiling.
    assert_eq!(f.charged, 425);
    assert_eq!(f.unit.as_deref(), Some("sat"));
    let change = client::recover_change(
        &paid.outputs,
        client::key_lookup(&w.keys),
        paid.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert!(change.matches_rule);
    let notes = change.notes;
    assert_eq!(notes.iter().map(|n| n.amount).sum::<u64>(), 5000 - 425);

    // The same credential again: replayed, the same outcome, no second
    // action, the kept answer.
    let replay = s
        .send("POST", CHAT, CHAT_BODY, &[cred_header(&paid.credential)])
        .await;
    assert_eq!(replay.status, 200, "{}", replay.body);
    let rr = checked_receipt(&s, &replay, &route, &paid.credential, chat);
    let g = rr.fields();
    assert!(g.replayed);
    assert_eq!(g.status, f.status);
    assert_eq!(g.charged, f.charged);
    assert_eq!(g.metered_units, f.metered_units);
    assert_eq!(g.scheme_result, f.scheme_result);
    assert_eq!(g.settled_at, f.settled_at);
    assert_eq!(replay.body, first.body);
    assert_eq!(s.calls(), 1);

    // The quote redeemed again in a new credential, for another request:
    // its payment's RailId is spent.
    let other = r#"{"model":"m-1","messages":[{"role":"user","content":"again"}]}"#;
    let reused = pay(
        &s,
        &mut w,
        &route,
        &[],
        Some((&q, &quote_key)),
        "POST",
        CHAT,
        other,
    );
    let r = s
        .send("POST", CHAT, other, &[cred_header(&reused.credential)])
        .await;
    assert_eq!(r.status, 409, "{}", r.body);
    assert_eq!(r.error(), Some(ErrorCode::Spent));
    assert_eq!(s.calls(), 1);

    // The change spends on a second metered call (100 tokens: 50 sat).
    let body = r#"{"model":"m-1","messages":[{"role":"user","content":"two"}],"mock_tokens":100}"#;
    let second = pay(&s, &mut w, &route, &notes, None, "POST", CHAT, body);
    let r = s
        .send("POST", CHAT, body, &[cred_header(&second.credential)])
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let f2 = checked_receipt(
        &s,
        &r,
        &route,
        &second.credential,
        s.scope("POST", CHAT, body),
    )
    .fields()
    .clone();
    assert_eq!(f2.metered_units, Some(100));
    assert_eq!(f2.charged, 50);
    let change2 = client::recover_change(
        &second.outputs,
        client::key_lookup(&w.keys),
        second.value,
        f2.charged,
        f2.scheme_result.as_deref(),
    )
    .unwrap();
    assert!(change2.matches_rule);
    assert_eq!(
        change2.notes.iter().map(|n| n.amount).sum::<u64>(),
        second.value - 50
    );
    assert_eq!(s.calls(), 2);

    // Those notes again, in a credential for yet another request: SPENT.
    let body3 = r#"{"model":"m-1","messages":[{"role":"user","content":"three"}]}"#;
    let third = pay(&s, &mut w, &route, &notes, None, "POST", CHAT, body3);
    let r = s
        .send("POST", CHAT, body3, &[cred_header(&third.credential)])
        .await;
    assert_eq!(r.status, 409, "{}", r.body);
    assert_eq!(r.error(), Some(ErrorCode::Spent));
    assert_eq!(s.calls(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_lightning_payment_via_l402_and_mpp_admits_one_action() {
    let s = Stack::start().await;
    let body = r#"{"n":1}"#;
    let scope = s.scope("POST", "/v1/fixed", body);
    let a = s.send("POST", "/v1/fixed", body, &[]).await;
    assert_eq!(a.status, 402, "{}", a.body);
    let offer = a.exact_offer();
    let natives = a.natives();
    let l402 = natives
        .iter()
        .find(|n| n.starts_with("L402"))
        .map(|v| bnap_scheme_l402::Challenge::parse(v).unwrap())
        .expect("an L402 challenge");
    let mpp = natives
        .iter()
        .find(|n| n.starts_with("Payment"))
        .map(|v| bnap_scheme_mpp::Challenge::parse(v).unwrap())
        .expect("an MPP challenge");
    let request = bnap_scheme_mpp::ChargeRequest::decode(&mpp.request).unwrap();
    assert_eq!(
        request.invoice, l402.invoice,
        "one invoice for both schemes"
    );
    assert!(l402.invoice.starts_with("lnbcrt210n"), "21 sat on regtest");

    let preimage = payer_pays(&l402.invoice);

    // L402 natively: admitted, the receipt over the native envelope (5.4).
    let token = bnap_scheme_l402::Token::new(&l402.token, preimage).unwrap();
    let auth = bnap_scheme_l402::authorization(&token);
    let r = s
        .send(
            "POST",
            "/v1/fixed",
            body,
            &[("authorization", auth.clone())],
        )
        .await;
    assert_eq!(r.status, 200, "{}\n{}", r.body, s.gate_log());
    let receipt = r.receipt().unwrap();
    let nctx = bnap_core::credential::native_context(&offer.offer_id(), &scope, "httpauth:L402");
    let ndig = bnap_core::credential::native_digest(&nctx, token.to_string().as_bytes());
    receipt
        .check_client(s.keys(), now(), &offer.offer_id(), &ndig)
        .unwrap();
    assert_eq!(receipt.fields().charged, 21);
    assert_eq!(s.calls(), 1);

    // The same token again: replayed, no second action.
    let again = s
        .send("POST", "/v1/fixed", body, &[("authorization", auth)])
        .await;
    assert_eq!(again.status, 200);
    assert!(again.receipt().unwrap().fields().replayed);
    assert_eq!(s.calls(), 1);

    // The same payment via MPP, natively and inside a BNAP credential:
    // the payment's RailId is spent.
    let mpp_cred = bnap_scheme_mpp::Credential::new(mpp, preimage).encode();
    let r = s
        .send(
            "POST",
            "/v1/fixed",
            body,
            &[("authorization", format!("Payment {mpp_cred}"))],
        )
        .await;
    assert_eq!(r.error(), Some(ErrorCode::Spent), "{}", r.body);
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(
        "payment:lightning/charge",
        mpp_cred.into_bytes(),
    ));
    let r = s.send("POST", "/v1/fixed", body, &[cred_header(&c)]).await;
    assert_eq!(r.error(), Some(ErrorCode::Spent), "{}", r.body);
    assert_eq!(s.calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bnap_cli_pays_end_to_end() {
    let s = Stack::start().await;
    let (ok, _, text) = s.bnap(&["init"]);
    assert!(ok, "{text}");
    let (ok, _, text) = s.bnap(&[
        "budget",
        "set",
        "--allow-experimental",
        "true",
        "--per-request",
        "3000",
        "--per-origin-day",
        "20000",
        "--per-task",
        "20000",
        "--daily",
        "20000",
    ]);
    assert!(ok, "{text}");
    let mut paysource = vec!["paysource", "command"];
    let argv = stack::payer_argv();
    paysource.extend(argv.iter().map(String::as_str));
    let (ok, _, text) = s.bnap(&paysource);
    assert!(ok, "{text}");

    // A metered chat call: the wallet funds inside the 402 (an invoice of
    // the payee node, paid from the payer node) and gets the answer.
    let chat = format!("{}{CHAT}", s.origin);
    let (ok, v, text) = s.bnap(&[
        "post",
        &chat,
        "-H",
        "content-type: application/json",
        "-d",
        CHAT_BODY,
    ]);
    assert!(ok, "{text}\n{}", s.gate_log());
    assert_eq!(v["status"], 200, "{text}");
    // Metered: 850 tokens at 500 sat per 1,000, the change kept as notes.
    assert_eq!(v["payment"]["scheme"], "bnap:notes", "{text}");
    assert_eq!(v["payment"]["charged"], 425, "{text}");
    assert_eq!(s.calls(), 1);

    // A GET route priced in notes only.
    let status = format!("{}/v1/status", s.origin);
    let (ok, v, text) = s.bnap(&["get", &status]);
    // Paid from the change notes of the first call, nothing over Lightning.
    assert_eq!(v["payment"]["scheme"], "bnap:notes", "{text}");
    assert_eq!(v["payment"]["charged"], 10, "{text}");
    assert!(ok, "{text}\n{}", s.gate_log());
    assert_eq!(v["status"], 200, "{text}");
    assert_eq!(s.calls(), 2);

    // An exact route that takes L402 and MPP only.
    let fixed = format!("{}/v1/fixed", s.origin);
    let (ok, v, text) = s.bnap(&[
        "post",
        &fixed,
        "-H",
        "content-type: application/json",
        "-d",
        "{}",
    ]);
    assert!(ok, "{text}\n{}", s.gate_log());
    assert_eq!(v["status"], 200, "{text}");
    assert_eq!(v["payment"]["charged"], 21, "{text}");
    assert!(
        ["httpauth:L402", "payment:lightning/charge"]
            .contains(&v["payment"]["scheme"].as_str().unwrap()),
        "{text}"
    );
    assert_eq!(s.calls(), 3);

    // Every receipt the wallet kept verifies against the pinned manifest.
    let (ok, v, text) = s.bnap(&["receipts", "verify"]);
    assert!(ok, "{text}");
    let receipts = v["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 3, "{text}");
    assert!(receipts.iter().all(|r| r["valid"] == true), "{text}");
}
