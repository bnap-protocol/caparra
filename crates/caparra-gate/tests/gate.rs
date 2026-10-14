//! The gate in-process against a mock OpenAI upstream: offers and natives,
//! L402 and MPP over the fake rail, notes funded and spent, DPoP waive and
//! discount, metering, replays, SPENT, size caps, scrubbing, the manifest.

#![allow(
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod common;

use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::response::Status;
use bnap_core::{Credential, ErrorCode, Offer, SignedManifest};
use common::*;

const CHAT_BODY: &str =
    r#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;

fn l402_challenge(a: &Answer) -> bnap_scheme_l402::Challenge {
    let v = a
        .natives()
        .into_iter()
        .find(|n| n.starts_with("L402"))
        .expect("an L402 challenge");
    bnap_scheme_l402::Challenge::parse(&v).unwrap()
}

fn mpp_challenge(a: &Answer) -> bnap_scheme_mpp::Challenge {
    let v = a
        .natives()
        .into_iter()
        .find(|n| n.starts_with("Payment"))
        .expect("a Payment challenge");
    bnap_scheme_mpp::Challenge::parse(&v).unwrap()
}

fn payment_hash(m: &bnap_scheme_mpp::Challenge) -> [u8; 32] {
    bnap_scheme_mpp::ChargeRequest::decode(&m.request)
        .unwrap()
        .payment_hash
}

#[tokio::test]
async fn the_manifest_is_served_and_verifies() {
    let w = World::new().await;
    let a = read(w.send("GET", "/.well-known/bnap", "", &[]).await).await;
    assert_eq!(a.status, 200);
    assert_eq!(a.headers["content-type"], "application/json");
    let file = std::fs::read(w.dir.path().join("manifest.json")).unwrap();
    assert_eq!(a.body.as_bytes(), &file[..], "served byte for byte");
    let m = SignedManifest::parse(a.body.as_bytes()).unwrap();
    m.verify().unwrap();
    assert_eq!(m.manifest().root, root_key().public_key());
    assert_eq!(m.manifest().origin, ORIGIN);
    let ids: Vec<_> = m.manifest().routes.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["chat", "status", "fixed"]);
}

#[tokio::test]
async fn a_402_carries_offers_natives_and_required() {
    let w = World::new().await;
    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    assert_eq!(a.status, 402);
    assert_eq!(a.error(), Some(ErrorCode::Required));
    assert_eq!(a.cache_control(), Some("private, no-store"));
    let route = a.route_offer();
    let f = route.fields();
    assert!(f.metered);
    assert_eq!(f.pay.len(), 1, "only notes may be metered");
    assert_eq!(f.pay[0].scheme, "bnap:notes");
    assert_eq!(f.pay[0].amount, 2100);
    assert_eq!(f.pay[0].rate, Some(500));
    assert_eq!(f.attest[0].scheme, "httpauth:DPoP");
    assert_eq!(f.native, Vec::new());
    let exact = a.exact_offer();
    let schemes: Vec<_> = exact
        .fields()
        .pay
        .iter()
        .map(|p| p.scheme.as_str())
        .collect();
    assert_eq!(schemes, ["httpauth:L402", "payment:lightning/charge"]);
    assert!(
        !exact.fields().metered,
        "priced at the ceiling, not metered"
    );
    assert_eq!(exact.fields().native.len(), 2);
    assert_eq!(exact.fields().scope, scope("POST", CHAT, CHAT_BODY));
    // Each native challenge is a native entry of the exact offer, byte for byte.
    for n in a.natives() {
        assert!(exact.fields().native.iter().any(|e| e.data == n.as_bytes()));
    }
    // Both natives share one invoice.
    assert_eq!(w.fake().invoice_count(), 1);
    // The route offer is the same for everyone within its interval.
    let b = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    assert_eq!(b.route_offer().bytes(), route.bytes());
    assert_eq!(w.calls(), 0);
}

#[tokio::test]
async fn pay_natively_with_l402_then_replay_then_spent_via_mpp_and_bnap() {
    let w = World::new().await;
    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    let l402 = l402_challenge(&a);
    let mpp = mpp_challenge(&a);
    let hash = payment_hash(&mpp);
    let preimage = w.fake().pay(&hash).unwrap();
    let token = bnap_scheme_l402::Token::new(&l402.token, preimage).unwrap();
    let auth = bnap_scheme_l402::authorization(&token);
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[("authorization", auth.clone())])
            .await,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.cache_control(), Some("private, no-store"));
    let receipt = r.receipt().expect("a receipt");
    receipt.verify_ack().unwrap();
    let f = receipt.fields();
    assert_eq!(f.status, Status::Ok);
    assert_eq!(f.charged, 2100);
    assert!(!f.replayed);
    assert_eq!(w.calls(), 1);
    // The application never saw the payment credential.
    let seen = w.seen.last.lock().unwrap().clone().unwrap();
    assert!(seen.2.get("authorization").is_none());
    assert_eq!(seen.1, CHAT);

    // The same native credential again: the recorded outcome, replayed,
    // and the action does not run twice.
    let again = read(
        w.send("POST", CHAT, CHAT_BODY, &[("authorization", auth)])
            .await,
    )
    .await;
    assert_eq!(again.status, 200);
    let rr = again.receipt().unwrap();
    assert!(rr.fields().replayed);
    assert_eq!(rr.fields().charged, 2100);
    assert_eq!(again.body, r.body, "the kept answer");
    assert_eq!(w.calls(), 1);

    // The same payment through MPP natively: one Lightning payment admits
    // one action.
    let mpp_cred = bnap_scheme_mpp::Credential::new(mpp, preimage).encode();
    let spent = read(
        w.send(
            "POST",
            CHAT,
            CHAT_BODY,
            &[("authorization", format!("Payment {mpp_cred}"))],
        )
        .await,
    )
    .await;
    assert_eq!(spent.status, 409, "{}", spent.body);
    assert_eq!(spent.error(), Some(ErrorCode::Spent));
    // And the native payment reused inside a BNAP Credential.
    let offer = a.exact_offer();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(
        "httpauth:L402",
        token.to_string().into_bytes(),
    ));
    let bn = read(w.send("POST", CHAT, CHAT_BODY, &[cred_header(&c)]).await).await;
    assert_eq!(bn.error(), Some(ErrorCode::Spent));
    assert_eq!(w.calls(), 1);
}

#[tokio::test]
async fn pay_with_mpp_inside_a_bnap_credential() {
    let w = World::new().await;
    let body = "{}";
    let a = read(w.send("POST", "/v1/fixed", body, &[]).await).await;
    assert_eq!(a.status, 402);
    assert!(
        a.offers().iter().all(|o| !o.fields().route_scope),
        "an exact route"
    );
    let offer = a.exact_offer();
    let mpp = mpp_challenge(&a);
    let preimage = w.fake().pay(&payment_hash(&mpp)).unwrap();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(
        "payment:lightning/charge",
        bnap_scheme_mpp::Credential::new(mpp, preimage)
            .encode()
            .into_bytes(),
    ));
    let r = read(w.send("POST", "/v1/fixed", body, &[cred_header(&c)]).await).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.receipt().unwrap().fields().charged, 21);
    assert!(
        r.headers.contains_key("payment-receipt"),
        "MPP's own receipt next to BNAP's"
    );
    // The credential is bound to its request: another body is WRONG_SCOPE,
    // answered with a fresh offer.
    let other = read(
        w.send("POST", "/v1/fixed", "{\"x\":1}", &[cred_header(&c)])
            .await,
    )
    .await;
    assert_eq!(other.status, 402);
    assert_eq!(other.error(), Some(ErrorCode::WrongScope));
    assert_ne!(other.offers().len(), 0);
}

#[tokio::test]
async fn an_offer_for_another_route_is_wrong_scope() {
    let w = World::new().await;
    let chat = read(w.send("POST", CHAT, CHAT_BODY, &[]).await)
        .await
        .route_offer();
    // Present the chat route offer on the status route.
    let mut c = Credential::new(OfferRef::Id(chat.offer_id()));
    c.pay = Some(SchemePart::new("bnap:notes", vec![]));
    let r = read(w.send("GET", "/v1/status", "", &[cred_header(&c)]).await).await;
    assert_eq!(r.status, 402);
    assert_eq!(r.error(), Some(ErrorCode::WrongScope));
}

#[tokio::test]
async fn oversize_and_double_credentials_are_refused() {
    let w = World::new().await;
    let big = "A".repeat(12_289);
    let r = read(
        w.send("POST", CHAT, CHAT_BODY, &[("bnap-credential", big)])
            .await,
    )
    .await;
    assert_eq!(r.status, 413);
    assert_eq!(r.error(), Some(ErrorCode::TooLarge));
    assert_eq!(r.cache_control(), Some("private, no-store"));
    // A BNAP credential and a native one: two value credentials.
    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    let offer = a.exact_offer();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new("httpauth:L402", b"x:y".to_vec()));
    let (k, v) = cred_header(&c);
    let r = read(
        w.send(
            "POST",
            CHAT,
            CHAT_BODY,
            &[(k, v), ("authorization", "L402 abc:def".into())],
        )
        .await,
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.error(), Some(ErrorCode::Malformed));
    assert_eq!(w.calls(), 0);
}

#[tokio::test]
async fn a_stripped_offer_does_not_verify() {
    let w = World::new().await;
    let a = read(w.send("POST", CHAT, CHAT_BODY, &[]).await).await;
    let route = a.route_offer();
    // Drop the DPoP discount (record 20), keep the signature and MAC: the
    // MAC no longer verifies.
    let tampered = {
        let s =
            bnap_core::tlv::TlvStream::parse(route.bytes(), bnap_core::tlv::StreamKind::TopLevel)
                .unwrap();
        let kept: Vec<_> = s
            .records()
            .iter()
            .filter(|(t, _)| *t != 20)
            .cloned()
            .collect();
        bnap_core::tlv::TlvStream::from_records(kept)
            .unwrap()
            .to_bytes()
    };
    assert_ne!(tampered, route.bytes());
    let mut c = Credential::new(OfferRef::Inline(tampered));
    c.pay = Some(SchemePart::new("bnap:notes", vec![]));
    let r = read(w.send("POST", CHAT, CHAT_BODY, &[cred_header(&c)]).await).await;
    assert_eq!(r.status, 402, "{}", r.body);
    assert_eq!(r.error(), Some(ErrorCode::BadOffer));
    // An unknown OfferID too.
    let c = {
        let mut c = Credential::new(OfferRef::Id(bnap_core::OfferId([9; 32])));
        c.pay = Some(SchemePart::new("bnap:notes", vec![]));
        c
    };
    let r = read(w.send("POST", CHAT, CHAT_BODY, &[cred_header(&c)]).await).await;
    assert_eq!(r.error(), Some(ErrorCode::BadOffer));
}

#[tokio::test]
async fn streaming_requests_on_a_metered_route_are_refused() {
    let w = World::new().await;
    let r = read(
        w.send(
            "POST",
            CHAT,
            r#"{"model":"m-1","stream":true,"messages":[]}"#,
            &[],
        )
        .await,
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(r.body.contains("STREAM_NOT_METERED"));
}

#[tokio::test]
async fn requests_off_every_route_pass_untouched() {
    let w = World::new().await;
    let r = read(w.send("GET", "/free", "", &[]).await).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "free");
    assert!(r.receipt().is_none());
}

/// An offer, read back.
fn offer_of(o: &Offer) -> Offer {
    Offer::parse(o.bytes()).unwrap()
}

#[tokio::test]
async fn the_gate_refuses_to_start_on_a_bad_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let base = config_text(dir.path(), "127.0.0.1:9", "");
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plan = |text: &str| {
        caparra_gate::config::Config::parse(text)
            .unwrap()
            .plan(&registry)
    };
    assert!(plan(&base).is_ok());
    // Unsatisfiable: notes is operator-IOU custody; nothing else on the route.
    let unsat = base.replace(
        "accept = [\"bnap:notes\"]\nattest = [{ scheme = \"httpauth:DPoP\", effect = \"waive\" }]",
        "accept = [\"bnap:notes\"]\nrequire = { custody = \"self-custody\" }",
    );
    assert_ne!(unsat, base);
    let e = plan(&unsat).unwrap_err().to_string();
    assert!(e.contains("satisfied by none"), "{e}");
    // Experimental schemes without allow_experimental.
    let exp = base.replacen(
        "allow_experimental = true\nupstream = \"openai\"",
        "upstream = \"openai\"",
        1,
    );
    assert_ne!(exp, base);
    let e = plan(&exp).unwrap_err().to_string();
    assert!(e.contains("satisfied by none"), "{e}");
    // A non-Bitcoin scheme without allow_non_bitcoin.
    let evm = base.replace(
        "accept = [\"httpauth:L402\", \"payment:lightning/charge\"]",
        "accept = [\"x402:exact@eip155:8453\"]",
    );
    let e = plan(&evm).unwrap_err().to_string();
    assert!(e.contains("non-Bitcoin"), "{e}");
    // A metered route behind an auth front.
    let auth = base.replace(
        "listen = \"127.0.0.1:0\"",
        "listen = \"127.0.0.1:0\"\nfront = \"forward_auth\"",
    );
    let e = plan(&auth).unwrap_err().to_string();
    assert!(e.contains("metered"), "{e}");
    // Envoy ext_authz is a documented stub.
    let envoy = base.replace(
        "listen = \"127.0.0.1:0\"",
        "listen = \"127.0.0.1:0\"\nfront = \"envoy_ext_authz\"",
    );
    assert!(plan(&envoy).is_err());
    // A class None attestation may not discount.
    let bearer = base.replace(
        "attest = [{ scheme = \"httpauth:DPoP\", effect = \"discount\", value = 2000 }]",
        "attest = [{ scheme = \"httpauth:Bearer\", effect = \"discount\", value = 2000 }]",
    );
    let e = plan(&bearer).unwrap_err().to_string();
    assert!(e.contains("class none"), "{e}");
}

#[tokio::test]
async fn the_gate_refuses_to_start_on_a_bad_manifest() {
    let w = World::new().await;
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plans = w.cfg.plan(&registry).unwrap();
    let good = std::fs::read(w.dir.path().join("manifest.json")).unwrap();
    assert!(caparra_gate::manifest::check(&good, &w.cfg, &plans, NOW).is_ok());
    // Unsigned (signature flipped).
    let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let sig = v["sig"].as_str().unwrap().to_owned();
    let flipped = format!(
        "{}{}",
        if sig.starts_with('0') { "1" } else { "0" },
        &sig[1..]
    );
    v["sig"] = flipped.into();
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(caparra_gate::manifest::check(&bad, &w.cfg, &plans, NOW).is_err());
    // Expired.
    assert!(caparra_gate::manifest::check(&good, &w.cfg, &plans, NOW + 30 * 86_400).is_err());
    // Routes that differ from the configuration.
    let mut other = w.cfg.clone();
    other.routes[2].price.insert("sat".into(), 22);
    let plans2 = other.plan(&registry).unwrap();
    assert!(caparra_gate::manifest::check(&good, &other, &plans2, NOW).is_err());
    // Keys past not_after.
    assert!(caparra_gate::manifest::check(&good, &w.cfg, &plans, NOT_AFTER - 10).is_err());
    let _ = offer_of;
}

#[test]
fn the_example_configuration_resolves() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/llm-proxy/gate.toml"
    ))
    .unwrap();
    let cfg = caparra_gate::config::Config::parse(&text).unwrap();
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plans = cfg.plan(&registry).unwrap();
    assert_eq!(plans[0].manifest.pay.len(), 3);
}

#[tokio::test]
async fn invoices_are_minted_under_a_per_address_limit() {
    let w = World::with_extra("\n[limits]\nmints_per_minute = 1\n").await;
    let a = read(w.send("POST", "/v1/fixed", "{}", &[]).await).await;
    assert_eq!(a.status, 402);
    assert_eq!(w.fake().invoice_count(), 1);
    // The second 402 of this address in the window would mint again.
    let b = read(w.send("POST", "/v1/fixed", "{}", &[]).await).await;
    assert_eq!(b.status, 429);
    assert_eq!(b.error(), Some(ErrorCode::RateLimited));
    assert!(b.headers.contains_key("retry-after"));
    // A refusal that owes a fresh offer says so too, instead of a 402
    // without one.
    let offer = a.exact_offer();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new("httpauth:L402", b"x:y".to_vec()));
    let r = read(
        w.send("POST", "/v1/fixed", "{\"other\":1}", &[cred_header(&c)])
            .await,
    )
    .await;
    assert_eq!(r.error(), Some(ErrorCode::RateLimited));
    assert_eq!(w.fake().invoice_count(), 1, "nothing more was minted");
    // Route offers mint nothing and are never limited.
    let chat = read(w.send("POST", CHAT, "{}", &[]).await).await;
    assert_eq!(chat.status, 402);
    assert!(chat.offers().iter().all(|o| o.fields().route_scope));
}

#[tokio::test]
async fn encoded_variants_of_a_paid_path_are_still_paid_routes() {
    let w = World::new().await;
    for path in [
        "/v1/chat/%63ompletions",
        "/v1%2Fchat%2Fcompletions",
        "/v1/chat/%63OMPLETIONS"
            .replace("OMPLETIONS", "ompletions")
            .as_str(),
        "/v1/./chat/completions",
        "//v1/chat/completions",
        "/v1/x/../chat/completions",
        "/v1/%66ixed",
        "/v1/chat/completions/",
        "/V1/chat/completions",
        "/v1/chat/completions;x=1",
        "/v1;a=b/chat/completions",
        "/v1/fixed/",
        "/V1/FIXED",
    ] {
        let method = "POST";
        let r = read(w.send(method, path, CHAT_BODY, &[]).await).await;
        assert!(
            r.status == 402 || r.body.contains("PATH_NOT_ROUTED"),
            "{path} must not reach the application unpaid: {} {}",
            r.status,
            r.body
        );
    }
    assert_eq!(w.calls(), 0);
}

#[tokio::test]
async fn a_binding_without_a_class_s_scheme_is_malformed_before_offered_schemes() {
    let w = World::new().await;
    let a = read(w.send("POST", "/v1/fixed", "{}", &[]).await).await;
    let offer = a.exact_offer();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new("vnd.hashcash.v1", b"x".to_vec()));
    c.binding = Some([7; 32]);
    let r = read(w.send("POST", "/v1/fixed", "{}", &[cred_header(&c)]).await).await;
    assert_eq!(r.error(), Some(ErrorCode::Malformed), "{}", r.body);
}

#[tokio::test]
async fn a_manifest_whose_keys_expire_too_soon_is_refused() {
    let w = World::new().await;
    let registry = caparra_gate::registry::Registry::embedded().unwrap();
    let plans = w.cfg.plan(&registry).unwrap();
    let pk = |s: &str| {
        bnap_core::schnorr::SigningKey::from_secret_bytes(
            &hex::decode(s).unwrap().try_into().unwrap(),
        )
        .unwrap()
        .public_key()
    };
    let sign = |offer_na: u64, receipt_na: u64| {
        caparra_gate::manifest::sign(
            &w.cfg,
            &plans,
            &caparra_gate::manifest::SignInput {
                root: root_key(),
                backup: bnap_core::schnorr::SigningKey::from_secret_bytes(&[0x53; 32])
                    .unwrap()
                    .public_key(),
                seq: 2,
                keys: vec![
                    bnap_core::manifest::ManifestKey {
                        kid: pk(OFFER_SECRET),
                        key_use: bnap_core::manifest::KeyUse::Offer,
                        not_after: offer_na,
                    },
                    bnap_core::manifest::ManifestKey {
                        kid: pk(RECEIPT_SECRET),
                        key_use: bnap_core::manifest::KeyUse::Receipt,
                        not_after: receipt_na,
                    },
                ],
                issued: NOW,
                aux: [0; 32],
            },
        )
        .unwrap()
    };
    let check = |b: &[u8]| caparra_gate::manifest::check(b, &w.cfg, &plans, NOW);
    assert!(check(&sign(NOW + 30 * 86_400, NOW + 30 * 86_400)).is_ok());
    // The offer key would expire before a route offer issued now.
    assert!(check(&sign(NOW + 600, NOW + 30 * 86_400)).is_err());
    // The receipt key would expire within pending_timeout.
    assert!(check(&sign(NOW + 30 * 86_400, NOW + 100)).is_err());
}

#[tokio::test]
async fn a_tls_binding_is_refused_by_a_gate_that_cannot_check_it() {
    let w = World::new().await;
    let chat = read(w.send("POST", CHAT, CHAT_BODY, &[]).await)
        .await
        .route_offer();
    let mut c = Credential::new(OfferRef::Id(chat.offer_id()));
    c.pay = Some(SchemePart::new("bnap:notes", vec![]));
    c.binding = Some([7; 32]);
    let r = read(w.send("POST", CHAT, CHAT_BODY, &[cred_header(&c)]).await).await;
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(r.error(), Some(ErrorCode::Binding));
}

#[tokio::test]
async fn a_gate_whose_signer_lacks_the_receipt_key_does_not_start() {
    let w = World::new().await;
    // The same keys without the receipt key; the manifest still lists it.
    let keys = key_file();
    let cut = keys.find("[[key]]\nuse = \"receipt\"").unwrap();
    let end = keys[cut..].find("[[keyset]]").unwrap() + cut;
    let no_receipt = format!("{}{}", &keys[..cut], &keys[end..]);
    std::fs::write(w.dir.path().join("keys.toml"), no_receipt).unwrap();
    let c = w.clock.clone();
    let clk: caparra_gate::plugs::Clock =
        std::sync::Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst));
    let e = caparra_gate::server::prepare(&w.cfg, &clk)
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("receipt"), "{e}");
}

#[tokio::test]
async fn nothing_is_offered_or_admitted_once_receipts_could_not_be_signed() {
    let w = World::new().await;
    // The receipt key expires within pending_timeout from here on.
    w.advance(NOT_AFTER - NOW - 100);
    let r = read(w.send("POST", "/v1/fixed", "{}", &[]).await).await;
    assert_eq!(r.status, 503, "{}", r.body);
    assert_eq!(r.error(), Some(ErrorCode::Unavailable));
    assert_eq!(
        w.fake().invoice_count(),
        0,
        "no invoice for an offer that could never be acknowledged"
    );
}
