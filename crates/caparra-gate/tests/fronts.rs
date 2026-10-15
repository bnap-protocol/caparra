//! The auth fronts: Caddy `forward_auth` and nginx `auth_request`. The
//! gate answers the subrequest, names the action by `X-Forwarded-Method`
//! and `X-Forwarded-Uri`, never sees the content or the answer, and
//! settles OK at admission.

#![allow(clippy::many_single_char_names)]

mod common;

use bnap_core::ErrorCode;
use common::*;

fn auth_config(front: &str) -> impl FnOnce(&std::path::Path, &str) -> String {
    let front = front.to_owned();
    move |dir, up| {
        // The default configuration without its metered route.
        let text = config_text(dir, up, "");
        let start = text.find("[[route]]\nid = \"chat\"").unwrap();
        let end = text.find("[[route]]\nid = \"status\"").unwrap();
        let text = format!("{}{}", &text[..start], &text[end..]);
        text.replace(
            "listen = \"127.0.0.1:0\"",
            &format!("listen = \"127.0.0.1:0\"\nfront = \"{front}\""),
        )
    }
}

fn forwarded(method: &str, uri: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-forwarded-method", method.into()),
        ("x-forwarded-uri", uri.into()),
        ("x-forwarded-for", "203.0.113.7".into()),
        ("x-original-content-length", String::new()),
    ]
}

#[tokio::test]
async fn forward_auth_challenges_admits_and_settles_without_the_content() {
    let w = World::with_text(auth_config("forward_auth")).await;
    let a = read(
        w.send("GET", "/auth", "", &forwarded("GET", "/v1/status"))
            .await,
    )
    .await;
    assert_eq!(a.status, 402);
    assert_eq!(a.error(), Some(ErrorCode::Required));
    // An exact route: L402 over the fake rail, natively.
    let a = read(
        w.send("GET", "/auth", "", &forwarded("POST", "/v1/fixed"))
            .await,
    )
    .await;
    assert_eq!(a.status, 402);
    let offer = a.exact_offer();
    assert_eq!(offer.fields().scope, scope("POST", "/v1/fixed", ""));
    let ch = a
        .natives()
        .into_iter()
        .find(|n| n.starts_with("L402"))
        .unwrap();
    let ch = bnap_scheme_l402::Challenge::parse(&ch).unwrap();
    let mpp = a
        .natives()
        .into_iter()
        .find(|n| n.starts_with("Payment"))
        .unwrap();
    let hash = bnap_scheme_mpp::ChargeRequest::decode(
        &bnap_scheme_mpp::Challenge::parse(&mpp).unwrap().request,
    )
    .unwrap()
    .payment_hash;
    let pre = w.fake().pay(&hash).unwrap();
    let token = bnap_scheme_l402::Token::new(&ch.token, pre).unwrap();
    let mut h = forwarded("POST", "/v1/fixed");
    h.push(("authorization", bnap_scheme_l402::authorization(&token)));
    let r = read(w.send("GET", "/auth", "", &h).await).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let receipt = r.receipt().unwrap();
    receipt.verify_ack().unwrap();
    assert_eq!(receipt.fields().charged, 21);
    assert_eq!(w.calls(), 0, "the gate never calls the application itself");
    // The same credential again: the front must not run the action again,
    // so the replay is not a 2xx, and it still carries the receipt.
    for _ in 0..3 {
        let again = read(w.send("GET", "/auth", "", &h).await).await;
        assert_eq!(again.status, 409, "{}", again.body);
        assert!(again.receipt().unwrap().fields().replayed);
    }
    // The front must say whether the original request had content.
    let mut no_len = forwarded("POST", "/v1/fixed");
    no_len.retain(|(k, _)| *k != "x-original-content-length");
    let r = read(w.send("GET", "/auth", "", &no_len).await).await;
    assert_eq!(r.status, 400);
    let mut with_len = forwarded("POST", "/v1/fixed");
    with_len.retain(|(k, _)| *k != "x-original-content-length");
    with_len.push(("x-original-content-length", "5".into()));
    let r = read(w.send("GET", "/auth", "", &with_len).await).await;
    assert_eq!(r.status, 400);
    // Content the gate cannot see is refused.
    let r = read(
        w.send("POST", "/auth", "hello", &forwarded("POST", "/v1/fixed"))
            .await,
    )
    .await;
    assert_eq!(r.status, 400);
    // Off every route: allowed.
    let r = read(w.send("GET", "/auth", "", &forwarded("GET", "/free")).await).await;
    assert_eq!(r.status, 200);
    // No forwarded request at all.
    let r = read(w.send("GET", "/auth", "", &[]).await).await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn auth_request_maps_statuses_nginx_cannot_pass() {
    let w = World::with_text(auth_config("auth_request")).await;
    let a = read(
        w.send("GET", "/auth", "", &forwarded("GET", "/v1/status"))
            .await,
    )
    .await;
    assert_eq!(a.status, 401, "nginx passes 2xx, 401 and 403 only");
    assert_eq!(a.headers["bnap-status"], "402");
    assert_eq!(a.error(), Some(ErrorCode::Required));
    assert_ne!(a.offers().len(), 0);
}
