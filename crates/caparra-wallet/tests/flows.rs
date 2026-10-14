//! End-to-end: the wallet against the in-test BNAP server.

#![allow(clippy::missing_panics_doc, missing_docs)]

use caparra_wallet::testkit::{self, Kit, ORIGIN, PRICE};
use caparra_wallet::{Code, FetchRequest, verify_receipt};

fn url(path: &str) -> String {
    format!("{ORIGIN}{path}")
}

#[tokio::test]
async fn fund_then_pay_with_notes_and_get_change() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    let f = w.fund(ORIGIN, 200, None).await.unwrap();
    assert_eq!(f.amount, 200);
    assert_eq!(f.balance, 200);
    let r = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"hi".to_vec()))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let p = r.payment.unwrap();
    assert_eq!(p.scheme.as_deref(), Some("bnap:notes"));
    assert_eq!(p.charged, PRICE);
    let bal = w.balances().await.unwrap()[ORIGIN];
    assert_eq!(200 - bal, p.cost_sat);
    assert!(
        p.cost_sat >= PRICE && p.cost_sat <= PRICE + 1,
        "{}",
        p.cost_sat
    );
    for rec in w.receipts().await.unwrap() {
        verify_receipt(&rec).unwrap();
    }
    // A second call pays from the change.
    let r = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"again".to_vec()))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(
        kit.pay.total(),
        200 + 1,
        "no Lightning payment for the second call"
    );
}

#[tokio::test]
async fn without_notes_the_cheapest_lightning_scheme_pays() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    let r = w.fetch(FetchRequest::get(url("/paid"))).await.unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let p = r.payment.unwrap();
    assert_eq!(p.scheme.as_deref(), Some("httpauth:L402"));
    assert_eq!(p.cost_sat, PRICE + 1);
    let recs = w.receipts().await.unwrap();
    assert_eq!(recs.len(), 1);
    verify_receipt(&recs[0]).unwrap();
}

#[tokio::test]
async fn plain_http_is_refused_and_never_pinned() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    let e = w
        .fetch(FetchRequest::get("http://api.example/paid"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::BadInput);
    assert!(w.pin("http://api.example").await.unwrap().is_none());
    assert!(kit.server.seen().is_empty());
}
