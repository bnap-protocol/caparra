//! End-to-end: the wallet against the in-test BNAP server.

#![allow(clippy::missing_panics_doc, clippy::result_large_err, missing_docs)]

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
    assert_eq!(kit.server.seen().len(), 0);
}

#[tokio::test]
async fn funding_inside_the_402_pays_and_returns_change() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    // The chat route takes notes only; the wallet holds none.
    let r = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let p = r.payment.unwrap();
    assert_eq!(p.scheme.as_deref(), Some("bnap:notes"));
    assert_eq!(p.charged, PRICE);
    // The quote was the price; the fee was 1 sat; no change.
    assert_eq!(p.cost_sat, PRICE + 1);
    assert_eq!(kit.pay.total(), PRICE + 1);
}

#[tokio::test]
async fn a_failed_action_refunds_the_notes() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 100, None).await.unwrap();
    kit.server.knobs.lock().unwrap().action_fails = true;
    let r = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap();
    let p = r.payment.unwrap();
    assert!(!p.ok);
    assert_eq!(p.charged, 0);
    // Only the input fee is kept.
    let bal = w.balances().await.unwrap()[ORIGIN];
    assert_eq!(100 - bal, p.cost_sat);
    assert!(p.cost_sat <= 1);
}

#[tokio::test]
async fn a_tampered_receipt_is_refused_and_kept_as_evidence() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 100, None).await.unwrap();
    kit.server.knobs.lock().unwrap().tamper_receipt = true;
    let e = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::BadReceipt);
    assert_eq!(w.receipts().await.unwrap().len(), 0);
    let out = w.resume().await.unwrap();
    assert!(
        out.iter().any(|o| o.result.is_err()),
        "the op is kept, disputed"
    );
}

#[tokio::test]
async fn pending_is_retried_by_itself() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 100, None).await.unwrap();
    kit.server
        .pending
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let r = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap();
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn a_crash_after_commit_is_resumed_into_a_refund() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 100, None).await.unwrap();
    kit.server.knobs.lock().unwrap().crash_after_commit = true;
    let e = w
        .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::Unavailable);
    assert!(e.message.contains("bnap resume"), "{}", e.message);
    // The notes stay locked until the replay answers.
    assert!(
        w.balances()
            .await
            .unwrap()
            .get(ORIGIN)
            .copied()
            .unwrap_or(0)
            < 100
    );
    kit.server.knobs.lock().unwrap().crash_after_commit = false;
    // Still pending: the replay is answered PENDING.
    let out = w.resume().await.unwrap();
    assert_eq!(out[0].result.as_ref().unwrap_err().code, Code::Pending);
    // After pending_timeout the outcome is FAILED and the value refunded.
    kit.clock.advance(301);
    let out = w.resume().await.unwrap();
    let p = out[0].result.clone().unwrap().unwrap();
    assert!(!p.ok);
    assert!(p.replayed);
    let bal = w.balances().await.unwrap()[ORIGIN];
    assert_eq!(100 - bal, p.cost_sat);
    assert!(p.cost_sat <= 1, "only the input fee");
}

#[tokio::test]
async fn receipts_survive_a_restart_and_verify_later() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    {
        let w = testkit::wallet(&kit, dir.path(), "t").await;
        w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
        w.fund(ORIGIN, 64, None).await.unwrap();
        w.fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
            .await
            .unwrap();
    }
    let w = caparra_wallet::Wallet::open(
        &dir.path().join("wallet.db"),
        "test passphrase",
        &kit.options("t"),
    )
    .await
    .unwrap();
    let recs = w.receipts().await.unwrap();
    assert_eq!(recs.len(), 2);
    kit.clock.advance(40 * 86_400);
    for r in &recs {
        verify_receipt(r).unwrap();
    }
}

#[tokio::test]
async fn restore_from_the_mnemonic_recovers_the_balance() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let (a, words) =
        caparra_wallet::Wallet::create(&dir.path().join("a.db"), "pa", &kit.options("a"))
            .await
            .unwrap();
    a.set_policy(|p| {
        p.allow_experimental = true;
        Ok(())
    })
    .await
    .unwrap();
    a.fund(ORIGIN, 300, None).await.unwrap();
    for i in 0..3 {
        a.fetch(FetchRequest::post(url("/v1/chat"), vec![i]))
            .await
            .unwrap();
    }
    let held = a.balances().await.unwrap()[ORIGIN];
    assert!(held > 0 && held < 300);
    let b = caparra_wallet::Wallet::create_from_mnemonic(
        &dir.path().join("b.db"),
        "pb",
        &words,
        &kit.options("b"),
    )
    .await
    .unwrap();
    let rep = b.restore(&[ORIGIN.to_owned()], None, &[]).await.unwrap();
    assert_eq!(rep[0].restored_sat, held);
    assert_eq!(b.balances().await.unwrap()[ORIGIN], held);
    // The restored notes spend (caps with room for the largest note).
    b.set_policy(|p| {
        p.allow_experimental = true;
        p.caps.per_request = 1_000;
        Ok(())
    })
    .await
    .unwrap();
    let before = kit.pay.total();
    b.fetch(FetchRequest::post(url("/v1/chat"), b"from b".to_vec()))
        .await
        .unwrap();
    assert_eq!(kit.pay.total(), before);
}
