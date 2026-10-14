//! Spend policy in code: whatever a caller (a model's tool call, a
//! prompt-injected page) asks for, the wallet pays only within the caps a
//! person set, only with allowed schemes, and counts routing fees.

#![allow(clippy::missing_panics_doc, clippy::result_large_err, missing_docs)]

use std::sync::Arc;

use caparra_wallet::testkit::{self, Kit, ORIGIN, PRICE};
use caparra_wallet::{CapKind, Code, FetchRequest, Linkability, Wallet};

fn url(path: &str) -> String {
    format!("{ORIGIN}{path}")
}

fn credentials_sent(kit: &Kit) -> usize {
    kit.server
        .seen()
        .iter()
        .filter(|r| {
            r.headers.iter().any(|(n, _)| {
                n.eq_ignore_ascii_case("bnap-credential") || n.eq_ignore_ascii_case("authorization")
            })
        })
        .count()
}

async fn caps(w: &Wallet, f: impl FnOnce(&mut caparra_wallet::Caps)) {
    w.set_policy(|p| {
        f(&mut p.caps);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_call_asking_for_more_than_the_hard_cap_is_refused_before_anything_is_sent() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    caps(&w, |c| c.per_request = 50).await;
    let mut req = FetchRequest::get(url("/paid"));
    req.max_sat = Some(1_000_000);
    let e = w.fetch(req).await.unwrap_err();
    assert_eq!(e.code, Code::AboveHardCap);
    assert_eq!(e.remaining, Some(50));
    assert_eq!(kit.server.seen().len(), 0);
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn a_price_above_the_cap_is_refused_with_what_the_cap_leaves() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    caps(&w, |c| c.per_request = 1_000).await;
    // 5,000 sat route.
    let e = w.fetch(FetchRequest::get(url("/big"))).await.unwrap_err();
    assert_eq!(e.code, Code::BudgetExceeded);
    assert_eq!(e.cap, Some(CapKind::PerRequest));
    assert_eq!(e.remaining, Some(1_000));
    assert!(e.message.contains("leaves 1000 sat"), "{}", e.message);
    assert_eq!(kit.pay.total(), 0);
    assert_eq!(credentials_sent(&kit), 0);
}

#[tokio::test]
async fn a_per_call_max_below_the_price_is_honoured() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    let mut req = FetchRequest::get(url("/paid"));
    req.max_sat = Some(PRICE - 1);
    assert_eq!(w.fetch(req).await.unwrap_err().code, Code::BudgetExceeded);
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn routing_fees_count_against_the_caps() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    // The price fits exactly; the fee ceiling does not.
    caps(&w, |c| c.per_request = PRICE).await;
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::BudgetExceeded);
    assert!(e.cost.unwrap() > PRICE);
    assert_eq!(kit.pay.total(), 0);
    // With room for the fee it pays, and the fee is in the ledger.
    caps(&w, |c| c.per_request = PRICE + 5).await;
    let r = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    assert_eq!(r.payment.unwrap().cost_sat, PRICE + 1);
    let spent: u64 = w
        .ledger()
        .await
        .unwrap()
        .iter()
        .map(caparra_wallet::policy::LedgerEntry::counted)
        .sum();
    assert_eq!(spent, PRICE + 1);
}

#[tokio::test]
async fn many_small_calls_stop_at_the_origin_cap() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    caps(&w, |c| c.per_origin_day = 50).await;
    let mut ok = 0;
    for _ in 0..5 {
        match w.fetch(FetchRequest::get(url("/ln"))).await {
            Ok(_) => ok += 1,
            Err(e) => {
                assert_eq!(e.code, Code::BudgetExceeded);
                assert_eq!(e.cap, Some(CapKind::PerOrigin));
            }
        }
    }
    assert_eq!(ok, 2);
    assert!(kit.pay.total() <= 50);
    // A day later the window has room again.
    kit.clock.advance(86_401);
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
}

#[tokio::test]
async fn concurrent_calls_never_pass_a_cap() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = Arc::new(testkit::wallet(&kit, dir.path(), "t").await);
    caps(&w, |c| c.daily = 100).await;
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let w = w.clone();
        tasks.push(tokio::spawn(async move {
            w.fetch(FetchRequest::get(url("/ln"))).await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert_eq!(e.code, Code::BudgetExceeded, "{e}"),
        }
    }
    assert!(ok >= 1, "at least one fits");
    assert!(kit.pay.total() <= 100, "paid {}", kit.pay.total());
    let spent: u64 = w
        .ledger()
        .await
        .unwrap()
        .iter()
        .map(caparra_wallet::policy::LedgerEntry::counted)
        .sum();
    assert!(spent <= 100);
}

#[tokio::test]
async fn the_per_task_cap_holds_across_origins_and_windows() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "task-a").await;
    caps(&w, |c| c.per_task = 30).await;
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    kit.clock.advance(3 * 86_400);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.cap, Some(CapKind::PerTask));
}

#[tokio::test]
async fn a_forbidden_scheme_is_never_used_whatever_the_server_offers() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.set_policy(|p| {
        p.allowed_schemes = vec!["bnap:notes".into()];
        Ok(())
    })
    .await
    .unwrap();
    // The /ln route offers only L402 and MPP.
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::Policy);
    assert!(e.scheme.is_some());
    assert_eq!(kit.pay.total(), 0);
    assert_eq!(credentials_sent(&kit), 0);
}

#[tokio::test]
async fn required_properties_come_from_the_registry() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.set_policy(|p| {
        p.require.insert("link-payment".into(), "unlinkable".into());
        Ok(())
    })
    .await
    .unwrap();
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::Policy);
    assert_eq!(e.property.as_deref(), Some("link-payment"));
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn experimental_schemes_need_the_opt_in() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.set_policy(|p| {
        p.allow_experimental = false;
        Ok(())
    })
    .await
    .unwrap();
    let e = w.fetch(FetchRequest::get(url("/paid"))).await.unwrap_err();
    assert_eq!(e.code, Code::Policy);
    assert_eq!(e.property.as_deref(), Some("maturity"));
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn never_linkable_refuses_lightning_and_funding() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.set_policy(|p| {
        p.linkable = Linkability::Never;
        Ok(())
    })
    .await
    .unwrap();
    // /paid offers L402, notes (no notes held: only funding, linkable) and MPP.
    let e = w.fetch(FetchRequest::get(url("/paid"))).await.unwrap_err();
    assert!(
        matches!(e.code, Code::Policy | Code::InsufficientNotes),
        "{e}"
    );
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn a_session_never_raises_a_cap_and_narrowing_holds() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    let hard = w.config().await.unwrap().policy.caps;
    let e = w
        .set_session_cap(CapKind::PerRequest, hard.per_request + 1)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::AboveHardCap);
    let e = w
        .set_session_cap(CapKind::Daily, u64::MAX)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::AboveHardCap);
    w.set_session_cap(CapKind::PerRequest, 10).await.unwrap();
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::BudgetExceeded);
    assert_eq!(e.remaining, Some(10));
    assert_eq!(kit.pay.total(), 0);
}

#[tokio::test]
async fn unlinkable_notes_win_over_cheaper_or_earlier_linkable_entries() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 64, None).await.unwrap();
    let paid_before = kit.pay.total();
    // /paid lists L402 first; the wallet holds notes, which are unlinkable.
    let r = w.fetch(FetchRequest::get(url("/paid"))).await.unwrap();
    assert_eq!(r.payment.unwrap().scheme.as_deref(), Some("bnap:notes"));
    assert_eq!(kit.pay.total(), paid_before, "no Lightning payment");
}
