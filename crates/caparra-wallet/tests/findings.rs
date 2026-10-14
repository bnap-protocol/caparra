//! Regression tests for the checker's findings: a pay source error that
//! may still settle, fees above the ceiling, a native payment whose request
//! is lost, and restoring another device's slot.

#![allow(clippy::missing_panics_doc, clippy::result_large_err, missing_docs)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use caparra_wallet::invoice::Invoice;
use caparra_wallet::paysource::{Paid, PaySource};
use caparra_wallet::policy::LedgerEntry;
use caparra_wallet::testkit::{self, Kit, ORIGIN};
use caparra_wallet::{
    Code, FetchRequest, HttpRequest, HttpResponse, Refusal, Transport, Wallet, verify_receipt,
};

fn url(path: &str) -> String {
    format!("{ORIGIN}{path}")
}

/// Pays the invoice, then reports a timeout, as an NWC wallet that gave up
/// waiting on a hold invoice would.
struct PaysThenFails {
    kit_rail: Arc<testkit::TestRail>,
    paid: AtomicU64,
}

#[async_trait::async_trait]
impl PaySource for PaysThenFails {
    async fn pay_invoice(
        &self,
        invoice: &str,
        amount: u64,
        _max_fee: u64,
    ) -> caparra_wallet::Result<Paid> {
        let inv = Invoice::decode(invoice).unwrap();
        self.kit_rail.pay(&inv.payment_hash).unwrap();
        self.paid.fetch_add(amount, Ordering::SeqCst);
        Err(Refusal::new(Code::PaymentFailed, "timed out"))
    }
}

fn counted(l: &[LedgerEntry]) -> u64 {
    l.iter().map(LedgerEntry::counted).sum()
}

#[tokio::test]
async fn a_pay_source_error_keeps_the_reservation_counted() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let pay = Arc::new(PaysThenFails {
        kit_rail: kit.server.rail.clone(),
        paid: AtomicU64::new(0),
    });
    let mut opts = kit.options("t");
    opts.pay_source = Some(pay.clone());
    let (w, _) = Wallet::create(&dir.path().join("w.db"), "p", &opts)
        .await
        .unwrap();
    w.set_policy(|p| {
        p.allow_experimental = true;
        p.caps.daily = 50;
        Ok(())
    })
    .await
    .unwrap();
    for _ in 0..10 {
        let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
        assert!(
            matches!(e.code, Code::PaymentFailed | Code::BudgetExceeded),
            "{e}"
        );
    }
    let out = pay.paid.load(Ordering::SeqCst);
    assert!(out <= 50, "{out} sat left the wallet under a 50 sat cap");
    assert!(counted(&w.ledger().await.unwrap()) >= out);
}

#[tokio::test]
async fn a_fee_above_the_ceiling_counts_in_full() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.pay.fee_sat.store(40, Ordering::SeqCst);
    w.set_policy(|p| {
        p.caps.daily = 100;
        Ok(())
    })
    .await
    .unwrap();
    for _ in 0..10 {
        let _ = w.fetch(FetchRequest::get(url("/ln"))).await;
    }
    assert_eq!(counted(&w.ledger().await.unwrap()), kit.pay.total());
    // After one overshoot the caps hold: nothing else is paid.
    assert!(kit.pay.total() <= 2 * (21 + 40), "{}", kit.pay.total());
}

/// Fails every request that carries `Authorization`.
struct DropsPaid(Arc<testkit::TestTransport>);

#[async_trait::async_trait]
impl Transport for DropsPaid {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        if req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        {
            return Err("connection reset".into());
        }
        self.0.send(req).await
    }
}

#[tokio::test]
async fn a_native_payment_keeps_its_proof_when_the_request_is_lost() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    kit.server.knobs.lock().unwrap().native_only = true;
    let mut opts = kit.options("t");
    opts.transport = Arc::new(DropsPaid(kit.transport.clone()));
    let (w, _) = Wallet::create(&dir.path().join("w.db"), "p", &opts)
        .await
        .unwrap();
    w.set_policy(|p| {
        p.allow_experimental = true;
        Ok(())
    })
    .await
    .unwrap();
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::Network);
    assert!(e.paid.is_some());
    let recs = w.receipts().await.unwrap();
    assert_eq!(recs.len(), 1);
    assert!(!recs[0].ok);
    verify_receipt(&recs[0]).unwrap();
}

#[tokio::test]
async fn restore_scans_the_slots_a_person_names() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let (a, words) = Wallet::create(&dir.path().join("a.db"), "p", &kit.options("a"))
        .await
        .unwrap();
    a.set_slot(3).await.unwrap();
    a.set_policy(|p| {
        p.allow_experimental = true;
        Ok(())
    })
    .await
    .unwrap();
    a.fund(ORIGIN, 300, None).await.unwrap();
    a.fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap();
    let held = a.balances().await.unwrap()[ORIGIN];
    let b = Wallet::create_from_mnemonic(&dir.path().join("b.db"), "p", &words, &kit.options("b"))
        .await
        .unwrap();
    let rep = b.restore(&[ORIGIN.to_owned()], None, &[]).await.unwrap();
    assert_eq!(rep[0].restored_sat, 0, "slot 3 is not scanned unless named");
    let rep = b.restore(&[ORIGIN.to_owned()], None, &[3]).await.unwrap();
    assert_eq!(rep[0].restored_sat, held);
}

/// Refuses every credential with `err` and every NUT-04 mint, as a hostile
/// operator that takes funding payments and never issues would.
struct RefusesAfterFunding {
    inner: Arc<testkit::TestTransport>,
    err: bnap_core::ErrorCode,
}

#[async_trait::async_trait]
impl Transport for RefusesAfterFunding {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        if req.url.ends_with("/cashu/v1/mint/bolt11") {
            return Ok(HttpResponse {
                status: 400,
                headers: Vec::new(),
                body: b"quote already issued".to_vec(),
            });
        }
        if req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("bnap-credential"))
        {
            let e = bnap_core::ErrorObject::new(self.err);
            return Ok(HttpResponse {
                status: 402,
                headers: vec![("BNAP-Error".into(), b64.encode(e.to_bytes().unwrap()))],
                body: Vec::new(),
            });
        }
        self.inner.send(req).await
    }
}

#[tokio::test]
async fn a_paid_fund_quote_counts_until_it_is_minted() {
    for err in [bnap_core::ErrorCode::Policy, bnap_core::ErrorCode::BadOffer] {
        let kit = Kit::new();
        let dir = tempfile::tempdir().unwrap();
        let mut opts = kit.options("t");
        opts.transport = Arc::new(RefusesAfterFunding {
            inner: kit.transport.clone(),
            err,
        });
        let (w, _) = Wallet::create(&dir.path().join("w.db"), "p", &opts)
            .await
            .unwrap();
        w.set_policy(|p| {
            p.allow_experimental = true;
            p.caps.daily = 100;
            Ok(())
        })
        .await
        .unwrap();
        for _ in 0..20 {
            let _ = w
                .fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
                .await;
        }
        let _ = w.resume().await;
        let out = kit.pay.total();
        assert!(out <= 100, "{err:?}: {out} sat out under a 100 sat cap");
        assert!(counted(&w.ledger().await.unwrap()) >= out, "{err:?}");
    }
}

#[tokio::test]
async fn a_minted_quote_counts_only_its_fee() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fund(ORIGIN, 200, None).await.unwrap();
    assert_eq!(counted(&w.ledger().await.unwrap()), 1, "the routing fee");
}
