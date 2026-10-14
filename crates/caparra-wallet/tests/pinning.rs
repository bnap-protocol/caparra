//! Manifest pinning (draft-00 9.3) and offer checks (4.4) from the
//! client's side.

#![allow(clippy::missing_panics_doc, clippy::result_large_err, missing_docs)]

use caparra_wallet::testkit::{self, Kit, ORIGIN};
use caparra_wallet::{Code, FetchRequest, verify_receipt};

fn url(path: &str) -> String {
    format!("{ORIGIN}{path}")
}

fn paid(kit: &Kit) -> u64 {
    kit.pay.total()
}

#[tokio::test]
async fn first_contact_pins_root_and_backup() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    assert!(w.pin(ORIGIN).await.unwrap().is_none());
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    let pin = w.pin(ORIGIN).await.unwrap().unwrap();
    let (root, backup) = kit.server.root_keys();
    assert_eq!(pin.root, root.public_key());
    assert_eq!(pin.backup, backup.public_key());
    assert_eq!(pin.seq, 1);
    assert!(!pin.required);
}

#[tokio::test]
async fn an_offer_key_rotation_with_a_higher_seq_is_followed() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    kit.clock.advance(600);
    kit.server.rotate_offer_key();
    // The new key is unknown to the pin: the wallet refetches once.
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    assert_eq!(w.pin(ORIGIN).await.unwrap().unwrap().seq, 2);
    for r in w.receipts().await.unwrap() {
        verify_receipt(&r).unwrap();
    }
}

#[tokio::test]
async fn the_backup_key_can_take_over_as_root() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    let (_, old_backup) = kit.server.root_keys();
    kit.clock.advance(600);
    kit.server.rotate_root();
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    let pin = w.pin(ORIGIN).await.unwrap().unwrap();
    assert_eq!(pin.root, old_backup.public_key());
    assert_eq!(pin.seq, 2);
}

#[tokio::test]
async fn a_rollback_to_a_lower_seq_is_refused() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.clock.advance(10);
    kit.server.rotate_offer_key(); // seq 2
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    assert_eq!(w.pin(ORIGIN).await.unwrap().unwrap().seq, 2);
    // An attacker replays an old, validly signed manifest (seq 1) that
    // lists a key it controls, and signs offers with that key.
    let (root, _) = kit.server.root_keys();
    let rogue = bnap_core::schnorr::SigningKey::from_secret_bytes(&[0x42; 32]).unwrap();
    let old = kit.server.forge_manifest(&root, |m| {
        m.seq = 1;
        m.keys[0].kid = rogue.public_key();
    });
    *kit.server.manifest_override.lock().unwrap() = Some(old);
    kit.server.knobs.lock().unwrap().rogue_offer_key = Some([0x42; 32]);
    kit.clock.advance(600);
    let before = paid(&kit);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
    assert_eq!(paid(&kit), before);
    assert_eq!(w.pin(ORIGIN).await.unwrap().unwrap().seq, 2);
}

#[tokio::test]
async fn a_manifest_signed_by_neither_root_nor_backup_is_refused() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    let attacker = bnap_core::schnorr::SigningKey::from_secret_bytes(&[0x24; 32]).unwrap();
    let forged = kit.server.forge_manifest(&attacker, |m| {
        m.seq = 99;
        m.root = attacker.public_key();
        m.keys[0].kid = attacker.public_key();
    });
    *kit.server.manifest_override.lock().unwrap() = Some(forged);
    kit.server.knobs.lock().unwrap().rogue_offer_key = Some([0x24; 32]);
    kit.clock.advance(600);
    let before = paid(&kit);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
    assert_eq!(paid(&kit), before);
    assert_eq!(w.pin(ORIGIN).await.unwrap().unwrap().seq, 1);
}

#[tokio::test]
async fn an_offer_signed_by_a_key_the_root_did_not_sign_is_refused_after_one_refetch() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.server.knobs.lock().unwrap().rogue_offer_key = Some([0x33; 32]);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::UnknownKey);
    assert_eq!(paid(&kit), 0);
    let manifest_fetches = kit
        .server
        .seen()
        .iter()
        .filter(|r| r.url.ends_with("/.well-known/bnap"))
        .count();
    assert_eq!(manifest_fetches, 1, "at most one fetch per five minutes");
}

#[tokio::test]
async fn a_bad_offer_sig_is_refused() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.server.knobs.lock().unwrap().bad_offer_sig = true;
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::BadOfferSig);
    assert_eq!(paid(&kit), 0);
}

#[tokio::test]
async fn bnap_required_means_no_native_payment_until_the_pin_lapses() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.server.set_required(true);
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    assert!(w.pin(ORIGIN).await.unwrap().unwrap().required);
    // Someone on the path deletes the BNAP challenges: native ones remain.
    kit.server.knobs.lock().unwrap().strip_bnap = true;
    let before = paid(&kit);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::BnapRequired);
    assert_eq!(paid(&kit), before);
    // Still refused a day later: the pin is live.
    kit.clock.advance(86_400);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::BnapRequired);
    assert_eq!(paid(&kit), before);
}

#[tokio::test]
async fn a_pinned_origin_without_required_still_never_pays_an_unlisted_native() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    kit.server.knobs.lock().unwrap().strip_bnap = true;
    let before = paid(&kit);
    let e = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap_err();
    assert_eq!(e.code, Code::NoOffer);
    assert_eq!(paid(&kit), before);
}

#[tokio::test]
async fn a_tier_0_origin_without_a_manifest_is_paid_natively() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    kit.server.knobs.lock().unwrap().native_only = true;
    let r = w.fetch(FetchRequest::get(url("/ln"))).await.unwrap();
    assert_eq!(r.status, 200);
    let p = r.payment.unwrap();
    assert_eq!(p.scheme.as_deref(), Some("httpauth:L402"));
    assert!(w.pin(ORIGIN).await.unwrap().is_none());
    let recs = w.receipts().await.unwrap();
    verify_receipt(&recs[0]).unwrap();
}

#[tokio::test]
async fn the_wallet_never_advertises_what_it_supports() {
    let kit = Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let w = testkit::wallet(&kit, dir.path(), "t").await;
    w.fetch(FetchRequest::get(url("/paid"))).await.unwrap();
    w.fetch(FetchRequest::post(url("/v1/chat"), b"x".to_vec()))
        .await
        .unwrap();
    let allowed = ["bnap-credential", "bnap-fund", "accept", "content-type"];
    for r in kit.server.seen() {
        for (n, _) in &r.headers {
            assert!(
                allowed.contains(&n.to_ascii_lowercase().as_str()),
                "the wallet sent {n} to {}",
                r.url
            );
        }
    }
}
