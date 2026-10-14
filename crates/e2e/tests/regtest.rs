//! Against the Lightning regtest network of `devenv/regtest`: the LND rail
//! on the payee node, payments made from the payer node with `lncli`.
//!
//! Needs the `regtest` feature and Docker. Each test runs
//! `devenv/regtest/up.sh` (idempotent, one at a time) unless
//! `BNAP_REGTEST_LND_ADDRESS` is already set, in which case it uses
//! `BNAP_REGTEST_LND_CERT` and `BNAP_REGTEST_LND_MACAROON` too.
//!
//! ```text
//! cargo nextest run -p e2e --features regtest
//! devenv/regtest/down.sh
//! ```

#![cfg(feature = "regtest")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::hash::{Scope, sha256};
use bnap_core::ids::{rail, rail_id};
use bnap_core::response::Status;
use bnap_core::{Credential, ErrorCode};
use bnap_plug::{FundingRail, PayState, RailRef, confirm_rail_id};
use bnap_rail_lnd::{LndConfig, LndRail};
use bnap_scheme_l402::{L402, MacaroonKeys, OfferInvoices, Token};
use bnap_scheme_mpp::{ChallengeKeys, ChargeRequest, LightningCharge, Network};
use e2e::{Gate, OFFER_LIFETIME, Refused};

fn devenv() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../devenv/regtest")
}

/// The payee node's gRPC address, TLS cert and invoice macaroon, with
/// invoices that end with the test gate's offers.
fn lnd_config() -> LndConfig {
    let mut config = lnd_node();
    config.expiry = OFFER_LIFETIME;
    config
}

fn lnd_node() -> LndConfig {
    if let (Ok(a), Ok(c), Ok(m)) = (
        std::env::var("BNAP_REGTEST_LND_ADDRESS"),
        std::env::var("BNAP_REGTEST_LND_CERT"),
        std::env::var("BNAP_REGTEST_LND_MACAROON"),
    ) {
        return LndConfig::new(a, c, m);
    }
    let up = Command::new("sh")
        .arg(devenv().join("up.sh"))
        .status()
        .expect("run devenv/regtest/up.sh");
    assert!(up.success(), "devenv/regtest/up.sh failed");
    let env = std::fs::read_to_string(devenv().join(".state/env")).expect("read .state/env");
    let get = |key: &str| {
        env.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("{key} missing from .state/env"))
            .to_owned()
    };
    LndConfig::new(
        get("BNAP_REGTEST_LND_ADDRESS"),
        get("BNAP_REGTEST_LND_CERT"),
        get("BNAP_REGTEST_LND_MACAROON"),
    )
}

/// Pays `invoice` from the payer node and returns the preimage it learned.
/// A failed attempt is retried a few times: right after the channel opens
/// the payer's router can briefly report no balance.
fn payer_pays(invoice: &str) -> [u8; 32] {
    let mut last = String::new();
    for _ in 0..10 {
        let out = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(devenv().join("compose.yml"))
            .args(["exec", "-T", "payer", "lncli", "--network=regtest"])
            .args(["payinvoice", "--force", "--json", invoice])
            .output()
            .expect("run lncli payinvoice");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success()
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout)
            && v["status"] == "SUCCEEDED"
        {
            let hex = v["payment_preimage"].as_str().expect("a preimage");
            let mut preimage = [0; 32];
            hex::decode_to_slice(hex, &mut preimage).expect("hex preimage");
            return preimage;
        }
        last = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("payinvoice did not succeed: {last}");
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn an_lnd_invoice_paid_from_the_payer_confirms_final_with_its_amount() {
    let rail = LndRail::connect(&lnd_config())
        .await
        .expect("connect to LND");
    let memo = sha256(b"e2e regtest memo");
    let req = rail.request(21, "sat", memo).await.expect("add invoice");
    assert_eq!(
        (req.rail_kind.as_str(), req.amount, req.unit.as_str()),
        ("ln", 21, "sat")
    );
    assert!(req.request.starts_with("lnbcrt"), "a regtest invoice");
    let hash: [u8; 32] = req
        .id
        .0
        .as_slice()
        .try_into()
        .expect("PayId is the payment hash");
    let reference = RailRef {
        kind: rail::LN.into(),
        reference: hash.to_vec(),
    };

    // Before payment: known to the node, not final, nothing paid.
    let before = rail.confirm(&reference).await.expect("look the invoice up");
    assert_eq!((before.state, before.amount), (PayState::Pending, 0));
    assert!(confirm_rail_id(&rail, &reference).await.is_err());

    let preimage = payer_pays(&req.request);
    assert_eq!(
        sha256(&preimage),
        hash,
        "the preimage opens the payment hash"
    );

    // After payment: final, with the amount the node received.
    let paid = rail.confirm(&reference).await.expect("look the invoice up");
    assert_eq!(paid.canonical, hash.to_vec());
    assert_eq!(
        (paid.state, paid.amount, paid.unit.as_str()),
        (PayState::Paid, 21_000, "msat")
    );
    assert_eq!(rail.status(&req.id).await.unwrap(), PayState::Paid);
    let p = confirm_rail_id(&rail, &reference)
        .await
        .expect("a final payment");
    assert_eq!(p.rail_id, rail_id(rail::LN, &hash));
    assert_eq!((p.amount, p.unit.as_str()), (21_000, "msat"));
    println!(
        "regtest: invoice {}... paid; rail confirmed {:?}, {} {}",
        &req.request[..20],
        paid.state,
        paid.amount,
        paid.unit
    );

    // A payment hash the node never issued.
    let unknown = RailRef {
        kind: rail::LN.into(),
        reference: sha256(b"never issued").to_vec(),
    };
    assert!(matches!(
        rail.confirm(&unknown).await,
        Err(bnap_plug::RailError::NotConfirmed(_))
    ));
}

#[tokio::test]
async fn one_regtest_payment_through_l402_and_mpp_admits_one_action() {
    let lnd: Arc<dyn FundingRail> = Arc::new(
        LndRail::connect(&lnd_config())
            .await
            .expect("connect to LND"),
    );
    let invoices: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(lnd.clone()));
    let l402 = Arc::new(L402::new(MacaroonKeys::new([0x31; 32]), invoices.clone()));
    let mpp = Arc::new(
        LightningCharge::new(
            ChallengeKeys::new([0x32; 32]).unwrap(),
            "api.example",
            Network::Regtest,
            invoices,
        )
        .unwrap(),
    );
    let gate = Gate::new(lnd, vec![l402, mpp]);
    let scope = Scope(sha256(b"POST https://api.example/v1/regtest"));
    let t = now();
    let offer = gate
        .issue(
            scope,
            &[
                (bnap_scheme_l402::SCHEME_ID, 21),
                (bnap_scheme_mpp::SCHEME_ID, 21),
            ],
            sha256(&t.to_be_bytes())[..16].try_into().unwrap(),
            t,
        )
        .await
        .expect("issue the offer");
    // Two challenges with a real regtest invoice fit in the default offer
    // size limit.
    assert!(offer.bytes().len() <= bnap_core::limits::MAX_OFFER);
    println!(
        "regtest: offer with both natives is {} bytes (limit {})",
        offer.bytes().len(),
        bnap_core::limits::MAX_OFFER
    );
    let native = |kind: &str| {
        let n = offer
            .fields()
            .native
            .iter()
            .find(|n| n.kind == kind)
            .unwrap();
        String::from_utf8(n.data.clone()).unwrap()
    };
    let l402_c = bnap_scheme_l402::Challenge::parse(&native("l402-macaroon")).unwrap();
    let mpp_c = bnap_scheme_mpp::Challenge::parse(&native("mpp-challenge")).unwrap();
    assert_eq!(
        ChargeRequest::decode(&mpp_c.request).unwrap().invoice,
        l402_c.invoice,
        "one invoice for the offer"
    );

    let preimage = payer_pays(&l402_c.invoice);
    let cred = |scheme: &str, body: String| {
        let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
        c.pay = Some(SchemePart::new(scheme, body.into_bytes()));
        c
    };
    let via_l402 = cred(
        bnap_scheme_l402::SCHEME_ID,
        Token::new(&l402_c.token, preimage).unwrap().to_string(),
    );
    let via_mpp = cred(
        bnap_scheme_mpp::SCHEME_ID,
        bnap_scheme_mpp::Credential::new(mpp_c, preimage).encode(),
    );

    let first = gate.handle(&via_l402, scope, t).await.expect("admitted");
    assert_eq!(first.fields().status, Status::Ok);
    assert_eq!(first.fields().charged, 21);
    assert!(!first.fields().replayed);
    first.verify_ack().unwrap();
    let spent = Err(Refused {
        code: ErrorCode::Spent,
        scheme_code: None,
    });
    assert_eq!(gate.handle(&via_mpp, scope, t + 1).await, spent);
    let again = gate
        .handle(&via_l402, scope, t + 2)
        .await
        .expect("replayed");
    assert!(again.fields().replayed);
    assert_eq!(again.fields().settled_at, t);
    assert_eq!(gate.handle(&via_mpp, scope, t + 3).await, spent);
    println!(
        "regtest: one payment, L402 admitted (charged {} sat), MPP SPENT, L402 replay replayed={}",
        first.fields().charged,
        again.fields().replayed
    );
}

#[tokio::test]
async fn an_lnd_rail_whose_invoices_outlive_the_offer_cannot_issue() {
    // An hour-long LND invoice in a five-minute offer could be paid after
    // the offer is STALE, and the payment kept: the gate fails closed.
    let mut long = lnd_config();
    long.expiry = 3_600;
    let lnd: Arc<dyn FundingRail> = Arc::new(LndRail::connect(&long).await.expect("connect"));
    let invoices: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(lnd.clone()));
    let l402 = Arc::new(L402::new(MacaroonKeys::new([0x41; 32]), invoices.clone()));
    let mpp = Arc::new(
        LightningCharge::new(
            ChallengeKeys::new([0x42; 32]).unwrap(),
            "api.example",
            Network::Regtest,
            invoices,
        )
        .unwrap(),
    );
    let gate = Gate::new(lnd, vec![l402, mpp]);
    let scope = Scope(sha256(b"POST https://api.example/v1/regtest-long"));
    let t = now();
    for scheme in [bnap_scheme_l402::SCHEME_ID, bnap_scheme_mpp::SCHEME_ID] {
        let nonce: [u8; 16] = sha256(scheme.as_bytes())[..16].try_into().unwrap();
        assert_eq!(
            gate.issue(scope, &[(scheme, 21)], nonce, t)
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unavailable,
            "{scheme}"
        );
    }
    println!("regtest: a 3600 s LND invoice in a {OFFER_LIFETIME} s offer is refused at issue");
}
