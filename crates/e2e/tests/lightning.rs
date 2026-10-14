//! One Lightning payment, two schemes: L402 and `payment:lightning/charge`
//! through bnap-core's `process`, against the fake Lightning rail. No
//! Docker needed.
//!
//! The offer carries both schemes and one invoice (`OfferInvoices`), so
//! the same preimage answers both native challenges. The payment's `ln`
//! `RailId` is the same whichever scheme presents it, so it admits exactly
//! one action (draft-00 6.1).

use std::sync::Arc;

use bnap_core::credential::{OfferRef, SchemePart};
use bnap_core::hash::{Scope, sha256};
use bnap_core::ids::{rail, rail_id};
use bnap_core::response::{Response, Status};
use bnap_core::store::UseTable;
use bnap_core::test_support::block_on;
use bnap_core::{Credential, ErrorCode, Offer};
use bnap_plug::FundingRail;
use bnap_rail_fake::FakeRail;
use bnap_scheme_l402::{L402, MacaroonKeys, OfferInvoices, Token};
use bnap_scheme_mpp::{ChallengeKeys, ChargeRequest, LightningCharge, Network};
use e2e::{Gate, Refused};

const NOW: u64 = 1_791_700_000;
const L402_ID: &str = bnap_scheme_l402::SCHEME_ID;
const MPP_ID: &str = bnap_scheme_mpp::SCHEME_ID;

struct World {
    fake: Arc<FakeRail>,
    gate: Gate,
    scope: Scope,
}

fn world() -> World {
    let fake = Arc::new(FakeRail::new([0x11; 32]));
    fake.set_now(NOW);
    // One invoice per offer, shared by both schemes.
    let invoices: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(fake.clone()));
    let l402 = Arc::new(L402::new(MacaroonKeys::new([0x21; 32]), invoices.clone()));
    let mpp = Arc::new(
        LightningCharge::new(
            ChallengeKeys::new([0x22; 32]).unwrap(),
            "api.example",
            Network::Regtest,
            invoices,
        )
        .unwrap(),
    );
    World {
        gate: Gate::new(fake.clone(), vec![l402, mpp]),
        fake,
        scope: Scope(sha256(b"POST https://api.example/v1/thing")),
    }
}

/// What a client reads off the 402: both native challenges.
struct Natives {
    l402: bnap_scheme_l402::Challenge,
    mpp: bnap_scheme_mpp::Challenge,
    payment_hash: [u8; 32],
}

impl World {
    fn offer(&self, nonce: u8, amount: u64) -> Offer {
        block_on(self.gate.issue(
            self.scope,
            &[(L402_ID, amount), (MPP_ID, amount)],
            [nonce; 16],
            NOW,
        ))
        .unwrap()
    }

    fn natives(offer: &Offer) -> Natives {
        let data = |kind: &str| {
            let n = offer
                .fields()
                .native
                .iter()
                .find(|n| n.kind == kind)
                .unwrap();
            String::from_utf8(n.data.clone()).unwrap()
        };
        let l402 = bnap_scheme_l402::Challenge::parse(&data("l402-macaroon")).unwrap();
        let mpp = bnap_scheme_mpp::Challenge::parse(&data("mpp-challenge")).unwrap();
        let req = ChargeRequest::decode(&mpp.request).unwrap();
        // One invoice answers both challenges.
        assert_eq!(l402.invoice, req.invoice);
        Natives {
            l402,
            mpp,
            payment_hash: req.payment_hash,
        }
    }

    /// The client pays the offer's one invoice and learns the preimage.
    fn pay(&self, n: &Natives) -> [u8; 32] {
        self.fake.pay(&n.payment_hash).unwrap()
    }

    fn handle(&self, cred: &Credential, now: u64) -> Result<Response, Refused> {
        block_on(self.gate.handle(cred, self.scope, now))
    }

    fn handle_native(&self, scheme: &str, native: &str, now: u64) -> Result<Response, Refused> {
        block_on(
            self.gate
                .handle_native(scheme, native.as_bytes(), self.scope, now),
        )
    }

    /// Outcome records and whether the payment's `RailId` is used.
    fn ledger(&self, payment_hash: &[u8; 32]) -> (usize, bool) {
        let id = rail_id(rail::LN, payment_hash);
        self.gate
            .store()
            .inspect(|t| (t.outcome_keys().len(), t.is_used(&id.0)))
    }
}

/// A BNAP Credential naming `offer` by ID, with `body` as its pay part.
fn credential(offer: &Offer, scheme: &str, body: &str) -> Credential {
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(scheme, body.as_bytes().to_vec()));
    c
}

fn l402_body(n: &Natives, preimage: [u8; 32]) -> String {
    Token::new(&n.l402.token, preimage).unwrap().to_string()
}

fn mpp_body(n: &Natives, preimage: [u8; 32]) -> String {
    bnap_scheme_mpp::Credential::new(n.mpp.clone(), preimage).encode()
}

fn spent() -> Result<Response, Refused> {
    Err(Refused {
        code: ErrorCode::Spent,
        scheme_code: None,
    })
}

fn ok(r: &Response, charged: u64, settled_at: u64, replayed: bool) {
    let f = r.fields();
    assert_eq!(f.status, Status::Ok);
    assert_eq!(f.charged, charged);
    assert_eq!(f.unit.as_deref(), Some("sat"));
    assert_eq!(f.settled_at, settled_at);
    assert_eq!(f.replayed, replayed);
    r.verify_ack().unwrap();
}

#[test]
fn one_payment_through_l402_then_mpp_admits_one_action() {
    let w = world();
    let offer = w.offer(1, 21);
    assert_eq!(w.fake.invoice_count(), 1, "one invoice per offer");
    let n = World::natives(&offer);
    let preimage = w.pay(&n);
    let via_l402 = credential(&offer, L402_ID, &l402_body(&n, preimage));
    let via_mpp = credential(&offer, MPP_ID, &mpp_body(&n, preimage));

    // L402 first: committed, settled OK, charged the entry's 21 sat.
    let first = w.handle(&via_l402, NOW).unwrap();
    ok(&first, 21, NOW, false);
    assert_eq!(first.fields().offer_id, offer.offer_id());
    assert_eq!(first.fields().receipt_key, w.gate.receipt_key());
    assert_eq!(first.fields().scheme_result, None);
    assert_eq!(w.ledger(&n.payment_hash), (1, true));

    // The same payment through payment:lightning/charge: its own UseId is
    // new, but the RailId is the same, so it is SPENT and commits nothing.
    assert_eq!(w.handle(&via_mpp, NOW + 1), spent());
    assert_eq!(w.ledger(&n.payment_hash), (1, true));

    // Each again. The L402 credential is a replay: the recorded outcome,
    // signed afresh with replayed, the original settled_at and charge.
    let again = w.handle(&via_l402, NOW + 2).unwrap();
    ok(&again, 21, NOW, true);
    assert_eq!(again.fields().digest, first.fields().digest);
    // The MPP credential has no outcome of its own: still SPENT.
    assert_eq!(w.handle(&via_mpp, NOW + 3), spent());
    assert_eq!(w.ledger(&n.payment_hash), (1, true));
}

#[test]
fn one_payment_through_mpp_then_l402_admits_one_action() {
    let w = world();
    let offer = w.offer(1, 21);
    let n = World::natives(&offer);
    let preimage = w.pay(&n);
    let via_l402 = credential(&offer, L402_ID, &l402_body(&n, preimage));
    let via_mpp = credential(&offer, MPP_ID, &mpp_body(&n, preimage));

    let first = w.handle(&via_mpp, NOW).unwrap();
    ok(&first, 21, NOW, false);
    // MPP's own receipt is the scheme_result, naming the payment hash.
    let receipt = bnap_scheme_mpp::Receipt {
        challenge_id: n.mpp.id.clone(),
        payment_hash: n.payment_hash,
        timestamp: NOW,
    };
    assert_eq!(
        first.fields().scheme_result.as_deref(),
        Some(receipt.encode().as_bytes())
    );

    assert_eq!(w.handle(&via_l402, NOW + 1), spent());
    let again = w.handle(&via_mpp, NOW + 2).unwrap();
    ok(&again, 21, NOW, true);
    assert_eq!(again.fields().scheme_result, first.fields().scheme_result);
    assert_eq!(w.handle(&via_l402, NOW + 3), spent());
    assert_eq!(w.ledger(&n.payment_hash), (1, true));
}

#[test]
fn native_credentials_go_through_the_synthetic_envelope() {
    let w = world();
    let offer = w.offer(1, 21);
    let n = World::natives(&offer);
    let preimage = w.pay(&n);

    // A client that speaks only L402 sends `Authorization: L402 …`.
    let header = bnap_scheme_l402::authorization(&Token::new(&n.l402.token, preimage).unwrap());
    let native = bnap_scheme_l402::credential_from_authorization(&header).unwrap();
    let first = w.handle_native(L402_ID, native, NOW).unwrap();
    ok(&first, 21, NOW, false);
    // The receipt answers the native envelope's Digest (5.4).
    let ctx = bnap_core::credential::native_context(&offer.offer_id(), &w.scope, L402_ID);
    assert_eq!(
        first.fields().digest,
        bnap_core::credential::native_digest(&ctx, native.as_bytes())
    );
    // Its replay is answered from the record.
    ok(
        &w.handle_native(L402_ID, native, NOW + 1).unwrap(),
        21,
        NOW,
        true,
    );

    // The same payment natively through MPP, or as a BNAP credential under
    // either scheme (another Context, so another ReplayKey): SPENT.
    let mpp_token = mpp_body(&n, preimage);
    let mpp_header = bnap_scheme_mpp::authorization(&mpp_token);
    let mpp_native = bnap_scheme_mpp::credential_from_authorization(&mpp_header).unwrap();
    assert_eq!(w.handle_native(MPP_ID, mpp_native, NOW + 2), spent());
    let via_l402 = credential(&offer, L402_ID, native);
    assert_eq!(w.handle(&via_l402, NOW + 3), spent());
    assert_eq!(
        w.handle(&credential(&offer, MPP_ID, &mpp_token), NOW + 4),
        spent()
    );
    assert_eq!(w.ledger(&n.payment_hash), (1, true));
}

#[test]
fn an_underpaid_invoice_is_refused_and_consumes_nothing() {
    let w = world();
    let offer = w.offer(1, 21);
    let n = World::natives(&offer);
    // The rail saw 20 of the 21 sat: the scheme's claim of 21 counts only
    // up to what the rail confirmed.
    let preimage = w.fake.pay_amount(&n.payment_hash, 20).unwrap();
    for cred in [
        credential(&offer, L402_ID, &l402_body(&n, preimage)),
        credential(&offer, MPP_ID, &mpp_body(&n, preimage)),
    ] {
        let e = w.handle(&cred, NOW).unwrap_err();
        assert_eq!(e.code, ErrorCode::Underpaid);
    }
    assert_eq!(
        w.ledger(&n.payment_hash),
        (0, false),
        "an abort consumes nothing"
    );

    // Once the rail reports the full amount, the same credential admits.
    w.fake.pay_amount(&n.payment_hash, 21).unwrap();
    let cred = credential(&offer, MPP_ID, &mpp_body(&n, preimage));
    ok(&w.handle(&cred, NOW + 1).unwrap(), 21, NOW + 1, false);
}

#[test]
fn an_offer_id_mismatch_is_refused() {
    let w = world();
    let a = w.offer(1, 21);
    let b = w.offer(2, 21);
    assert_eq!(w.fake.invoice_count(), 2);
    let na = World::natives(&a);
    let preimage = w.pay(&na);

    // Offer A's paid artifacts, presented in a credential that names offer
    // B (valid, issued by this gate, same price and scope).
    let cases = [
        (
            L402_ID,
            l402_body(&na, preimage),
            "httpauth:L402/OFFER_MISMATCH",
        ),
        (
            MPP_ID,
            mpp_body(&na, preimage),
            "payment:lightning/charge/OFFER_MISMATCH",
        ),
    ];
    for (scheme, body, code) in &cases {
        let e = w.handle(&credential(&b, scheme, body), NOW).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadCredential);
        assert_eq!(e.scheme_code.as_deref(), Some(*code));
    }
    assert_eq!(w.ledger(&na.payment_hash), (0, false));

    // Under the offer they were issued for, they work (once).
    ok(
        &w.handle(&credential(&a, cases[0].0, &cases[0].1), NOW)
            .unwrap(),
        21,
        NOW,
        false,
    );
    assert_eq!(
        w.handle(&credential(&a, cases[1].0, &cases[1].1), NOW),
        spent()
    );
}

#[test]
fn an_unpaid_invoice_or_a_wrong_preimage_never_reaches_commit() {
    let w = world();
    let offer = w.offer(1, 21);
    let n = World::natives(&offer);
    // The right preimage, read off the rail, but the invoice is unpaid: the
    // rail does not confirm it.
    let preimage = w.fake.invoice(&n.payment_hash).unwrap().preimage;
    let e = w
        .handle(&credential(&offer, L402_ID, &l402_body(&n, preimage)), NOW)
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::BadCredential);
    // A preimage that does not hash to the payment hash.
    w.pay(&n);
    for (scheme, body) in [
        (L402_ID, l402_body(&n, [0; 32])),
        (MPP_ID, mpp_body(&n, [0; 32])),
    ] {
        let e = w
            .handle(&credential(&offer, scheme, &body), NOW)
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::BadCredential);
    }
    assert_eq!(w.ledger(&n.payment_hash), (0, false));
}

#[test]
fn a_rail_outage_fails_closed() {
    let w = world();
    let offer = w.offer(1, 21);
    let n = World::natives(&offer);
    let preimage = w.pay(&n);
    w.fake.set_unavailable(true);
    let cred = credential(&offer, L402_ID, &l402_body(&n, preimage));
    assert_eq!(
        w.handle(&cred, NOW).unwrap_err().code,
        ErrorCode::Unavailable
    );
    w.fake.set_unavailable(false);
    ok(&w.handle(&cred, NOW).unwrap(), 21, NOW, false);
}
