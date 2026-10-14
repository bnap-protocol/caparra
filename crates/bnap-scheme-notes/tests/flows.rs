//! Full flows of `bnap:notes` through bnap-core's `process`, the in-memory
//! use store, the keyset-holding test signer and a fake Lightning rail.

#![allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::field_reassign_with_default
)]

mod common;

use bnap_core::ErrorCode;
use bnap_core::hash::sha256;
use bnap_core::limits::Limits;
use bnap_core::response::Status;
use bnap_core::test_support::block_on;
use bnap_plug::CredentialScheme;
use bnap_scheme_notes::client::{self, Note};
use bnap_scheme_notes::codes;
use bnap_scheme_notes::issuer::IssuerStore;
use bnap_scheme_notes::keyset::{
    KeysetState, RotationPolicy, apply_rotation, plan_rotation, revoke,
};
use bnap_scheme_notes::test_support::{keyset_a, keyset_b, keyset_c, test_keyset};
use bnap_scheme_notes::wire::Body;
use bnap_scheme_notes::{MintEnv, MintError, Output, admission_cutoff};
use common::*;

fn a() -> [u8; 33] {
    id(&keyset_a())
}

#[test]
fn spend_with_change() {
    let g = Gate::new();
    let mut w = Wallet::new("change");
    // 64 + 32 on keyset A: two inputs at 100 ppk pay a 1 sat fee.
    let notes = w.notes(&keyset_a(), &[64, 32]);
    let offer = g.exact_offer(50, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(paid.value, 95);
    let resp = g.handle(&paid.credential, &Opts::default()).unwrap();
    let f = resp.fields();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Ok, 50, false));
    let got = change(&g, &paid, &resp);
    assert!(got.matches_rule);
    assert_eq!(total(&got.notes), 45);
    assert_eq!(g.signer.minted(), 45, "exactly value - charged was signed");
    // The change spends again: 45 sat in 32 + 8 + 4 + 1, fee 1 (4 inputs at
    // 100 ppk), for a 40 sat offer.
    let offer2 = g.exact_offer(40, NOW + 900);
    let paid2 = w.pay(&offer2, &got.notes, None, &a(), &Opts::default());
    assert_eq!(paid2.value, 44);
    let resp2 = g.handle(&paid2.credential, &Opts::default()).unwrap();
    assert_eq!(resp2.fields().charged, 40);
    assert_eq!(total(&change(&g, &paid2, &resp2).notes), 4);
}

#[test]
fn metered_spend_charges_the_meter() {
    let g = Gate::new();
    let mut w = Wallet::new("metered");
    // 2,048 on B (no fee) is below the 2,100 ceiling a metered admission
    // asks for (draft-00 7), so: UNDERPAID, nothing consumed.
    let short = w.notes(&keyset_b(), &[2048]);
    let offer = g.route_offer(2100, 500, NOW + 3600);
    let paid = w.pay(&offer, &short, None, &a(), &Opts::default());
    let e = g.handle(&paid.credential, &Opts::default()).unwrap_err();
    assert_eq!(e.code, ErrorCode::Underpaid);
    // 2,048 + 64 pays it. 850 tokens at 500 per 1,000 is 425 sat.
    let mut notes = short;
    notes.extend(w.notes(&keyset_b(), &[64]));
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(paid.value, 2112);
    let mut o = Opts::default();
    o.action_scope = act();
    o.units = 850;
    let resp = g.handle(&paid.credential, &o).unwrap();
    let f = resp.fields();
    assert_eq!((f.charged, f.metered_units), (425, Some(850)));
    let got = change(&g, &paid, &resp);
    assert!(got.matches_rule);
    assert_eq!(total(&got.notes), 2112 - 425);
    assert_eq!(g.signer.minted(), 1687);
}

#[test]
fn a_failed_action_refunds_the_whole_value() {
    let g = Gate::new();
    let mut w = Wallet::new("failed");
    let notes = w.notes(&keyset_a(), &[128]);
    let offer = g.exact_offer(100, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(paid.value, 127, "one input at 100 ppk pays 1 sat");
    let mut o = Opts::default();
    o.status = Status::Failed;
    let resp = g.handle(&paid.credential, &o).unwrap();
    let f = resp.fields();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    let got = change(&g, &paid, &resp);
    assert!(got.matches_rule);
    assert_eq!(
        total(&got.notes),
        127,
        "the input fee is kept on FAILED too"
    );
    // The notes stay spent.
    let again = w.pay(&offer, &notes, None, &a(), &Opts::default());
    let e = g.handle(&again.credential, &Opts::default()).unwrap_err();
    assert_eq!(e.code, ErrorCode::Spent);
}

#[test]
fn a_double_spend_is_spent_and_consumes_nothing_else() {
    let g = Gate::new();
    let mut w = Wallet::new("double");
    let notes = w.notes(&keyset_a(), &[64]);
    let fresh = w.notes(&keyset_a(), &[64]);
    let offer = g.exact_offer(10, NOW + 900);
    let first = w.pay(&offer, &notes, None, &a(), &Opts::default());
    g.handle(&first.credential, &Opts::default()).unwrap();
    // The same note with other outputs, and with a second, fresh note.
    let second = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(
        g.handle(&second.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Spent
    );
    let both: Vec<Note> = notes.iter().chain(&fresh).cloned().collect();
    let third = w.pay(&offer, &both, None, &a(), &Opts::default());
    assert_eq!(
        g.handle(&third.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Spent
    );
    // The fresh note was not consumed by the refused commit.
    let fourth = w.pay(&offer, &fresh, None, &a(), &Opts::default());
    g.handle(&fourth.credential, &Opts::default()).unwrap();
}

#[test]
fn concurrent_spends_of_one_note_admit_one_action() {
    let g = std::sync::Arc::new(Gate::new());
    let mut w = Wallet::new("race");
    let notes = w.notes(&keyset_a(), &[256]);
    let offer = g.exact_offer(10, NOW + 900);
    let creds: Vec<_> = (0..8)
        .map(|_| {
            w.pay(&offer, &notes, None, &a(), &Opts::default())
                .credential
        })
        .collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(creds.len()));
    let handles: Vec<_> = creds
        .into_iter()
        .map(|c| {
            let (g, b) = (g.clone(), barrier.clone());
            std::thread::spawn(move || {
                b.wait();
                g.handle(&c, &Opts::default())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| e.code == ErrorCode::Spent)
    );
    assert_eq!(g.signer.minted(), 255 - 10);
}

#[test]
fn an_overspend_is_underpaid_and_consumes_nothing() {
    let g = Gate::new();
    let mut w = Wallet::new("over");
    let notes = w.notes(&keyset_a(), &[32, 16]);
    let offer = g.exact_offer(48, NOW + 900);
    // 48 sat of notes pay 1 sat in fees: 47 < 48.
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(paid.value, 47);
    let e = g.handle(&paid.credential, &Opts::default()).unwrap_err();
    assert_eq!(e.code, ErrorCode::Underpaid);
    assert_eq!(g.signer.minted(), 0);
    // Nothing was consumed: the notes pay a cheaper offer.
    let cheaper = g.exact_offer(47, NOW + 900);
    let paid = w.pay(&cheaper, &notes, None, &a(), &Opts::default());
    assert_eq!(
        g.handle(&paid.credential, &Opts::default())
            .unwrap()
            .fields()
            .charged,
        47
    );
}

#[test]
fn change_is_never_more_than_value_minus_charged_minus_fees() {
    let g = Gate::new();
    let mut w = Wallet::new("bound");
    let mut minted = 0;
    for (amounts, price, metered_units) in [
        (vec![1u64, 2, 4, 8], 3u64, None),
        (vec![512, 256, 1], 600, None),
        (vec![1024], 1023, None),
        (vec![4096, 4096], 2100, Some(4000u64)),
        (vec![16; 1], 15, None),
    ] {
        let notes = w.notes(&keyset_a(), &amounts);
        let i: u64 = amounts.iter().sum();
        let fee = (100 * amounts.len() as u64).div_ceil(1000);
        let (offer, o) = match metered_units {
            None => (g.exact_offer(price, NOW + 900), Opts::default()),
            Some(u) => {
                let mut o = Opts::default();
                o.units = u;
                (g.route_offer(price, 500, NOW + 3600), o)
            }
        };
        let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
        assert_eq!(paid.value, i - fee);
        let resp = g.handle(&paid.credential, &o).unwrap();
        let charged = resp.fields().charged;
        let got = change(&g, &paid, &resp);
        assert_eq!(total(&got.notes), i - fee - charged);
        minted += i - fee - charged;
        assert_eq!(
            g.signer.minted(),
            minted,
            "the signer minted only the change"
        );
    }
}

#[test]
fn a_witness_over_another_digest_is_refused() {
    let g = Gate::new();
    let mut w = Wallet::new("digest");
    let notes = w.notes(&keyset_a(), &[64]);
    let offer = g.exact_offer(10, NOW + 900);
    // Signed for one connection, presented on another: the binding is in
    // the Digest.
    let mut bound = Opts::default();
    bound.binding = Some(sha256(b"tls-exporter one"));
    let mut paid = w.pay(&offer, &notes, None, &a(), &bound);
    paid.credential.binding = Some(sha256(b"tls-exporter two"));
    let mut other = Opts::default();
    other.binding = Some(sha256(b"tls-exporter two"));
    let e = g.handle(&paid.credential, &other).unwrap_err();
    assert_eq!(code(&e), notes_code(codes::BAD_SIGNATURE));
    // A witness made for one credential, moved to another with the same
    // notes and other outputs.
    let honest = w.pay(&offer, &notes, None, &a(), &Opts::default());
    let mut thief = w.pay(&offer, &notes, None, &a(), &Opts::default());
    thief.credential.pay.as_mut().unwrap().witness = honest.credential.pay.unwrap().witness;
    let e = g.handle(&thief.credential, &Opts::default()).unwrap_err();
    assert_eq!(code(&e), notes_code(codes::BAD_SIGNATURE));
    assert_eq!(g.signer.minted(), 0);
}

#[test]
fn a_wrong_keyset_is_refused() {
    let g = Gate::new();
    let mut w = Wallet::new("keyset");
    let offer = g.exact_offer(10, NOW + 900);
    // A keyset the signer could check but the offer does not list (C is
    // not in this gate's table).
    let foreign = keyset_c();
    g.signer.add_keyset(foreign.clone());
    let notes = w.notes(&foreign, &[64]);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(
        code(&g.handle(&paid.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::UNKNOWN_KEYSET)
    );
    // Outputs on B, which the offer lists without `active`.
    let notes = w.notes(&keyset_a(), &[64]);
    let paid = w.pay(&offer, &notes, None, &id(&keyset_b()), &Opts::default());
    assert_eq!(
        code(&g.handle(&paid.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::UNKNOWN_KEYSET)
    );
    // B revoked after the offer was made: its notes are refused at once.
    let b_notes = w.notes(&keyset_b(), &[64]);
    let mut b = keyset_b().info().clone();
    revoke(&mut b);
    block_on(g.issuer.put_keyset(&b)).unwrap();
    let paid = w.pay(&offer, &b_notes, None, &a(), &Opts::default());
    assert_eq!(
        code(&g.handle(&paid.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::UNKNOWN_KEYSET)
    );
    // A keyset past its final expiry plus 60 s of skew, in an offer that
    // still lists it (offers stop listing it 60 s before their own expiry,
    // so only an offer built by hand does).
    let g = Gate::new();
    let params = bnap_scheme_notes::Params::new(
        ISSUER,
        vec![keyset_a().info().entry(), keyset_b().info().entry()],
    );
    let mut f = bnap_core::OfferFields::new(act(), 1_800_000_900, g.signer.offer_key(), nonce(5));
    let mut e = bnap_core::PayEntry::new(bnap_scheme_notes::SCHEME_ID, 10, "sat");
    e.params = Some(params.to_bytes());
    f.pay = vec![e];
    let offer = g.sign(&f);
    let b_notes = w.notes(&keyset_b(), &[64]);
    let o = Opts::at(1_800_000_061);
    let paid = w.pay(&offer, &b_notes, None, &a(), &o);
    assert_eq!(
        code(&Refusal::from(
            g.verify_only(&paid.credential, &o)
                .unwrap_err()
                .to_error_object()
        )),
        notes_code(codes::UNKNOWN_KEYSET)
    );
    let o = Opts::at(1_800_000_060);
    g.verify_only(&paid.credential, &o).unwrap();
}

#[test]
fn a_forged_note_is_refused() {
    let g = Gate::new();
    let mut w = Wallet::new("forged");
    let mut notes = w.notes(&keyset_a(), &[64]);
    // Claim the 64-sat note is worth 128: C is checked with the 128 key.
    notes[0].amount = 128;
    let offer = g.exact_offer(100, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    assert_eq!(
        code(&g.handle(&paid.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::BAD_SIGNATURE)
    );
}

#[test]
fn a_replay_returns_the_recorded_change() {
    let g = Gate::new();
    let mut w = Wallet::new("replay");
    let notes = w.notes(&keyset_a(), &[256]);
    let offer = g.exact_offer(100, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    let first = g.handle(&paid.credential, &Opts::default()).unwrap();
    let again = g.handle(&paid.credential, &Opts::at(NOW + 30)).unwrap();
    assert!(again.fields().replayed);
    assert_eq!(again.fields().scheme_result, first.fields().scheme_result);
    assert_eq!(again.fields().settled_at, first.fields().settled_at);
    assert_eq!(g.signer.minted(), 155);
}

#[test]
fn a_crash_after_commit_refunds_on_replay() {
    let g = Gate::new();
    let mut w = Wallet::new("crash");
    let notes = w.notes(&keyset_a(), &[1024]);
    let offer = g.exact_offer(500, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    let mut o = Opts::default();
    o.crash_after_commit = true;
    assert_eq!(
        g.handle(&paid.credential, &o).unwrap_err().code,
        ErrorCode::Unavailable
    );
    // Still in flight.
    let e = g.handle(&paid.credential, &Opts::at(NOW + 10)).unwrap_err();
    assert_eq!(e.code, ErrorCode::Pending);
    // After the timeout the replay collects the whole value.
    let resp = g.handle(&paid.credential, &Opts::at(NOW + 301)).unwrap();
    let f = resp.fields();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Failed, 0, true));
    let got = change(&g, &paid, &resp);
    assert!(got.matches_rule);
    assert_eq!(total(&got.notes), 1023);
    assert_eq!(g.signer.minted(), 1023);
}

#[test]
fn an_action_that_outlives_the_timeout_refunds_the_whole_value() {
    // The sweep times the outcome out while the action runs: the OK settle
    // can reserve nothing, the gate settles FAILED, and the refund is the
    // 7.2 selection for the whole value.
    for (amounts, price) in [(vec![2048u64], 500u64), (vec![1024, 512, 128, 16], 340)] {
        let b = test_keyset("B", 0, 1_800_000_000, KeysetState::Active);
        let g = Gate::with_keysets(vec![keyset_a(), b.clone()]);
        let mut w = Wallet::new("slow");
        let notes = w.notes(&b, &amounts);
        let offer = g.exact_offer(price, NOW + 900);
        let paid = w.pay(&offer, &notes, None, &id(&b), &Opts::default());
        let mut o = Opts::default();
        o.slow_action = true;
        let resp = g.handle(&paid.credential, &o).unwrap();
        let f = resp.fields();
        assert_eq!((f.status, f.charged), (Status::Failed, 0));
        let got = change(&g, &paid, &resp);
        assert!(got.matches_rule);
        assert_eq!(total(&got.notes), paid.value);
        assert_eq!(g.signer.minted(), paid.value);
    }
}

#[test]
fn a_late_ok_settle_then_the_timeout_never_signs_more_than_the_value() {
    // The action settles OK after pending_timeout with no sweep: its change
    // was reserved and signed while the outcome was PENDING, then the
    // settle loses to the timeout. The refund re-signs that change and adds
    // what the other outputs can form, never more than the value.
    for (amounts, price, want) in [
        // 2,048 on the ladder 1..2,048: change 1,548 = 1,024 + 512 + 8 + 4,
        // and 500 more from 256, 128, 64, 32, 16, 2, 1 is 499.
        (vec![2048u64], 500u64, 1548 + 499),
        // 1,680 on the ladder 1..1,024: change 1,340, and 340 more from
        // 512, 128, 64, 2, 1 is 195 (ERRATA candidate N6-1).
        (vec![1024, 512, 128, 16], 340, 1340 + 195),
    ] {
        let b = test_keyset("B", 0, 1_800_000_000, KeysetState::Active);
        let g = Gate::with_keysets(vec![keyset_a(), b.clone()]);
        let mut w = Wallet::new("late");
        let notes = w.notes(&b, &amounts);
        let offer = g.exact_offer(price, NOW + 900);
        let paid = w.pay(&offer, &notes, None, &id(&b), &Opts::default());
        let mut o = Opts::default();
        o.late_settle = true;
        let resp = g.handle(&paid.credential, &o).unwrap();
        let f = resp.fields();
        assert_eq!((f.status, f.charged), (Status::Failed, 0));
        let got = change(&g, &paid, &resp);
        assert!(
            !got.matches_rule,
            "the refund is not the plain 7.2 selection"
        );
        assert_eq!(total(&got.notes), want);
        assert!(want <= paid.value);
        assert_eq!(
            g.signer.minted(),
            want,
            "what was minted is what the client got"
        );
        // A replay gets the same recorded refund.
        let again = g.handle(&paid.credential, &Opts::at(NOW + 400)).unwrap();
        assert_eq!(again.fields().scheme_result, f.scheme_result);
        assert_eq!(g.signer.minted(), want);
    }
}

#[test]
fn the_admission_cutoff_refuses_new_credentials_but_serves_replays() {
    let g = Gate::new();
    let mut w = Wallet::new("cutoff");
    let expires = NOW + 600;
    let cutoff = admission_cutoff(expires, g.limits.pending_timeout);
    assert_eq!(cutoff, NOW + 240);
    let offer = g.exact_offer(10, expires);
    let n1 = w.notes(&keyset_a(), &[64]);
    let early = w.pay(&offer, &n1, None, &a(), &Opts::default());
    g.handle(&early.credential, &Opts::at(cutoff)).unwrap();
    let n2 = w.notes(&keyset_a(), &[64]);
    let late = w.pay(&offer, &n2, None, &a(), &Opts::default());
    let e = g
        .handle(&late.credential, &Opts::at(cutoff + 1))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Stale);
    assert_eq!(g.signer.minted(), 53, "nothing for the late one");
    // The late credential consumed nothing: its notes pay a fresh offer.
    // The early one still replays up to the deadline plus skew.
    let r = g
        .handle(&early.credential, &Opts::at(expires + 60))
        .unwrap();
    assert!(r.fields().replayed);
}

#[test]
fn offers_leave_notes_out_when_the_cutoff_is_too_close() {
    let g = Gate::new();
    // expires - 300 - 60 must be at least now + 60.
    let cx = |expires| bnap_plug::OfferCtx {
        now: NOW,
        route_id: "chat",
        scope: &bnap_core::Scope([0; 32]),
        route_scope: false,
        metered: false,
        expires,
        role: bnap_plug::OfferRole::Pay {
            amount: 1,
            unit: "sat",
        },
    };
    assert!(block_on(g.scheme.offer(&cx(NOW + 419))).is_err());
    assert!(block_on(g.scheme.offer(&cx(NOW + 420))).is_ok());
}

#[test]
fn funding_inside_the_402_in_one_round_trip() {
    let g = Gate::new();
    let mut w = Wallet::new("fund");
    let quote_key = sha256(b"wallet quote key 1");
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    // The 402 carries an exact-scope offer with a quote for 2,100 sat.
    let (offer, q) = g.funded_offer(1000, 2100, pubkey);
    assert_eq!(q.amount, 2100);
    // The client checks the quote, saves it, and pays.
    client::check_fund_quote(&q, &pubkey, 2100, NOW).unwrap();
    assert!(client::check_fund_quote(&q, &pubkey, 2000, NOW).is_err());
    let hash = client::invoice_payment_hash(&q).unwrap();
    // Unpaid: QUOTE_UNPAID, nothing consumed.
    let paid = w.pay(&offer, &[], Some((&q, &quote_key)), &a(), &Opts::default());
    assert_eq!(
        code(&g.handle(&paid.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::QUOTE_UNPAID)
    );
    g.rail.pay(&hash);
    let resp = g.handle(&paid.credential, &Opts::default()).unwrap();
    assert_eq!(resp.fields().charged, 1000);
    let got = change(&g, &paid, &resp);
    assert_eq!(total(&got.notes), 1100);
    let state = block_on(g.scheme.quote_state(&q.quote)).unwrap().unwrap();
    assert!(state.paid && state.issued);
    // The quote cannot be redeemed again, nor minted.
    let again = w.pay(&offer, &[], Some((&q, &quote_key)), &a(), &Opts::default());
    assert_eq!(
        g.handle(&again.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Spent
    );
    let outs = w.outputs(&a(), &[2048, 32, 16, 4]);
    let req = client::mint_request(
        &q.quote,
        &outs.iter().map(|p| p.output).collect::<Vec<_>>(),
        &quote_key,
    )
    .unwrap();
    assert_eq!(
        block_on(g.scheme.mint(&mint_env(&g, NOW), &req)),
        Err(MintError::Issued)
    );
    // Change from funding spends like any note.
    let next = g.exact_offer(100, NOW + 900);
    let paid = w.pay(&next, &got.notes, None, &a(), &Opts::default());
    g.handle(&paid.credential, &Opts::default()).unwrap();
}

#[test]
fn a_funded_credential_with_notes_adds_both_and_signs_both() {
    let g = Gate::new();
    let mut w = Wallet::new("fund-notes");
    let quote_key = sha256(b"wallet quote key 2");
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    let (offer, q) = g.funded_offer(300, 200, pubkey);
    g.rail.pay(&client::invoice_payment_hash(&q).unwrap());
    let notes = w.notes(&keyset_a(), &[128]);
    let paid = w.pay(
        &offer,
        &notes,
        Some((&q, &quote_key)),
        &a(),
        &Opts::default(),
    );
    // 128 - 1 fee + 200 (the fund pays no fee).
    assert_eq!(paid.value, 327);
    // fund_sig by another key.
    let mut bad = paid.credential.clone();
    let (body, ordered) = {
        let b = Body::parse(&bad.pay.as_ref().unwrap().body).unwrap();
        (b, paid.notes.clone())
    };
    let ctx = bad.context(&offer.offer_id(), &act());
    let digest = bad.digest(&ctx);
    let wit = client::sign_witness(
        &body,
        &ordered,
        Some(&sha256(b"not the quote key")),
        &digest,
        &AUX0,
    )
    .unwrap();
    bad.pay.as_mut().unwrap().witness = wit.to_bytes();
    assert_eq!(
        code(&g.handle(&bad, &Opts::default()).unwrap_err()),
        notes_code(codes::BAD_SIGNATURE)
    );
    let resp = g.handle(&paid.credential, &Opts::default()).unwrap();
    assert_eq!(total(&change(&g, &paid, &resp).notes), 27);
}

#[test]
fn an_unlinkable_route_refuses_funded_credentials_and_offers_no_quote() {
    let g = Gate::new();
    let mut w = Wallet::new("unlinkable");
    let quote_key = sha256(b"wallet quote key 3");
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    let (offer, q) = g.funded_offer(100, 500, pubkey);
    g.rail.pay(&client::invoice_payment_hash(&q).unwrap());
    let paid = w.pay(&offer, &[], Some((&q, &quote_key)), &a(), &Opts::default());
    let mut o = Opts::default();
    o.unlinkable = true;
    assert_eq!(
        g.handle(&paid.credential, &o).unwrap_err().code,
        ErrorCode::Policy
    );
    // Nothing consumed: the quote still mints.
    let outs = w.outputs(&a(), &[256, 128, 64, 32, 16, 4]);
    let req = client::mint_request(
        &q.quote,
        &outs.iter().map(|p| p.output).collect::<Vec<_>>(),
        &quote_key,
    )
    .unwrap();
    block_on(g.scheme.mint(&mint_env(&g, NOW), &req)).unwrap();
    // No quote on such a route.
    let none = block_on(g.scheme.create_fund_quote(
        &bnap_scheme_notes::FundRequest {
            amount: 500,
            pubkey,
        },
        "private",
        &nonce(99),
        NOW,
    ))
    .unwrap();
    assert_eq!(none, None);
}

fn mint_env(g: &Gate, now: u64) -> MintEnv<'static> {
    static LIMITS: std::sync::LazyLock<Limits> = std::sync::LazyLock::new(Limits::default);
    MintEnv {
        store: g.store.clone(),
        signer: g.signer.clone(),
        limits: &LIMITS,
        now,
    }
}

#[test]
fn a_paid_quote_mints_through_nut_04_once() {
    let g = Gate::new();
    let mut w = Wallet::new("mint");
    let quote_key = sha256(b"wallet quote key 4");
    let pubkey = client::quote_pubkey(&quote_key).unwrap();
    let q = block_on(g.scheme.create_fund_quote(
        &bnap_scheme_notes::FundRequest {
            amount: 100,
            pubkey,
        },
        "chat",
        &nonce(1),
        NOW,
    ))
    .unwrap()
    .unwrap();
    // The same nonce gives the same quote, never a second invoice.
    let same = block_on(g.scheme.create_fund_quote(
        &bnap_scheme_notes::FundRequest {
            amount: 100,
            pubkey,
        },
        "chat",
        &nonce(1),
        NOW,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(same, q);
    let outs = w.outputs(&a(), &[64, 32, 4]);
    let outputs: Vec<Output> = outs.iter().map(|p| p.output).collect();
    let req = client::mint_request(&q.quote, &outputs, &quote_key).unwrap();
    let env = mint_env(&g, NOW);
    assert_eq!(block_on(g.scheme.mint(&env, &req)), Err(MintError::Unpaid));
    g.rail.pay(&client::invoice_payment_hash(&q).unwrap());
    // A request signed by another key, or for other amounts, is refused.
    let forged = client::mint_request(&q.quote, &outputs, &sha256(b"other key")).unwrap();
    assert_eq!(
        block_on(g.scheme.mint(&env, &forged)),
        Err(MintError::BadSignature)
    );
    let short = w.outputs(&a(), &[64, 32]);
    let short = client::mint_request(
        &q.quote,
        &short.iter().map(|p| p.output).collect::<Vec<_>>(),
        &quote_key,
    )
    .unwrap();
    assert!(matches!(
        block_on(g.scheme.mint(&env, &short)),
        Err(MintError::BadOutputs(_))
    ));
    let sigs = block_on(g.scheme.mint(&env, &req)).unwrap();
    let keys = g.keys();
    let notes = client::unblind_mint(&outs, &sigs, client::key_lookup(&keys)).unwrap();
    assert_eq!(total(&notes), 100);
    assert_eq!(g.signer.minted(), 100);
    // A retry gets the same signatures and mints nothing new.
    assert_eq!(
        block_on(g.scheme.mint(&mint_env(&g, NOW + 5), &req)).unwrap(),
        sigs
    );
    assert_eq!(g.signer.minted(), 100);
    // Other outputs for the same quote: issued.
    let other = w.outputs(&a(), &[64, 32, 4]);
    let other = client::mint_request(
        &q.quote,
        &other.iter().map(|p| p.output).collect::<Vec<_>>(),
        &quote_key,
    )
    .unwrap();
    assert_eq!(
        block_on(g.scheme.mint(&env, &other)),
        Err(MintError::Issued)
    );
    // A credential redeeming the minted quote: SPENT at commit.
    let offer = g.exact_offer(10, NOW + 900);
    let fq = bnap_scheme_notes::FundQuote {
        quote: q.quote.clone(),
        ..q.clone()
    };
    let paid = w.pay(&offer, &[], Some((&fq, &quote_key)), &a(), &Opts::default());
    assert_eq!(
        g.handle(&paid.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Spent
    );
    // The minted notes spend.
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    g.handle(&paid.credential, &Opts::default()).unwrap();
    // An output signed before under another source is refused by a mint.
    let q2 = block_on(g.scheme.create_fund_quote(
        &bnap_scheme_notes::FundRequest {
            amount: 100,
            pubkey,
        },
        "chat",
        &nonce(2),
        NOW,
    ))
    .unwrap()
    .unwrap();
    g.rail.pay(&client::invoice_payment_hash(&q2).unwrap());
    let reused = client::mint_request(&q2.quote, &outputs, &quote_key).unwrap();
    assert_eq!(
        block_on(g.scheme.mint(&env, &reused)),
        Err(MintError::OutputSigned)
    );
}

#[test]
fn a_reused_output_is_signed_again_with_the_same_proof() {
    let g = Gate::new();
    let mut w = Wallet::new("reuse");
    let offer = g.exact_offer(10, NOW + 900);
    let n1 = w.notes(&keyset_a(), &[64]);
    let first = w.pay(&offer, &n1, None, &a(), &Opts::default());
    let r1 = g.handle(&first.credential, &Opts::default()).unwrap();
    // A second credential reuses the first one's outputs (a broken wallet,
    // or a front-runner copying them).
    let n2 = w.notes(&keyset_a(), &[64]);
    let outs: Vec<Output> = first.outputs.iter().map(|p| p.output).collect();
    let second = w.build(
        &offer,
        &n2,
        &outs,
        None,
        &Opts::default(),
        first.outputs.clone(),
        63,
    );
    g.verify_only(&second.credential, &Opts::default()).unwrap();
    let r2 = g.handle(&second.credential, &Opts::default()).unwrap();
    assert_eq!(
        r1.fields().scheme_result,
        r2.fields().scheme_result,
        "same C' and DLEQ"
    );
    // Two records, one per source.
    let records = g.issuer.all_outputs();
    let b = first.outputs[0].output.blinded;
    assert_eq!(records.iter().filter(|r| r.blinded == b).count(), 2);
    // And NUT-09 restore answers for it.
    let restored = block_on(g.scheme.restore(&outs)).unwrap();
    let amounts: Vec<u64> = outs.iter().map(|o| o.amount).collect();
    let signed = bnap_scheme_notes::amount::select(&amounts, 53).unwrap();
    assert_eq!(restored.len(), signed.len());
}

#[test]
fn outages_fail_closed() {
    let g = Gate::new();
    let mut w = Wallet::new("outage");
    let notes = w.notes(&keyset_a(), &[64]);
    let offer = g.exact_offer(10, NOW + 900);
    let paid = w.pay(&offer, &notes, None, &a(), &Opts::default());
    g.issuer.set_unavailable(true);
    assert_eq!(
        g.handle(&paid.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
    g.issuer.set_unavailable(false);
    g.store.set_unavailable(true);
    assert_eq!(
        g.handle(&paid.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
    g.store.set_unavailable(false);
    // A funded credential while the rail is down.
    let quote_key = sha256(b"wallet quote key 5");
    let (offer, q) = g.funded_offer(10, 100, client::quote_pubkey(&quote_key).unwrap());
    let funded = w.pay(&offer, &[], Some((&q, &quote_key)), &a(), &Opts::default());
    g.rail.set_down(true);
    assert_eq!(
        g.handle(&funded.credential, &Opts::default())
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
    g.rail.set_down(false);
    g.handle(&paid.credential, &Opts::default()).unwrap();
}

#[test]
fn keyset_rotation_keeps_old_notes_spendable() {
    let a_ks = keyset_a();
    let mut d = test_keyset("D", 100, 1_840_000_000, KeysetState::Standby);
    d.info_mut().published_at = NOW - 31 * 86_400;
    let mut a_info = a_ks.info().clone();
    a_info.activated_at = Some(NOW - 92 * 86_400);
    let g = Gate::with_keysets(vec![a_ks.clone(), keyset_b(), d.clone()]);
    block_on(g.issuer.put_keyset(&a_info)).unwrap();
    let mut table = block_on(g.issuer.keysets()).unwrap();
    let plan = plan_rotation(&table, NOW, &RotationPolicy::default());
    assert_eq!(plan.activate, Some(id(&d)));
    assert_eq!(plan.retire, vec![id(&a_ks)]);
    assert!(plan.needs_standby);
    apply_rotation(&mut table, &plan, NOW);
    for k in &table {
        block_on(g.issuer.put_keyset(k)).unwrap();
    }
    let mut w = Wallet::new("rotate");
    let old = w.notes(&a_ks, &[64]);
    let offer = g.exact_offer(10, NOW + 900);
    // Outputs on A are refused now, on D accepted; A's notes still pay.
    let on_a = w.pay(&offer, &old, None, &a(), &Opts::default());
    assert_eq!(
        code(&g.handle(&on_a.credential, &Opts::default()).unwrap_err()),
        notes_code(codes::UNKNOWN_KEYSET)
    );
    let on_d = w.pay(&offer, &old, None, &id(&d), &Opts::default());
    let resp = g.handle(&on_d.credential, &Opts::default()).unwrap();
    assert_eq!(total(&change(&g, &on_d, &resp).notes), 53);
}

#[test]
fn a_wallet_picks_notes_for_a_price() {
    let mut w = Wallet::new("select");
    let notes = w.notes(&keyset_a(), &[1, 2, 8, 64, 512]);
    let fee = |_: &[u8; 33]| Some(100);
    // One note pays 60: 64 - 1.
    let s = client::select_notes(&notes, fee, 60, 16).unwrap();
    assert_eq!((s.notes, s.value), (vec![3], 63));
    // 570 needs 512 + 64: 576 - 1.
    let s = client::select_notes(&notes, fee, 570, 16).unwrap();
    assert_eq!(s.value, 575);
    assert!(client::select_notes(&notes, fee, 600, 16).is_none());
    assert!(client::select_notes(&notes, fee, 570, 1).is_none());
}
