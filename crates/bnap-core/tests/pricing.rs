//! Pricing table tests (draft-00 section 7).

use bnap_core::class::BindingClass;
use bnap_core::hash::{CounterKey, Scope};
use bnap_core::ids::use_id;
use bnap_core::offer::{AttestEntry, Effect, OfferFields, PayEntry};
use bnap_core::pricing::{
    AdmitInput, PayValue, PriceError, VerifiedAttest, admit, decide, metered_entry_allowed,
    quota_candidates,
};
use bnap_core::response::Status;
use bnap_core::schnorr::Key;
use proptest::prelude::*;

const NOW: u64 = 1_791_700_000;

fn offer(amount: u64, attest: Vec<AttestEntry>) -> OfferFields {
    let mut o = OfferFields::new(Scope([1; 32]), NOW + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", amount, "sat"));
    o.attest = attest;
    o
}

fn att(scheme: &str, class: BindingClass) -> VerifiedAttest {
    VerifiedAttest::new(scheme, class)
}

fn empty(_: &CounterKey) -> u64 {
    0
}

fn price(o: &OfferFields, verified: &[VerifiedAttest]) -> u64 {
    decide(o, verified, o.pay[0].amount, NOW, empty).price(o.pay[0].amount)
}

/// Section 7, as a table: offer attestations, which verified, and the price.
#[test]
fn price_table() {
    use BindingClass::{A, None as Bearer, O, S};
    let d = |s: &str, bp| AttestEntry::discount(s, bp);
    let w = |s: &str| AttestEntry::new(s, Effect::Waive);
    let rows: Vec<(&str, u64, Vec<AttestEntry>, Vec<VerifiedAttest>, u64)> = vec![
        ("no attestations", 10_000, vec![], vec![], 10_000),
        (
            "one 20% discount",
            10_000,
            vec![d("a", 2000)],
            vec![att("a", S)],
            8_000,
        ),
        (
            "two 20% discounts give 36% off, not 40%",
            10_000,
            vec![d("a", 2000), d("b", 2000)],
            vec![att("a", S), att("b", A)],
            6_400,
        ),
        (
            "an unverified discount has no effect",
            10_000,
            vec![d("a", 2000), d("b", 2000)],
            vec![att("a", S)],
            8_000,
        ),
        (
            "waive beats a discount listed before it",
            10_000,
            vec![d("a", 2000), w("b")],
            vec![att("a", S), att("b", O)],
            0,
        ),
        (
            "waive beats a discount listed after it",
            10_000,
            vec![w("b"), d("a", 2000)],
            vec![att("a", S), att("b", A)],
            0,
        ),
        (
            "a bearer attestation cannot discount",
            10_000,
            vec![d("bearer", 5000)],
            vec![att("bearer", Bearer)],
            10_000,
        ),
        (
            "a bearer attestation cannot waive",
            10_000,
            vec![w("bearer")],
            vec![att("bearer", Bearer)],
            10_000,
        ),
        (
            "class O may discount",
            10_000,
            vec![d("o", 5000)],
            vec![att("o", O)],
            5_000,
        ),
        (
            "rounding takes off the floor: 999 at 20% is 800",
            999,
            vec![d("a", 2000)],
            vec![att("a", S)],
            800,
        ),
        (
            "a 100% discount is free",
            21,
            vec![d("a", 10_000)],
            vec![att("a", S)],
            0,
        ),
        (
            "the 10.3 example: 2,100 sat ceiling, 20% Web Bot Auth",
            2_100,
            vec![d("httpsig:web-bot-auth", 2000)],
            vec![att("httpsig:web-bot-auth", A)],
            1_680,
        ),
    ];
    for (name, amount, attest, verified, want) in rows {
        let o = offer(amount, attest);
        assert_eq!(price(&o, &verified), want, "{name}");
    }
}

#[test]
fn ignored_price_effects_are_reported() {
    let o = offer(100, vec![AttestEntry::discount("bearer", 5000)]);
    let d = decide(
        &o,
        &[att("bearer", BindingClass::None)],
        100,
        NOW,
        empty,
    );
    assert_eq!(d.ignored, vec!["bearer".to_owned()]);
    assert!(d.discounts.is_empty());
}

fn input<'a>(
    o: &'a OfferFields,
    value: Option<u64>,
    verified: &'a [VerifiedAttest],
) -> AdmitInput<'a> {
    AdmitInput {
        offer: o,
        pay: value.map(|value| PayValue {
            scheme: "bnap:notes",
            value,
        }),
        attest: verified,
        now: NOW,
    }
}

#[test]
fn admission_rules() {
    let req = AttestEntry::new("httpauth:DPoP", Effect::Required);
    let o = offer(100, vec![req.clone()]);
    // A required attestation that did not verify: POLICY.
    let e = admit(&input(&o, Some(100), &[]), empty).unwrap_err();
    assert_eq!(e, PriceError::Policy("httpauth:DPoP".into()));
    assert_eq!(e.code(), bnap_core::ErrorCode::Policy);
    // A required attestation of class None is fine: it only gates.
    let ok = [att("httpauth:DPoP", BindingClass::None)];
    assert_eq!(admit(&input(&o, Some(100), &ok), empty).unwrap().price, 100);

    let o = offer(100, vec![]);
    // Value below the price: UNDERPAID.
    let e = admit(&input(&o, Some(99), &[]), empty).unwrap_err();
    assert_eq!(
        e,
        PriceError::Underpaid {
            price: 100,
            value: 99
        }
    );
    assert_eq!(e.code(), bnap_core::ErrorCode::Underpaid);
    // Exactly the price is admitted.
    let a = admit(&input(&o, Some(100), &[]), empty).unwrap();
    assert_eq!(a.price, 100);
    assert_eq!(a.pay.as_ref().unwrap().unit, "sat");
    // No pay and a price above 0: UNDERPAID.
    assert!(matches!(
        admit(&input(&o, None, &[]), empty),
        Err(PriceError::Underpaid { value: 0, .. })
    ));
    // A pay scheme the offer does not list.
    let mut i = input(&o, Some(100), &[]);
    i.pay = Some(PayValue {
        scheme: "httpauth:L402",
        value: 100,
    });
    assert_eq!(
        admit(&i, empty),
        Err(PriceError::NotOffered("httpauth:L402".into()))
    );
}

#[test]
fn attestation_only_waive_needs_no_pay() {
    let mut o = offer(0, vec![AttestEntry::new("httpauth:DPoP", Effect::Waive)]);
    o.pay.clear();
    let v = [att("httpauth:DPoP", BindingClass::A)];
    let a = admit(&input(&o, None, &v), empty).unwrap();
    assert_eq!(a.price, 0);
    assert!(a.pay.is_none());
    assert_eq!(a.settle(Status::Ok, 0).charged, 0);
    // The waive did not verify: UNDERPAID, never a free admission
    // (ERRATA N3b-1; the literal base of 0 would admit it).
    assert!(matches!(
        admit(&input(&o, None, &[]), empty),
        Err(PriceError::Underpaid { value: 0, .. })
    ));
}

#[test]
fn no_pay_with_only_a_discount_is_never_free() {
    // The bypass the literal "or 0" base opens: an offer with a priced pay
    // entry and a discount attestation, and a credential carrying only the
    // attestation.
    let o = offer(21, vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)]);
    let v = [att("httpsig:web-bot-auth", BindingClass::A)];
    assert!(matches!(
        admit(&input(&o, None, &v), empty),
        Err(PriceError::Underpaid { value: 0, .. })
    ));
    assert!(matches!(
        admit(&input(&o, None, &[]), empty),
        Err(PriceError::Underpaid { value: 0, .. })
    ));
    // A full discount or a quota does admit it.
    let o = offer(21, vec![AttestEntry::discount("full", 10_000)]);
    let v = [att("full", BindingClass::S)];
    assert_eq!(admit(&input(&o, None, &v), empty).unwrap().price, 0);
    let id = use_id("q", b"acct");
    let o = offer(21, vec![AttestEntry::quota("q", 1, 60)]);
    let v = [att("q", BindingClass::S).with_quota_id(id)];
    let a = admit(&input(&o, None, &v), empty).unwrap();
    assert_eq!(a.price, 0);
    assert!(a.decision.quota.is_some());
}

#[test]
fn quotas_pick_the_first_with_room_in_offer_order() {
    let a_id = use_id("q:a", b"account");
    let b_id = use_id("q:b", b"account");
    let o = offer(
        50,
        vec![
            AttestEntry::quota("q:a", 2, 60),
            AttestEntry::quota("q:b", 5, 3600),
        ],
    );
    let v = [
        att("q:a", BindingClass::S).with_quota_id(a_id),
        att("q:b", BindingClass::A).with_quota_id(b_id),
    ];
    let cands = quota_candidates(&o, &v, NOW);
    assert_eq!(cands.len(), 2);
    let (ka, kb) = (cands[0].counter.key, cands[1].counter.key);
    // Both have room: the first in offer order wins.
    let a = admit(&input(&o, Some(0), &v), empty).unwrap();
    assert_eq!(a.price, 0);
    assert_eq!(a.decision.quota.as_ref().unwrap().scheme, "q:a");
    assert_eq!(a.decision.quota_counter().unwrap().limit, 2);
    // The first is full: the second.
    let full_a = |k: &CounterKey| if *k == ka { 2 } else { 0 };
    let a = admit(&input(&o, Some(0), &v), full_a).unwrap();
    assert_eq!(a.decision.quota.as_ref().unwrap().scheme, "q:b");
    // Both full: the full price.
    let full = |k: &CounterKey| if *k == ka { 2 } else if *k == kb { 5 } else { 0 };
    let e = admit(&input(&o, Some(0), &v), full).unwrap_err();
    assert_eq!(e, PriceError::Underpaid { price: 50, value: 0 });
}

#[test]
fn quotas_are_not_consumed_when_the_price_is_already_zero() {
    let id = use_id("q", b"acct");
    let o = offer(
        50,
        vec![
            AttestEntry::new("w", Effect::Waive),
            AttestEntry::quota("q", 1, 60),
        ],
    );
    let v = [
        att("w", BindingClass::S),
        att("q", BindingClass::S).with_quota_id(id),
    ];
    let a = admit(&input(&o, Some(0), &v), empty).unwrap();
    assert_eq!(a.price, 0);
    assert!(a.decision.quota.is_none());
}

#[test]
fn quotas_need_a_class_and_an_identity() {
    let o = offer(50, vec![AttestEntry::quota("q", 1, 60)]);
    // Bearer: no quota.
    let bearer = [att("q", BindingClass::None).with_quota_id(use_id("q", b"x"))];
    assert!(quota_candidates(&o, &bearer, NOW).is_empty());
    // No stable identity: no quota.
    assert!(quota_candidates(&o, &[att("q", BindingClass::S)], NOW).is_empty());
}

#[test]
fn quota_counters_follow_the_epoch() {
    let id = use_id("q", b"acct");
    let o = offer(50, vec![AttestEntry::quota("q", 3, 60)]);
    let v = [att("q", BindingClass::S).with_quota_id(id)];
    let at = |now| quota_candidates(&o, &v, now)[0].counter;
    assert_eq!(at(120).key, at(179).key);
    assert_ne!(at(120).key, at(180).key);
    assert_eq!(at(150).resets_at, 180);
}

#[test]
fn metered_charge_matches_the_10_3_example() {
    let mut o = offer(2_100, vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)]);
    o.metered = true;
    o.pay[0].rate = Some(500);
    let v = [att("httpsig:web-bot-auth", BindingClass::A)];
    let a = admit(&input(&o, Some(1_680), &v), empty).unwrap();
    assert_eq!(a.price, 1_680, "the client sends price(ceiling)");
    // 850 tokens: ⌈850 × 500 / 1000⌉ = 425 before the discount, 340 after.
    let c = a.settle(Status::Ok, 850);
    assert_eq!(c.charged, 340);
    assert_eq!(c.metered_units, Some(850));
    assert_eq!(c.cap.get(), 1_340, "the notes scheme signs 1,340 sat of change");
    // Rounding up the metered amount: 1 token at 500/1000 is 1 sat, 0 after
    // a 20% discount takes off ⌊1 × 0.2⌋ = 0.
    assert_eq!(a.settle(Status::Ok, 1).charged, 1);
    assert_eq!(a.settle(Status::Ok, 0).charged, 0);
    // Beyond the ceiling: price(amount).
    assert_eq!(a.settle(Status::Ok, 10_000).charged, 1_680);
    // A product beyond 2^64 yields the ceiling.
    let mut huge = o.clone();
    huge.pay[0].rate = Some(u64::MAX);
    let a = admit(&input(&huge, Some(1_680), &v), empty).unwrap();
    assert_eq!(a.settle(Status::Ok, u64::MAX).charged, 1_680);
    // Metered FAILED: nothing charged, the count still reported.
    let f = a.settle(Status::Failed, 850);
    assert_eq!((f.charged, f.metered_units, f.cap.get()), (0, Some(850), 1_680));
}

#[test]
fn settlement_reuses_the_quota_decision() {
    let id = use_id("q", b"acct");
    let mut o = offer(1000, vec![AttestEntry::quota("q", 1, 60)]);
    o.metered = true;
    o.pay[0].rate = Some(1000);
    let v = [att("q", BindingClass::S).with_quota_id(id)];
    let a = admit(&input(&o, Some(0), &v), empty).unwrap();
    assert!(a.decision.quota.is_some());
    assert_eq!(a.settle(Status::Ok, 500).charged, 0);
}

#[test]
fn overpayment_and_failure() {
    let o = offer(100, vec![]);
    let a = admit(&input(&o, Some(150), &[]), empty).unwrap();
    let ok = a.settle(Status::Ok, 0);
    assert_eq!((ok.charged, ok.cap.get(), ok.metered_units), (100, 50, None));
    let failed = a.settle(Status::Failed, 0);
    assert_eq!((failed.charged, failed.cap.get()), (0, 150));
}

#[test]
fn metered_entries_need_atomic_refund_or_upto() {
    assert!(metered_entry_allowed("atomic", false));
    assert!(metered_entry_allowed("none", true));
    assert!(!metered_entry_allowed("out-of-band", false));
    assert!(!metered_entry_allowed("none", false));
}

proptest! {
    #[test]
    fn price_is_monotone_and_min_commutes(
        a in any::<u64>(),
        b in any::<u64>(),
        bps in proptest::collection::vec(1u64..=10_000, 0..4),
    ) {
        let attest: Vec<AttestEntry> = bps
            .iter()
            .enumerate()
            .map(|(i, bp)| AttestEntry::discount(format!("d{i}"), *bp))
            .collect();
        let verified: Vec<VerifiedAttest> = (0..bps.len())
            .map(|i| att(&format!("d{i}"), BindingClass::S))
            .collect();
        let o = offer(a, attest);
        let d = decide(&o, &verified, a, NOW, empty);
        let (pa, pb) = (d.price(a), d.price(b));
        prop_assert!(pa <= a && pb <= b);
        if a <= b {
            prop_assert!(pa <= pb);
        }
        prop_assert_eq!(d.price(a.min(b)), pa.min(pb));
    }

    #[test]
    fn metered_charges_never_exceed_the_admitted_price(
        amount in any::<u64>(),
        rate in any::<u64>(),
        units in any::<u64>(),
        bp in 1u64..=10_000,
    ) {
        let mut o = offer(amount, vec![AttestEntry::discount("d", bp)]);
        o.metered = true;
        o.pay[0].rate = Some(rate);
        let v = [att("d", BindingClass::S)];
        let a = admit(&input(&o, Some(u64::MAX), &v), empty).unwrap();
        let c = a.settle(Status::Ok, units);
        prop_assert!(c.charged <= a.price);
        prop_assert_eq!(c.cap.get(), u64::MAX - c.charged);
    }
}
