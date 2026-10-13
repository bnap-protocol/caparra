//! Pricing table tests (draft-00 section 7).

use bnap_core::class::BindingClass;
use bnap_core::hash::{CounterKey, RailId, Scope};
use bnap_core::ids::use_id;
use bnap_core::offer::{AttestEntry, Effect, OfferFields, PayEntry};
use bnap_core::pricing::{
    AdmitInput, Backing, BackingSource, PayValue, PriceError, VerifiedAttest, admit, backed_value,
    decide, metered_entry_allowed, quota_candidates,
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

/// One pricing row: name, amount, offer attestations, verified ones, price.
type Row = (
    &'static str,
    u64,
    Vec<AttestEntry>,
    Vec<VerifiedAttest>,
    u64,
);

/// Section 7, as a table: offer attestations, which verified, and the price.
#[test]
fn price_table() {
    use BindingClass::{A, None as Bearer, O, S};
    let d = |s: &str, bp| AttestEntry::discount(s, bp);
    let w = |s: &str| AttestEntry::new(s, Effect::Waive);
    let rows: Vec<Row> = vec![
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
    let d = decide(&o, &[att("bearer", BindingClass::None)], 100, NOW, empty);
    assert_eq!(d.ignored, vec!["bearer".to_owned()]);
    assert_eq!(d.discounts, Vec::<(String, u64)>::new());
}

/// A payment a rail confirmed, `amount` in `unit`.
fn paid(n: u8, amount: u64, unit: &str) -> Backing {
    Backing {
        source: BackingSource::Rail(RailId([n; 32])),
        amount,
        unit: unit.into(),
    }
}

/// A note the signer verified.
fn note(y: &[u8], amount: u64) -> Backing {
    Backing {
        source: BackingSource::Note(y.to_vec()),
        amount,
        unit: "sat".into(),
    }
}

/// A credential whose pay part claims `value` and is backed by one
/// payment of exactly that much.
fn input<'a>(
    o: &'a OfferFields,
    value: Option<u64>,
    verified: &'a [VerifiedAttest],
) -> AdmitInput<'a> {
    AdmitInput {
        offer: o,
        pay: value.map(|value| PayValue {
            scheme: "bnap:notes",
            claimed: value,
            backing: vec![paid(1, value, "sat")],
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
    assert_eq!(
        admit(&input(&o, Some(100), &ok), empty).unwrap().price(),
        100
    );

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
    assert_eq!(a.price(), 100);
    assert_eq!(a.pay().unwrap().unit(), "sat");
    // No pay and a price above 0: UNDERPAID.
    assert!(matches!(
        admit(&input(&o, None, &[]), empty),
        Err(PriceError::Underpaid { value: 0, .. })
    ));
    // A pay scheme the offer does not list.
    let mut i = input(&o, Some(100), &[]);
    i.pay = Some(PayValue {
        scheme: "httpauth:L402",
        claimed: 100,
        backing: vec![paid(1, 100, "sat")],
    });
    assert_eq!(
        admit(&i, empty),
        Err(PriceError::NotOffered("httpauth:L402".into()))
    );
}

#[test]
fn the_value_is_what_the_rails_and_the_signer_confirmed() {
    let o = offer(100, vec![]);
    let pay = |claimed, backing| AdmitInput {
        offer: &o,
        pay: Some(PayValue {
            scheme: "bnap:notes",
            claimed,
            backing,
        }),
        attest: &[],
        now: NOW,
    };
    let under = |value| PriceError::Underpaid { price: 100, value };
    // The review's probe: the rail confirmed 21 msat and the scheme claimed
    // 1,000,000 sat. 21 msat is 0 sat.
    assert_eq!(
        admit(&pay(1_000_000, vec![paid(1, 21, "msat")]), empty),
        Err(under(0))
    );
    // An underpaying rail reference: 99 sat confirmed.
    assert_eq!(
        admit(&pay(1_000_000, vec![paid(1, 99, "sat")]), empty),
        Err(under(99))
    );
    // No backing at all counts nothing.
    assert_eq!(admit(&pay(1_000_000, vec![]), empty), Err(under(0)));
    // The same payment named twice counts once.
    assert_eq!(
        admit(
            &pay(120, vec![paid(1, 60, "sat"), paid(1, 60, "sat")]),
            empty
        ),
        Err(under(60))
    );
    // Two payments add up.
    let a = admit(
        &pay(120, vec![paid(1, 60, "sat"), paid(2, 60, "sat")]),
        empty,
    )
    .unwrap();
    assert_eq!(a.pay().unwrap().value(), 120);
    // An overclaim on enough backing is cut to the backing, and so is the
    // change cap: backed minus price, never claimed minus price.
    let a = admit(&pay(1_000_000, vec![paid(1, 150, "sat")]), empty).unwrap();
    let p = a.pay().unwrap();
    assert_eq!((p.claimed(), p.backed(), p.value()), (1_000_000, 150, 150));
    assert_eq!(p.backing(), &[BackingSource::Rail(RailId([1; 32]))]);
    assert_eq!(a.settle(Status::Ok, 0).cap.get(), 50);
    assert_eq!(a.settle(Status::Failed, 0).cap.get(), 150);
    // A claim below the backing is the value: the scheme gives up the rest.
    let a = admit(&pay(120, vec![paid(1, 150, "sat")]), empty).unwrap();
    assert_eq!(a.pay().unwrap().value(), 120);
    // msat backing converts exactly, rounded down to the entry's unit.
    let a = admit(&pay(100, vec![paid(1, 100_999, "msat")]), empty).unwrap();
    assert_eq!(a.pay().unwrap().backed(), 100);
    assert_eq!(
        admit(&pay(100, vec![paid(1, 99_999, "msat")]), empty),
        Err(under(99))
    );
}

#[test]
fn a_wrong_unit_is_refused() {
    let o = offer(100, vec![]);
    let i = AdmitInput {
        offer: &o,
        pay: Some(PayValue {
            scheme: "bnap:notes",
            claimed: 100,
            backing: vec![paid(1, 100, "USD")],
        }),
        attest: &[],
        now: NOW,
    };
    let e = admit(&i, empty).unwrap_err();
    assert_eq!(
        e,
        PriceError::UnitMismatch {
            want: "sat".into(),
            got: "USD".into()
        }
    );
    assert_eq!(e.code(), bnap_core::ErrorCode::BadCredential);
}

#[test]
fn a_value_larger_than_the_verified_notes_is_cut_to_them() {
    let o = offer(50, vec![]);
    let notes = vec![note(b"Y1", 64), note(b"Y2", 32), note(b"Y1", 64)];
    let i = AdmitInput {
        offer: &o,
        pay: Some(PayValue {
            scheme: "bnap:notes",
            claimed: 1_000,
            backing: notes.clone(),
        }),
        attest: &[],
        now: NOW,
    };
    let a = admit(&i, empty).unwrap();
    let p = a.pay().unwrap();
    assert_eq!((p.claimed(), p.value()), (1_000, 96), "Y1 counts once");
    assert_eq!(
        p.backing(),
        &[
            BackingSource::Note(b"Y1".to_vec()),
            BackingSource::Note(b"Y2".to_vec())
        ]
    );
    assert_eq!(a.settle(Status::Ok, 0).cap.get(), 46);
    // A price above the notes: UNDERPAID at the notes' value.
    let o = offer(100, vec![]);
    let mut i = i;
    i.offer = &o;
    assert_eq!(
        admit(&i, empty),
        Err(PriceError::Underpaid {
            price: 100,
            value: 96
        })
    );
}

#[test]
fn backing_converts_only_between_sat_and_msat() {
    let sum = |unit: &str, b: &[Backing]| backed_value(unit, b).map(|(v, _)| v);
    assert_eq!(
        sum("msat", &[paid(1, 2, "sat"), paid(2, 5, "msat")]),
        Ok(2_005)
    );
    // 1 sat + 999 msat is 1,999 msat: 1 sat.
    assert_eq!(
        sum("sat", &[paid(1, 1, "sat"), paid(2, 999, "msat")]),
        Ok(1)
    );
    assert_eq!(
        sum("sat", &[paid(1, 1, "sat"), paid(2, 1_000, "msat")]),
        Ok(2)
    );
    assert_eq!(sum("USD", &[paid(1, 5, "USD"), paid(2, 6, "USD")]), Ok(11));
    assert!(sum("USD", &[paid(1, 5, "sat")]).is_err());
    assert!(sum("sat", &[paid(1, 5, "USD")]).is_err());
    assert!(sum("sat", &[paid(1, 5, "SAT")]).is_err(), "units are exact");
    // The sum saturates.
    assert_eq!(
        sum(
            "sat",
            &[paid(1, u64::MAX, "sat"), paid(2, u64::MAX, "msat")]
        ),
        Ok(u64::MAX)
    );
}

#[test]
fn attestation_only_waive_needs_no_pay() {
    let mut o = offer(0, vec![AttestEntry::new("httpauth:DPoP", Effect::Waive)]);
    o.pay.clear();
    let v = [att("httpauth:DPoP", BindingClass::A)];
    let a = admit(&input(&o, None, &v), empty).unwrap();
    assert_eq!(a.price(), 0);
    assert!(a.pay().is_none());
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
    let o = offer(
        21,
        vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)],
    );
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
    assert_eq!(admit(&input(&o, None, &v), empty).unwrap().price(), 0);
    let id = use_id("q", b"acct");
    let o = offer(21, vec![AttestEntry::quota("q", 1, 60)]);
    let v = [att("q", BindingClass::S).with_quota_id(id)];
    let a = admit(&input(&o, None, &v), empty).unwrap();
    assert_eq!(a.price(), 0);
    assert!(a.decision().quota.is_some());
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
    assert_eq!(a.price(), 0);
    assert_eq!(a.decision().quota.as_ref().unwrap().scheme, "q:a");
    assert_eq!(a.decision().quota_counter().unwrap().limit, 2);
    // The first is full: the second.
    let full_a = |k: &CounterKey| if *k == ka { 2 } else { 0 };
    let a = admit(&input(&o, Some(0), &v), full_a).unwrap();
    assert_eq!(a.decision().quota.as_ref().unwrap().scheme, "q:b");
    // Both full: the full price.
    let full = |k: &CounterKey| {
        if *k == ka {
            2
        } else if *k == kb {
            5
        } else {
            0
        }
    };
    let e = admit(&input(&o, Some(0), &v), full).unwrap_err();
    assert_eq!(
        e,
        PriceError::Underpaid {
            price: 50,
            value: 0
        }
    );
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
    assert_eq!(a.price(), 0);
    assert!(a.decision().quota.is_none());
}

#[test]
fn quotas_need_a_class_and_an_identity() {
    let o = offer(50, vec![AttestEntry::quota("q", 1, 60)]);
    // Bearer: no quota.
    let bearer = [att("q", BindingClass::None).with_quota_id(use_id("q", b"x"))];
    assert_eq!(quota_candidates(&o, &bearer, NOW).len(), 0);
    // No stable identity: no quota.
    assert_eq!(
        quota_candidates(&o, &[att("q", BindingClass::S)], NOW).len(),
        0
    );
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
    let mut route = offer(
        2_100,
        vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)],
    );
    route.metered = true;
    route.pay[0].rate = Some(500);
    let verified = [att("httpsig:web-bot-auth", BindingClass::A)];
    let adm = admit(&input(&route, Some(1_680), &verified), empty).unwrap();
    assert_eq!(adm.price(), 1_680, "the client sends price(ceiling)");
    // 850 tokens: ⌈850 × 500 / 1000⌉ = 425 before the discount, 340 after.
    let charge = adm.settle(Status::Ok, 850);
    assert_eq!(charge.charged, 340);
    assert_eq!(charge.metered_units, Some(850));
    assert_eq!(
        charge.cap.get(),
        1_340,
        "the notes scheme signs 1,340 sat of change"
    );
    // Rounding up the metered amount: 1 token at 500/1000 is 1 sat, and a
    // 20% discount takes off ⌊1 × 0.2⌋ = 0.
    assert_eq!(adm.settle(Status::Ok, 1).charged, 1);
    assert_eq!(adm.settle(Status::Ok, 0).charged, 0);
    // Beyond the ceiling: price(amount).
    assert_eq!(adm.settle(Status::Ok, 10_000).charged, 1_680);
    // A product beyond 2^64 yields the ceiling.
    let mut huge = route.clone();
    huge.pay[0].rate = Some(u64::MAX);
    let adm = admit(&input(&huge, Some(1_680), &verified), empty).unwrap();
    assert_eq!(adm.settle(Status::Ok, u64::MAX).charged, 1_680);
    // Metered FAILED: nothing charged, the count still reported.
    let failed = adm.settle(Status::Failed, 850);
    assert_eq!(
        (failed.charged, failed.metered_units, failed.cap.get()),
        (0, Some(850), 1_680)
    );
}

#[test]
fn settlement_reuses_the_quota_decision() {
    let id = use_id("q", b"acct");
    let mut o = offer(1000, vec![AttestEntry::quota("q", 1, 60)]);
    o.metered = true;
    o.pay[0].rate = Some(1000);
    let v = [att("q", BindingClass::S).with_quota_id(id)];
    let a = admit(&input(&o, Some(0), &v), empty).unwrap();
    assert!(a.decision().quota.is_some());
    assert_eq!(a.settle(Status::Ok, 500).charged, 0);
}

#[test]
fn overpayment_and_failure() {
    let o = offer(100, vec![]);
    let a = admit(&input(&o, Some(150), &[]), empty).unwrap();
    let ok = a.settle(Status::Ok, 0);
    assert_eq!(
        (ok.charged, ok.cap.get(), ok.metered_units),
        (100, 50, None)
    );
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
        prop_assert!(c.charged <= a.price());
        prop_assert_eq!(c.cap.get(), u64::MAX - c.charged);
    }
}
