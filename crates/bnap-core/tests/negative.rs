//! Negative cases: the conformance list of draft-00 section 14 that the
//! socket core can decide, plus the structural rules of sections 2, 4, 5,
//! 8 and 9.

#![allow(clippy::too_many_lines)]

use bnap_core::credential::{Credential, CredentialParse, OfferRef, SchemePart};
use bnap_core::error::{BadOffer, MalformedKind, Stale};
use bnap_core::hash::sha256;
use bnap_core::manifest::{self, KeyUse, Manifest, ManifestError, ManifestKey, ManifestLimits};
use bnap_core::offer::{
    AttestEntry, Effect, GateOfferCheck, NativeEntry, Offer, OfferFields, PayEntry,
};
use bnap_core::response::{ReceiptError, Response, ResponseFields, Status};
use bnap_core::tlv::{TlvStream, entry_list, write_record};
use bnap_core::{BindingClass, Error, ErrorCode, Object, Scope, SigningKey, encoding, http};

const AUX0: [u8; 32] = [0; 32];
const EXPIRES: u64 = 1_791_700_300;
const NOW: u64 = 1_791_700_000;
const ORIGIN: &str = "https://api.example";

fn key(label: &[u8]) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(label)).unwrap()
}

fn offer_key() -> SigningKey {
    key(b"bnap test offer key")
}

fn mac() -> [u8; 32] {
    sha256(b"bnap test mac key")
}

fn act() -> Scope {
    http::action_scope(
        "POST",
        "https://api.example/v1/chat/completions",
        b"{}",
        &[],
    )
}

fn route() -> Scope {
    http::route_scope(ORIGIN, "chat")
}

fn exact_fields() -> OfferFields {
    let mut f = OfferFields::new(act(), EXPIRES, offer_key().public_key(), [0; 16]);
    f.pay = vec![PayEntry::new("payment:lightning/charge", 21, "sat")];
    f
}

fn route_fields() -> OfferFields {
    let mut f = OfferFields::new(route(), EXPIRES, offer_key().public_key(), [7; 16]);
    f.route_scope = true;
    f.pay = vec![PayEntry::new("bnap:notes", 2100, "sat")];
    f.attest = vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)];
    f
}

fn class_of(s: &str) -> Option<BindingClass> {
    match s {
        "bnap:notes" => Some(BindingClass::S),
        "httpsig:web-bot-auth" | "httpauth:DPoP" => Some(BindingClass::A),
        "payment:lightning/charge" => Some(BindingClass::O),
        "bearer:token" => Some(BindingClass::None),
        _ => None,
    }
}

fn gate() -> GateOfferCheck<'static> {
    static MACS: std::sync::OnceLock<[[u8; 32]; 1]> = std::sync::OnceLock::new();
    GateOfferCheck {
        now: NOW,
        max_offer: bnap_core::limits::MAX_OFFER,
        mac_keys: MACS.get_or_init(|| [mac()]),
        offer_keys: &[],
        action_scope: act(),
        route_scope: Some(route()),
    }
}

fn malformed(r: Result<impl std::fmt::Debug, Error>) -> MalformedKind {
    match r {
        Err(Error::Malformed { kind, .. }) => kind,
        other => panic!("expected MALFORMED, got {other:?}"),
    }
}

fn code<T: std::fmt::Debug>(r: Result<T, Error>) -> ErrorCode {
    r.map(|_| ()).unwrap_err().code()
}

/// Re-encodes a parsed stream with one record's value replaced.
fn with_record(bytes: &[u8], typ: u64, value: Option<Vec<u8>>) -> Vec<u8> {
    let s = TlvStream::parse(bytes, bnap_core::tlv::StreamKind::TopLevel).unwrap();
    let mut out = TlvStream::new();
    for (t, v) in s.records() {
        if *t != typ {
            out.insert(*t, v.clone()).unwrap();
        }
    }
    if let Some(v) = value {
        out.insert(typ, v).unwrap();
    }
    out.to_bytes()
}

#[test]
fn non_minimal_bigsize_is_malformed() {
    let o = exact_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    // Re-encode the version record's type 0 as fd 00 00.
    let mut b = vec![0xfd, 0x00, 0x00];
    b.extend_from_slice(&o.bytes()[1..]);
    assert_eq!(
        malformed(Offer::parse(&b)),
        MalformedKind::NonMinimalBigSize
    );
    // A non-minimal length.
    let mut b = vec![0x00, 0xfd, 0x00, 0x01];
    b.extend_from_slice(&o.bytes()[2..]);
    assert_eq!(
        malformed(Offer::parse(&b)),
        MalformedKind::NonMinimalBigSize
    );
}

#[test]
fn records_out_of_order_are_malformed() {
    let o = exact_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let s = TlvStream::parse(o.bytes(), bnap_core::tlv::StreamKind::TopLevel).unwrap();
    let recs = s.records();
    let mut b = Vec::new();
    write_record(&mut b, recs[1].0, &recs[1].1);
    write_record(&mut b, recs[0].0, &recs[0].1);
    for (t, v) in &recs[2..] {
        write_record(&mut b, *t, v);
    }
    assert!(matches!(
        malformed(Offer::parse(&b)),
        MalformedKind::TypeOrder { .. }
    ));
    // A duplicate record.
    let mut b = o.bytes().to_vec();
    write_record(&mut b, 3_000_000_001, b"");
    write_record(&mut b, 3_000_000_001, b"");
    assert!(matches!(
        malformed(Offer::parse(&b)),
        MalformedKind::TypeOrder { .. }
    ));
}

#[test]
fn unknown_even_is_malformed_and_unknown_odd_is_covered() {
    let o = exact_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let b = with_record(o.bytes(), 22, Some(vec![1]));
    assert_eq!(
        malformed(Offer::parse(&b)),
        MalformedKind::UnknownEvenType(22)
    );
    let b = with_record(o.bytes(), 2_000_000_000, Some(vec![]));
    assert_eq!(
        malformed(Offer::parse(&b)),
        MalformedKind::UnknownEvenType(2_000_000_000)
    );
    // An odd record added on the path parses, but the MAC and the signature
    // cover it, and the OfferID changes.
    let b = with_record(o.bytes(), 23, Some(vec![1]));
    let tampered = Offer::parse(&b).unwrap();
    assert_ne!(tampered.offer_id(), o.offer_id());
    assert_eq!(
        tampered.verify_mac(&[mac()]),
        Err(Error::BadOffer(BadOffer::Mac))
    );
    assert_eq!(
        tampered.verify_signature(),
        Err(Error::BadOffer(BadOffer::Signature))
    );
    // An odd record in the signature range is not covered.
    let b = with_record(o.bytes(), 241, Some(vec![1]));
    let extra = Offer::parse(&b).unwrap();
    assert_eq!(extra.offer_id(), o.offer_id());
    extra.verify_mac(&[mac()]).unwrap();
    assert_eq!(extra.signature_unknown(), &[(241, vec![1])]);
}

#[test]
fn a_flipped_bit_anywhere_in_the_offer_is_caught() {
    let o = route_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let sig = o.offer_sig().0;
    let sig_at = o.bytes().windows(64).position(|w| w == sig).unwrap();
    // S is every byte before the offer_sig record (2 header bytes).
    let s_end = sig_at - 2;
    assert_eq!(&o.bytes()[..s_end], o.signed_bytes());
    let mut parsed = 0;
    for byte in 0..o.bytes().len() {
        for bit in 0..8 {
            let mut b = o.bytes().to_vec();
            b[byte] ^= 1 << bit;
            let Ok(p) = Offer::parse(&b) else { continue };
            parsed += 1;
            if byte < s_end {
                // A signed record changed: the MAC and the signature fail.
                assert!(p.verify_mac(&[mac()]).is_err(), "byte {byte} bit {bit}");
                assert!(p.verify_signature().is_err(), "byte {byte} bit {bit}");
            } else if (sig_at..sig_at + 64).contains(&byte) {
                // Inside offer_sig: the MAC still holds, the signature fails.
                assert!(p.verify_signature().is_err(), "byte {byte} bit {bit}");
            } else {
                // The signature records' framing or the MAC: the gate's
                // authenticity check fails.
                assert!(
                    p.check_authenticity(&[mac()], &[]).is_err(),
                    "byte {byte} bit {bit}"
                );
            }
        }
    }
    assert!(parsed > 0);
}

#[test]
fn a_flipped_bit_anywhere_in_the_response_is_caught() {
    let k = key(b"bnap test receipt key");
    let r = ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 340,
        unit: Some("sat".into()),
        offer_id: bnap_core::OfferId([5; 32]),
        digest: bnap_core::Digest([6; 32]),
        metered_units: Some(850),
        scheme_result: Some(b"change".to_vec()),
        receipt_key: k.public_key(),
        settled_at: NOW,
        unknown: vec![(3_000_000_003, vec![1])],
    }
    .sign(&k, &AUX0)
    .unwrap();
    for byte in 0..r.bytes().len() {
        for bit in 0..8 {
            let mut b = r.bytes().to_vec();
            b[byte] ^= 1 << bit;
            if let Ok(p) = Response::parse(&b) {
                assert!(p.verify_ack().is_err(), "byte {byte} bit {bit}");
            }
        }
    }
}

#[test]
fn offer_without_mac_needs_a_held_key_and_issued_at() {
    let mut f = exact_fields();
    f.issued_at = Some(NOW - 10);
    let o = f.sign(&offer_key(), None, &AUX0).unwrap();
    assert!(o.mac().is_none());
    let held = [offer_key().public_key()];
    // A key the gate does not hold.
    assert_eq!(
        gate().check(&o, None),
        Err(Error::BadOffer(BadOffer::UnknownKey))
    );
    let g = GateOfferCheck {
        offer_keys: &held,
        route_scope: None,
        ..gate()
    };
    g.check(&o, None).unwrap();
    // A stranger signs an offer naming its own key: still unknown.
    let stranger = key(b"stranger");
    let mut f2 = exact_fields();
    f2.offer_key = stranger.public_key();
    f2.issued_at = Some(NOW);
    let o2 = f2.sign(&stranger, None, &AUX0).unwrap();
    assert_eq!(
        g.check(&o2, None),
        Err(Error::BadOffer(BadOffer::UnknownKey))
    );
    // A stranger's signature over an offer naming the held key.
    let forged = with_record(o2.bytes(), 14, Some(offer_key().public_key().0.to_vec()));
    let forged = Offer::parse(&forged).unwrap();
    assert_eq!(
        g.check(&forged, None),
        Err(Error::BadOffer(BadOffer::Signature))
    );
    // No issued_at: the builder refuses, and crafted bytes fail authenticity.
    assert!(exact_fields().sign(&offer_key(), None, &AUX0).is_err());
    let no_issued = with_record(o.bytes(), 24, None);
    let no_issued = Offer::parse(&no_issued).unwrap();
    assert_eq!(
        g.check(&no_issued, None),
        Err(Error::BadOffer(BadOffer::MissingIssuedAt))
    );
    // issued_at in the future.
    let mut f3 = exact_fields();
    f3.issued_at = Some(NOW + 61);
    let o3 = f3.sign(&offer_key(), None, &AUX0).unwrap();
    assert_eq!(g.check(&o3, None), Err(Error::Stale(Stale::IssuedInFuture)));
}

#[test]
fn quote_expiry_and_skew() {
    let mut f = exact_fields();
    f.pay[0].quote_expires = Some(NOW);
    let o = f.sign(&offer_key(), Some(&mac()), &AUX0).unwrap();
    let g = GateOfferCheck {
        route_scope: None,
        ..gate()
    };
    GateOfferCheck { now: NOW + 60, ..g }
        .check(&o, Some("payment:lightning/charge"))
        .unwrap();
    assert_eq!(
        GateOfferCheck { now: NOW + 61, ..g }.check(&o, Some("payment:lightning/charge")),
        Err(Error::Stale(Stale::QuoteExpired))
    );
    // quote_expires beyond expires is malformed.
    f.pay[0].quote_expires = Some(EXPIRES + 1);
    assert!(f.sign(&offer_key(), Some(&mac()), &AUX0).is_err());
}

#[test]
fn exact_offer_on_another_request_is_wrong_scope() {
    let o = exact_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let other = http::action_scope(
        "POST",
        "https://api.example/v1/chat/completions",
        b"{ }",
        &[],
    );
    let g = GateOfferCheck {
        action_scope: other,
        route_scope: None,
        ..gate()
    };
    assert_eq!(g.check(&o, None), Err(Error::WrongScope));
    // A route offer for another route.
    let r = route_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let g = GateOfferCheck {
        route_scope: Some(http::route_scope(ORIGIN, "embed")),
        ..gate()
    };
    assert_eq!(g.check(&r, None), Err(Error::WrongScope));
}

#[test]
fn class_o_or_native_in_a_route_offer() {
    // A class O scheme in a route-scope offer.
    let mut f = route_fields();
    f.pay
        .push(PayEntry::new("payment:lightning/charge", 2100, "sat"));
    let o = f.sign(&offer_key(), Some(&mac()), &AUX0).unwrap();
    assert!(matches!(
        malformed(o.check_binding_classes(class_of)),
        MalformedKind::ClassViolation { scheme, .. } if scheme == "payment:lightning/charge"
    ));
    // An unknown scheme counts as class None.
    let mut f = route_fields();
    f.attest
        .push(AttestEntry::new("unknown:x", Effect::Required));
    assert!(f.check_binding_classes(class_of).is_err());
    // A native in a route-scope offer: the builder refuses and the parser
    // rejects crafted bytes.
    let mut f = route_fields();
    f.native = vec![NativeEntry::new(0, "bolt11", b"lnbc".to_vec())];
    assert!(f.sign(&offer_key(), Some(&mac()), &AUX0).is_err());
    let good = route_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let native = entry_list(&[NativeEntry::new(0, "bolt11", b"lnbc".to_vec())
        .to_bytes()
        .unwrap()]);
    let crafted = with_record(good.bytes(), 26, Some(native));
    assert_eq!(
        malformed(Offer::parse(&crafted)),
        MalformedKind::Rule("a route-scope offer carries no native record")
    );
    // A native whose pay entry is not class O.
    let mut f = exact_fields();
    f.pay.insert(0, PayEntry::new("bnap:notes", 21, "sat"));
    f.native = vec![NativeEntry::new(0, "bolt11", b"lnbc".to_vec())];
    assert!(f.check_binding_classes(class_of).is_err());
    f.native[0].pay_index = 1;
    f.check_binding_classes(class_of).unwrap();
    f.native[0].pay_index = 2;
    assert!(f.offer_id().is_err());
    // Class None may not waive, and a None value scheme only at price 0.
    let mut f = exact_fields();
    f.attest = vec![AttestEntry::new("bearer:token", Effect::Waive)];
    assert!(f.check_binding_classes(class_of).is_err());
    let mut f = exact_fields();
    f.pay = vec![PayEntry::new("bearer:token", 1, "sat")];
    assert!(f.check_binding_classes(class_of).is_err());
    f.pay[0].amount = 0;
    f.check_binding_classes(class_of).unwrap();
}

#[test]
fn offer_record_rules() {
    let k = offer_key();
    let sign = |f: &OfferFields| f.sign(&k, Some(&mac()), &AUX0);
    // Effect outside 0 to 3, crafted.
    let bad = TlvStream::from_records([(0, b"s".to_vec()), (2, encoding::tu64(4))])
        .unwrap()
        .to_bytes();
    assert_eq!(
        malformed(AttestEntry::parse(&bad)),
        MalformedKind::Rule("effect outside 0 to 3")
    );
    // Discount range.
    for bp in [0, 10_001] {
        let mut f = exact_fields();
        f.attest = vec![AttestEntry::discount("httpsig:web-bot-auth", bp)];
        assert!(sign(&f).is_err(), "{bp}");
    }
    let mut f = exact_fields();
    f.attest = vec![AttestEntry::discount("httpsig:web-bot-auth", 10_000)];
    sign(&f).unwrap();
    // Quota value and epoch.
    for (v, e) in [(0, 60), (5, 0)] {
        let mut f = exact_fields();
        f.attest = vec![AttestEntry::quota("httpsig:web-bot-auth", v, e)];
        assert!(sign(&f).is_err());
    }
    // pay is required unless attest holds a waive.
    let mut f = exact_fields();
    f.pay.clear();
    assert!(sign(&f).is_err());
    f.attest = vec![AttestEntry::new("httpauth:DPoP", Effect::Waive)];
    sign(&f).unwrap();
    // Duplicate schemes.
    let mut f = exact_fields();
    f.pay.push(f.pay[0].clone());
    assert!(matches!(
        malformed(sign(&f)),
        MalformedKind::DuplicateScheme(_)
    ));
    // Metered offers need a rate.
    let mut f = exact_fields();
    f.metered = true;
    assert!(sign(&f).is_err());
    f.pay[0].rate = Some(500);
    sign(&f).unwrap();
    // Flags carry no value.
    let o = sign(&exact_fields()).unwrap();
    assert_eq!(
        malformed(Offer::parse(&with_record(o.bytes(), 4, Some(vec![1])))),
        MalformedKind::FlagNotEmpty(4)
    );
    // Wrong lengths.
    assert_eq!(
        malformed(Offer::parse(&with_record(o.bytes(), 16, Some(vec![0; 15])))),
        MalformedKind::Length { typ: 16, len: 15 }
    );
    // Non-minimal tu64.
    assert_eq!(
        malformed(Offer::parse(&with_record(o.bytes(), 10, Some(vec![0, 1])))),
        MalformedKind::NonMinimalTu64(10)
    );
    // Missing required records.
    assert_eq!(
        malformed(Offer::parse(&with_record(o.bytes(), 240, None))),
        MalformedKind::MissingRecord(240)
    );
    assert_eq!(
        malformed(Offer::parse(&with_record(o.bytes(), 2, None))),
        MalformedKind::MissingRecord(2)
    );
    // A nested stream may not use the signature range.
    let entry = TlvStream::from_records([
        (0, b"s".to_vec()),
        (2, encoding::tu64(1)),
        (4, b"sat".to_vec()),
        (241, vec![]),
    ])
    .unwrap()
    .to_bytes();
    assert_eq!(
        malformed(PayEntry::parse(&entry)),
        MalformedKind::TypeNotAllowed(241)
    );
    // Headers must be lower-case field names.
    let mut f = exact_fields();
    f.headers = vec!["Accept".into()];
    assert!(sign(&f).is_err());
    f.headers = vec!["accept".into(), "anthropic-version".into()];
    let o = sign(&f).unwrap();
    assert_eq!(Offer::parse(o.bytes()).unwrap().fields().headers, f.headers);
    // Unsupported version.
    let v2 = with_record(o.bytes(), 0, Some(encoding::tu64(2)));
    assert_eq!(
        Offer::parse(&v2),
        Err(Error::Version {
            object: Object::Offer,
            version: 2
        })
    );
    // The signing key must be the offer key.
    assert!(
        exact_fields()
            .sign(&key(b"other"), Some(&mac()), &AUX0)
            .is_err()
    );
}

#[test]
fn size_limits() {
    let mut f = exact_fields();
    f.pay[0].params = Some(vec![0; 4096]);
    assert_eq!(
        code(f.sign(&offer_key(), Some(&mac()), &AUX0)),
        ErrorCode::TooLarge
    );
    f.sign_with_limit(&offer_key(), Some(&mac()), &AUX0, 8192)
        .unwrap();
    assert_eq!(code(Offer::parse(&[0; 4097])), ErrorCode::TooLarge);
    assert_eq!(
        code(Credential::parse(&vec![0; 16_385])),
        ErrorCode::TooLarge
    );
    assert_eq!(code(Response::parse(&[0; 8193])), ErrorCode::TooLarge);
    // A limit only grows from the manifest.
    let l = bnap_core::Limits::from_manifest(&ManifestLimits {
        max_offer: Some(100),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.max_offer, 4096);
    let l = bnap_core::Limits::from_manifest(&ManifestLimits {
        max_offer: Some(9000),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(l.max_offer, 9000);
}

fn credential() -> (Offer, Credential) {
    let o = route_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    let mut c = Credential::new(OfferRef::Id(o.offer_id()));
    c.pay = Some(SchemePart {
        scheme: "bnap:notes".into(),
        body: b"body".to_vec(),
        witness: vec![1; 64],
    });
    c.attest = vec![SchemePart::new("httpsig:web-bot-auth", b"wba".to_vec())];
    c.binding = Some([3; 32]);
    (o, c)
}

#[test]
fn attest_list_out_of_order_or_duplicate() {
    let (_, mut c) = credential();
    c.attest
        .push(SchemePart::new("httpauth:DPoP", b"dpop".to_vec()));
    assert_eq!(
        malformed(c.to_bytes()),
        MalformedKind::Rule("attest list out of order")
    );
    c.sort_attest();
    let b = c.to_bytes().unwrap();
    assert_eq!(Credential::parse(&b).unwrap(), c);
    // Crafted out-of-order bytes.
    let items: Vec<Vec<u8>> = [&c.attest[1], &c.attest[0]]
        .iter()
        .map(|p| p.to_bytes().unwrap())
        .collect();
    let crafted = with_record(&b, 6, Some(entry_list(&items)));
    assert_eq!(
        malformed(Credential::parse(&crafted)),
        MalformedKind::Rule("attest list out of order")
    );
    let items: Vec<Vec<u8>> = [&c.attest[0], &c.attest[0]]
        .iter()
        .map(|p| p.to_bytes().unwrap())
        .collect();
    let crafted = with_record(&b, 6, Some(entry_list(&items)));
    assert!(matches!(
        malformed(Credential::parse(&crafted)),
        MalformedKind::DuplicateScheme(_)
    ));
}

#[test]
fn binding_without_a_class_s_scheme() {
    let (_, mut c) = credential();
    c.check_binding_classes(class_of).unwrap();
    c.pay = None;
    assert_eq!(
        malformed(c.check_binding_classes(class_of)),
        MalformedKind::Rule("binding without a class S scheme")
    );
    c.binding = None;
    c.check_binding_classes(class_of).unwrap();
}

#[test]
fn offer_and_offer_id_exactly_one() {
    let (o, c) = credential();
    let b = c.to_bytes().unwrap();
    let both = with_record(&b, 2, Some(o.bytes().to_vec()));
    assert_eq!(
        malformed(Credential::parse(&both)),
        MalformedKind::Rule("exactly one of offer and offer_id")
    );
    let neither = with_record(&b, 12, None);
    assert_eq!(
        malformed(Credential::parse(&neither)),
        MalformedKind::Rule("exactly one of offer and offer_id")
    );
    // Neither pay nor attest.
    let empty = with_record(&with_record(&b, 4, None), 6, None);
    assert_eq!(
        malformed(Credential::parse(&empty)),
        MalformedKind::Rule("a credential holds pay, attest, or both")
    );
    // Version 2.
    let v2 = with_record(&b, 0, Some(encoding::tu64(2)));
    assert_eq!(code(Credential::parse(&v2)), ErrorCode::Version);
}

#[test]
fn credential_unknown_odd_is_ignored_and_ext_is_covered() {
    let (o, c) = credential();
    let bytes = c.to_bytes().unwrap();
    let ctx = c.context(&o.offer_id(), &act());
    let dg = c.digest(&ctx);
    // GREASE and other odd records change nothing.
    let mut greased = c.clone();
    greased.unknown = vec![(3_000_000_101, vec![9, 9])];
    let gp = Credential::parse(&greased.to_bytes().unwrap()).unwrap();
    assert_eq!(gp.digest(&gp.context(&o.offer_id(), &act())), dg);
    // An unknown even top-level record is malformed.
    assert_eq!(
        malformed(Credential::parse(&with_record(&bytes, 14, Some(vec![])))),
        MalformedKind::UnknownEvenType(14)
    );
    // ext enters the Context; unknown even ext types are malformed.
    let ext = TlvStream::from_records([(1, b"hint".to_vec())]).unwrap();
    let mut with_ext = c.clone();
    with_ext.ext = ext;
    let ep = Credential::parse(&with_ext.to_bytes().unwrap()).unwrap();
    assert_ne!(ep.context(&o.offer_id(), &act()), ctx);
    let even = TlvStream::from_records([(2, b"x".to_vec())]).unwrap();
    let crafted = with_record(&bytes, 10, Some(even.to_bytes()));
    assert_eq!(
        malformed(Credential::parse(&crafted)),
        MalformedKind::UnknownEvenType(2)
    );
    let opts = CredentialParse {
        known_ext_types: &[2],
        ..Default::default()
    };
    Credential::parse_with(&crafted, &opts).unwrap();
    // An empty binding record means no binding.
    let nb = with_record(&bytes, 8, Some(vec![]));
    assert_eq!(Credential::parse(&nb).unwrap().binding, None);
}

#[test]
fn credential_scheme_not_offered() {
    let (o, mut c) = credential();
    c.attest = vec![SchemePart::new("httpauth:DPoP", b"x".to_vec())];
    let cached = o.clone();
    assert_eq!(
        gate().check_credential(&c, move |_| Some(cached)),
        Err(Error::NotOffered("httpauth:DPoP".into()))
    );
    // The cache must return the offer the credential names.
    let other = exact_fields()
        .sign(&offer_key(), Some(&mac()), &AUX0)
        .unwrap();
    assert_eq!(
        code(gate().check_credential(&c, move |_| Some(other))),
        ErrorCode::BadOffer
    );
}

fn manifest(root: &SigningKey, backup: &SigningKey, seq: u64, issued: u64) -> Manifest {
    Manifest {
        bnap: 1,
        origin: ORIGIN.into(),
        seq,
        issued,
        max_age: 604_800,
        root: root.public_key(),
        backup: backup.public_key(),
        keys: vec![ManifestKey {
            kid: offer_key().public_key(),
            key_use: KeyUse::Offer,
            not_after: issued + 1000,
        }],
        required: false,
        limits: ManifestLimits::default(),
        carriers: vec!["http".into()],
        routes: vec![],
    }
}

#[test]
fn manifest_rollback_and_double_rotation() {
    let (a, b, c, d) = (
        key(b"root a"),
        key(b"root b"),
        key(b"root c"),
        key(b"root d"),
    );
    let m1 = manifest(&a, &b, 5, NOW).sign(&a, &AUX0).unwrap();
    let (pin, _) = manifest::accept(None, ORIGIN, &m1, NOW).unwrap();
    // The same bytes again are fine; an older seq with other bytes is a rollback.
    manifest::accept(Some(&pin), ORIGIN, &m1, NOW + 10).unwrap();
    let m0 = manifest(&a, &b, 4, NOW + 5).sign(&a, &AUX0).unwrap();
    assert_eq!(
        manifest::accept(Some(&pin), ORIGIN, &m0, NOW + 10).unwrap_err(),
        ManifestError::Rollback
    );
    let m5 = manifest(&a, &b, 5, NOW + 5).sign(&a, &AUX0).unwrap();
    assert_eq!(
        manifest::accept(Some(&pin), ORIGIN, &m5, NOW + 10).unwrap_err(),
        ManifestError::Rollback
    );
    // The current root may not change the backup.
    let swap = manifest(&a, &c, 6, NOW + 5).sign(&a, &AUX0).unwrap();
    assert_eq!(
        manifest::accept(Some(&pin), ORIGIN, &swap, NOW + 10).unwrap_err(),
        ManifestError::PinMismatch
    );
    // A rotation to the backup is accepted.
    let rot = manifest(&b, &c, 6, NOW + 5).sign(&b, &AUX0).unwrap();
    let (pin2, _) = manifest::accept(Some(&pin), ORIGIN, &rot, NOW + 10).unwrap();
    assert_eq!(pin2.root, b.public_key());
    // A client that missed the first rotation cannot follow a second one.
    let rot2 = manifest(&c, &d, 7, NOW + 6).sign(&c, &AUX0).unwrap();
    assert_eq!(
        manifest::accept(Some(&pin), ORIGIN, &rot2, NOW + 10).unwrap_err(),
        ManifestError::PinMismatch
    );
    manifest::accept(Some(&pin2), ORIGIN, &rot2, NOW + 10).unwrap();
    // Once the pin lapses the client trusts on first use again.
    manifest::accept(
        Some(&pin),
        ORIGIN,
        &manifest(&c, &d, 1, NOW + 700_000).sign(&c, &AUX0).unwrap(),
        NOW + 700_000,
    )
    .unwrap();
}

#[test]
fn manifest_document_rules() {
    let a = key(b"root a");
    let b = key(b"root b");
    let good = manifest(&a, &b, 1, NOW);
    let doc = good.sign(&a, &AUX0).unwrap();
    // Another origin.
    assert_eq!(
        manifest::accept(None, "https://evil.example", &doc, NOW).unwrap_err(),
        ManifestError::Origin
    );
    // Not yet issued, or past max_age.
    assert_eq!(
        manifest::accept(None, ORIGIN, &doc, NOW - 61).unwrap_err(),
        ManifestError::Time
    );
    assert_eq!(
        manifest::accept(None, ORIGIN, &doc, NOW + 604_861).unwrap_err(),
        ManifestError::Time
    );
    manifest::accept(None, ORIGIN, &doc, NOW + 604_860).unwrap();
    // Signed by a key other than root.
    let mut v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    v["seq"] = 2.into();
    let edited = serde_json::to_vec(&v).unwrap();
    assert_eq!(
        manifest::accept(None, ORIGIN, &edited, NOW).unwrap_err(),
        ManifestError::Signature
    );
    // An unknown member is covered by the signature.
    let mut v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    v["future"] = "x".into();
    let edited = serde_json::to_vec(&v).unwrap();
    assert_eq!(
        manifest::accept(None, ORIGIN, &edited, NOW).unwrap_err(),
        ManifestError::Signature
    );
    // Value rules.
    let mut v: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    v["seq"] = serde_json::json!(1.5);
    assert!(matches!(
        manifest::SignedManifest::parse(&serde_json::to_vec(&v).unwrap()),
        Err(ManifestError::Value(_))
    ));
    // bnap and max_age.
    let mut m = good.clone();
    m.bnap = 2;
    assert_eq!(
        manifest::SignedManifest::parse(&m.sign(&a, &AUX0).unwrap()).unwrap_err(),
        ManifestError::Version
    );
    let mut m = good.clone();
    m.max_age = 2_592_001;
    assert_eq!(
        manifest::SignedManifest::parse(&m.sign(&a, &AUX0).unwrap()).unwrap_err(),
        ManifestError::MaxAge
    );
    // Signing with a key other than root is refused.
    assert!(good.sign(&b, &AUX0).is_err());
    // Missing sig.
    assert!(manifest::SignedManifest::parse(&good.jcs().unwrap()).is_err());
}

#[test]
fn receipt_client_rules() {
    let k = key(b"bnap test receipt key");
    let fields = ResponseFields {
        status: Status::Failed,
        replayed: false,
        charged: 0,
        unit: None,
        offer_id: bnap_core::OfferId([5; 32]),
        digest: bnap_core::Digest([6; 32]),
        metered_units: None,
        scheme_result: None,
        receipt_key: k.public_key(),
        settled_at: NOW,
        unknown: vec![],
    };
    let r = fields.sign(&k, &AUX0).unwrap();
    let id = bnap_core::OfferId([5; 32]);
    let dg = bnap_core::Digest([6; 32]);
    let pin = [ManifestKey {
        kid: k.public_key(),
        key_use: KeyUse::Receipt,
        not_after: NOW,
    }];
    r.check_client(&pin, NOW + 60, &id, &dg).unwrap();
    assert_eq!(
        r.check_client(&pin, NOW + 61, &id, &dg),
        Err(ReceiptError::Clock)
    );
    assert_eq!(
        r.check_client(&pin, NOW, &bnap_core::OfferId([0; 32]), &dg),
        Err(ReceiptError::WrongRequest)
    );
    let offer_use = [ManifestKey {
        kid: k.public_key(),
        key_use: KeyUse::Offer,
        not_after: NOW,
    }];
    assert_eq!(
        r.check_client(&offer_use, NOW, &id, &dg),
        Err(ReceiptError::NotPinned)
    );
    let lapsed = [ManifestKey {
        kid: k.public_key(),
        key_use: KeyUse::Receipt,
        not_after: NOW - 1,
    }];
    assert_eq!(
        r.check_client(&lapsed, NOW, &id, &dg),
        Err(ReceiptError::NotPinned)
    );
    // A replay keeps the original settled_at, so the clock rule is off.
    let replay = ResponseFields {
        replayed: true,
        ..fields
    }
    .sign(&k, &AUX0)
    .unwrap();
    replay.check_client(&pin, NOW + 100_000, &id, &dg).unwrap();
    // unit and metered_units presence.
    r.check_required(false, false).unwrap();
    assert!(r.check_required(false, true).is_err());
    assert!(r.check_required(true, false).is_err());
    // status outside 0 to 1.
    let b = with_record(r.bytes(), 2, Some(encoding::tu64(2)));
    assert_eq!(
        malformed(Response::parse(&b)),
        MalformedKind::Rule("status outside 0 to 1")
    );
}

#[test]
fn error_objects() {
    use bnap_core::ErrorObject;
    let mut e = ErrorObject::new(ErrorCode::RateLimited);
    e.retry_after = Some(30);
    e.scheme_code = Some("bnap:notes/OUTPUT_REUSED".into());
    let b = e.to_bytes().unwrap();
    assert_eq!(ErrorObject::parse(&b).unwrap(), e);
    let long = ErrorObject {
        detail: Some("x".repeat(257)),
        ..ErrorObject::new(ErrorCode::Malformed)
    };
    assert!(long.to_bytes().is_err());
    // A registry code above 1,000 round-trips but is not a socket code.
    let reg = ErrorObject {
        code: 1001,
        ..ErrorObject::new(ErrorCode::Malformed)
    };
    let p = ErrorObject::parse(&reg.to_bytes().unwrap()).unwrap();
    assert_eq!(p.code, 1001);
    assert_eq!(p.socket_code(), None);
    // Typed errors map to their codes.
    let r = Offer::parse(&[0xff]);
    assert_eq!(code(r), ErrorCode::Malformed);
}
