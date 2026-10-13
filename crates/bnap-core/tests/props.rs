//! Property tests: encoding roundtrips for BigSize, tu64, TLV streams,
//! Offers, Credentials and Responses, and "the parser never panics" for every
//! parser in the crate.

use std::collections::BTreeMap;

use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::error::ErrorObject;
use bnap_core::hash::sha256;
use bnap_core::manifest::{self, SignedManifest};
use bnap_core::offer::{AttestEntry, Effect, NativeEntry, Offer, OfferFields, PayEntry};
use bnap_core::response::{Response, ResponseFields, Status};
use bnap_core::tlv::{StreamKind, TlvStream, parse_entry_list};
use bnap_core::{Digest, Key, OfferId, Scope, SigningKey, encoding};
use proptest::prelude::*;

const AUX0: [u8; 32] = [0; 32];
const BIG: usize = 1 << 20;

fn offer_key() -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(b"bnap test offer key")).unwrap()
}

fn mac() -> [u8; 32] {
    sha256(b"bnap test mac key")
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn scheme_id() -> impl Strategy<Value = String> {
    "[a-z]{1,8}:[a-zA-Z0-9/_.-]{1,12}"
}

fn odd_nested_type() -> impl Strategy<Value = u64> {
    prop_oneof![
        (0u64..120).prop_map(|t| 2 * t + 1),
        (0u64..500).prop_map(|t| 3_000_000_001 + 2 * t),
        (500_000_000u64..999_999_999).prop_map(|t| 2 * t + 1),
    ]
}

fn odd_top_type() -> impl Strategy<Value = u64> {
    prop_oneof![odd_nested_type(), (1001u64..1_000_000).prop_map(|t| 2 * t + 1)]
}

fn unknown(kind: impl Strategy<Value = u64>) -> impl Strategy<Value = Vec<(u64, Vec<u8>)>> {
    prop::collection::btree_map(kind, bytes(6), 0..3).prop_map(|m| m.into_iter().collect())
}

fn pay_entry(metered: bool, expires: u64) -> impl Strategy<Value = PayEntry> {
    (
        scheme_id(),
        any::<u64>(),
        "[A-Za-z]{1,6}",
        prop::option::of(0u64..=expires),
        prop::option::of(bytes(16)),
        prop::option::of(any::<u64>()),
        unknown(odd_nested_type()),
    )
        .prop_map(move |(scheme, amount, unit, quote_expires, params, rate, unknown)| PayEntry {
            scheme,
            amount,
            unit,
            quote_expires,
            params,
            rate: if metered { Some(rate.unwrap_or(1)) } else { rate },
            unknown,
        })
}

fn attest_entry() -> impl Strategy<Value = AttestEntry> {
    (
        scheme_id(),
        0u8..4,
        1u64..=10_000,
        1u64..=u64::MAX,
        prop::option::of(bytes(16)),
        unknown(odd_nested_type()),
    )
        .prop_map(|(scheme, e, v, epoch, params, unknown)| {
            let mut a = match e {
                0 => AttestEntry::new(scheme, Effect::Required),
                1 => AttestEntry::new(scheme, Effect::Waive),
                2 => AttestEntry::discount(scheme, v),
                _ => AttestEntry::quota(scheme, v, epoch),
            };
            a.params = params;
            a.unknown = unknown;
            a
        })
}

fn dedup_by_scheme<T>(v: Vec<T>, scheme: impl Fn(&T) -> &str) -> Vec<T> {
    let mut seen = std::collections::BTreeSet::new();
    v.into_iter().filter(|e| seen.insert(scheme(e).to_owned())).collect()
}

prop_compose! {
    fn offer_fields()(
        route_scope in any::<bool>(),
        metered in any::<bool>(),
        expires in any::<u64>(),
    )(
        scope in any::<[u8; 32]>(),
        route_scope in Just(route_scope),
        metered in Just(metered),
        expires in Just(expires),
        headers in prop::collection::vec("[a-z0-9-]{1,10}", 0..3),
        info in prop::option::of("https://[a-z]{1,8}\\.example/[a-z]{0,8}"),
        nonce in any::<[u8; 16]>(),
        pay in prop::collection::vec(pay_entry(metered, expires), 0..4),
        attest in prop::collection::vec(attest_entry(), 0..3),
        issued_at in prop::option::of(any::<u64>()),
        native in prop::collection::vec((0u64..4, "[a-z0-9]{1,8}", bytes(24)), 0..3),
        unknown in unknown(odd_top_type()),
    ) -> OfferFields {
        let mut f = OfferFields::new(Scope(scope), expires, offer_key().public_key(), nonce);
        f.route_scope = route_scope;
        f.metered = metered;
        f.headers = headers;
        f.info = info;
        f.pay = dedup_by_scheme(pay, |e| &e.scheme);
        f.attest = dedup_by_scheme(attest, |e| &e.scheme);
        if f.pay.is_empty() && !f.attest.iter().any(|a| a.effect == Effect::Waive) {
            f.attest.retain(|a| a.scheme != "waive:x");
            f.attest.push(AttestEntry::new("waive:x", Effect::Waive));
        }
        f.issued_at = issued_at;
        if !route_scope && !f.pay.is_empty() {
            let n = u64::try_from(f.pay.len()).unwrap();
            f.native = native.into_iter().map(|(i, k, d)| NativeEntry::new(i % n, k, d)).collect();
        }
        f.unknown = unknown;
        f
    }
}

fn scheme_part() -> impl Strategy<Value = SchemePart> {
    (scheme_id(), bytes(40), bytes(70)).prop_map(|(scheme, body, witness)| SchemePart { scheme, body, witness })
}

prop_compose! {
    fn credential()(
        inline in any::<bool>(),
        offer_bytes in bytes(80),
        offer_id in any::<[u8; 32]>(),
        pay in prop::option::of(scheme_part()),
        attest in prop::collection::vec(scheme_part(), 0..4),
        binding in prop::option::of(any::<[u8; 32]>()),
        ext in prop::collection::btree_map(odd_nested_type(), bytes(8), 0..3),
        unknown in unknown(odd_top_type()),
    ) -> Credential {
        let mut c = Credential::new(if inline { OfferRef::Inline(offer_bytes) } else { OfferRef::Id(OfferId(offer_id)) });
        c.attest = dedup_by_scheme(attest, |p| &p.scheme);
        c.sort_attest();
        c.pay = pay.or_else(|| c.attest.is_empty().then(|| SchemePart::new("pay:x", b"b".to_vec())));
        c.binding = binding;
        c.ext = TlvStream::from_records(ext).unwrap();
        c.unknown = unknown;
        c
    }
}

prop_compose! {
    fn response_fields()(
        failed in any::<bool>(),
        replayed in any::<bool>(),
        charged in any::<u64>(),
        unit in prop::option::of("[a-z]{1,5}"),
        offer_id in any::<[u8; 32]>(),
        digest in any::<[u8; 32]>(),
        metered_units in prop::option::of(any::<u64>()),
        scheme_result in prop::option::of(bytes(40)),
        settled_at in any::<u64>(),
        unknown in unknown(odd_top_type()),
    ) -> ResponseFields {
        ResponseFields {
            status: if failed { Status::Failed } else { Status::Ok },
            replayed,
            charged,
            unit,
            offer_id: OfferId(offer_id),
            digest: Digest(digest),
            metered_units,
            scheme_result,
            receipt_key: offer_key().public_key(),
            settled_at,
            unknown: unknown.into_iter().filter(|(t, _)| !bnap_core::tlv::is_signature_type(*t)).collect(),
        }
    }
}

/// Random TLV-shaped input: well-framed streams with random small types, so
/// the object parsers get past the framing and exercise their record rules.
fn tlv_shaped() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::btree_map(
        prop_oneof![0u64..30, 238u64..246, Just(3_000_000_001)],
        prop_oneof![bytes(40), Just(Vec::new()), Just(vec![1]), any::<[u8; 32]>().prop_map(|a| a.to_vec())],
        0..14,
    )
    .prop_map(|m| TlvStream::from_records(m).unwrap().to_bytes())
}

/// Applies random edits to a valid encoding.
fn mutate(base: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    let n = base.len().max(1);
    prop::collection::vec((0..n, any::<u8>(), 0u8..4), 1..6).prop_map(move |edits| {
        let mut b = base.clone();
        for (i, v, op) in edits {
            let i = i.min(b.len());
            match op {
                0 if i < b.len() => b[i] = v,
                1 => b.insert(i, v),
                2 if i < b.len() => {
                    b.remove(i);
                }
                _ => b.truncate(i),
            }
        }
        b
    })
}

fn sample_offer() -> Vec<u8> {
    let mut f = OfferFields::new(Scope([2; 32]), 100, offer_key().public_key(), [0; 16]);
    let mut p = PayEntry::new("bnap:notes", 2100, "sat");
    p.rate = Some(500);
    f.pay = vec![p, PayEntry::new("payment:lightning/charge", 21, "sat")];
    f.attest = vec![AttestEntry::discount("httpsig:web-bot-auth", 2000), AttestEntry::quota("q:x", 5, 60)];
    f.native = vec![NativeEntry::new(1, "bolt11", b"lnbc".to_vec())];
    f.headers = vec!["accept".into()];
    f.unknown = vec![(3_000_000_001, vec![10, 10])];
    f.sign(&offer_key(), Some(&mac()), &AUX0).unwrap().bytes().to_vec()
}

fn sample_credential() -> Vec<u8> {
    let mut c = Credential::new(OfferRef::Inline(sample_offer()));
    c.pay = Some(SchemePart { scheme: "bnap:notes".into(), body: b"b".to_vec(), witness: vec![7; 64] });
    c.attest = vec![SchemePart::new("httpsig:web-bot-auth", b"w".to_vec())];
    c.binding = Some([1; 32]);
    c.ext = TlvStream::from_records([(1, b"e".to_vec())]).unwrap();
    c.to_bytes().unwrap()
}

fn sample_response() -> Vec<u8> {
    ResponseFields {
        status: Status::Ok,
        replayed: true,
        charged: 340,
        unit: Some("sat".into()),
        offer_id: OfferId([1; 32]),
        digest: Digest([2; 32]),
        metered_units: Some(850),
        scheme_result: Some(b"r".to_vec()),
        receipt_key: offer_key().public_key(),
        settled_at: 5,
        unknown: vec![],
    }
    .sign(&offer_key(), &AUX0)
    .unwrap()
    .bytes()
    .to_vec()
}

/// Feeds bytes to every byte parser; none may panic.
fn parse_all(b: &[u8]) {
    let _ = encoding::read_bigsize(b);
    let _ = encoding::read_tu64(b, 0);
    let _ = encoding::read_lp(b);
    let _ = TlvStream::parse(b, StreamKind::TopLevel);
    let _ = TlvStream::parse(b, StreamKind::Nested);
    let _ = parse_entry_list(b);
    if let Ok(o) = Offer::parse_with_limit(b, BIG) {
        let _ = o.verify_signature();
        let _ = o.verify_mac(&[mac()]);
        let _ = o.check_authenticity(&[mac()], &[offer_key().public_key()]);
        let _ = o.check_expiry(u64::MAX, Some("bnap:notes"));
        let _ = o.check_binding_classes(|_| None);
        let _ = o.fields().offer_id();
    }
    let _ = PayEntry::parse(b);
    let _ = AttestEntry::parse(b);
    let _ = NativeEntry::parse(b);
    let _ = SchemePart::parse(b);
    if let Ok(c) = Credential::parse(b) {
        let ctx = c.context(&OfferId([0; 32]), &Scope([0; 32]));
        let _ = c.digest(&ctx);
        let _ = c.replay_key(&ctx, &[[0; 32]]);
        let _ = c.to_bytes();
    }
    if let Ok(r) = Response::parse_with_limit(b, BIG) {
        let _ = r.verify_ack();
        let _ = r.check_client(&[], u64::MAX, &OfferId([0; 32]), &Digest([0; 32]));
    }
    let _ = ErrorObject::parse(b);
    let _ = SignedManifest::parse(b);
    let _ = manifest::accept(None, "https://api.example", b, 0);
}

fn json_value() -> impl Strategy<Value = serde_json::Value> {
    use serde_json::Value;
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>().prop_filter("finite", |f| f.is_finite()).prop_map(Value::from),
        "[a-z0-9]{0,70}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
            prop::collection::btree_map(
                prop_oneof![
                    Just("bnap".to_owned()),
                    Just("origin".to_owned()),
                    Just("seq".to_owned()),
                    Just("root".to_owned()),
                    Just("keys".to_owned()),
                    Just("sig".to_owned()),
                    Just("routes".to_owned()),
                    "[a-z]{1,6}"
                ],
                inner,
                0..8
            )
            .prop_map(|m: BTreeMap<String, serde_json::Value>| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn bigsize_roundtrip(n in any::<u64>()) {
        let e = encoding::bigsize(n);
        prop_assert_eq!(e.len(), encoding::bigsize_len(n));
        prop_assert_eq!(encoding::read_bigsize(&e), Ok((n, e.len())));
        let mut ext = e.clone();
        ext.push(0xaa);
        prop_assert_eq!(encoding::read_bigsize(&ext), Ok((n, e.len())));
    }

    #[test]
    fn bigsize_non_minimal_rejected(n in any::<u64>()) {
        let mut wide = Vec::new();
        if n <= 0xfc {
            wide.push(0xfd);
            wide.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
        } else if n <= 0xffff {
            wide.push(0xfe);
            wide.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
        } else if n <= 0xffff_ffff {
            wide.push(0xff);
            wide.extend_from_slice(&n.to_be_bytes());
        } else {
            return Ok(());
        }
        prop_assert!(encoding::read_bigsize(&wide).is_err());
    }

    #[test]
    fn tu64_roundtrip(n in any::<u64>(), pad in 1usize..8) {
        let e = encoding::tu64(n);
        prop_assert!(e.len() <= 8);
        prop_assert!(e.first() != Some(&0));
        prop_assert_eq!(encoding::read_tu64(&e, 0), Ok(n));
        if e.len() + pad <= 8 {
            let mut z = vec![0; pad];
            z.extend_from_slice(&e);
            prop_assert!(encoding::read_tu64(&z, 0).is_err());
        }
    }

    #[test]
    fn lp_roundtrip(x in bytes(300)) {
        let e = encoding::lp(&x);
        prop_assert_eq!(encoding::read_lp(&e), Ok((x.as_slice(), e.len())));
    }

    #[test]
    fn tlv_roundtrip(m in prop::collection::btree_map(any::<u64>(), bytes(40), 0..12)) {
        let s = TlvStream::from_records(m.clone()).unwrap();
        let b = s.to_bytes();
        let p = TlvStream::parse(&b, StreamKind::TopLevel).unwrap();
        prop_assert_eq!(&p, &s);
        prop_assert_eq!(p.records().iter().map(|(t, _)| *t).collect::<Vec<_>>(), m.keys().copied().collect::<Vec<_>>());
        prop_assert_eq!(p.to_bytes(), b);
    }

    #[test]
    fn tlv_nested_ranges(t in any::<u64>()) {
        let b = TlvStream::from_records([(t, vec![])]).unwrap().to_bytes();
        prop_assert_eq!(TlvStream::parse(&b, StreamKind::Nested).is_ok(), bnap_core::tlv::nested_type_allowed(t));
    }

    #[test]
    fn entry_list_roundtrip(items in prop::collection::vec(bytes(30), 0..6)) {
        let l = bnap_core::tlv::entry_list(&items);
        let back: Vec<Vec<u8>> = parse_entry_list(&l).unwrap().into_iter().map(<[u8]>::to_vec).collect();
        prop_assert_eq!(back, items);
    }

    #[test]
    fn offer_roundtrip(f in offer_fields()) {
        let o = f.sign_with_limit(&offer_key(), Some(&mac()), &AUX0, BIG).unwrap();
        prop_assert_eq!(o.fields(), &f);
        let p = Offer::parse_with_limit(o.bytes(), BIG).unwrap();
        prop_assert_eq!(&p, &o);
        prop_assert_eq!(p.offer_id(), f.offer_id().unwrap());
        prop_assert!(p.verify_signature().is_ok());
        prop_assert!(p.verify_mac(&[mac()]).is_ok());
        // Natives never change the OfferID.
        let mut bare = f.clone();
        bare.native.clear();
        prop_assert_eq!(bare.offer_id().unwrap(), p.offer_id());
    }

    #[test]
    fn credential_roundtrip(c in credential()) {
        let b = c.to_bytes().unwrap();
        let p = Credential::parse_with(&b, &bnap_core::CredentialParse { max_credential: BIG, known_ext_types: &[] }).unwrap();
        prop_assert_eq!(&p, &c);
        prop_assert_eq!(p.to_bytes().unwrap(), b);
        let ctx = p.context(&OfferId([3; 32]), &Scope([4; 32]));
        prop_assert_eq!(ctx, c.context(&OfferId([3; 32]), &Scope([4; 32])));
        // The witness is outside the Digest; the binding is outside the Context.
        let mut w = c.clone();
        if let Some(pay) = &mut w.pay { pay.witness.push(1); }
        w.binding = None;
        prop_assert_eq!(w.context(&OfferId([3; 32]), &Scope([4; 32])), ctx);
        let mut w2 = c.clone();
        if let Some(pay) = &mut w2.pay { pay.witness.push(1); }
        prop_assert_eq!(w2.digest(&ctx), c.digest(&ctx));
    }

    #[test]
    fn response_roundtrip(f in response_fields()) {
        let r = f.sign_with_limit(&offer_key(), &AUX0, BIG).unwrap();
        prop_assert_eq!(r.fields(), &f);
        let p = Response::parse_with_limit(r.bytes(), BIG).unwrap();
        prop_assert_eq!(&p, &r);
        prop_assert!(p.verify_ack().is_ok());
    }

    #[test]
    fn error_object_roundtrip(code in any::<u64>(), sc in prop::option::of("[a-z:/_A-Z]{0,30}"), d in prop::option::of(".{0,80}"), ra in prop::option::of(any::<u64>())) {
        let e = ErrorObject { code, scheme_code: sc, detail: d, retry_after: ra, unknown: vec![] };
        let e = match &e.detail { Some(d) if d.len() > 256 => ErrorObject { detail: None, ..e }, _ => e };
        prop_assert_eq!(ErrorObject::parse(&e.to_bytes().unwrap()).unwrap(), e);
    }

    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(b in bytes(700)) {
        parse_all(&b);
    }

    #[test]
    fn parsers_never_panic_on_tlv_shaped_input(b in tlv_shaped()) {
        parse_all(&b);
    }

    #[test]
    fn parsers_never_panic_on_mutated_offers(b in mutate(sample_offer())) {
        parse_all(&b);
    }

    #[test]
    fn parsers_never_panic_on_mutated_credentials(b in mutate(sample_credential())) {
        parse_all(&b);
    }

    #[test]
    fn parsers_never_panic_on_mutated_responses(b in mutate(sample_response())) {
        parse_all(&b);
    }

    #[test]
    fn manifest_parser_never_panics_on_json(v in json_value()) {
        let b = serde_json::to_vec(&v).unwrap();
        let _ = SignedManifest::parse(&b);
        let _ = manifest::accept(None, "https://api.example", &b, 1);
    }

    #[test]
    fn keys_from_arbitrary_bytes_never_panic(k in any::<[u8; 32]>(), m in any::<[u8; 32]>(), s in prop::collection::vec(any::<u8>(), 64)) {
        let sig = bnap_core::Signature(<[u8; 64]>::try_from(s.as_slice()).unwrap());
        let _ = Key(k).verify(&m, &sig);
        let _ = SigningKey::from_secret_bytes(&k);
    }
}
