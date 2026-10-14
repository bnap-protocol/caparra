//! The signer recomputes every message from the object's bytes: anything
//! that is not an offer's `S` or a Response's signed part under the
//! requested key is refused before a key is touched.

use bnap_core::hash::{Digest, OfferId, Scope, sha256, tagged_hash};
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::response::{ResponseFields, Status};
use bnap_core::schnorr::{Key, SigningKey};
use bnap_core::sign::{Purpose, UnsignedOffer};
use bnap_core::test_support::unsigned_response;
use bnap_signer_file::object::{MAX_OBJECT, ObjectError, recompute};

fn key(label: &[u8]) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(label)).unwrap()
}

fn offer(k: Key) -> UnsignedOffer {
    let mut f = OfferFields::new(Scope([1; 32]), 1_791_700_300, k, [2; 16]);
    f.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    f.unknown = vec![(3_000_000_001, vec![0x0a])];
    UnsignedOffer::new(&f, Some(&[7; 32])).unwrap()
}

fn response(k: Key) -> ResponseFields {
    ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 21,
        unit: Some("sat".into()),
        offer_id: OfferId([5; 32]),
        digest: Digest([6; 32]),
        metered_units: None,
        scheme_result: None,
        receipt_key: k,
        settled_at: 1_791_700_042,
        unknown: Vec::new(),
    }
}

#[test]
fn offers_and_acks_recompute_to_their_core_message() {
    let k = key(b"o").public_key();
    let u = offer(k);
    let m = u.message();
    assert_eq!(
        recompute(Purpose::OfferSig, &k, m.signed_bytes()),
        Ok(*m.digest())
    );
    let r = key(b"r").public_key();
    let u = unsigned_response(&response(r)).unwrap();
    let m = u.message();
    assert_eq!(
        recompute(Purpose::Ack, &r, m.signed_bytes()),
        Ok(*m.digest())
    );
}

#[test]
fn bytes_that_are_not_the_named_object_are_refused() {
    let k = key(b"o").public_key();
    let u = offer(k);
    let s = u.message().signed_bytes().to_vec();
    // The offer under another key, and as an ack.
    let other = key(b"x").public_key();
    assert_eq!(
        recompute(Purpose::OfferSig, &other, &s),
        Err(ObjectError::OtherKey)
    );
    assert!(matches!(
        recompute(Purpose::Ack, &k, &s),
        Err(ObjectError::Invalid {
            object: "response",
            ..
        })
    ));
    // A Response's signed part as an offer.
    let r = key(b"r").public_key();
    let resp = unsigned_response(&response(r)).unwrap();
    let rs = resp.message().signed_bytes().to_vec();
    assert!(matches!(
        recompute(Purpose::OfferSig, &r, &rs),
        Err(ObjectError::Invalid {
            object: "offer",
            ..
        })
    ));
    assert_eq!(recompute(Purpose::Ack, &k, &rs), Err(ObjectError::OtherKey));
    // A bare digest, a sighash-like 32 bytes, nothing.
    for raw in [
        &tagged_hash("bnap/offer-sig", &s)[..],
        &[0u8; 32][..],
        &[][..],
    ] {
        assert!(recompute(Purpose::OfferSig, &k, raw).is_err());
        assert!(recompute(Purpose::Ack, &r, raw).is_err());
    }
    // Truncated, or with trailing bytes.
    assert_eq!(
        recompute(Purpose::OfferSig, &k, &s[..s.len() - 1]),
        Err(ObjectError::Framing)
    );
    let mut longer = s.clone();
    longer.push(0);
    assert!(recompute(Purpose::OfferSig, &k, &longer).is_err());
    // A whole signed offer: its offer_sig and mac are in the signature range.
    let sig = u.message().sign_with(&key(b"o"), &[0; 32]).unwrap();
    let whole = u.finish(&sig).unwrap();
    assert_eq!(
        recompute(Purpose::OfferSig, &k, whole.bytes()),
        Err(ObjectError::SignatureRange(240))
    );
    // A record the offer rules forbid (an unknown even type).
    let mut bad = s.clone();
    bad.extend_from_slice(&[0xfe, 0xb2, 0xd0, 0x5e, 0x10, 0x00]);
    assert!(recompute(Purpose::OfferSig, &k, &bad).is_err());
    // Too large.
    assert_eq!(
        recompute(Purpose::OfferSig, &k, &vec![0; MAX_OBJECT + 1]),
        Err(ObjectError::TooLarge(MAX_OBJECT + 1))
    );
}
