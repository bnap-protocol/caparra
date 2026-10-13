//! Signing through sealed core messages reproduces the draft-00 vectors,
//! and refuses bad signatures and wrong keys.

use bnap_core::hash::{Digest, OfferId, sha256};
use bnap_core::manifest::KeyUse;
use bnap_core::offer::{AttestEntry, OfferFields, PayEntry};
use bnap_core::response::{ResponseFields, Status};
use bnap_core::sign::{Purpose, SignError, UnsignedOffer, UnsignedResponse};
use bnap_core::{Scope, SigningKey, http};
use serde_json::Value;

const VECTORS: &str = include_str!("data/vectors.json");
const AUX0: [u8; 32] = [0; 32];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    let mut b = [0u8; 32];
    hex::decode_to_slice(v.as_str().unwrap(), &mut b).unwrap();
    b
}

fn sk(label: &[u8]) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(label)).unwrap()
}

/// The 305-byte route offer of draft-00 section 14.
fn route_offer_fields(offer_key: &SigningKey) -> OfferFields {
    let nonce: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let scope: Scope = http::route_scope("https://api.example", "chat");
    let mut f = OfferFields::new(scope, 1_791_700_300, offer_key.public_key(), nonce);
    f.route_scope = true;
    f.metered = true;
    f.info = Some("https://api.example/.well-known/bnap".into());
    let mut notes = PayEntry::new("bnap:notes", 2100, "sat");
    notes.rate = Some(500);
    f.pay = vec![notes];
    f.attest = vec![AttestEntry::discount("httpsig:web-bot-auth", 2000)];
    f.unknown = vec![(3_000_000_001, vec![0x0a, 0x0a])];
    f
}

#[test]
fn the_offer_vector_through_a_core_message() {
    let v = vectors();
    let key = sk(b"bnap test offer key");
    let mac = sha256(b"bnap test mac key");
    let unsigned = UnsignedOffer::new(&route_offer_fields(&key), Some(&mac)).unwrap();
    let msg = unsigned.message();
    assert_eq!(msg.purpose(), Purpose::OfferSig);
    assert_eq!(msg.purpose().key_use(), KeyUse::Offer);
    assert_eq!(msg.key(), &key.public_key());
    let sig = msg.sign_with(&key, &AUX0).unwrap();
    let offer = unsigned.finish(&sig).unwrap();
    assert_eq!(
        hex::encode(offer.bytes()),
        v["offer"]["bytes"].as_str().unwrap()
    );
    assert_eq!(offer.offer_id(), OfferId(hex32(&v["offer"]["offer_id"])));
}

#[test]
fn the_response_vector_through_a_core_message() {
    let v = vectors();
    let key = sk(b"bnap test receipt key");
    let fields = ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 340,
        unit: Some("sat".into()),
        offer_id: OfferId(hex32(&v["offer"]["offer_id"])),
        digest: Digest(hex32(&v["credential"]["digest"])),
        metered_units: Some(850),
        scheme_result: Some(b"change signatures placeholder".to_vec()),
        receipt_key: key.public_key(),
        settled_at: 1_791_700_042,
        unknown: Vec::new(),
    };
    let unsigned = UnsignedResponse::new(&fields).unwrap();
    assert_eq!(unsigned.message().purpose(), Purpose::Ack);
    assert_eq!(unsigned.message().purpose().key_use(), KeyUse::Receipt);
    let sig = unsigned.message().sign_with(&key, &AUX0).unwrap();
    let resp = unsigned.finish(&sig).unwrap();
    assert_eq!(
        hex::encode(resp.bytes()),
        v["response"]["bytes"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(resp.ack().0),
        v["response"]["ack"].as_str().unwrap()
    );
    // Same bytes as the local-key path of part A.
    assert_eq!(resp, fields.sign(&key, &AUX0).unwrap());
}

#[test]
fn a_bad_signature_or_a_wrong_key_is_refused() {
    let key = sk(b"bnap test offer key");
    let other = sk(b"someone else");
    let mac = sha256(b"k");
    let fields = route_offer_fields(&key);

    let unsigned = UnsignedOffer::new(&fields, Some(&mac)).unwrap();
    assert_eq!(
        unsigned.message().sign_with(&other, &AUX0),
        Err(SignError::WrongKey)
    );
    // A signer that signs with the wrong key, or returns garbage.
    let wrong = other.sign(unsigned.message().digest(), &AUX0);
    assert_eq!(
        unsigned.finish(&wrong).unwrap_err(),
        SignError::BadSignature
    );

    let unsigned = UnsignedOffer::new(&fields, Some(&mac)).unwrap();
    let mut sig = unsigned.message().sign_with(&key, &AUX0).unwrap();
    sig.0[0] ^= 1;
    assert_eq!(unsigned.finish(&sig).unwrap_err(), SignError::BadSignature);
}

#[test]
fn an_offer_without_mac_needs_issued_at() {
    let key = sk(b"bnap test offer key");
    let mut fields = route_offer_fields(&key);
    assert!(matches!(
        UnsignedOffer::new(&fields, None),
        Err(SignError::Object(_))
    ));
    fields.issued_at = Some(1_791_700_000);
    let unsigned = UnsignedOffer::new(&fields, None).unwrap();
    let sig = unsigned.message().sign_with(&key, &AUX0).unwrap();
    let offer = unsigned.finish(&sig).unwrap();
    assert!(offer.mac().is_none());
    offer.verify_signature().unwrap();
}

#[test]
fn messages_are_domain_separated() {
    // Each purpose has its own socket tag, so no signature made for one can
    // be replayed as the other.
    assert_eq!(Purpose::OfferSig.tag(), bnap_core::hash::tags::OFFER_SIG);
    assert_eq!(Purpose::Ack.tag(), bnap_core::hash::tags::ACK);
    assert_ne!(Purpose::OfferSig.tag(), Purpose::Ack.tag());
}
