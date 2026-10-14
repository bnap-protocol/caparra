//! The test vectors of `bnap-notes-draft-00.md` section 18.
//!
//! - 18.1 (the notes route offer, the fee offer, keysets A, B and C) is
//!   published in the spec and reproduced here byte for byte.
//! - 18.2 (items 1 to 9) is not published yet. This file generates it with
//!   this crate as the reference encoder, checks every number the spec
//!   states (amounts, charges, selected indices, `scheme_result` sizes,
//!   scheme codes), and compares the result with
//!   `tests/data/notes-vectors.json`. Regenerate that file with
//!   `BNAP_NOTES_REGEN=1` after a deliberate change. It should move to
//!   `bnap/vectors` once the spec repository takes it.
//!
//! Secret keys are SHA-256 of fixed strings and BIP-340 auxiliary
//! randomness is 32 zero bytes, as for the socket vectors.

#![allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::field_reassign_with_default
)]

mod common;

use std::sync::Arc;

use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::hash::{Context, sha256};
use bnap_core::ids::{self, rail};
use bnap_core::note::hash_to_curve;
use bnap_core::offer::{AttestEntry, Offer, OfferFields, PayEntry};
use bnap_core::pricing::{AdmitInput, Backing, BackingSource, PayValue, Refund, VerifiedAttest};
use bnap_core::response::Status;
use bnap_core::test_support::block_on;
use bnap_core::tlv::{entry_list, write_record};
use bnap_core::{BindingClass, SigningKey};
use bnap_plug::{CredentialScheme, OfferCtx, OfferRole};
use bnap_scheme_notes::client::{self, Derived, Note, PendingOutput};
use bnap_scheme_notes::issuer::{IssuerStore, QuoteRecord};
use bnap_scheme_notes::keyset::{BlindSigned, IssuerKeyset, verify_dleq};
use bnap_scheme_notes::test_support::{MemoryIssuerStore, keyset_a, keyset_b, keyset_c};
use bnap_scheme_notes::wire::{
    Body, FundQuote, Output, PointBytes, body_types, input_types, parse_scheme_result,
};
use bnap_scheme_notes::{NotesConfig, NotesScheme, SCHEME_ID, amount, codes, rk_mint};
use common::*;
use serde_json::{Value, json};

const EXPIRES: u64 = 1_791_703_600;
const SOCKET_EXPIRES: u64 = 1_791_700_300;
const VECTORS: &str = "tests/data/notes-vectors.json";

/// The notes route offer of 18.1, 413 bytes.
const ROUTE_OFFER_HEX: &str = concat!(
    "0001010220862d641e67813f6e78b20a81aa929519e66a978e69e8a4d3e27280990697f3a0040008000a046acb3a30",
    "0c2468747470733a2f2f6170692e6578616d706c652f2e77656c6c2d6b6e6f776e2f626e61700e20b28dad5f717c51",
    "44bdb0aa6db94bb6c79afa9b8bd9bc84825a2c1baafe64add91010000102030405060708090a0b0c0d0e0f12868500",
    "0a626e61703a6e6f746573020208340403736174086a001968747470733a2f2f6170692e6578616d706c652f636173",
    "6875024d280021011decbc482233faf1b58395ddb55c465e3bf6d8fa1c5a5b17219f7d5883b112a702016404002300",
    "21014423cf221427bb65863007387bbc9b74963e47b24c3ec3a25ddd673e9ed6e8980a0201f4141e1d001468747470",
    "7369673a7765622d626f742d61757468020102040207d0f040108b3bf0b2354e7363ba171b73ad57dfb594f6281ee8",
    "5067dbb6d74eb1bbe558fd03765abf702d22562f8399ee60fdb4d54bcdf1c05bf3f26776cd79eb9f5fecf220e77e4e",
    "3ef6ce609745c194c160d1814295ad7e4d6d5a56178d68cf40b4a5dd4cfeb2d05e01020a0a",
);

fn x(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

/// The scheme with exactly these keysets in its table and no funding, as
/// the 18.1 offer is built.
fn scheme_with(keysets: &[IssuerKeyset], max_fund: Option<u64>) -> NotesScheme {
    let issuer = Arc::new(MemoryIssuerStore::with_keysets(
        keysets.iter().map(|k| k.info().clone()),
    ));
    let mut config = NotesConfig::new(ISSUER);
    config.max_fund = max_fund;
    NotesScheme::new(config, issuer, None)
}

/// The `bnap:notes` params of the route offer, from the scheme's own
/// `offer`.
fn route_params(keysets: &[IssuerKeyset]) -> Vec<u8> {
    let scope = route();
    let cx = OfferCtx {
        now: NOW,
        route_id: "chat",
        scope: &scope,
        route_scope: true,
        metered: true,
        expires: EXPIRES,
        role: OfferRole::Pay {
            amount: 2100,
            unit: "sat",
        },
    };
    block_on(scheme_with(keysets, None).offer(&cx))
        .unwrap()
        .params
        .unwrap()
}

/// The draft-00 route offer's fields with these params and expiry.
fn route_fields(params: Option<Vec<u8>>, expires: u64) -> OfferFields {
    let offer = SigningKey::from_secret_bytes(&offer_sk()).unwrap();
    let nonce: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let mut f = OfferFields::new(route(), expires, offer.public_key(), nonce);
    f.route_scope = true;
    f.metered = true;
    f.info = Some("https://api.example/.well-known/bnap".into());
    let mut e = PayEntry::new(SCHEME_ID, 2100, "sat");
    e.rate = Some(500);
    e.params = params;
    f.pay = vec![e];
    f.attest = vec![AttestEntry::discount(WBA, 2000)];
    f.unknown = vec![(3_000_000_001, vec![0x0a, 0x0a])];
    f
}

fn sign(f: &OfferFields) -> Offer {
    let key = SigningKey::from_secret_bytes(&offer_sk()).unwrap();
    f.sign(&key, Some(&mac_key()), &AUX0).unwrap()
}

/// The notes route offer (18.1).
fn notes_route_offer() -> Offer {
    sign(&route_fields(
        Some(route_params(&[keyset_a(), keyset_b()])),
        EXPIRES,
    ))
}

/// The fee offer (18.1): keyset C added.
fn fee_offer() -> Offer {
    sign(&route_fields(
        Some(route_params(&[keyset_a(), keyset_b(), keyset_c()])),
        EXPIRES,
    ))
}

fn context_of(offer: &Offer) -> Context {
    bnap_core::credential::context(&offer.offer_id(), &act(), Some(SCHEME_ID), &[WBA], b"")
}

#[test]
fn the_notes_route_offer_of_18_1() {
    // Keyset IDs.
    assert_eq!(
        x(keyset_a().info().id),
        "011decbc482233faf1b58395ddb55c465e3bf6d8fa1c5a5b17219f7d5883b112a7"
    );
    assert_eq!(
        x(keyset_b().info().id),
        "014423cf221427bb65863007387bbc9b74963e47b24c3ec3a25ddd673e9ed6e898"
    );
    assert_eq!(
        x(keyset_c().info().id),
        "01fd899e9c7a7f4940273d43ec1dcd3bafc9fe4fe80ba292b9f021ab09b5aecf46"
    );
    // Without params and with the socket expiry, the same records are the
    // draft-00 route offer.
    assert_eq!(
        x(sign(&route_fields(None, SOCKET_EXPIRES)).offer_id()),
        "5c8640261f6f1de3206a2e9cd1c2599a2e9256547242061c95f9d2e06cf6696d"
    );
    // The params the scheme builds are 106 bytes, and the offer is the
    // published one, byte for byte.
    assert_eq!(route_params(&[keyset_a(), keyset_b()]).len(), 106);
    let offer = notes_route_offer();
    assert_eq!(offer.bytes().len(), 413);
    assert_eq!(x(offer.bytes()), ROUTE_OFFER_HEX);
    assert_eq!(
        x(offer.offer_id()),
        "666b28f7f1d68d92e9c180f0d11fe743730d3932ab5bc566d68f53b17b0cbd95"
    );
    let sig = x(offer.offer_sig().0);
    assert!(sig.starts_with("108b3bf0") && sig.ends_with("eb9f5fec"));
    assert_eq!(
        x(offer.mac().unwrap()),
        "e77e4e3ef6ce609745c194c160d1814295ad7e4d6d5a56178d68cf40b4a5dd4c"
    );
    assert_eq!(
        x(context_of(&offer)),
        "29c131cbf11af082d603f2246516d288565da10bc3703cc556b87575f43cbdf3"
    );
    // The fee offer.
    assert_eq!(
        route_params(&[keyset_a(), keyset_b(), keyset_c()]).len(),
        146
    );
    let fee = fee_offer();
    assert_eq!(fee.bytes().len(), 453);
    assert_eq!(
        x(fee.offer_id()),
        "b958c89e56ef83bb05dd98e88b0a4746f79ebac53c09c53f306e74635be1f2aa"
    );
    assert_eq!(
        x(context_of(&fee)),
        "a6f07b0ed275845d2d088e724cd9a7fc9cd7093df6e6456c613f40ca788bab11"
    );
}

#[test]
fn dleq_and_hash_to_curve_agree_with_the_nut_vectors() {
    // NUT-12, the deterministic nonce vector: a = 2.
    let mut secrets = std::collections::BTreeMap::new();
    let mut two = [0u8; 32];
    two[31] = 2;
    secrets.insert(1u64, two);
    let k = IssuerKeyset::from_secrets(&secrets, 0, 2_000_000_000, 0).unwrap();
    let b: PointBytes =
        hex::decode("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
            .unwrap()
            .try_into()
            .unwrap();
    let s = k.sign(1, &b).unwrap();
    assert_eq!(
        x(s.c),
        "0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787"
    );
    assert_eq!(
        x(s.e),
        "2a16ffee280aff3c429045607f9b8e0bf8b35910c44c1b20b9dfaf01b263d7b3"
    );
    assert_eq!(
        x(s.s),
        "9df27731238334718d120d4f74611a7c668233f988e687ac3fb188f0a34a2dab"
    );
    assert!(verify_dleq(k.info().key(1).unwrap(), &b, &s));
    // NUT-12, the verification vector: a = 1, so C' = B'.
    let g: PointBytes =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    let e: [u8; 32] =
        hex::decode("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9")
            .unwrap()
            .try_into()
            .unwrap();
    let s1: [u8; 32] =
        hex::decode("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(verify_dleq(&g, &b, &BlindSigned { c: b, e, s: s1 }));
    // NUT-00 hash_to_curve (bnap-core checks all three vectors).
    let y = hash_to_curve(&[0u8; 32]).unwrap();
    assert_eq!(
        x(y),
        "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
    );
}

// -------------------------------------------------------------- 18.2

fn seed() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[..32].copy_from_slice(&sha256(b"bnap notes test seed 0"));
    s[32..].copy_from_slice(&sha256(b"bnap notes test seed 1"));
    s
}

fn quote_key() -> [u8; 32] {
    sha256(b"bnap notes test quote key")
}

fn binding() -> [u8; 32] {
    sha256(b"tls-exporter placeholder")
}

/// The note of `amount` on `keyset` from seed counter `counter`, its `C`
/// signed by the keyset: `C = a·Y`.
fn note(keyset: &IssuerKeyset, amount: u64, counter: u64) -> (Note, Derived) {
    let d = client::derive(&seed(), &keyset.info().id, counter).unwrap();
    let c = keyset.sign(amount, &d.y).unwrap().c;
    (
        Note {
            keyset: keyset.info().id,
            amount,
            note_key: d.note_key,
            c,
        },
        d,
    )
}

/// The canonical ladder for `value` on keyset A from seed counter `start`.
fn ladder(value: u64, start: u64) -> Vec<PendingOutput> {
    client::ladder_outputs(&seed(), &keyset_a().info().id, value, start).0
}

/// A notes credential for `offer` with the action scope, the Web Bot Auth
/// placeholder and the binding of draft-00 section 14, naming the offer by
/// `offer_id`.
struct Built {
    credential: Credential,
    body: Vec<u8>,
    witness: Vec<u8>,
    context: Context,
    digest: bnap_core::Digest,
    ys: Vec<PointBytes>,
    value: u64,
    outputs: Vec<PendingOutput>,
    notes: Vec<Note>,
}

fn build(
    offer: &Offer,
    notes: &[Note],
    outputs: Vec<PendingOutput>,
    fund: Option<&FundQuote>,
    value: u64,
) -> Built {
    let outs: Vec<Output> = outputs.iter().map(|p| p.output).collect();
    let (body, ordered) = client::build_body(notes, &outs, fund.map(|q| q.quote.as_str())).unwrap();
    let body_bytes = body.to_bytes().unwrap();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(SCHEME_ID, body_bytes.clone()));
    c.attest = vec![SchemePart::new(WBA, WBA_BODY.to_vec())];
    c.binding = Some(binding());
    let ctx = c.context(&offer.offer_id(), &act());
    let digest = c.digest(&ctx);
    let qk = quote_key();
    let w = client::sign_witness(&body, &ordered, fund.map(|_| &qk), &digest, &AUX0)
        .unwrap()
        .to_bytes();
    c.pay.as_mut().unwrap().witness.clone_from(&w);
    Built {
        credential: c,
        body: body_bytes,
        witness: w,
        context: ctx,
        digest,
        ys: ordered.iter().map(|n| n.y().unwrap()).collect(),
        value,
        outputs,
        notes: ordered,
    }
}

fn credential_3a(offer: &Offer) -> Built {
    let (n1, _) = note(&keyset_a(), 1024, 1);
    let (n2, _) = note(&keyset_b(), 1024, 0);
    build(offer, &[n1, n2], ladder(2047, 16), None, 2047)
}

fn credential_3b(offer: &Offer) -> Built {
    let notes: Vec<Note> = [1024, 512, 128, 16]
        .iter()
        .zip(1..)
        .map(|(&a, c)| note(&keyset_b(), a, c).0)
        .collect();
    build(offer, &notes, ladder(1680, 32), None, 1680)
}

fn wba_use_id() -> bnap_core::UseId {
    ids::use_id(WBA, &sha256(b"bot key thumbprint"))
}

fn use_ids(b: &Built, rail_ids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = b.ys.iter().map(|y| ids::use_id(SCHEME_ID, y).0).collect();
    v.push(wba_use_id().0);
    v.extend_from_slice(rail_ids);
    v
}

fn credential_json(b: &Built, rail_ids: &[[u8; 32]]) -> Value {
    let ids = use_ids(b, rail_ids);
    let rk = ids::replay_key(&b.context, &b.body, &[WBA_BODY], &ids);
    let bytes = b.credential.to_bytes().unwrap();
    json!({
        "inputs": b.notes.iter().map(|n| json!({
            "keyset": x(n.keyset), "amount": n.amount, "note_key": x(n.note_key),
            "key": x(n.key().unwrap()), "C": x(n.c), "Y": x(n.y().unwrap()),
        })).collect::<Vec<_>>(),
        "outputs": b.outputs.iter().map(|p| json!({
            "keyset": x(p.output.keyset), "amount": p.output.amount, "counter": p.derived.counter,
            "r": x(p.derived.r), "B_": x(p.output.blinded),
        })).collect::<Vec<_>>(),
        "value": b.value,
        "body": x(&b.body),
        "body_len": b.body.len(),
        "witness": x(&b.witness),
        "context": x(b.context),
        "digest": x(b.digest),
        "use_ids": ids.iter().map(x).collect::<Vec<_>>(),
        "replay_key": x(rk),
        "credential": x(&bytes),
        "credential_len": bytes.len(),
    })
}

/// A gate with keysets A and B (and C for the fee vector) that knows the
/// two route offers, the fund quote and its payment.
fn vector_gate(with_c: bool) -> Gate {
    let mut keysets = vec![keyset_a(), keyset_b()];
    if with_c {
        keysets.push(keyset_c());
    }
    let g = Gate::with_keysets(keysets);
    g.cache(&notes_route_offer());
    g.cache(&fee_offer());
    let q = fund_quote();
    let hash = payment_hash();
    block_on(g.issuer.insert_quote(&QuoteRecord {
        id: q.quote.clone(),
        method: "bolt11".into(),
        unit: "sat".into(),
        amount: q.amount,
        request: q.request.clone(),
        payment_hash: hash,
        expiry: q.expiry,
        pubkey: Some(q.pubkey),
        paid: true,
        issued: false,
        created: NOW,
    }))
    .unwrap();
    g.rail.add_paid(hash, q.amount);
    g
}

fn payment_hash() -> [u8; 32] {
    sha256(&sha256(b"bnap notes test preimage"))
}

/// The fund quote of items 2 and 4: 2,100 sat, a real regtest BOLT11
/// invoice signed by the test node key.
fn fund_quote() -> FundQuote {
    let memo = sha256(b"bnap:notes quote bnap-notes-test-quote-0");
    FundQuote {
        quote: "bnap-notes-test-quote-0".into(),
        request: FakeLn::new().invoice(payment_hash(), memo, 2100, NOW),
        amount: 2100,
        expiry: NOW + 600,
        pubkey: client::quote_pubkey(&quote_key()).unwrap(),
        unknown: Vec::new(),
    }
}

fn settle_json(name: &str, b: &Built, status: Status, units: u64) -> (Value, Option<Vec<u8>>) {
    let g = vector_gate(false);
    let mut o = Opts::default();
    o.status = status;
    o.units = units;
    o.binding = Some(binding());
    let resp = g.handle(&b.credential, &o).unwrap();
    let f = resp.fields();
    let entries = parse_scheme_result(f.scheme_result.as_deref().unwrap_or_default()).unwrap();
    let indices: Vec<u64> = entries.iter().map(|e| e.index).collect();
    let got = client::recover_change(
        &b.outputs,
        client::key_lookup(&g.keys()),
        b.value,
        f.charged,
        f.scheme_result.as_deref(),
    )
    .unwrap();
    assert!(got.matches_rule, "{name}");
    assert_eq!(
        got.notes.iter().map(|n| n.amount).sum::<u64>(),
        b.value - f.charged
    );
    (
        json!({
            "name": name,
            "status": if status == Status::Ok { "OK" } else { "FAILED" },
            "units": units,
            "charged": f.charged,
            "metered_units": f.metered_units,
            "change": b.value - f.charged,
            "indices": indices,
            "scheme_result": f.scheme_result.as_ref().map(x),
            "scheme_result_len": f.scheme_result.as_ref().map_or(0, Vec::len),
            "response": x(resp.bytes()),
            "settled_at": f.settled_at,
        }),
        f.scheme_result.clone(),
    )
}

/// A credential whose body is these raw bytes and whose witness is signed
/// over its own Digest by the given keys (`None`: the witness bytes as
/// given).
fn raw_credential(
    offer: &Offer,
    body: &[u8],
    keys: &[[u8; 32]],
    witness: Option<Vec<u8>>,
) -> Credential {
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(SCHEME_ID, body.to_vec()));
    c.attest = vec![SchemePart::new(WBA, WBA_BODY.to_vec())];
    c.binding = Some(binding());
    let ctx = c.context(&offer.offer_id(), &act());
    let digest = c.digest(&ctx);
    let w = witness.unwrap_or_else(|| {
        let sigs: Vec<u8> = keys
            .iter()
            .flat_map(|k| {
                SigningKey::from_secret_bytes(k)
                    .unwrap()
                    .sign(&digest.0, &AUX0)
                    .0
            })
            .collect();
        let mut w = Vec::new();
        if !sigs.is_empty() {
            write_record(&mut w, 0, &sigs);
        }
        w
    });
    c.pay.as_mut().unwrap().witness = w;
    c
}

fn input_entry(keyset: &[u8], amount: u64, key: &[u8; 32], c: Option<&PointBytes>) -> Vec<u8> {
    let mut s = Vec::new();
    write_record(&mut s, input_types::KEYSET, keyset);
    write_record(
        &mut s,
        input_types::AMOUNT,
        &bnap_core::encoding::tu64(amount),
    );
    write_record(&mut s, input_types::KEY, key);
    if let Some(c) = c {
        write_record(&mut s, input_types::C, c);
    }
    s
}

fn body_of(inputs: &[Vec<u8>], outputs: &[Vec<u8>], extra: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut b = Vec::new();
    if !inputs.is_empty() {
        write_record(&mut b, body_types::INPUTS, &entry_list(inputs));
    }
    if !outputs.is_empty() {
        write_record(&mut b, body_types::OUTPUTS, &entry_list(outputs));
    }
    for (t, v) in extra {
        write_record(&mut b, *t, v);
    }
    b
}

fn negatives() -> Vec<Value> {
    let offer = notes_route_offer();
    let fee = fee_offer();
    let g = vector_gate(false);
    let gc = vector_gate(true);
    let base = credential_3a(&offer);
    let body = Body::parse(&base.body).unwrap();
    let inputs: Vec<Vec<u8>> = base
        .notes
        .iter()
        .map(|n| input_entry(&n.keyset, n.amount, &n.key().unwrap(), Some(&n.c)))
        .collect();
    let outputs: Vec<Vec<u8>> = body.outputs.iter().map(Output::entry_bytes).collect();
    let keys: Vec<[u8; 32]> = base.notes.iter().map(|n| n.note_key).collect();
    let mut cases: Vec<(&str, &Offer, Credential, &str)> = Vec::new();
    // 1. Inputs out of order.
    let rev: Vec<Vec<u8>> = inputs.iter().rev().cloned().collect();
    let rev_keys: Vec<[u8; 32]> = keys.iter().rev().copied().collect();
    cases.push((
        "inputs out of order",
        &offer,
        raw_credential(&offer, &body_of(&rev, &outputs, &[]), &rev_keys, None),
        codes::NON_CANONICAL,
    ));
    // 2. A repeated K.
    let twice = vec![inputs[0].clone(), inputs[0].clone()];
    cases.push((
        "a repeated K",
        &offer,
        raw_credential(
            &offer,
            &body_of(&twice, &outputs, &[]),
            &[keys[0], keys[0]],
            None,
        ),
        codes::NON_CANONICAL,
    ));
    // 3. Two outputs with one B'.
    let mut dup = outputs.clone();
    dup[1] = Output {
        amount: 2,
        ..body.outputs[0]
    }
    .entry_bytes();
    cases.push((
        "two outputs with one B'",
        &offer,
        raw_credential(&offer, &body_of(&inputs, &dup, &[]), &keys, None),
        codes::NON_CANONICAL,
    ));
    // 4. An unknown odd record in the body.
    cases.push((
        "an unknown odd record in the body",
        &offer,
        raw_credential(
            &offer,
            &body_of(&inputs, &outputs, &[(5, vec![1])]),
            &keys,
            None,
        ),
        codes::NON_CANONICAL,
    ));
    // 5. A record with an empty value (fund).
    cases.push((
        "a record with an empty value",
        &offer,
        raw_credential(
            &offer,
            &body_of(&inputs, &outputs, &[(body_types::FUND, Vec::new())]),
            &keys,
            None,
        ),
        codes::NON_CANONICAL,
    ));
    // 6. An input entry without its C record.
    let mut no_c = inputs.clone();
    let n0 = &base.notes[0];
    no_c[0] = input_entry(&n0.keyset, n0.amount, &n0.key().unwrap(), None);
    cases.push((
        "an input entry without C",
        &offer,
        raw_credential(&offer, &body_of(&no_c, &outputs, &[]), &keys, None),
        codes::NON_CANONICAL,
    ));
    // 7. An output entry that is the empty stream: the single byte 00.
    let mut b7 = Vec::new();
    write_record(&mut b7, body_types::INPUTS, &entry_list(&inputs));
    let mut list = entry_list(&outputs);
    list.push(0);
    write_record(&mut b7, body_types::OUTPUTS, &list);
    cases.push((
        "an output entry that is the empty stream",
        &offer,
        raw_credential(&offer, &b7, &keys, None),
        codes::NON_CANONICAL,
    ));
    // 8. A short keyset ID.
    let mut short = inputs.clone();
    short[0] = input_entry(&n0.keyset[..32], n0.amount, &n0.key().unwrap(), Some(&n0.c));
    cases.push((
        "a short keyset ID",
        &offer,
        raw_credential(&offer, &body_of(&short, &outputs, &[]), &keys, None),
        codes::NON_CANONICAL,
    ));
    // 9. A non-power-of-two amount (an output of 3 sat).
    let mut three = outputs.clone();
    three[1] = Output {
        amount: 3,
        ..body.outputs[1]
    }
    .entry_bytes();
    cases.push((
        "a non-power-of-two amount",
        &offer,
        raw_credential(&offer, &body_of(&inputs, &three, &[]), &keys, None),
        codes::BAD_AMOUNT,
    ));
    // 10. An incomplete ladder: no 2-sat output.
    let mut gap = outputs.clone();
    gap.remove(1);
    cases.push((
        "an incomplete ladder",
        &offer,
        raw_credential(&offer, &body_of(&inputs, &gap, &[]), &keys, None),
        codes::BAD_OUTPUTS,
    ));
    // 11. A ladder whose total is below the value: 1 to 512, 1,023 < 2,047.
    let low = outputs[..10].to_vec();
    cases.push((
        "a ladder whose total is below the value",
        &offer,
        raw_credential(&offer, &body_of(&inputs, &low, &[]), &keys, None),
        codes::BAD_OUTPUTS,
    ));
    // 12. Fees above the inputs, under the fee offer: one 1-sat input on C.
    let (nc, _) = note(&keyset_c(), 1, 0);
    let c_input = input_entry(&nc.keyset, 1, &nc.key().unwrap(), Some(&nc.c));
    cases.push((
        "fees above the inputs",
        &fee,
        raw_credential(&fee, &body_of(&[c_input], &[], &[]), &[nc.note_key], None),
        codes::BAD_AMOUNT,
    ));
    // 13. input_sigs of the wrong length: one signature for two inputs.
    let mut one_sig = Vec::new();
    write_record(&mut one_sig, 0, &[0u8; 64]);
    cases.push((
        "input_sigs of the wrong length",
        &offer,
        raw_credential(&offer, &base.body, &[], Some(one_sig)),
        codes::NON_CANONICAL,
    ));
    // 14. fund without fund_sig.
    let q = fund_quote();
    cases.push((
        "fund without fund_sig",
        &offer,
        raw_credential(
            &offer,
            &body_of(
                &inputs,
                &outputs,
                &[(body_types::FUND, q.quote.as_bytes().to_vec())],
            ),
            &keys,
            None,
        ),
        codes::NON_CANONICAL,
    ));
    // 15. A witness signature over another Digest (the Digest without a
    // binding).
    let mut other = base.credential.clone();
    other.binding = None;
    let ctx = other.context(&offer.offer_id(), &act());
    let wrong_digest = other.digest(&ctx);
    let sigs: Vec<u8> = keys
        .iter()
        .flat_map(|k| {
            SigningKey::from_secret_bytes(k)
                .unwrap()
                .sign(&wrong_digest.0, &AUX0)
                .0
        })
        .collect();
    let mut w15 = Vec::new();
    write_record(&mut w15, 0, &sigs);
    cases.push((
        "a witness signature over another Digest",
        &offer,
        raw_credential(&offer, &base.body, &[], Some(w15)),
        codes::BAD_SIGNATURE,
    ));
    // 16. A note whose C does not verify: the C of another note.
    let mut forged = inputs.clone();
    forged[0] = input_entry(
        &n0.keyset,
        n0.amount,
        &n0.key().unwrap(),
        Some(&base.notes[1].c),
    );
    cases.push((
        "a note whose C does not verify",
        &offer,
        raw_credential(&offer, &body_of(&forged, &outputs, &[]), &keys, None),
        codes::BAD_SIGNATURE,
    ));
    // 17. An output keyset that is not active (B).
    let mut on_b = outputs.clone();
    on_b[0] = Output {
        keyset: keyset_b().info().id,
        ..body.outputs[0]
    }
    .entry_bytes();
    cases.push((
        "an output keyset that is not active",
        &offer,
        raw_credential(&offer, &body_of(&inputs, &on_b, &[]), &keys, None),
        codes::UNKNOWN_KEYSET,
    ));
    let mut out = Vec::new();
    for (name, o, cred, want) in cases {
        let gate = if o.offer_id() == fee.offer_id() {
            &gc
        } else {
            &g
        };
        let mut opts = Opts::default();
        opts.binding = Some(binding());
        let err = gate.verify_only(&cred, &opts).unwrap_err();
        assert_eq!(codes::code_of(&err), Some(want), "{name}: {err}");
        // And through the whole gate, with nothing consumed.
        let e = gate.handle(&cred, &opts).unwrap_err();
        assert_eq!(
            e.scheme_code.as_deref(),
            Some(codes::scheme_code(want).as_str()),
            "{name}"
        );
        let part = cred.pay.as_ref().unwrap();
        out.push(json!({
            "name": name,
            "offer": if o.offer_id() == fee.offer_id() { "fee offer" } else { "notes route offer" },
            "body": x(&part.body),
            "witness": x(&part.witness),
            "credential": x(cred.to_bytes().unwrap()),
            "scheme_code": codes::scheme_code(want),
        }));
    }
    assert_eq!(g.signer.minted() + gc.signer.minted(), 0);
    out
}

fn generate() -> Value {
    let offer = notes_route_offer();
    let fee = fee_offer();
    let ka = keyset_a();

    // 1. Note math.
    let d = client::derive(&seed(), &ka.info().id, 0).unwrap();
    let a_1024 = bnap_scheme_notes::test_support::test_key("A", 1024);
    let signed = ka.sign(1024, &d.blinded).unwrap();
    let a_pub = *ka.info().key(1024).unwrap();
    let c = client::unblind(&signed.c, &d.r, &a_pub).unwrap();
    assert_eq!(ka.verify_note(1024, d.secret.as_bytes(), &c), Some(d.y));
    assert!(verify_dleq(&a_pub, &d.blinded, &signed));
    let note_math = json!({
        "seed": x(seed()),
        "keyset": x(ka.info().id),
        "counter": 0,
        "k_n": x(d.note_key),
        "K": x(d.key),
        "secret": d.secret,
        "Y": x(d.y),
        "r": x(d.r),
        "B_": x(d.blinded),
        "amount": 1024,
        "a": x(a_1024),
        "A": x(a_pub),
        "C_": x(signed.c),
        "dleq_e": x(signed.e),
        "dleq_s": x(signed.s),
        "C": x(c),
    });

    // 2. Offer parameters.
    let q = fund_quote();
    let exact_scope = act();
    let cx = OfferCtx {
        now: NOW,
        route_id: "chat",
        scope: &exact_scope,
        route_scope: false,
        metered: false,
        expires: NOW + 900,
        role: OfferRole::Pay {
            amount: 2100,
            unit: "sat",
        },
    };
    let exact =
        block_on(scheme_with(&[keyset_a(), keyset_b()], Some(5000)).offer_with_quote(&cx, &q))
            .unwrap()
            .params
            .unwrap();
    let route = route_params(&[keyset_a(), keyset_b()]);
    let params = json!({
        "route": {"bytes": x(&route), "len": route.len()},
        "exact_with_fund_quote": {
            "max_fund": 5000,
            "fund_quote": {
                "quote": q.quote, "request": q.request, "amount": q.amount,
                "expiry": q.expiry, "pubkey": x(q.pubkey), "payment_hash": x(payment_hash()),
            },
            "bytes": x(&exact),
            "len": exact.len(),
        },
    });

    // 3. Two credentials.
    let c3a = credential_3a(&offer);
    let c3b = credential_3b(&offer);
    assert_eq!((c3a.value, c3b.value), (2047, 1680));
    assert_eq!(
        x(c3a.context),
        "29c131cbf11af082d603f2246516d288565da10bc3703cc556b87575f43cbdf3"
    );
    let g = vector_gate(false);
    for (b, want) in [(&c3a, 2047), (&c3b, 1680)] {
        let mut o = Opts::default();
        o.binding = Some(binding());
        let v = g.verify_only(&b.credential, &o).unwrap();
        assert_eq!(v.value, want);
        assert_eq!(
            v.use_ids,
            b.ys.iter().map(|y| y.to_vec()).collect::<Vec<_>>()
        );
    }
    // Without the stub verifier the attestation has no effect and both are
    // UNDERPAID at 2,100 (18.2 item 3).
    for b in [&c3a, &c3b] {
        let admit = |attest: &[VerifiedAttest]| {
            bnap_core::pricing::admit(
                &AdmitInput {
                    offer: offer.fields(),
                    pay: Some(PayValue {
                        scheme: SCHEME_ID,
                        claimed: b.value,
                        backing: b
                            .ys
                            .iter()
                            .zip(&b.notes)
                            .map(|(y, n)| Backing {
                                source: BackingSource::Note(y.to_vec()),
                                amount: n.amount,
                                unit: "sat".into(),
                            })
                            .collect(),
                        refund: Refund::Atomic,
                    }),
                    attest,
                    now: NOW,
                },
                |_| 0,
            )
        };
        assert!(admit(&[]).is_err());
        let stub = [VerifiedAttest::new(WBA, BindingClass::A)];
        assert_eq!(admit(&stub).unwrap().price(), 1680);
    }

    // 4. A funded credential: one 512-sat note on B and the 2,100-sat quote.
    let (n512, _) = note(&keyset_b(), 512, 5);
    let funded = build(&offer, &[n512], ladder(2612, 48), Some(&q), 2612);
    let rid = ids::rail_id(rail::LN, &rail::ln(&payment_hash()));
    {
        let mut o = Opts::default();
        o.binding = Some(binding());
        let v = g.verify_only(&funded.credential, &o).unwrap();
        assert_eq!(v.value, 2612);
        assert_eq!(v.rail_ids[0].reference, payment_hash().to_vec());
    }
    let mut funded_json = credential_json(&funded, &[rid.0]);
    funded_json["quote"] = json!(q.quote);
    funded_json["fund_amount"] = json!(q.amount);
    funded_json["rail_id"] = json!(x(rid));

    // 5. Value and fees.
    let fee_rows: Vec<Value> = [
        (vec![("A", 100u64, 1024u64)], 0u64),
        (vec![("A", 100, 1024), ("B", 0, 1024)], 0),
        (
            vec![
                ("A", 100, 1024),
                ("A", 100, 512),
                ("A", 100, 128),
                ("A", 100, 16),
            ],
            0,
        ),
        (vec![("A", 100, 1); 10], 0),
        (vec![("A", 100, 1); 11], 0),
        (vec![("C", 2000, 1)], 0),
        (vec![("C", 2000, 1)], 21),
        (vec![("A", 100, 2048)], 0),
    ]
    .iter()
    .map(|(inputs, f)| {
        let ppk: u64 = inputs.iter().map(|i| i.1).sum();
        let fee = amount::input_fee(inputs.iter().map(|i| i.1)).unwrap();
        let v = amount::value(inputs.iter().map(|i| (i.2, i.1)), *f);
        json!({
            "inputs": inputs.iter().map(|i| json!([i.0, i.2])).collect::<Vec<_>>(),
            "fund": f,
            "ppk_sum": ppk,
            "fee": fee,
            "value": v.ok(),
            "error": v.err().map(|_| codes::scheme_code(codes::BAD_AMOUNT)),
        })
    })
    .collect();

    // 6. Settlement.
    let (s1, r1) = settle_json("3a OK metered", &c3a, Status::Ok, 850);
    let (s2, r2) = settle_json("3a FAILED", &c3a, Status::Failed, 0);
    let (s3, r3) = settle_json("3b OK, charge equal to the value", &c3b, Status::Ok, 4200);
    assert_eq!(
        (s1["charged"].as_u64(), s1["change"].as_u64()),
        (Some(340), Some(1707))
    );
    assert_eq!(s1["indices"], json!([0, 1, 3, 5, 7, 9, 10]));
    assert_eq!(r1.as_ref().map(Vec::len), Some(752));
    assert_eq!(s2["indices"], json!((0..11).collect::<Vec<u64>>()));
    assert_eq!(
        (s2["charged"].as_u64(), s2["metered_units"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(r2.as_ref().map(Vec::len), Some(1180));
    assert_eq!(s3["charged"].as_u64(), Some(1680));
    assert_eq!(r3, None, "no record 16");
    // Both signed sets contain index 0, written as 00 00 (7.3).
    for r in [&r1, &r2] {
        let r = r.as_ref().unwrap();
        assert_eq!(
            &r[4..9],
            &[0x69, 0x00, 0x00, 0x02, 0x21],
            "the first entry is index 0"
        );
    }

    // 7. Minting.
    let mint_outs = client::derive_outputs(&seed(), &ka.info().id, &[1024, 512], 80).0;
    let mint_outputs: Vec<Output> = mint_outs.iter().map(|p| p.output).collect();
    let mint = json!({
        "quote": "bnap-notes-test-quote-1",
        "outputs": mint_outputs.iter().map(|o| x(o.entry_bytes())).collect::<Vec<_>>(),
        "rk_mint": x(rk_mint("bnap-notes-test-quote-1", &mint_outputs)),
    });

    // 8. A reused output: a credential reusing 3a's 1-sat output (index 0)
    // after 3a settled, under an exact-scope offer of 10 sat.
    let reuse_gate = vector_gate(false);
    let mut o = Opts::default();
    o.binding = Some(binding());
    o.units = 850;
    let r3a = reuse_gate.handle(&c3a.credential, &o).unwrap();
    let first = parse_scheme_result(r3a.fields().scheme_result.as_deref().unwrap()).unwrap()[0];
    let mut f = OfferFields::new(act(), NOW + 900, reuse_gate.signer.offer_key(), [9; 16]);
    let mut e = PayEntry::new(SCHEME_ID, 10, "sat");
    e.params = Some(route.clone());
    f.pay = vec![e];
    let exact_offer = reuse_gate.sign(&f);
    let (n64, _) = note(&keyset_a(), 64, 2);
    let mut outs = vec![c3a.outputs[0].clone()];
    outs.extend(client::derive_outputs(&seed(), &ka.info().id, &[2, 4, 8, 16, 32], 64).0);
    let reused = {
        let outputs: Vec<Output> = outs.iter().map(|p| p.output).collect();
        let (body, ordered) = client::build_body(&[n64], &outputs, None).unwrap();
        let mut cr = Credential::new(OfferRef::Id(exact_offer.offer_id()));
        cr.pay = Some(SchemePart::new(SCHEME_ID, body.to_bytes().unwrap()));
        cr.binding = Some(binding());
        let ctx = cr.context(&exact_offer.offer_id(), &act());
        let w = client::sign_witness(&body, &ordered, None, &cr.digest(&ctx), &AUX0).unwrap();
        cr.pay.as_mut().unwrap().witness = w.to_bytes();
        cr
    };
    let mut o = Opts::default();
    o.binding = Some(binding());
    reuse_gate.verify_only(&reused, &o).unwrap();
    let rr = reuse_gate.handle(&reused, &o).unwrap();
    // 63 - 10 = 53 = 32 + 16 + 4 + 1: index 0, the reused output, is signed.
    let again = parse_scheme_result(rr.fields().scheme_result.as_deref().unwrap()).unwrap();
    assert_eq!(again[0].index, 0);
    assert_eq!(
        (again[0].c, again[0].e, again[0].s),
        (first.c, first.e, first.s)
    );
    let b0 = c3a.outputs[0].output.blinded;
    let records: Vec<_> = reuse_gate
        .issuer
        .all_outputs()
        .into_iter()
        .filter(|r| r.blinded == b0)
        .collect();
    assert_eq!(records.len(), 2, "one record per source");
    let reused_json = json!({
        "offer": x(exact_offer.bytes()),
        "credential": x(reused.to_bytes().unwrap()),
        "reused_output": x(c3a.outputs[0].output.entry_bytes()),
        "first_source": x(sha256(&c3a.body)),
        "second_source": x(sha256(&reused.pay.as_ref().unwrap().body)),
        "C_": x(first.c),
        "dleq_e": x(first.e),
        "dleq_s": x(first.s),
        "scheme_result": x(rr.fields().scheme_result.as_ref().unwrap()),
    });

    let keysets_json: Vec<Value> = [keyset_a(), keyset_b(), keyset_c()]
        .iter()
        .zip(["A", "B", "C"])
        .map(|(k, l)| {
            json!({
                "label": l, "id": x(k.info().id), "input_fee_ppk": k.info().input_fee_ppk,
                "final_expiry": k.info().final_expiry,
            })
        })
        .collect();
    json!({
        "description": "bnap:notes draft-00 section 18 vectors, generated by crates/bnap-scheme-notes/tests/vectors.rs (to move to bnap/vectors). Keys are SHA-256 of fixed strings; BIP-340 aux is 32 zero bytes; the wallet seed is SHA-256('bnap notes test seed 0') || SHA-256('bnap notes test seed 1'); a note's C is a·Y; counters: note math A/0, 3a inputs A/1 and B/0, 3b inputs B/1..4, funded input B/5, reused input A/2, 3a outputs A/16.., 3b outputs A/32.., funded outputs A/48.., reused outputs A/64.., mint outputs A/80..; the Web Bot Auth body is the draft-00 placeholder under the stub verifier of P37",
        "reference_time": NOW,
        "keysets": keysets_json,
        "offers": {
            "notes_route_offer": {"bytes": x(offer.bytes()), "offer_id": x(offer.offer_id()), "context": x(context_of(&offer))},
            "fee_offer": {"bytes": x(fee.bytes()), "offer_id": x(fee.offer_id()), "context": x(context_of(&fee))},
        },
        "1_note_math": note_math,
        "2_params": params,
        "3_credentials": {"3a": credential_json(&c3a, &[]), "3b": credential_json(&c3b, &[])},
        "4_funded": funded_json,
        "5_fees": fee_rows,
        "6_settlement": [s1, s2, s3],
        "7_mint": mint,
        "8_reused_output": reused_json,
        "9_negative": negatives(),
    })
}

#[test]
fn the_vectors_of_18_2_reproduce() {
    let got = generate();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    if std::env::var_os("BNAP_NOTES_REGEN").is_some() {
        let mut s = serde_json::to_string_pretty(&got).unwrap();
        s.push('\n');
        std::fs::write(&path, s).unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        got, want,
        "regenerate with BNAP_NOTES_REGEN=1 if the change is deliberate"
    );
}

/// A credential of 3.6: notes on B from seed counters `start..`, an
/// optional quote ID, the canonical ladder on A, named by `offer_id`, with
/// the binding, a GREASE record of 8 bytes (14 in all) and, when asked, the
/// Web Bot Auth attest record.
fn sized(
    offer: &Offer,
    amounts: &[u64],
    start: u64,
    quote: Option<&str>,
    fund: u64,
    attest: bool,
    keyset: &IssuerKeyset,
) -> (usize, usize, usize) {
    let notes: Vec<Note> = amounts
        .iter()
        .zip(start..)
        .map(|(&a, c)| note(keyset, a, c).0)
        .collect();
    let fee_ppk = keyset.info().input_fee_ppk;
    let value = amount::value(amounts.iter().map(|&a| (a, fee_ppk)), fund).unwrap();
    let outs: Vec<Output> = ladder(value, 500).iter().map(|p| p.output).collect();
    let (body, ordered) = client::build_body(&notes, &outs, quote).unwrap();
    let mut c = Credential::new(OfferRef::Id(offer.offer_id()));
    c.pay = Some(SchemePart::new(SCHEME_ID, body.to_bytes().unwrap()));
    if attest {
        c.attest = vec![SchemePart::new(WBA, WBA_BODY.to_vec())];
    }
    c.binding = Some(binding());
    c.unknown = vec![(3_000_000_001, vec![0x0a; 8])];
    let ctx = c.context(&offer.offer_id(), &act());
    let qk = quote_key();
    let w = client::sign_witness(&body, &ordered, quote.map(|_| &qk), &c.digest(&ctx), &AUX0)
        .unwrap()
        .to_bytes();
    c.pay.as_mut().unwrap().witness.clone_from(&w);
    (
        body.to_bytes().unwrap().len(),
        w.len(),
        c.to_bytes().unwrap().len(),
    )
}

#[test]
fn the_credential_sizes_of_3_6() {
    let offer = notes_route_offer();
    let b = keyset_b();
    // 16 inputs: 1, 2, 4, …, 16,384 and a second 16,384, with a 36-byte
    // quote ID for F = 16,384: value 65,535, 16 outputs.
    let mut amounts: Vec<u64> = (0..15).map(|i| 1u64 << i).collect();
    amounts.push(16_384);
    let q36 = "q".repeat(36);
    assert_eq!(
        sized(&offer, &amounts, 100, Some(&q36), 16_384, false, &b),
        (2974, 1094, 4177)
    );
    // The largest at the defaults: 256 … 16,384 once each and nine more of
    // 256, a 64-byte quote ID, F = 30,719.
    let mut amounts: Vec<u64> = (8..15).map(|i| 1u64 << i).collect();
    amounts.extend([256; 9]);
    let q64 = "q".repeat(64);
    assert_eq!(
        sized(&offer, &amounts, 200, Some(&q64), 30_719, false, &b),
        (3010, 1094, 4213)
    );
    // 1,680 on B with the attest record and the 11-output ladder: 1,719.
    assert_eq!(
        sized(&offer, &[1024, 512, 128, 16], 300, None, 0, true, &b).2,
        1719
    );
    // One 2,048-sat note on B and the 12-output ladder: 1,271.
    assert_eq!(sized(&offer, &[2048], 400, None, 0, true, &b).2, 1271);
    // On keyset A the 2,048-sat note is worth 2,047: 11 outputs, 1,196.
    assert_eq!(
        sized(&offer, &[2048], 400, None, 0, true, &keyset_a()).2,
        1196
    );
}
