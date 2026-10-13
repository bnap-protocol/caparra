//! Reproduces every value in `tests/data/vectors.json` byte for byte, by
//! rebuilding each object from the same inputs `bnap_ref.py` uses.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;

use base64::Engine as _;
use bnap_core::credential::{self, Credential, OfferRef, SchemePart};
use bnap_core::hash::{sha256, tagged_hash};
use bnap_core::manifest::{
    KeyUse, Manifest, ManifestKey, ManifestLimits, Route, RouteAttest, RouteScopeMode,
    SignedManifest,
};
use bnap_core::offer::{
    AttestEntry, Effect, GateOfferCheck, NativeEntry, Offer, OfferFields, PayEntry,
};
use bnap_core::response::{ResponseFields, Status};
use bnap_core::tlv::{TlvStream, entry_list};
use bnap_core::{BindingClass, Error, ErrorCode, Scope, SigningKey, encoding, http, ids};
use serde_json::Value;

const VECTORS: &str = include_str!("data/vectors.json");
const AUX0: [u8; 32] = [0; 32];
const ORIGIN: &str = "https://api.example";
const BODY: &[u8] =
    br#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;
const EXPIRES: u64 = 1_791_700_300;
const NOW: u64 = 1_791_700_000;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
}

fn x(b: impl AsRef<[u8]>) -> String {
    hex::encode(b)
}

struct Keys {
    offer: SigningKey,
    receipt: SigningKey,
    root: SigningKey,
    backup: SigningKey,
    note: SigningKey,
    mac: [u8; 32],
}

fn sk(label: &[u8]) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(label)).unwrap()
}

fn keys() -> Keys {
    Keys {
        offer: sk(b"bnap test offer key"),
        receipt: sk(b"bnap test receipt key"),
        root: sk(b"bnap test root key"),
        backup: sk(b"bnap test backup key"),
        note: sk(b"bnap test note key"),
        mac: sha256(b"bnap test mac key"),
    }
}

fn target() -> String {
    http::target(ORIGIN, "/v1/chat/completions")
}

fn act() -> Scope {
    http::action_scope("POST", &target(), BODY, &[])
}

fn route() -> Scope {
    http::route_scope(ORIGIN, "chat")
}

/// The route offer: route scope, metered, `bnap:notes` up to 2,100 sat at
/// 500 sat per 1,000 tokens, a 20% Web Bot Auth discount, GREASE `0a0a`.
fn route_offer_fields(k: &Keys) -> OfferFields {
    let nonce: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let mut f = OfferFields::new(route(), EXPIRES, k.offer.public_key(), nonce);
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

fn route_offer(k: &Keys) -> Offer {
    route_offer_fields(k)
        .sign(&k.offer, Some(&k.mac), &AUX0)
        .unwrap()
}

/// The exact-scope offer for `payment:lightning/charge`, 21 sat.
fn exact_offer_fields(k: &Keys) -> OfferFields {
    let mut f = OfferFields::new(act(), EXPIRES, k.offer.public_key(), [0; 16]);
    f.pay = vec![PayEntry::new("payment:lightning/charge", 21, "sat")];
    f
}

fn class_of(s: &str) -> Option<BindingClass> {
    match s {
        "bnap:notes" => Some(BindingClass::S),
        "httpsig:web-bot-auth" | "httpauth:DPoP" => Some(BindingClass::A),
        "payment:lightning/charge" | "httpauth:L402" => Some(BindingClass::O),
        _ => None,
    }
}

#[test]
fn tagged_hash_vector() {
    let v = vectors();
    let tv = &v["tagged_hash"];
    assert_eq!(s(tv, &["tag"]), "bnap/offer");
    assert_eq!(s(tv, &["msg"]), "");
    assert_eq!(
        x(tagged_hash(s(tv, &["tag"]), s(tv, &["msg"]).as_bytes())),
        s(tv, &["out"])
    );
}

#[test]
fn bigsize_vectors() {
    let v = vectors();
    let obj = v["bigsize"].as_object().unwrap();
    assert_eq!(obj.len(), 6);
    for (n, hx) in obj {
        let n: u64 = n.parse().unwrap();
        let enc = encoding::bigsize(n);
        assert_eq!(x(&enc), hx.as_str().unwrap(), "{n}");
        assert_eq!(encoding::read_bigsize(&enc), Ok((n, enc.len())));
    }
}

#[test]
fn tu64_vectors() {
    let v = vectors();
    let obj = v["tu64"].as_object().unwrap();
    assert_eq!(obj.len(), 4);
    for (n, hx) in obj {
        let n: u64 = n.parse().unwrap();
        let enc = encoding::tu64(n);
        assert_eq!(x(&enc), hx.as_str().unwrap(), "{n}");
        assert_eq!(encoding::read_tu64(&enc, 0), Ok(n));
    }
}

#[test]
fn http_scope_vectors() {
    let v = vectors();
    let tv = &v["http_scope"];
    assert_eq!(s(tv, &["method"]), "POST");
    assert_eq!(s(tv, &["uri"]), target());
    assert_eq!(s(tv, &["content"]).as_bytes(), BODY);
    let scope = http::action_scope(
        s(tv, &["method"]),
        s(tv, &["uri"]),
        s(tv, &["content"]).as_bytes(),
        &[],
    );
    assert_eq!(x(scope), s(tv, &["action_scope"]));
    assert_eq!(scope, act());
    assert_eq!(
        x(http::route_scope(ORIGIN, s(tv, &["route"]))),
        s(tv, &["route_scope"])
    );
}

#[test]
fn offer_vector() {
    let v = vectors();
    let tv = &v["offer"];
    let k = keys();
    assert_eq!(x(k.offer.secret_bytes()), s(tv, &["offer_sk"]));
    assert_eq!(x(k.offer.public_key().0), s(tv, &["offer_key"]));
    assert_eq!(x(k.mac), s(tv, &["mac_key"]));

    let offer = route_offer(&k);
    assert_eq!(x(offer.bytes()), s(tv, &["bytes"]));
    assert_eq!(
        u64::try_from(offer.bytes().len()).unwrap(),
        tv["len"].as_u64().unwrap()
    );
    assert_eq!(x(offer.offer_id()), s(tv, &["offer_id"]));
    assert_eq!(x(offer.offer_sig().0), s(tv, &["offer_sig"]));
    assert_eq!(route_offer_fields(&k).offer_id().unwrap(), offer.offer_id());

    // Parse the vector bytes and check them as client and gate.
    let parsed = Offer::parse(&hex::decode(s(tv, &["bytes"])).unwrap()).unwrap();
    assert_eq!(parsed, offer);
    assert_eq!(parsed.fields(), &route_offer_fields(&k));
    parsed.verify_signature().unwrap();
    parsed.verify_mac(&[k.mac]).unwrap();
    parsed.check_binding_classes(class_of).unwrap();
    let gate = GateOfferCheck {
        now: NOW,
        max_offer: bnap_core::limits::MAX_OFFER,
        mac_keys: &[[9; 32], k.mac],
        offer_keys: &[],
        action_scope: act(),
        route_scope: Some(route()),
    };
    gate.check_bytes(parsed.bytes(), Some("bnap:notes"))
        .unwrap();
    assert_eq!(
        GateOfferCheck {
            route_scope: None,
            ..gate
        }
        .check(&parsed, None),
        Err(Error::WrongScope)
    );
    assert_eq!(
        GateOfferCheck {
            mac_keys: &[[9; 32]],
            ..gate
        }
        .check(&parsed, None)
        .map_err(|e| e.code()),
        Err(ErrorCode::BadOffer)
    );
    assert_eq!(
        GateOfferCheck {
            now: EXPIRES + 61,
            ..gate
        }
        .check(&parsed, None)
        .map_err(|e| e.code()),
        Err(ErrorCode::Stale)
    );
    gate.check(&parsed, None).unwrap();
    GateOfferCheck {
        now: EXPIRES + 60,
        ..gate
    }
    .check(&parsed, None)
    .unwrap();
    parsed
        .check_offered(Some("bnap:notes"), ["httpsig:web-bot-auth"])
        .unwrap();
    assert_eq!(
        parsed.check_offered(Some("httpauth:L402"), []),
        Err(Error::NotOffered("httpauth:L402".into()))
    );

    // draft-00 10.3: the 402 carries `BNAP offer="AAEBAiCGLWQe…"`.
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(offer.bytes());
    assert!(b64.starts_with("AAEBAiCGLWQeZ4E_bniyCoGqkpUZ5mqXjmnopNPicoCZBpfzoAQACAAKBGrLLUwM"));
}

#[test]
fn offer_native_vector() {
    let v = vectors();
    let tv = &v["offer_native"];
    let k = keys();
    let mut f = exact_offer_fields(&k);
    let id_before = f.offer_id().unwrap();
    let without = f.sign(&k.offer, Some(&k.mac), &AUX0).unwrap();
    f.native = vec![NativeEntry::new(
        0,
        "bolt11",
        b"lnbc210n1...placeholder".to_vec(),
    )];
    let with = f.sign(&k.offer, Some(&k.mac), &AUX0).unwrap();
    assert_eq!(x(without.bytes()), s(tv, &["without_native"]));
    assert_eq!(x(with.bytes()), s(tv, &["with_native"]));
    assert_eq!(x(without.offer_id()), s(tv, &["offer_id"]));
    assert_eq!(with.offer_id(), without.offer_id());
    assert_eq!(f.offer_id().unwrap(), id_before);
    assert_ne!(with.offer_sig(), without.offer_sig());
    with.check_binding_classes(class_of).unwrap();
    with.verify_signature().unwrap();
    with.verify_mac(&[k.mac]).unwrap();
}

/// Rebuilds the credential vector: notes (class S) plus Web Bot Auth.
struct Cred {
    offer: Offer,
    ctx: bnap_core::Context,
    digest: bnap_core::Digest,
    notes_body: Vec<u8>,
    wba_body: Vec<u8>,
    cred: Credential,
}

fn build_credential(k: &Keys, binding: [u8; 32]) -> Cred {
    let offer = route_offer(k);
    let wba_body = b"sig1=:...placeholder web bot auth signature over the Context...:".to_vec();
    let ctx = credential::context(
        &offer.offer_id(),
        &act(),
        Some("bnap:notes"),
        &["httpsig:web-bot-auth"],
        b"",
    );
    let note_y = sha256(b"note secret 1");
    let notes_body = TlvStream::from_records([
        (0, note_y.to_vec()),
        (2, b"proofs+outputs placeholder".to_vec()),
    ])
    .unwrap()
    .to_bytes();
    let digest = credential::digest(&ctx, Some(&binding), &notes_body, &[&wba_body]);
    let witness = k.note.sign(&digest.0, &AUX0);
    let mut cred = Credential::new(OfferRef::Inline(offer.bytes().to_vec()));
    cred.pay = Some(SchemePart {
        scheme: "bnap:notes".into(),
        body: notes_body.clone(),
        witness: witness.0.to_vec(),
    });
    cred.attest = vec![SchemePart::new("httpsig:web-bot-auth", wba_body.clone())];
    cred.binding = Some(binding);
    Cred {
        offer,
        ctx,
        digest,
        notes_body,
        wba_body,
        cred,
    }
}

#[test]
fn credential_vector() {
    let v = vectors();
    let tv = &v["credential"];
    let k = keys();
    assert_eq!(x(k.note.secret_bytes()), s(tv, &["note_sk"]));
    let binding = sha256(b"tls-exporter placeholder");
    let c = build_credential(&k, binding);
    assert_eq!(x(c.ctx), s(tv, &["context"]));
    assert_eq!(x(c.digest), s(tv, &["digest"]));
    let witness = &c.cred.pay.as_ref().unwrap().witness;
    assert_eq!(x(witness), s(tv, &["witness"]));
    k.note
        .public_key()
        .verify(
            &c.digest.0,
            &bnap_core::Signature(witness.as_slice().try_into().unwrap()),
        )
        .unwrap();

    let bytes = c.cred.to_bytes().unwrap();
    assert_eq!(
        u64::try_from(bytes.len()).unwrap(),
        tv["bytes_len"].as_u64().unwrap()
    );
    // The bytes are exactly the reference construction.
    let reference = TlvStream::from_records([
        (0, encoding::tu64(1)),
        (2, c.offer.bytes().to_vec()),
        (
            4,
            TlvStream::from_records([
                (0, b"bnap:notes".to_vec()),
                (2, c.notes_body.clone()),
                (4, witness.clone()),
            ])
            .unwrap()
            .to_bytes(),
        ),
        (
            6,
            entry_list(&[TlvStream::from_records([
                (0, b"httpsig:web-bot-auth".to_vec()),
                (2, c.wba_body.clone()),
            ])
            .unwrap()
            .to_bytes()]),
        ),
        (8, binding.to_vec()),
    ])
    .unwrap()
    .to_bytes();
    assert_eq!(bytes, reference);

    // Parse it back and recompute everything as the gate does.
    let parsed = Credential::parse(&bytes).unwrap();
    assert_eq!(parsed, c.cred);
    let gate = GateOfferCheck {
        now: NOW,
        max_offer: bnap_core::limits::MAX_OFFER,
        mac_keys: &[k.mac],
        offer_keys: &[],
        action_scope: act(),
        route_scope: Some(route()),
    };
    let offer = gate.check_credential(&parsed, |_| None).unwrap();
    assert_eq!(offer, c.offer);
    let ctx = parsed.context(&offer.offer_id(), &act());
    assert_eq!(ctx, c.ctx);
    assert_eq!(parsed.digest(&ctx), c.digest);
    parsed.check_binding_classes(class_of).unwrap();
    parsed.check_tls_binding(Some(&binding)).unwrap();
    assert_eq!(parsed.check_tls_binding(None), Err(Error::Binding));
    assert_eq!(
        parsed.check_tls_binding(Some(&[0; 32])),
        Err(Error::Binding)
    );

    let u_note = ids::use_id("bnap:notes", &sha256(b"note secret 1"));
    let u_wba = ids::use_id("httpsig:web-bot-auth", &sha256(b"bot key thumbprint"));
    let want: Vec<&str> = tv["use_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(vec![x(u_note), x(u_wba)], want);
    let rk = ids::replay_key(&c.ctx, &c.notes_body, &[&c.wba_body], &[u_note.0, u_wba.0]);
    assert_eq!(x(rk), s(tv, &["replay_key"]));
    assert_eq!(parsed.replay_key(&ctx, &[u_wba.0, u_note.0]), rk);

    // A new connection changes the Digest only.
    let other = build_credential(&k, sha256(b"other connection"));
    assert_eq!(x(other.digest), s(tv, &["digest_other_binding"]));
    assert_eq!(other.ctx, c.ctx);
    let rk2 = other.cred.replay_key(&other.ctx, &[u_note.0, u_wba.0]);
    assert_eq!(rk2, rk);

    // draft-00 10.3: `BNAP-Credential: AAEBAv0BMQABAQIghi1kHmeBP254sgqB…`.
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    assert!(b64.starts_with("AAEBAv0BMQABAQIghi1kHmeBP254sgqB"));

    // By reference: the same credential naming its offer by OfferID.
    let mut by_id = parsed.clone();
    by_id.offer = OfferRef::Id(offer.offer_id());
    let by_id = Credential::parse(&by_id.to_bytes().unwrap()).unwrap();
    assert_eq!(by_id.context(&offer.offer_id(), &act()), c.ctx);
    let cached = offer.clone();
    assert_eq!(
        gate.check_credential(&by_id, |_| Some(cached)).unwrap(),
        offer
    );
    assert_eq!(
        gate.check_credential(&by_id, |_| None)
            .map_err(|e| e.code()),
        Err(ErrorCode::BadOffer)
    );
}

#[test]
fn attest_only_vector() {
    let v = vectors();
    let tv = &v["attest_only"];
    let k = keys();
    let mut f = OfferFields::new(act(), EXPIRES, k.offer.public_key(), [1; 16]);
    f.attest = vec![AttestEntry::new("httpauth:DPoP", Effect::Waive)];
    let offer = f.sign(&k.offer, Some(&k.mac), &AUX0).unwrap();
    assert_eq!(x(offer.bytes()), s(tv, &["offer"]));
    assert_eq!(x(offer.offer_id()), s(tv, &["offer_id"]));

    let dpop_body = b"DPoP proof placeholder with claim bnap_ctx";
    let ctx = credential::context(&offer.offer_id(), &act(), None, &["httpauth:DPoP"], b"");
    assert_eq!(x(ctx), s(tv, &["context"]));
    let dg = credential::digest(&ctx, None, b"", &[dpop_body]);
    assert_eq!(x(dg), s(tv, &["digest"]));
    let u = ids::use_id("httpauth:DPoP", &sha256(b"client key thumbprint"));
    assert_eq!(x(u), s(tv, &["use_id"]));
    assert_eq!(
        x(ids::replay_key(&ctx, b"", &[dpop_body], &[u.0])),
        s(tv, &["replay_key"])
    );

    // The same values through a parsed Credential envelope.
    let mut cred = Credential::new(OfferRef::Inline(offer.bytes().to_vec()));
    cred.attest = vec![SchemePart::new("httpauth:DPoP", dpop_body.to_vec())];
    let cred = Credential::parse(&cred.to_bytes().unwrap()).unwrap();
    let cctx = cred.context(&offer.offer_id(), &act());
    assert_eq!(cctx, ctx);
    assert_eq!(cred.digest(&cctx), dg);
    assert_eq!(x(cred.replay_key(&cctx, &[u.0])), s(tv, &["replay_key"]));
}

#[test]
fn native_vector() {
    let v = vectors();
    let tv = &v["native"];
    let k = keys();
    let offer = exact_offer_fields(&k)
        .sign(&k.offer, Some(&k.mac), &AUX0)
        .unwrap();
    let ctx = credential::native_context(&offer.offer_id(), &act(), s(tv, &["scheme"]));
    assert_eq!(x(ctx), s(tv, &["context"]));
    assert_eq!(
        x(credential::native_digest(
            &ctx,
            s(tv, &["native_bytes"]).as_bytes()
        )),
        s(tv, &["digest"])
    );
    let gate = GateOfferCheck {
        now: NOW,
        max_offer: bnap_core::limits::MAX_OFFER,
        mac_keys: &[k.mac],
        offer_keys: &[],
        action_scope: act(),
        route_scope: None,
    };
    gate.check_native(&offer, "payment:lightning/charge")
        .unwrap();
}

#[test]
fn rail_id_vector() {
    let v = vectors();
    let tv = &v["rail_id"];
    let ph = sha256(b"preimage");
    assert_eq!(x(ph), s(tv, &["payment_hash"]));
    assert_eq!(s(tv, &["kind"]), ids::rail::LN);
    assert_eq!(
        x(ids::rail_id(ids::rail::LN, &ids::rail::ln(&ph))),
        s(tv, &["rail_id"])
    );
}

#[test]
fn response_vector() {
    let v = vectors();
    let tv = &v["response"];
    let k = keys();
    assert_eq!(x(k.receipt.secret_bytes()), s(tv, &["receipt_sk"]));
    let c = build_credential(&k, sha256(b"tls-exporter placeholder"));
    let fields = ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 340,
        unit: Some("sat".into()),
        offer_id: c.offer.offer_id(),
        digest: c.digest,
        metered_units: Some(850),
        scheme_result: Some(b"change signatures placeholder".to_vec()),
        receipt_key: k.receipt.public_key(),
        settled_at: 1_791_700_042,
        unknown: Vec::new(),
    };
    let resp = fields.sign(&k.receipt, &AUX0).unwrap();
    assert_eq!(x(resp.bytes()), s(tv, &["bytes"]));
    assert_eq!(x(resp.ack().0), s(tv, &["ack"]));

    let parsed = bnap_core::Response::parse(&hex::decode(s(tv, &["bytes"])).unwrap()).unwrap();
    assert_eq!(parsed, resp);
    assert_eq!(parsed.fields(), &fields);
    parsed.verify_ack().unwrap();
    assert!(parsed.answers(&c.offer.offer_id(), &c.digest));
    let pinned = [ManifestKey {
        kid: k.receipt.public_key(),
        key_use: KeyUse::Receipt,
        not_after: 1_792_304_800,
    }];
    parsed
        .check_client(&pinned, 1_791_700_050, &c.offer.offer_id(), &c.digest)
        .unwrap();

    // draft-00 10.3: `data: AAEBAgAGAgFUCANzYXQKIFyGQCYfbx3jIGounNHC…`.
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(resp.bytes());
    assert!(b64.starts_with("AAEBAgAGAgFUCANzYXQKIFyGQCYfbx3jIGounNHC"));
}

fn vector_manifest(k: &Keys) -> Manifest {
    Manifest {
        bnap: 1,
        origin: ORIGIN.into(),
        seq: 1,
        issued: NOW,
        max_age: 604_800,
        root: k.root.public_key(),
        backup: k.backup.public_key(),
        keys: vec![
            ManifestKey {
                kid: k.offer.public_key(),
                key_use: KeyUse::Offer,
                not_after: 1_792_304_800,
            },
            ManifestKey {
                kid: k.receipt.public_key(),
                key_use: KeyUse::Receipt,
                not_after: 1_792_304_800,
            },
        ],
        required: true,
        limits: ManifestLimits {
            replay_window: Some(86_400),
            pending_timeout: Some(300),
            max_offer: Some(4096),
            max_credential: Some(16_384),
            max_response: Some(8192),
        },
        carriers: vec!["http".into()],
        routes: vec![Route {
            id: "chat".into(),
            match_: "POST /v1/chat/completions".into(),
            scope: RouteScopeMode::Route,
            metered: true,
            meter: Some("tokens".into()),
            price: BTreeMap::from([("sat".to_owned(), 2100)]),
            pay: vec!["bnap:notes".into(), "httpauth:L402".into()],
            attest: vec![RouteAttest {
                scheme: "httpsig:web-bot-auth".into(),
                effect: Effect::Discount,
                value: Some(2000),
                epoch: None,
            }],
            require: None,
            headers: vec![],
        }],
    }
}

#[test]
fn manifest_vector() {
    let v = vectors();
    let tv = &v["manifest"];
    let k = keys();
    assert_eq!(x(k.root.secret_bytes()), s(tv, &["root_sk"]));
    let m = vector_manifest(&k);
    let jcs = m.jcs().unwrap();
    assert_eq!(std::str::from_utf8(&jcs).unwrap(), s(tv, &["jcs"]));
    let doc = m.sign(&k.root, &AUX0).unwrap();
    let sm = SignedManifest::parse(&doc).unwrap();
    assert_eq!(x(sm.sig().0), s(tv, &["sig"]));
    assert_eq!(sm.manifest(), &m);
    assert_eq!(sm.jcs().unwrap(), jcs);
    sm.verify().unwrap();

    // The JCS string of the vector plus its sig, as any server might
    // serialize it, verifies too.
    let mut val: Value = serde_json::from_str(s(tv, &["jcs"])).unwrap();
    val["sig"] = Value::String(s(tv, &["sig"]).into());
    let pretty = serde_json::to_vec_pretty(&val).unwrap();
    let (pin, _) = bnap_core::manifest::accept(None, ORIGIN, &pretty, NOW).unwrap();
    assert_eq!(pin.root, k.root.public_key());
    assert_eq!(pin.until, NOW + 604_800);
    assert!(pin.required);

    // The pinned keys admit the vector offer as a client.
    let offer = route_offer(&k);
    offer
        .check_client(&bnap_core::offer::ClientOfferCheck {
            now: NOW,
            origin: ORIGIN,
            pinned_keys: Some(&pin.keys),
            action_scope: act(),
            route_scope: Some(route()),
        })
        .unwrap();

    // Limits from the manifest.
    let l = bnap_core::Limits::from_manifest(&m.limits);
    assert_eq!(l, bnap_core::Limits::default());
}

#[test]
fn every_vector_section_is_covered() {
    let v = vectors();
    let mut sections: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    sections.sort_unstable();
    assert_eq!(
        sections,
        [
            "attest_only",
            "bigsize",
            "credential",
            "http_scope",
            "manifest",
            "native",
            "offer",
            "offer_native",
            "rail_id",
            "response",
            "tagged_hash",
            "tu64"
        ]
    );
}
