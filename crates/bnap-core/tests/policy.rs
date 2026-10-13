//! Route policy tests (draft-00 section 11; overview, "Scheme properties
//! and route policy"). The vectors are copied from the registry export
//! (`registry/generated/registry.json`, format 1) of the spec repository.

use std::collections::BTreeMap;

use bnap_core::offer::Effect;
use bnap_core::policy::{
    Candidate, EffectiveVector, PROPERTIES, Part, PartKind, PolicyError, PropertyVector, Require,
    RoutePolicy, property,
};
use serde_json::{Value, json};

fn vector(pairs: &[(&str, &str)]) -> PropertyVector {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn notes() -> PropertyVector {
    vector(&[
        ("binding", "S"),
        ("custody", "operator-iou"),
        ("finality", "final-on-verification"),
        ("issuer", "self-issued"),
        ("link-actions", "unlinkable"),
        ("link-payment", "unlinkable"),
        ("maturity", "experimental"),
        ("pq", "no"),
        ("refund", "atomic"),
        ("theft", "key-witnessed"),
        ("use", "single"),
        ("verify", "offline"),
    ])
}

/// `httpauth:L402` and `payment:lightning/charge` share this vector.
fn ln_class_o() -> PropertyVector {
    vector(&[
        ("binding", "O"),
        ("custody", "self-custody"),
        ("finality", "final-on-verification"),
        ("issuer", "self-issued"),
        ("link-actions", "unlinkable"),
        ("link-payment", "linkable"),
        ("maturity", "experimental"),
        ("pq", "no"),
        ("refund", "none"),
        ("theft", "bearer"),
        ("use", "single"),
        ("verify", "offline"),
    ])
}

fn bearer() -> PropertyVector {
    vector(&[
        ("binding", "none"),
        ("issuer", "third-party"),
        ("link-actions", "linkable"),
        ("maturity", "standard"),
        ("pq", "no"),
        ("theft", "bearer"),
        ("use", "reusable"),
        ("verify", "online"),
    ])
}

fn web_bot_auth() -> PropertyVector {
    vector(&[
        ("binding", "A"),
        ("issuer", "third-party"),
        ("link-actions", "linkable"),
        ("maturity", "experimental"),
        ("pq", "no"),
        ("theft", "bearer"),
        ("use", "reusable"),
        ("verify", "online"),
    ])
}

fn phoenixd() -> PropertyVector {
    vector(&[
        ("custody", "self-custody"),
        ("finality", "final-on-verification"),
        ("link-payment", "unlinkable"),
        ("maturity", "standard"),
        ("pq", "no"),
    ])
}

fn card() -> PropertyVector {
    vector(&[
        ("custody", "third-party-custodial"),
        ("finality", "reversible"),
        ("link-payment", "linkable"),
        ("maturity", "standard"),
        ("pq", "no"),
    ])
}

fn local() -> PropertyVector {
    vector(&[
        ("custody", "self-custody"),
        ("finality", "final-on-verification"),
        ("issuer", "self-issued"),
        ("maturity", "standard"),
        ("verify", "offline"),
    ])
}

fn custodial_facilitator() -> PropertyVector {
    vector(&[
        ("custody", "third-party-custodial"),
        ("finality", "final-at-settlement"),
        ("issuer", "facilitator"),
        ("maturity", "experimental"),
        ("verify", "online"),
    ])
}

fn pay_vector(scheme: &PropertyVector, rails: &[&PropertyVector], verifier: &PropertyVector) -> EffectiveVector {
    let mut parts = vec![Part::known(PartKind::Credential, scheme)];
    parts.extend(rails.iter().map(|r| Part::known(PartKind::Rail, r)));
    parts.push(Part::known(PartKind::Verifier, verifier));
    EffectiveVector::compute(&parts)
}

fn attest_vector(scheme: &PropertyVector) -> EffectiveVector {
    EffectiveVector::compute(&[
        Part::known(PartKind::Attestation, scheme),
        Part::known(PartKind::Verifier, &local()),
    ])
}

fn pay(scheme: &str, v: EffectiveVector) -> Candidate {
    Candidate {
        scheme: scheme.into(),
        effect: None,
        vector: v,
    }
}

fn attest(scheme: &str, effect: Effect, v: EffectiveVector) -> Candidate {
    Candidate {
        scheme: scheme.into(),
        effect: Some(effect),
        vector: v,
    }
}

fn route(require: &[(&str, &str)], allow_experimental: bool) -> RoutePolicy {
    RoutePolicy {
        route: "chat".into(),
        require: Require::from_pairs(require.iter().copied()).unwrap(),
        allow_experimental,
    }
}

#[test]
fn the_embedded_table_is_ordered_weakest_first() {
    assert_eq!(PROPERTIES.len(), 12);
    let binding = property("binding").unwrap();
    assert!(binding.rank("S") > binding.rank("A"));
    assert!(binding.rank("A") > binding.rank("O"));
    assert!(binding.rank("O") > binding.rank("none"));
    let finality = property("finality").unwrap();
    assert_eq!(finality.value(0), Some("reversible"));
    assert!(!property("refund").unwrap().applies(PartKind::Attestation));
    assert!(!property("binding").unwrap().applies(PartKind::Rail));
}

/// The overview's route example: notes and per-action Lightning through
/// MPP or L402 qualify at binding O; a reusable bearer token never does;
/// at binding A only notes remain.
#[test]
fn the_overview_route_example() {
    let candidates = [
        pay("bnap:notes", pay_vector(&notes(), &[&phoenixd()], &local())),
        pay(
            "payment:lightning/charge",
            pay_vector(&ln_class_o(), &[&phoenixd()], &local()),
        ),
        pay("httpauth:L402", pay_vector(&ln_class_o(), &[&phoenixd()], &local())),
    ];
    let attestations = [
        attest("httpauth:Bearer", Effect::Waive, attest_vector(&bearer())),
        attest(
            "httpsig:web-bot-auth",
            Effect::Discount,
            attest_vector(&web_bot_auth()),
        ),
    ];
    let r = route(
        &[("use", "single"), ("binding", "O"), ("link-actions", "unlinkable")],
        true,
    );
    let sel = r.select(&candidates, &attestations).unwrap();
    assert_eq!(
        sel.pay,
        vec!["bnap:notes", "payment:lightning/charge", "httpauth:L402"]
    );
    assert!(sel.attest.is_empty(), "both attestations are reusable");

    let r = route(
        &[("use", "single"), ("binding", "A"), ("link-actions", "unlinkable")],
        true,
    );
    assert_eq!(r.select(&candidates, &[]).unwrap().pay, vec!["bnap:notes"]);
}

#[test]
fn notes_funded_by_card_are_reversible_and_linkable() {
    let v = pay_vector(&notes(), &[&phoenixd(), &card()], &local());
    assert_eq!(v.value("finality"), Some("reversible"));
    assert_eq!(v.value("link-payment"), Some("linkable"));
    assert_eq!(v.value("custody"), Some("third-party-custodial"));
    // Properties rails do not carry keep the scheme's value.
    assert_eq!(v.value("binding"), Some("S"));
    assert_eq!(v.value("theft"), Some("key-witnessed"));
}

#[test]
fn a_custodial_facilitator_makes_the_entry_custodial() {
    let v = pay_vector(&ln_class_o(), &[&phoenixd()], &custodial_facilitator());
    assert_eq!(v.value("custody"), Some("third-party-custodial"));
    assert_eq!(v.value("issuer"), Some("facilitator"));
    assert_eq!(v.value("verify"), Some("online"));
}

#[test]
fn unknown_counts_as_weakest() {
    // A rail with no registry entry: every rail property at its weakest,
    // nothing else touched.
    let v = EffectiveVector::compute(&[
        Part::known(PartKind::Credential, &notes()),
        Part::unknown(PartKind::Rail),
        Part::known(PartKind::Verifier, &local()),
    ]);
    assert_eq!(v.value("finality"), Some("reversible"));
    assert_eq!(v.value("maturity"), Some("experimental"));
    assert_eq!(v.value("binding"), Some("S"));
    // A scheme with no entry: weakest everywhere.
    let v = EffectiveVector::compute(&[Part::unknown(PartKind::Credential)]);
    assert_eq!(v.value("binding"), Some("none"));
    assert_eq!(v.value("use"), Some("reusable"));
    // A missing property and an unknown token in an entry.
    let mut n = notes();
    n.remove("theft");
    n.insert("binding".into(), "Z".into());
    let v = EffectiveVector::compute(&[Part::known(PartKind::Credential, &n)]);
    assert_eq!(v.value("theft"), Some("bearer"));
    assert_eq!(v.value("binding"), Some("none"));
}

#[test]
fn credential_only_properties_do_not_constrain_attestations() {
    let r = route(&[("refund", "atomic"), ("finality", "final-on-verification")], true);
    let v = attest_vector(&web_bot_auth());
    assert_eq!(v.rank("refund"), None);
    assert!(r.admits(&v));
    let sel = r
        .select(
            &[pay("bnap:notes", pay_vector(&notes(), &[&phoenixd()], &local()))],
            &[attest("httpsig:web-bot-auth", Effect::Discount, v)],
        )
        .unwrap();
    assert_eq!(sel.attest, vec!["httpsig:web-bot-auth"]);
}

#[test]
fn an_unsatisfiable_route_is_refused() {
    let only_bearer = [pay(
        "httpauth:L402",
        pay_vector(&ln_class_o(), &[&phoenixd()], &local()),
    )];
    let r = route(&[("binding", "S")], true);
    assert_eq!(
        r.select(&only_bearer, &[]),
        Err(PolicyError::Unsatisfiable("chat".into()))
    );
    // Experimental entries need allow_experimental.
    let r = route(&[], false);
    let notes_only = [pay("bnap:notes", pay_vector(&notes(), &[&phoenixd()], &local()))];
    assert_eq!(
        r.select(&notes_only, &[]),
        Err(PolicyError::Unsatisfiable("chat".into()))
    );
    assert!(route(&[], true).select(&notes_only, &[]).is_ok());
}

#[test]
fn an_attestation_waive_can_satisfy_a_route_without_pay() {
    let dpop = vector(&[
        ("binding", "A"),
        ("issuer", "third-party"),
        ("link-actions", "linkable"),
        ("maturity", "standard"),
        ("pq", "no"),
        ("theft", "bearer"),
        ("use", "reusable"),
        ("verify", "online"),
    ]);
    let r = route(&[("binding", "A")], false);
    let sel = r
        .select(&[], &[attest("httpauth:DPoP", Effect::Waive, attest_vector(&dpop))])
        .unwrap();
    assert_eq!(sel.attest, vec!["httpauth:DPoP"]);
    // A discount alone cannot.
    assert!(matches!(
        r.select(&[], &[attest("httpauth:DPoP", Effect::Discount, attest_vector(&dpop))]),
        Err(PolicyError::Unsatisfiable(_))
    ));
}

#[test]
fn a_required_attestation_that_fails_the_policy_is_refused() {
    let r = route(&[("binding", "O")], true);
    let notes_only = [pay("bnap:notes", pay_vector(&notes(), &[&phoenixd()], &local()))];
    let err = r
        .select(
            &notes_only,
            &[attest("httpauth:Bearer", Effect::Required, attest_vector(&bearer()))],
        )
        .unwrap_err();
    assert_eq!(
        err,
        PolicyError::RequiredAttestation {
            route: "chat".into(),
            scheme: "httpauth:Bearer".into()
        }
    );
}

#[test]
fn require_parsing() {
    let raw: BTreeMap<String, Value> =
        serde_json::from_value(json!({"use": "single", "binding": "O"})).unwrap();
    let req = Require::parse(Some(&raw)).unwrap();
    assert!(req.satisfied_by(&pay_vector(&notes(), &[&phoenixd()], &local())));
    assert_eq!(Require::parse(None).unwrap(), Require::default());

    let bad: BTreeMap<String, Value> = serde_json::from_value(json!({"speed": "fast"})).unwrap();
    assert_eq!(
        Require::parse(Some(&bad)),
        Err(PolicyError::UnknownProperty("speed".into()))
    );
    let bad: BTreeMap<String, Value> = serde_json::from_value(json!({"binding": "B"})).unwrap();
    assert!(matches!(
        Require::parse(Some(&bad)),
        Err(PolicyError::UnknownValue { .. })
    ));
    let bad: BTreeMap<String, Value> = serde_json::from_value(json!({"binding": 3})).unwrap();
    assert!(matches!(
        Require::parse(Some(&bad)),
        Err(PolicyError::UnknownValue { .. })
    ));
}

#[test]
fn tokens_for_the_judge() {
    let v = pay_vector(&notes(), &[&phoenixd()], &local());
    let t = v.to_tokens();
    assert_eq!(t.len(), 12);
    assert_eq!(t["binding"], "S");
    assert_eq!(t["custody"], "operator-iou");
}
