//! `httpauth:DPoP` and `httpauth:Bearer` driven through bnap-core's
//! `outcome::process` on the in-memory store, the way a gate runs them:
//! the gate takes each scheme's class and use model from the registry,
//! verifies every part, drops attestations that fail (section 7: no effect,
//! no error) and hands the rest to `process`, which prices and commits.

use std::cell::Cell;
use std::sync::Arc;

use bnap_core::class::BindingClass;
use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::hash::{Context, Scope, sha256};
use bnap_core::ids;
use bnap_core::limits::Limits;
use bnap_core::offer::{AttestEntry, Effect, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ProcessError, ReceiptInput, Recorded, Request};
use bnap_core::pricing::{Backing, BackingSource, PayValue, Refund, VerifiedAttest};
use bnap_core::response::Status;
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{SchemeUses, Settlement, UseModel, UseStore};
use bnap_core::test_support::{MemoryStore, block_on};
use bnap_core::{ErrorCode, Offer, Pending};
use bnap_plug::{
    BlindSignature, BlindedOutput, CappedSigner, ChangeLimit, CoreMessage, CredentialScheme, Entry,
    KeysetId, OfferCtx, Point, SchemeError, SchemeOffer, Signer, SignerError, Verified, VerifyCtx,
};
use bnap_scheme_dpop::body::BearerBody;
use bnap_scheme_dpop::client::{self, ProofClaims, ProofKey};
use bnap_scheme_dpop::jose::b64u;
use bnap_scheme_dpop::{
    Authority, AuthorityError, BEARER, BearerScheme, DPOP, DpopScheme, StaticAuthority, Thumbprint,
    TokenInfo, TokenStatus, codes,
};

const NOW: u64 = 1_791_700_000;
const NOTES: &str = "bnap:notes";

// ---------------------------------------------------------------- registry

/// The registry's word on each scheme (`registry/schemes.toml`): class and
/// use model. A gate takes both from the registry, never from a plug.
fn registry(scheme: &str) -> (BindingClass, UseModel) {
    match scheme {
        DPOP => (BindingClass::A, UseModel::Reusable),
        BEARER => (BindingClass::None, UseModel::Reusable),
        NOTES => (BindingClass::S, UseModel::Single),
        _ => (BindingClass::None, UseModel::Single),
    }
}

// ------------------------------------------------------------------ plugs

/// Attestations sign nothing; a signer that refuses everything shows it.
struct NoSigner;

#[async_trait::async_trait]
impl Signer for NoSigner {
    async fn schnorr(&self, _msg: &CoreMessage) -> Result<Signature, SignerError> {
        Err(SignerError::Refused("attestation tests sign nothing".into()))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        _unit: &str,
        _amount: u64,
        _secret: &[u8],
        _c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        Err(SignerError::Refused("attestation tests check no notes".into()))
    }

    async fn blind_sign(
        &self,
        _keyset: &KeysetId,
        _outputs: &[BlindedOutput],
        _limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        Err(SignerError::Refused("attestation tests sign nothing".into()))
    }
}

/// A stand-in for `bnap:notes`, class S: the body names one note (`Y`
/// and its amount) and the key that spends it, and the witness is that
/// key's BIP-340 signature over the Digest, as a notes witness is. The
/// gate counts the note as backing; a real gate gets the note from the
/// signer's verify-only view instead.
struct StubNotes;

fn notes_body(key: &SigningKey, y: [u8; 33], amount: u64) -> Vec<u8> {
    let mut b = key.public_key().0.to_vec();
    b.extend_from_slice(&y);
    b.extend_from_slice(&amount.to_be_bytes());
    b
}

#[async_trait::async_trait]
impl CredentialScheme for StubNotes {
    fn id(&self) -> &str {
        NOTES
    }

    async fn offer(&self, _cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        Ok(SchemeOffer::default())
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let bad = |d: &str| SchemeError::rejected(NOTES, "BAD_SIGNATURE", d);
        let b = &part.body;
        if b.len() != 32 + 33 + 8 {
            return Err(bad("body"));
        }
        let key = Key(b[..32].try_into().unwrap());
        let sig = Signature(part.witness.as_slice().try_into().map_err(|_| bad("witness"))?);
        key.verify(&cx.digest.0, &sig)
            .map_err(|_| bad("the witness does not sign this Digest"))?;
        Ok(Verified {
            use_ids: vec![b[32..65].to_vec()],
            rail_ids: Vec::new(),
            value: u64::from_be_bytes(b[65..].try_into().unwrap()),
            quota_id: None,
        })
    }
}

/// An authority that cannot be reached.
struct Down;

#[async_trait::async_trait]
impl Authority for Down {
    async fn check_token(&self, _t: &str, _now: u64) -> Result<TokenStatus, AuthorityError> {
        Err(AuthorityError("introspection endpoint timed out".into()))
    }

    async fn check_key(&self, _j: &Thumbprint, _now: u64) -> Result<bool, AuthorityError> {
        Err(AuthorityError("key registry timed out".into()))
    }
}

// ------------------------------------------------------------------- gate

struct Gate {
    store: MemoryStore,
    offer: Offer,
    scope: Scope,
    limits: Limits,
    dpop: DpopScheme,
    bearer: BearerScheme,
    /// Overrides the registry class of `httpauth:DPoP`, to show that the
    /// price rule follows the class whatever the plug verified.
    dpop_class: Cell<Option<BindingClass>>,
    /// Overrides the registry use model of `httpauth:DPoP`.
    dpop_model: Cell<Option<UseModel>>,
}

fn offer_key() -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(b"bnap test offer key")).unwrap()
}

fn scope() -> Scope {
    Scope(sha256(b"POST https://api.example/v1/thing"))
}

impl Gate {
    /// A gate whose offer lists `bnap:notes` at `price` sat (none without
    /// a price) and `attest`.
    fn new(price: Option<u64>, attest: Vec<AttestEntry>, authority: Arc<dyn Authority>) -> Self {
        Self::with_offer(scope(), price, attest, authority)
    }

    fn with_offer(
        scope: Scope,
        price: Option<u64>,
        attest: Vec<AttestEntry>,
        authority: Arc<dyn Authority>,
    ) -> Self {
        let key = offer_key();
        let mut f = OfferFields::new(scope, NOW + 300, key.public_key(), [5; 16]);
        if let Some(p) = price {
            f.pay = vec![PayEntry::new(NOTES, p, "sat")];
        }
        f.attest = attest;
        let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
        let sig = unsigned.message().sign_with(&key, &[0; 32]).unwrap();
        Self {
            store: MemoryStore::new(),
            offer: unsigned.finish(&sig).unwrap(),
            scope,
            limits: Limits::default(),
            dpop: DpopScheme::new(authority.clone()),
            bearer: BearerScheme::new(authority),
            dpop_class: Cell::new(None),
            dpop_model: Cell::new(None),
        }
    }

    fn registry(&self, scheme: &str) -> (BindingClass, UseModel) {
        let (class, model) = registry(scheme);
        if scheme == DPOP {
            (
                self.dpop_class.get().unwrap_or(class),
                self.dpop_model.get().unwrap_or(model),
            )
        } else {
            (class, model)
        }
    }

    fn context(&self, cred: &Credential) -> Context {
        cred.context(&self.offer.offer_id(), &self.scope)
    }

    /// One attestation part through its scheme's `verify`.
    fn verify_attest(&self, cred: &Credential, scheme: &str, now: u64) -> Result<Verified, SchemeError> {
        let part = cred.attest.iter().find(|p| p.scheme == scheme).unwrap();
        let entry = self.offer.fields().attest_entry(scheme).unwrap();
        let ctx = self.context(cred);
        let digest = cred.digest(&ctx);
        let view = CappedSigner::verify_only(Arc::new(NoSigner), "sat");
        let plug: &dyn CredentialScheme = match scheme {
            DPOP => &self.dpop,
            _ => &self.bearer,
        };
        block_on(plug.verify(
            part,
            &VerifyCtx {
                now,
                offer: &self.offer,
                entry: Entry::Attest(entry),
                action_scope: &self.scope,
                context: &ctx,
                digest: &digest,
                signer: &view,
            },
        ))
    }

    /// The gate's flow after the 4.4 checks: verify every part, then
    /// `process`. An error a plug raises is mapped to its code.
    fn process(&self, cred: &Credential, now: u64) -> Result<Admitted, ErrorCode> {
        cred.check_binding_classes(|s| Some(self.registry(s).0))
            .map_err(|e| e.code())?;
        let ctx = self.context(cred);
        let digest = cred.digest(&ctx);
        let mut uses: Vec<(String, UseModel, Vec<Vec<u8>>)> = Vec::new();
        let mut attest = Vec::new();
        for part in &cred.attest {
            let (class, model) = self.registry(&part.scheme);
            match self.verify_attest(cred, &part.scheme, now) {
                Ok(v) => {
                    let mut a = VerifiedAttest::new(&part.scheme, class);
                    if let Some(q) = v.quota_use_id(&part.scheme) {
                        a = a.with_quota_id(q);
                    }
                    attest.push(a);
                    uses.push((part.scheme.clone(), model, v.use_ids));
                }
                // Section 7: an attestation that fails has no effect and
                // causes no error; a required one is POLICY at admission.
                Err(SchemeError::Rejected { .. }) => {}
                Err(e) => return Err(e.code()),
            }
        }
        let mut pay = None;
        if let Some(part) = &cred.pay {
            let entry = self.offer.fields().pay_entry(NOTES).unwrap().1;
            let view = CappedSigner::verify_only(Arc::new(NoSigner), "sat");
            let v = block_on(StubNotes.verify(
                part,
                &VerifyCtx {
                    now,
                    offer: &self.offer,
                    entry: Entry::Pay(entry),
                    action_scope: &self.scope,
                    context: &ctx,
                    digest: &digest,
                    signer: &view,
                },
            ))
            .map_err(|e| e.code())?;
            pay = Some(PayValue {
                scheme: NOTES,
                claimed: v.value,
                backing: vec![Backing {
                    source: BackingSource::Note(v.use_ids[0].clone()),
                    amount: v.value,
                    unit: "sat".into(),
                }],
                refund: Refund::Atomic,
            });
            uses.push((NOTES.into(), UseModel::Single, v.use_ids));
        }
        let bodies: Vec<&[u8]> = cred.attest.iter().map(|p| p.body.as_slice()).collect();
        let schemes: Vec<SchemeUses<'_>> = uses
            .iter()
            .map(|(s, m, ids)| SchemeUses {
                scheme: s,
                model: *m,
                local_ids: ids,
            })
            .collect();
        let pay_body = cred.pay.as_ref().map_or(&[][..], |p| p.body.as_slice());
        block_on(outcome::process(
            &self.store,
            &Request {
                offer: self.offer.fields(),
                context: &ctx,
                pay_body,
                attest_bodies: &bodies,
                schemes: &schemes,
                rail_ids: &[],
                pay,
                attest: &attest,
                now,
            },
            &self.limits,
        ))
        .map_err(|e: ProcessError| e.code())
    }

    /// Runs the action and settles OK, keeping `answer` as the response.
    fn settle_ok(&self, p: &Pending, answer: &[u8], now: u64) -> Recorded {
        let charge = p.charge(Status::Ok, 0);
        let s = Settlement::new(&charge, now).with_response(Some(answer.to_vec()));
        block_on(outcome::settle(&self.store, p, &s, &self.limits)).unwrap()
    }

    fn receipt_input(&self, cred: &Credential) -> ReceiptInput {
        ReceiptInput {
            offer_id: self.offer.offer_id(),
            digest: cred.digest(&self.context(cred)),
            unit: cred.pay.as_ref().map(|_| "sat".to_owned()),
            metered: false,
            receipt_key: Key([2; 32]),
        }
    }
}

fn new(r: Result<Admitted, ErrorCode>) -> Pending {
    match r {
        Ok(Admitted::New(p)) => p,
        other => panic!("expected New, got {other:?}"),
    }
}

fn replayed(r: Result<Admitted, ErrorCode>) -> Recorded {
    match r {
        Ok(Admitted::Replay(r)) => r,
        other => panic!("expected a replay, got {other:?}"),
    }
}

fn rejected_with(r: Result<Verified, SchemeError>, scheme: &str, code: &str) {
    match r {
        Err(SchemeError::Rejected { scheme_code, .. }) => {
            assert_eq!(scheme_code, format!("{scheme}/{code}"));
        }
        other => panic!("expected {scheme}/{code}, got {other:?}"),
    }
}

// ----------------------------------------------------------------- client

/// A client key, P-256 unless `ed`.
fn key(tag: &str) -> ProofKey {
    ProofKey::es256(&sha256(tag.as_bytes())).unwrap()
}

fn ed_key(tag: &str) -> ProofKey {
    ProofKey::ed25519(&sha256(tag.as_bytes()))
}

/// What a client puts in one credential.
#[derive(Clone)]
struct Cred {
    /// A note worth this many sat, spent by a key derived from the tag.
    notes: Option<(&'static str, u64)>,
    /// A DPoP key, the access token it presents, and the proof's `jti`.
    dpop: Option<(ProofKey, Option<&'static str>, &'static str)>,
    /// A bearer token.
    bearer: Option<&'static str>,
    /// The proof's `iat`.
    iat: u64,
}

impl Cred {
    fn dpop(k: &ProofKey, token: Option<&'static str>, jti: &'static str) -> Self {
        Self {
            notes: None,
            dpop: Some((k.clone(), token, jti)),
            bearer: None,
            iat: NOW,
        }
    }

    fn with_notes(mut self, tag: &'static str, amount: u64) -> Self {
        self.notes = Some((tag, amount));
        self
    }

    /// Builds the credential: parts first (the Context names their scheme
    /// IDs), then the proof over that Context, then the notes witness over
    /// the Digest, which covers the proof.
    fn build(&self, gate: &Gate) -> Credential {
        let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
        if let Some((tag, amount)) = self.notes {
            let k = notes_key(tag);
            let y = note_y(tag);
            c.pay = Some(SchemePart::new(NOTES, notes_body(&k, y, amount)));
        }
        if self.dpop.is_some() {
            c.attest.push(SchemePart::new(DPOP, Vec::new()));
        }
        if let Some(t) = self.bearer {
            c.attest.push(SchemePart::new(
                BEARER,
                BearerBody {
                    token: t.to_owned(),
                }
                .to_bytes(),
            ));
        }
        c.sort_attest();
        let ctx = gate.context(&c);
        if let Some((k, token, jti)) = &self.dpop {
            let proof = proof_for(k, &ctx, *token, jti, self.iat);
            set_dpop_body(&mut c, client::body(&proof, *token));
        }
        sign_notes(gate, &mut c);
        c
    }
}

fn notes_key(tag: &str) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(format!("notes key {tag}").as_bytes())).unwrap()
}

fn note_y(tag: &str) -> [u8; 33] {
    let mut y = [2u8; 33];
    y[1..].copy_from_slice(&sha256(format!("note {tag}").as_bytes()));
    y
}

/// (Re)signs the notes witness over the credential's current Digest.
fn sign_notes(gate: &Gate, c: &mut Credential) {
    let digest = c.digest(&gate.context(c));
    if let Some(p) = c.pay.as_mut() {
        let k = Key(p.body[..32].try_into().unwrap());
        let tag_key = ["a", "b", "c", "d"]
            .into_iter()
            .map(notes_key)
            .find(|s| s.public_key() == k)
            .unwrap();
        p.witness = tag_key.sign(&digest.0, &[0; 32]).0.to_vec();
    }
}

fn set_dpop_body(c: &mut Credential, body: Vec<u8>) {
    c.attest.iter_mut().find(|p| p.scheme == DPOP).unwrap().body = body;
}

fn proof_for(k: &ProofKey, ctx: &Context, token: Option<&str>, jti: &str, iat: u64) -> String {
    client::sign_proof(
        k,
        &ProofClaims {
            context: ctx,
            htm: "POST",
            htu: "https://api.example/v1/thing",
            iat,
            jti,
            access_token: token,
        },
    )
}

/// An authority that registered the keys `a` (P-256) and `ed` (Ed25519)
/// and knows the tokens: `tok-a` bound to `a`, `tok-b` bound to `b`,
/// `bearer-1` bound to no key.
fn authority() -> Arc<StaticAuthority> {
    Arc::new(
        StaticAuthority::new()
            .with_key(key("a").thumbprint())
            .with_key(ed_key("ed").thumbprint())
            .with_token("tok-a", TokenInfo::bound_to(key("a").thumbprint()))
            .with_token("tok-b", TokenInfo::bound_to(key("b").thumbprint()))
            .with_token("bearer-1", TokenInfo::bearer()),
    )
}

fn waive_gate() -> Gate {
    Gate::new(None, vec![AttestEntry::new(DPOP, Effect::Waive)], authority())
}

/// The 10.3 shape: notes at 2,100 sat with a 20% discount.
fn discount_gate() -> Gate {
    Gate::new(
        Some(2100),
        vec![AttestEntry::discount(DPOP, 2000)],
        authority(),
    )
}

// ----------------------------------------------------------------- tests

#[test]
fn a_verified_proof_names_the_key_thumbprint_as_use_and_quota_id() {
    let gate = waive_gate();
    let k = key("a");
    let cred = Cred::dpop(&k, None, "j1").build(&gate);
    let v = gate.verify_attest(&cred, DPOP, NOW).unwrap();
    let jkt = k.thumbprint().0.to_vec();
    assert_eq!(v.use_ids, vec![jkt.clone()]);
    assert_eq!(v.quota_id, Some(jkt.clone()));
    assert_eq!((v.value, v.rail_ids.len()), (0, 0));
    assert_eq!(v.quota_use_id(DPOP), Some(ids::use_id(DPOP, &jkt)));
    // With a token bound to the key, and with an Ed25519 key.
    let with_token = Cred::dpop(&k, Some("tok-a"), "j2").build(&gate);
    assert_eq!(gate.verify_attest(&with_token, DPOP, NOW).unwrap(), v);
    let ed = ed_key("ed");
    let cred = Cred::dpop(&ed, None, "j3").build(&gate);
    assert_eq!(
        gate.verify_attest(&cred, DPOP, NOW).unwrap().use_ids,
        vec![ed.thumbprint().0.to_vec()]
    );
}

#[test]
fn a_waive_admits_an_attestation_only_credential_and_its_replay_returns_the_outcome() {
    // The draft-00 attestation-only shape: an exact offer whose only entry
    // is an httpauth:DPoP waive; no pay, ext or binding.
    let gate = waive_gate();
    let cred = Cred::dpop(&key("a"), None, "j1").build(&gate);
    let p = new(gate.process(&cred, NOW));
    assert_eq!(p.admission().price(), 0);
    let rec = gate.settle_ok(&p, b"the answer", NOW + 1);
    assert!(!rec.replayed());

    // The same credential again: the recorded outcome, never a second
    // action, whatever the clock says within the replay window.
    for later in [NOW + 2, NOW + 600, NOW + 3600] {
        let again = replayed(gate.process(&cred, later));
        assert!(again.replayed());
        assert_eq!(again.replay_key(), p.replay_key());
        assert_eq!(again.record().response.as_deref(), Some(&b"the answer"[..]));
        let r = again.receipt(&gate.receipt_input(&cred)).unwrap();
        assert_eq!((r.status, r.charged, r.replayed), (Status::Ok, 0, true));
        assert_eq!(r.settled_at, NOW + 1);
    }
    // A copy still in flight is PENDING, not a second action.
    let other = Cred::dpop(&key("a"), None, "j2").build(&gate);
    let _p2 = new(gate.process(&other, NOW));
    assert_eq!(gate.process(&other, NOW + 1).unwrap_err(), ErrorCode::Pending);
}

#[test]
fn a_discount_takes_its_basis_points_and_a_failed_proof_takes_none() {
    let gate = discount_gate();
    let paid = Cred::dpop(&key("a"), None, "j1").with_notes("a", 1680);
    let p = new(gate.process(&paid.build(&gate), NOW));
    // 2,100 - floor(2,100 x 2,000 / 10,000) = 1,680 (draft-00 10.3).
    assert_eq!(p.admission().price(), 1680);

    // A proof the scheme refuses has no effect and causes no error: the
    // full price applies, and 1,680 sat is not enough.
    let unknown_key = Cred::dpop(&key("z"), None, "j2").with_notes("b", 1680);
    assert_eq!(
        gate.process(&unknown_key.build(&gate), NOW).unwrap_err(),
        ErrorCode::Underpaid
    );
    let full = Cred::dpop(&key("z"), None, "j3").with_notes("c", 2100);
    assert_eq!(new(gate.process(&full.build(&gate), NOW)).admission().price(), 2100);
}

#[test]
fn waive_and_discount_apply_only_for_classes_s_a_and_o() {
    // The same verified DPoP attestation, with the class the registry
    // gives it changed: the price rule follows the class, never the plug.
    for (class, waived, discounted) in [
        (BindingClass::S, true, true),
        (BindingClass::A, true, true),
        (BindingClass::O, true, true),
        (BindingClass::None, false, false),
    ] {
        let gate = waive_gate();
        gate.dpop_class.set(Some(class));
        let cred = Cred::dpop(&key("a"), None, "j1").build(&gate);
        let r = gate.process(&cred, NOW);
        if waived {
            assert_eq!(new(r).admission().price(), 0, "{class}");
        } else {
            assert_eq!(r.unwrap_err(), ErrorCode::Underpaid, "{class}");
        }

        let gate = discount_gate();
        gate.dpop_class.set(Some(class));
        let cred = Cred::dpop(&key("a"), None, "j1").with_notes("a", 1680).build(&gate);
        let r = gate.process(&cred, NOW);
        if discounted {
            assert_eq!(new(r).admission().price(), 1680, "{class}");
        } else {
            assert_eq!(r.unwrap_err(), ErrorCode::Underpaid, "{class}");
        }
    }
}

#[test]
fn a_bearer_attestation_can_never_waive_or_discount() {
    // The offer builder refuses an offer in which a class none attestation
    // waives, discounts or carries a quota (draft-00 section 7).
    for e in [
        AttestEntry::new(BEARER, Effect::Waive),
        AttestEntry::discount(BEARER, 2000),
        AttestEntry::quota(BEARER, 5, 3600),
    ] {
        let mut f = OfferFields::new(scope(), NOW + 300, offer_key().public_key(), [5; 16]);
        f.pay = vec![PayEntry::new(NOTES, 2100, "sat")];
        f.attest = vec![e.clone()];
        assert!(
            f.check_binding_classes(|s| Some(registry(s).0)).is_err(),
            "{e:?}"
        );
    }

    // A gate that skipped that check: the bearer token verifies, but its
    // waive and its discount have no effect.
    let token = Cred {
        notes: None,
        dpop: None,
        bearer: Some("bearer-1"),
        iat: NOW,
    };
    let gate = Gate::new(None, vec![AttestEntry::new(BEARER, Effect::Waive)], authority());
    let cred = token.build(&gate);
    assert!(gate.verify_attest(&cred, BEARER, NOW).is_ok());
    assert_eq!(gate.process(&cred, NOW).unwrap_err(), ErrorCode::Underpaid);

    let gate = Gate::new(
        Some(2100),
        vec![AttestEntry::discount(BEARER, 2000)],
        authority(),
    );
    let cred = token.clone().with_notes("a", 1680).build(&gate);
    assert_eq!(gate.process(&cred, NOW).unwrap_err(), ErrorCode::Underpaid);
    let cred = token.clone().with_notes("b", 2100).build(&gate);
    assert_eq!(new(gate.process(&cred, NOW)).admission().price(), 2100);

    // What class none may do: satisfy a required attestation.
    let gate = Gate::new(
        Some(21),
        vec![AttestEntry::new(BEARER, Effect::Required)],
        authority(),
    );
    let cred = token.clone().with_notes("c", 21).build(&gate);
    assert_eq!(new(gate.process(&cred, NOW)).admission().price(), 21);
}

#[test]
fn without_dpop_binding_a_token_is_class_none() {
    // The OAuth-with-DPoP pairing. A bearer token (no cnf.jkt) cannot be
    // dressed up as httpauth:DPoP, even with a valid proof by a key the
    // authority registered ...
    let gate = waive_gate();
    let cred = Cred::dpop(&key("a"), Some("bearer-1"), "j1").build(&gate);
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::UNBOUND_TOKEN);
    assert_eq!(gate.process(&cred, NOW).unwrap_err(), ErrorCode::Underpaid);

    // ... and a DPoP-bound token is never accepted without its proof.
    let gate = Gate::new(
        Some(21),
        vec![AttestEntry::new(BEARER, Effect::Required)],
        authority(),
    );
    let bound = Cred {
        notes: None,
        dpop: None,
        bearer: Some("tok-a"),
        iat: NOW,
    }
    .with_notes("a", 21)
    .build(&gate);
    rejected_with(gate.verify_attest(&bound, BEARER, NOW), BEARER, codes::DPOP_BOUND_TOKEN);
    assert_eq!(gate.process(&bound, NOW).unwrap_err(), ErrorCode::Policy);
}

#[test]
fn tokens_must_be_active_and_bound_to_the_proof_key() {
    let gate = waive_gate();
    let a = key("a");
    // Bound to another key.
    let cred = Cred::dpop(&a, Some("tok-b"), "j1").build(&gate);
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::KEY_MISMATCH);
    // Not active.
    let cred = Cred::dpop(&a, Some("revoked"), "j2").build(&gate);
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::INVALID_TOKEN);
    // No token, and a key nobody registered.
    let cred = Cred::dpop(&key("b"), None, "j3").build(&gate);
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::UNKNOWN_KEY);
    // The token key b holds works with b's proof.
    let cred = Cred::dpop(&key("b"), Some("tok-b"), "j4").build(&gate);
    assert!(gate.verify_attest(&cred, DPOP, NOW).is_ok());

    // ath names the token the proof was made for: a proof for tok-a
    // presented with tok-b, or without any token, is refused, and so is a
    // proof without ath presented with a token.
    let mut cred = Cred::dpop(&a, Some("tok-a"), "j5").build(&gate);
    let ctx = gate.context(&cred);
    let for_a = proof_for(&a, &ctx, Some("tok-a"), "j5", NOW);
    set_dpop_body(&mut cred, client::body(&for_a, Some("tok-b")));
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::ATH_MISMATCH);
    set_dpop_body(&mut cred, client::body(&for_a, None));
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::ATH_MISMATCH);
    let no_ath = proof_for(&a, &ctx, None, "j5", NOW);
    set_dpop_body(&mut cred, client::body(&no_ath, Some("tok-a")));
    rejected_with(gate.verify_attest(&cred, DPOP, NOW), DPOP, codes::ATH_MISMATCH);
}

#[test]
fn a_proof_whose_bnap_ctx_names_another_context_is_refused() {
    let gate = discount_gate();
    let a = key("a");
    let cred = Cred::dpop(&a, None, "j1").with_notes("a", 1680).build(&gate);
    assert!(gate.verify_attest(&cred, DPOP, NOW).is_ok());

    // Each of these is a Context the client did not choose for this
    // credential: another request (action scope), another offer, the
    // credential without its pay part, another extension.
    let other_request = cred.context(&gate.offer.offer_id(), &Scope(sha256(b"GET /admin")));
    let other_gate = Gate::with_offer(
        scope(),
        Some(2100),
        vec![AttestEntry::discount(DPOP, 1000)],
        authority(),
    );
    let other_offer = cred.context(&other_gate.offer.offer_id(), &gate.scope);
    let mut no_pay = cred.clone();
    no_pay.pay = None;
    let without_pay = gate.context(&no_pay);
    let mut with_ext = cred.clone();
    with_ext.ext.push(1, b"ext".to_vec()).unwrap();
    let other_ext = gate.context(&with_ext);
    for wrong in [other_request, other_offer, without_pay, other_ext] {
        assert_ne!(wrong, gate.context(&cred));
        let mut c = cred.clone();
        set_dpop_body(&mut c, client::body(&proof_for(&a, &wrong, None, "j1", NOW), None));
        sign_notes(&gate, &mut c);
        rejected_with(gate.verify_attest(&c, DPOP, NOW), DPOP, codes::WRONG_CONTEXT);
        // The discount is gone, so 1,680 sat no longer pays.
        assert_eq!(gate.process(&c, NOW).unwrap_err(), ErrorCode::Underpaid);
    }

    // The claim is the exact lowercase hex: upper case is another string.
    let ctx = gate.context(&cred);
    let mut claims = client::claims(&ProofClaims {
        context: &ctx,
        htm: "POST",
        htu: "https://api.example/v1/thing",
        iat: NOW,
        jti: "j1",
        access_token: None,
    });
    claims["bnap_ctx"] = hex::encode_upper(ctx.0).into();
    let upper = client::sign_raw(&a, client::header(&a).to_string().as_bytes(), claims.to_string().as_bytes());
    let mut c = cred.clone();
    set_dpop_body(&mut c, client::body(&upper, None));
    rejected_with(gate.verify_attest(&c, DPOP, NOW), DPOP, codes::WRONG_CONTEXT);

    // A plain RFC 9449 proof, made for no BNAP request, has no bnap_ctx.
    let mut plain = client::claims(&ProofClaims {
        context: &ctx,
        htm: "POST",
        htu: "https://api.example/v1/thing",
        iat: NOW,
        jti: "j1",
        access_token: None,
    });
    plain.as_object_mut().unwrap().remove("bnap_ctx");
    let plain = client::sign_raw(&a, client::header(&a).to_string().as_bytes(), plain.to_string().as_bytes());
    set_dpop_body(&mut c, client::body(&plain, None));
    rejected_with(gate.verify_attest(&c, DPOP, NOW), DPOP, codes::BAD_PROOF);
}

#[test]
fn a_stripped_or_altered_attestation_breaks_the_digest() {
    let gate = discount_gate();
    let a = key("a");
    let cred = Cred::dpop(&a, None, "j1").with_notes("a", 1680).build(&gate);
    let ctx = gate.context(&cred);
    let digest = cred.digest(&ctx);

    // Stripped: the Context loses the attestation scheme and the Digest
    // its body, so the class S witness no longer signs it. The notes part
    // fails verification (BAD_CREDENTIAL) before any price is computed.
    let mut stripped = cred.clone();
    stripped.attest.clear();
    assert_ne!(gate.context(&stripped), ctx);
    assert_ne!(stripped.digest(&gate.context(&stripped)), digest);
    assert_eq!(gate.process(&stripped, NOW).unwrap_err(), ErrorCode::BadCredential);

    // Altered: another valid proof by the same key for the same Context
    // (another jti). The Context is the same, the Digest is not, and the
    // witness fails again.
    let mut swapped = cred.clone();
    set_dpop_body(&mut swapped, client::body(&proof_for(&a, &ctx, None, "j2", NOW), None));
    assert_eq!(gate.context(&swapped), ctx);
    assert_ne!(swapped.digest(&ctx), digest);
    assert!(gate.verify_attest(&swapped, DPOP, NOW).is_ok());
    assert_eq!(gate.process(&swapped, NOW).unwrap_err(), ErrorCode::BadCredential);

    // Altered bytes: one flipped bit in the proof also breaks the proof.
    let body = cred.attest[0].body.clone();
    for i in [2, body.len() / 2, body.len() - 2] {
        let mut flipped = cred.clone();
        let mut b = body.clone();
        b[i] ^= 0x01;
        set_dpop_body(&mut flipped, b);
        assert_ne!(flipped.digest(&ctx), digest);
        assert!(gate.verify_attest(&flipped, DPOP, NOW).is_err(), "byte {i}");
        assert_eq!(gate.process(&flipped, NOW).unwrap_err(), ErrorCode::BadCredential);
    }

    // The original still goes through.
    assert_eq!(new(gate.process(&cred, NOW)).admission().price(), 1680);
}

#[test]
fn a_re_encoded_proof_cannot_take_the_credential_under_another_replay_key() {
    // Without a class S witness, nothing but the proof's own canonical form
    // keeps someone on the path from re-encoding the body and committing
    // it first under another ReplayKey (draft-00 5.1). The high-s twin of
    // an ES256 signature is valid ECDSA, so it is refused as non-canonical.
    let gate = waive_gate();
    let cred = Cred::dpop(&key("a"), None, "j1").build(&gate);
    let body = bnap_scheme_dpop::body::DpopBody::parse(&cred.attest[0].body).unwrap();
    let parts: Vec<&str> = body.proof.split('.').collect();
    let sig = bnap_scheme_dpop::jose::b64u_decode(parts[2].as_bytes()).unwrap();
    let low = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
    let twin = format!("{}.{}.{}", parts[0], parts[1], b64u(&high.to_bytes()));
    let mut c = cred.clone();
    set_dpop_body(&mut c, client::body(&twin, None));
    rejected_with(gate.verify_attest(&c, DPOP, NOW), DPOP, codes::BAD_SIGNATURE);
    assert_eq!(gate.process(&c, NOW).unwrap_err(), ErrorCode::Underpaid);
    // The original is unaffected and is the only one committed.
    let p = new(gate.process(&cred, NOW));
    gate.settle_ok(&p, b"answer", NOW);
    assert!(replayed(gate.process(&cred, NOW + 1)).replayed());
}

#[test]
fn a_quota_counts_down_and_refuses_past_its_limit() {
    // 3 actions per hour per DPoP key, on a 21 sat entry.
    let gate = Gate::new(
        Some(21),
        vec![AttestEntry::quota(DPOP, 3, 3600)],
        authority(),
    );
    let a = key("a");
    let counter = |now: u64| {
        let id = ids::use_id(DPOP, &a.thumbprint().0);
        let k = ids::quota_key(&id, 3, 3600, now).unwrap();
        block_on(gate.store.counter(&k)).unwrap()
    };
    let jtis = ["q1", "q2", "q3", "q4", "q5", "q6"];
    for (n, jti) in jtis[..3].iter().enumerate() {
        let cred = Cred::dpop(&a, None, jti).build(&gate);
        let p = new(gate.process(&cred, NOW));
        assert_eq!(p.admission().price(), 0);
        assert_eq!(counter(NOW), n as u64 + 1);
        gate.settle_ok(&p, b"answer", NOW);
    }
    // The fourth has no room: without pay it is UNDERPAID, and consumes
    // nothing.
    let fourth = Cred::dpop(&a, None, jtis[3]).build(&gate);
    assert_eq!(gate.process(&fourth, NOW).unwrap_err(), ErrorCode::Underpaid);
    assert_eq!(counter(NOW), 3);
    // With pay it is priced in full.
    let paying = Cred::dpop(&a, None, jtis[4]).with_notes("a", 21).build(&gate);
    assert_eq!(new(gate.process(&paying, NOW)).admission().price(), 21);
    assert_eq!(counter(NOW), 3);
    // The quota counts per key: another registered key has its own.
    let ed = ed_key("ed");
    let other = Cred::dpop(&ed, None, "e1").build(&gate);
    assert_eq!(new(gate.process(&other, NOW)).admission().price(), 0);
    // A replay of a quota-priced credential is answered from its record,
    // though the quota it filled is full.
    let first = Cred::dpop(&a, None, jtis[0]).build(&gate);
    assert!(replayed(gate.process(&first, NOW + 10)).replayed());
    // The next epoch has room again.
    let next = Cred::dpop(&a, None, jtis[5]).build(&gate);
    assert_eq!(new(gate.process(&next, NOW + 3600)).admission().price(), 0);
    assert_eq!(counter(NOW + 3600), 1);
}

#[test]
fn a_required_attestation_must_verify() {
    let gate = Gate::new(
        Some(21),
        vec![AttestEntry::new(DPOP, Effect::Required)],
        authority(),
    );
    // Missing, or present but refused: POLICY.
    let no_proof = Cred {
        notes: Some(("a", 21)),
        dpop: None,
        bearer: None,
        iat: NOW,
    };
    assert_eq!(gate.process(&no_proof.build(&gate), NOW).unwrap_err(), ErrorCode::Policy);
    let refused = Cred::dpop(&key("z"), None, "j1").with_notes("b", 21);
    assert_eq!(gate.process(&refused.build(&gate), NOW).unwrap_err(), ErrorCode::Policy);
    // Verified: admitted at the entry's price, which it does not change.
    let ok = Cred::dpop(&key("a"), None, "j2").with_notes("c", 21);
    assert_eq!(new(gate.process(&ok.build(&gate), NOW)).admission().price(), 21);
}

#[test]
fn the_same_attestation_under_another_replay_key_follows_its_use_model() {
    // One DPoP proof (the same attest body, the same Context) in two
    // credentials that pay with different notes: two ReplayKeys.
    let a = key("a");
    let build = |gate: &Gate, tag: &'static str| {
        let mut c = Cred::dpop(&a, None, "j1").with_notes(tag, 1680).build(gate);
        // The same proof bytes in both.
        let first = Cred::dpop(&a, None, "j1").with_notes("a", 1680).build(gate);
        c.attest = first.attest.clone();
        sign_notes(gate, &mut c);
        c
    };

    // Reusable, as the registry says: both run.
    let gate = discount_gate();
    let one = build(&gate, "a");
    let two = build(&gate, "b");
    assert_eq!(one.attest, two.attest);
    let p1 = new(gate.process(&one, NOW));
    let p2 = new(gate.process(&two, NOW));
    assert_ne!(p1.replay_key(), p2.replay_key());

    // Under the single model the second would be SPENT: the model is the
    // registry's to set, and the store follows it.
    let gate = discount_gate();
    gate.dpop_model.set(Some(UseModel::Single));
    let one = build(&gate, "a");
    let two = build(&gate, "b");
    let _p = new(gate.process(&one, NOW));
    assert_eq!(gate.process(&two, NOW).unwrap_err(), ErrorCode::Spent);

    // The notes stay single under any attestation: two proofs, one note.
    let gate = discount_gate();
    let x = Cred::dpop(&a, None, "x1").with_notes("a", 1680).build(&gate);
    let y = Cred::dpop(&a, None, "y1").with_notes("a", 1680).build(&gate);
    let _p = new(gate.process(&x, NOW));
    assert_eq!(gate.process(&y, NOW).unwrap_err(), ErrorCode::Spent);
}

#[test]
fn proof_freshness_is_bounded_by_iat_and_optionally_by_max_age() {
    let gate = waive_gate();
    let a = key("a");
    // iat at most one clock skew in the future.
    let mut ok = Cred::dpop(&a, None, "j1");
    ok.iat = NOW + 60;
    assert!(gate.verify_attest(&ok.build(&gate), DPOP, NOW).is_ok());
    let mut future = Cred::dpop(&a, None, "j2");
    future.iat = NOW + 61;
    rejected_with(gate.verify_attest(&future.build(&gate), DPOP, NOW), DPOP, codes::STALE_PROOF);
    // By default an old proof still verifies: the offer bounds its age, and
    // a replay must verify again to find its outcome.
    let cred = Cred::dpop(&a, None, "j3").build(&gate);
    assert!(gate.verify_attest(&cred, DPOP, NOW + 86_400).is_ok());
    // A max_age refuses it once age and skew have passed.
    let strict = Gate::new(None, vec![AttestEntry::new(DPOP, Effect::Waive)], authority());
    let strict = Gate {
        dpop: DpopScheme::new(authority()).with_max_age(300),
        ..strict
    };
    let cred = Cred::dpop(&a, None, "j4").build(&strict);
    assert!(strict.verify_attest(&cred, DPOP, NOW + 360).is_ok());
    rejected_with(strict.verify_attest(&cred, DPOP, NOW + 361), DPOP, codes::STALE_PROOF);
}

#[test]
fn malformed_proofs_are_refused() {
    let gate = waive_gate();
    let a = key("a");
    let cred = Cred::dpop(&a, None, "j1").build(&gate);
    let ctx = gate.context(&cred);
    let good_claims = client::claims(&ProofClaims {
        context: &ctx,
        htm: "POST",
        htu: "https://api.example/v1/thing",
        iat: NOW,
        jti: "j1",
        access_token: None,
    });
    let good_header = client::header(&a);
    let try_proof = |h: &[u8], p: &[u8], code: &str| {
        let mut c = cred.clone();
        set_dpop_body(&mut c, client::body(&client::sign_raw(&a, h, p), None));
        rejected_with(gate.verify_attest(&c, DPOP, NOW), DPOP, code);
    };
    let edit = |v: &serde_json::Value, f: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
        let mut v = v.clone();
        f(v.as_object_mut().unwrap());
        v.to_string().into_bytes()
    };
    let gc = good_claims.to_string().into_bytes();
    let gh = good_header.to_string().into_bytes();
    // Header rules.
    try_proof(&edit(&good_header, &|h| { h.insert("typ".into(), "JWT".into()); }), &gc, codes::BAD_PROOF);
    try_proof(&edit(&good_header, &|h| { h.remove("typ"); }), &gc, codes::BAD_PROOF);
    try_proof(&edit(&good_header, &|h| { h.insert("alg".into(), "none".into()); }), &gc, codes::UNSUPPORTED_ALG);
    try_proof(&edit(&good_header, &|h| { h.insert("alg".into(), "HS256".into()); }), &gc, codes::UNSUPPORTED_ALG);
    try_proof(&edit(&good_header, &|h| { h.insert("alg".into(), "EdDSA".into()); }), &gc, codes::BAD_KEY);
    try_proof(&edit(&good_header, &|h| { h.insert("crit".into(), serde_json::json!(["exp"])); }), &gc, codes::BAD_PROOF);
    try_proof(&edit(&good_header, &|h| { h.remove("jwk"); }), &gc, codes::BAD_PROOF);
    try_proof(
        &edit(&good_header, &|h| {
            h["jwk"]["d"] = b64u(&[1; 32]).into();
        }),
        &gc,
        codes::BAD_KEY,
    );
    // Another key in the header than the one that signed: the signature
    // fails.
    let b = key("b");
    try_proof(&client::header(&b).to_string().into_bytes(), &gc, codes::BAD_SIGNATURE);
    // Claim rules.
    for claim in ["jti", "htm", "htu", "iat"] {
        try_proof(&gh, &edit(&good_claims, &|c| { c.remove(claim); }), codes::BAD_PROOF);
    }
    try_proof(&gh, &edit(&good_claims, &|c| { c.insert("iat".into(), "1791700000".into()); }), codes::BAD_PROOF);
    try_proof(&gh, &edit(&good_claims, &|c| { c.insert("iat".into(), serde_json::json!(1.5)); }), codes::BAD_PROOF);
    try_proof(&gh, &edit(&good_claims, &|c| { c.insert("htm".into(), "PO ST".into()); }), codes::BAD_PROOF);
    try_proof(&gh, &edit(&good_claims, &|c| { c.insert("jti".into(), "x".repeat(257).into()); }), codes::BAD_PROOF);
    // A claim named twice: the JSON is not I-JSON, whichever copy a parser
    // would keep.
    let dup = format!(
        r#"{{"jti":"j1","htm":"POST","htu":"u","iat":{NOW},"bnap_ctx":"{}","bnap_ctx":"{}"}}"#,
        hex::encode([0u8; 32]),
        hex::encode(ctx.0)
    );
    try_proof(&gh, dup.as_bytes(), codes::BAD_PROOF);
    // The good one, for contrast.
    let mut c = cred.clone();
    set_dpop_body(&mut c, client::body(&client::sign_raw(&a, &gh, &gc), None));
    assert!(gate.verify_attest(&c, DPOP, NOW).is_ok());
}

#[test]
fn only_attest_parts_without_a_witness_verify() {
    let gate = waive_gate();
    let cred = Cred::dpop(&key("a"), None, "j1").build(&gate);
    // A witness is not part of a class A scheme: it is refused, not
    // ignored.
    let mut w = cred.clone();
    w.attest[0].witness = vec![1; 64];
    rejected_with(gate.verify_attest(&w, DPOP, NOW), DPOP, codes::BAD_BODY);
    // Used as a pay entry, the scheme refuses.
    let pay_entry = PayEntry::new(DPOP, 0, "sat");
    let ctx = gate.context(&cred);
    let digest = cred.digest(&ctx);
    let view = CappedSigner::verify_only(Arc::new(NoSigner), "sat");
    let r = block_on(gate.dpop.verify(
        &cred.attest[0],
        &VerifyCtx {
            now: NOW,
            offer: &gate.offer,
            entry: Entry::Pay(&pay_entry),
            action_scope: &gate.scope,
            context: &ctx,
            digest: &digest,
            signer: &view,
        },
    ));
    rejected_with(r, DPOP, codes::NOT_AN_ATTESTATION);
    // An unknown record in the body.
    let mut extra = cred.clone();
    let mut body = extra.attest[0].body.clone();
    body.extend_from_slice(&[0x03, 0x01, 0x00]);
    extra.attest[0].body = body;
    rejected_with(gate.verify_attest(&extra, DPOP, NOW), DPOP, codes::BAD_BODY);
}

#[test]
fn an_unreachable_authority_fails_closed() {
    let gate = Gate::new(None, vec![AttestEntry::new(DPOP, Effect::Waive)], Arc::new(Down));
    for token in [None, Some("tok-a")] {
        let cred = Cred::dpop(&key("a"), token, "j1").build(&gate);
        assert!(matches!(
            gate.verify_attest(&cred, DPOP, NOW),
            Err(SchemeError::Unavailable(_))
        ));
        assert_eq!(gate.process(&cred, NOW).unwrap_err(), ErrorCode::Unavailable);
    }
    // A proof that fails its own checks never reaches the authority.
    let mut cred = Cred::dpop(&key("a"), None, "j2").build(&gate);
    let mut b = cred.attest[0].body.clone();
    let last = b.len() - 1;
    b[last] ^= 1;
    cred.attest[0].body = b;
    assert!(matches!(
        gate.verify_attest(&cred, DPOP, NOW),
        Err(SchemeError::Rejected { .. })
    ));
}

#[test]
fn the_plugs_offer_no_pay_entries() {
    let s = scope();
    let ctx = |role| OfferCtx {
        now: NOW,
        route_id: "chat",
        scope: &s,
        route_scope: true,
        metered: false,
        expires: NOW + 300,
        role,
    };
    let dpop = DpopScheme::new(authority());
    let bearer = BearerScheme::new(authority());
    for plug in [&dpop as &dyn CredentialScheme, &bearer] {
        assert_eq!(
            block_on(plug.offer(&ctx(bnap_plug::OfferRole::Attest {
                effect: Effect::Discount
            })))
            .unwrap(),
            SchemeOffer::default()
        );
        assert_eq!(
            block_on(plug.offer(&ctx(bnap_plug::OfferRole::Pay {
                amount: 21,
                unit: "sat"
            }))),
            Err(SchemeError::Unsupported)
        );
    }
    assert_eq!(dpop.id(), "httpauth:DPoP");
    assert_eq!(bearer.id(), "httpauth:Bearer");
    // A scheme error carries its namespaced code into the Error object.
    let e = SchemeError::rejected(DPOP, codes::WRONG_CONTEXT, "detail stays in logs");
    assert_eq!(
        e.to_error_object().scheme_code.as_deref(),
        Some("httpauth:DPoP/WRONG_CONTEXT")
    );
}
