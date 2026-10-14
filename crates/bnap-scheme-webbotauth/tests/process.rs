//! `httpsig:web-bot-auth` driven through bnap-core's `outcome::process` on
//! the in-memory store, the way a gate runs it: the gate takes the class
//! and use model from the registry, verifies every part, drops
//! attestations that fail (section 7: no effect, no error) and hands the
//! rest to `process`, which prices and commits.

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
    KeysetId, OfferCtx, OfferRole, Point, SchemeError, SchemeOffer, Signer, SignerError, Verified,
    VerifyCtx,
};
use bnap_scheme_webbotauth::body::WbaBody;
use bnap_scheme_webbotauth::client::{self, SignParams};
use bnap_scheme_webbotauth::{
    DirectoryError, ID, KeyDirectory, KeyQuery, StaticDirectory, WebBotAuthScheme, codes, keyid,
    thumbprint,
};

const NOW: u64 = 1_791_700_000;
const NOTES: &str = "bnap:notes";
const AUTHORITY: &str = "api.example";
const AGENT: &str = "https://bot.example";

// ---------------------------------------------------------------- registry

/// The registry's word on each scheme (`registry/schemes.toml`).
fn registry(scheme: &str) -> (BindingClass, UseModel) {
    match scheme {
        ID => (BindingClass::A, UseModel::Reusable),
        NOTES => (BindingClass::S, UseModel::Single),
        _ => (BindingClass::None, UseModel::Single),
    }
}

// ------------------------------------------------------------------ plugs

/// Attestations sign nothing.
struct NoSigner;

#[async_trait::async_trait]
impl Signer for NoSigner {
    async fn schnorr(&self, _msg: &CoreMessage) -> Result<Signature, SignerError> {
        Err(SignerError::Refused(
            "attestation tests sign nothing".into(),
        ))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        _unit: &str,
        _amount: u64,
        _secret: &[u8],
        _c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        Err(SignerError::Refused(
            "attestation tests check no notes".into(),
        ))
    }

    async fn blind_sign(
        &self,
        _keyset: &KeysetId,
        _outputs: &[BlindedOutput],
        _limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        Err(SignerError::Refused(
            "attestation tests sign nothing".into(),
        ))
    }
}

/// A stand-in for `bnap:notes`, class S: one note (`Y`, amount) and the
/// key that spends it, whose BIP-340 signature over the Digest is the
/// witness.
struct StubNotes;

fn notes_key(tag: &str) -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(format!("notes key {tag}").as_bytes())).unwrap()
}

fn notes_body(tag: &str, amount: u64) -> Vec<u8> {
    let mut b = notes_key(tag).public_key().0.to_vec();
    b.push(2);
    b.extend_from_slice(&sha256(format!("note {tag}").as_bytes()));
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
        let sig = Signature(
            part.witness
                .as_slice()
                .try_into()
                .map_err(|_| bad("witness"))?,
        );
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

/// A directory that cannot be reached.
struct Down;

#[async_trait::async_trait]
impl KeyDirectory for Down {
    async fn resolve(&self, _q: &KeyQuery<'_>) -> Result<Option<[u8; 32]>, DirectoryError> {
        Err(DirectoryError("directory fetch timed out".into()))
    }
}

/// A directory that answers with a key other than the one `keyid` names.
struct Lying([u8; 32]);

#[async_trait::async_trait]
impl KeyDirectory for Lying {
    async fn resolve(&self, _q: &KeyQuery<'_>) -> Result<Option<[u8; 32]>, DirectoryError> {
        Ok(Some(self.0))
    }
}

// ------------------------------------------------------------------- keys

fn bot(tag: &str) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&sha256(format!("bot key {tag}").as_bytes()))
}

fn public(tag: &str) -> [u8; 32] {
    bot(tag).verifying_key().to_bytes()
}

/// The operator honours bot `a` at its agent URL and holds bot `held`
/// itself.
fn directory() -> Arc<StaticDirectory> {
    Arc::new(
        StaticDirectory::new()
            .with_agent_key(AGENT, public("a"))
            .with_agent_key(AGENT, public("b"))
            .with_held_key(public("held")),
    )
}

// ------------------------------------------------------------------- gate

struct Gate {
    store: MemoryStore,
    offer: Offer,
    scope: Scope,
    limits: Limits,
    wba: WebBotAuthScheme,
    /// Overrides the registry class of the scheme.
    class: Cell<Option<BindingClass>>,
    /// Overrides the registry use model of the scheme.
    model: Cell<Option<UseModel>>,
}

fn offer_key() -> SigningKey {
    SigningKey::from_secret_bytes(&sha256(b"bnap test offer key")).unwrap()
}

impl Gate {
    fn new(price: Option<u64>, attest: Vec<AttestEntry>) -> Self {
        Self::with(NOW + 300, price, attest, directory())
    }

    fn with(
        expires: u64,
        price: Option<u64>,
        attest: Vec<AttestEntry>,
        dir: Arc<dyn KeyDirectory>,
    ) -> Self {
        let key = offer_key();
        let scope = Scope(sha256(b"POST https://api.example/v1/chat/completions"));
        let mut f = OfferFields::new(scope, expires, key.public_key(), [5; 16]);
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
            wba: WebBotAuthScheme::new(AUTHORITY, dir),
            class: Cell::new(None),
            model: Cell::new(None),
        }
    }

    fn registry(&self, scheme: &str) -> (BindingClass, UseModel) {
        let (class, model) = registry(scheme);
        if scheme == ID {
            (
                self.class.get().unwrap_or(class),
                self.model.get().unwrap_or(model),
            )
        } else {
            (class, model)
        }
    }

    fn context(&self, cred: &Credential) -> Context {
        cred.context(&self.offer.offer_id(), &self.scope)
    }

    fn verify(&self, cred: &Credential, now: u64) -> Result<Verified, SchemeError> {
        let part = cred.attest.iter().find(|p| p.scheme == ID).unwrap();
        let entry = self.offer.fields().attest_entry(ID).unwrap();
        let ctx = self.context(cred);
        let digest = cred.digest(&ctx);
        let view = CappedSigner::verify_only(Arc::new(NoSigner), "sat");
        block_on(self.wba.verify(
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

    /// Verify every part, then `process`.
    fn process(&self, cred: &Credential, now: u64) -> Result<Admitted, ErrorCode> {
        cred.check_binding_classes(|s| Some(self.registry(s).0))
            .map_err(|e| e.code())?;
        let ctx = self.context(cred);
        let digest = cred.digest(&ctx);
        let mut uses: Vec<(String, UseModel, Vec<Vec<u8>>)> = Vec::new();
        let mut attest = Vec::new();
        if cred.attest.iter().any(|p| p.scheme == ID) {
            let (class, model) = self.registry(ID);
            match self.verify(cred, now) {
                Ok(v) => {
                    let mut a = VerifiedAttest::new(ID, class);
                    if let Some(q) = v.quota_use_id(ID) {
                        a = a.with_quota_id(q);
                    }
                    attest.push(a);
                    uses.push((ID.into(), model, v.use_ids));
                }
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

    fn settle_ok(&self, p: &Pending, answer: &[u8], now: u64) -> Recorded {
        let charge = p.charge(Status::Ok, 0);
        let s = Settlement::new(&charge, now).with_response(Some(answer.to_vec()));
        block_on(outcome::settle(&self.store, p, &s, &self.limits)).unwrap()
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

fn rejected_with(r: Result<Verified, SchemeError>, code: &str) {
    match r {
        Err(SchemeError::Rejected { scheme_code, .. }) => {
            assert_eq!(scheme_code, format!("{ID}/{code}"));
        }
        other => panic!("expected {ID}/{code}, got {other:?}"),
    }
}

// ----------------------------------------------------------------- client

/// What a client puts in one credential.
#[derive(Clone)]
struct Cred {
    notes: Option<(&'static str, u64)>,
    bot: Option<&'static str>,
    agent: Option<&'static str>,
    nonce: &'static str,
    created: u64,
    expires: u64,
}

impl Cred {
    fn bot(tag: &'static str, nonce: &'static str) -> Self {
        Self {
            notes: None,
            bot: Some(tag),
            agent: Some(AGENT),
            nonce,
            created: NOW,
            expires: NOW + 3600,
        }
    }

    fn with_notes(mut self, tag: &'static str, amount: u64) -> Self {
        self.notes = Some((tag, amount));
        self
    }

    /// Parts first (the Context names their scheme IDs), then the
    /// signature over that Context, then the notes witness over the Digest.
    fn build(&self, gate: &Gate) -> Credential {
        let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
        if let Some((tag, amount)) = self.notes {
            c.pay = Some(SchemePart::new(NOTES, notes_body(tag, amount)));
        }
        if self.bot.is_some() {
            c.attest.push(SchemePart::new(ID, Vec::new()));
        }
        let ctx = gate.context(&c);
        if let Some(tag) = self.bot {
            let body = self.sign(tag, &ctx, AUTHORITY);
            set_body(&mut c, body.to_bytes());
        }
        sign_notes(gate, &mut c);
        c
    }

    fn sign(&self, tag: &str, ctx: &Context, authority: &str) -> WbaBody {
        client::sign(
            &bot(tag),
            &SignParams {
                authority,
                context: ctx,
                agent: self.agent,
                label: "sig1",
                created: self.created,
                expires: self.expires,
                nonce: Some(self.nonce),
            },
        )
        .unwrap()
    }
}

fn set_body(c: &mut Credential, body: Vec<u8>) {
    c.attest.iter_mut().find(|p| p.scheme == ID).unwrap().body = body;
}

fn sign_notes(gate: &Gate, c: &mut Credential) {
    let digest = c.digest(&gate.context(c));
    if let Some(p) = c.pay.as_mut() {
        let k = Key(p.body[..32].try_into().unwrap());
        let key = ["a", "b", "c", "d"]
            .into_iter()
            .map(notes_key)
            .find(|s| s.public_key() == k)
            .unwrap();
        p.witness = key.sign(&digest.0, &[0; 32]).0.to_vec();
    }
}

fn waive_gate() -> Gate {
    Gate::new(None, vec![AttestEntry::new(ID, Effect::Waive)])
}

/// Draft-00 10.3: notes at 2,100 sat, 20% off for agents that sign with
/// Web Bot Auth.
fn discount_gate() -> Gate {
    Gate::new(Some(2100), vec![AttestEntry::discount(ID, 2000)])
}

/// Swaps one field of a credential's body, keeping the rest.
fn with_field(c: &Credential, f: impl Fn(&mut WbaBody)) -> Credential {
    let part = c.attest.iter().find(|p| p.scheme == ID).unwrap();
    let mut b = WbaBody::parse(&part.body).unwrap();
    f(&mut b);
    let mut out = c.clone();
    set_body(&mut out, b.to_bytes());
    out
}

// ----------------------------------------------------------------- tests

#[test]
fn a_signature_over_the_context_names_the_key_thumbprint() {
    let gate = waive_gate();
    let cred = Cred::bot("a", "n1").build(&gate);
    let v = gate.verify(&cred, NOW).unwrap();
    let local = thumbprint(&public("a")).to_vec();
    assert_eq!(v.use_ids, vec![local.clone()]);
    assert_eq!(v.quota_id, Some(local.clone()));
    assert_eq!((v.value, v.rail_ids.len()), (0, 0));
    assert_eq!(v.quota_use_id(ID), Some(ids::use_id(ID, &local)));
    // The body is what the client signed: three fields, the agent keyed to
    // its label, the Context among the covered components.
    let body = WbaBody::parse(&cred.attest[0].body).unwrap();
    assert!(
        body.signature_input
            .starts_with(r#"sig1=("@authority" "bnap-context" "signature-agent";key="sig1")"#)
    );
    assert!(body.signature_input.contains(&keyid(&public("a"))));
    assert_eq!(
        body.signature_agent.as_deref(),
        Some(r#"sig1="https://bot.example""#)
    );
    // A key the verifier holds, with no agent URL at all (section 4.3).
    let held = Cred {
        agent: None,
        ..Cred::bot("held", "n2")
    }
    .build(&gate);
    assert_eq!(
        gate.verify(&held, NOW).unwrap().use_ids,
        vec![thumbprint(&public("held")).to_vec()]
    );
}

#[test]
fn a_waive_admits_an_attestation_only_credential_and_its_replay_returns_the_outcome() {
    let gate = waive_gate();
    let cred = Cred::bot("a", "n1").build(&gate);
    let p = new(gate.process(&cred, NOW));
    assert_eq!(p.admission().price(), 0);
    gate.settle_ok(&p, b"the answer", NOW + 1);
    for later in [NOW + 2, NOW + 3600] {
        let again = replayed(gate.process(&cred, later));
        assert!(again.replayed());
        assert_eq!(again.replay_key(), p.replay_key());
        assert_eq!(again.record().response.as_deref(), Some(&b"the answer"[..]));
        let r = again
            .receipt(&ReceiptInput {
                offer_id: gate.offer.offer_id(),
                digest: cred.digest(&gate.context(&cred)),
                unit: None,
                metered: false,
                receipt_key: Key([2; 32]),
            })
            .unwrap();
        assert_eq!((r.status, r.charged, r.replayed), (Status::Ok, 0, true));
    }
}

#[test]
fn a_discount_takes_its_basis_points_and_a_failed_signature_takes_none() {
    let gate = discount_gate();
    let paid = Cred::bot("a", "n1").with_notes("a", 1680).build(&gate);
    // 2,100 - 420 = 1,680 sat (draft-00 10.3).
    assert_eq!(new(gate.process(&paid, NOW)).admission().price(), 1680);
    // A bot the operator does not honour: no effect, no error, full price.
    let stranger = Cred::bot("z", "n2").with_notes("b", 1680).build(&gate);
    assert_eq!(
        gate.process(&stranger, NOW).unwrap_err(),
        ErrorCode::Underpaid
    );
    let full = Cred::bot("z", "n3").with_notes("c", 2100).build(&gate);
    assert_eq!(new(gate.process(&full, NOW)).admission().price(), 2100);
}

#[test]
fn waive_and_discount_apply_only_for_classes_s_a_and_o() {
    for (class, applies) in [
        (BindingClass::S, true),
        (BindingClass::A, true),
        (BindingClass::O, true),
        (BindingClass::None, false),
    ] {
        let gate = waive_gate();
        gate.class.set(Some(class));
        let r = gate.process(&Cred::bot("a", "n1").build(&gate), NOW);
        if applies {
            assert_eq!(new(r).admission().price(), 0, "{class}");
        } else {
            assert_eq!(r.unwrap_err(), ErrorCode::Underpaid, "{class}");
        }
        let gate = discount_gate();
        gate.class.set(Some(class));
        let cred = Cred::bot("a", "n1").with_notes("a", 1680).build(&gate);
        let r = gate.process(&cred, NOW);
        if applies {
            assert_eq!(new(r).admission().price(), 1680, "{class}");
        } else {
            assert_eq!(r.unwrap_err(), ErrorCode::Underpaid, "{class}");
        }
    }
    // And no gate can offer it as a class none waive or discount.
    let mut f = OfferFields::new(Scope([1; 32]), NOW + 300, offer_key().public_key(), [5; 16]);
    f.attest = vec![AttestEntry::discount(ID, 2000)];
    assert!(
        f.check_binding_classes(|_| Some(BindingClass::None))
            .is_err()
    );
    assert!(f.check_binding_classes(|s| Some(registry(s).0)).is_ok());
}

#[test]
fn a_signature_over_another_context_or_authority_is_refused() {
    let gate = discount_gate();
    let c = Cred::bot("a", "n1").with_notes("a", 1680);
    let cred = c.build(&gate);
    let ctx = gate.context(&cred);
    // Another request's Context, the Context of the credential without its
    // pay part, another gate's authority.
    let other_request = cred.context(&gate.offer.offer_id(), &Scope(sha256(b"GET /admin")));
    let mut no_pay = cred.clone();
    no_pay.pay = None;
    for (wrong_ctx, authority) in [
        (other_request, AUTHORITY),
        (gate.context(&no_pay), AUTHORITY),
        (ctx, "evil.example"),
    ] {
        let mut x = cred.clone();
        set_body(&mut x, c.sign("a", &wrong_ctx, authority).to_bytes());
        sign_notes(&gate, &mut x);
        rejected_with(gate.verify(&x, NOW), codes::BAD_SIGNATURE);
        assert_eq!(gate.process(&x, NOW).unwrap_err(), ErrorCode::Underpaid);
    }
    // The authority is compared in lower case, as RFC 9421 2.2.3 has it.
    let mut upper = cred.clone();
    set_body(&mut upper, c.sign("a", &ctx, "API.Example").to_bytes());
    sign_notes(&gate, &mut upper);
    assert!(gate.verify(&upper, NOW).is_ok());
}

#[test]
fn a_stripped_or_altered_attestation_breaks_the_digest() {
    let gate = discount_gate();
    let c = Cred::bot("a", "n1").with_notes("a", 1680);
    let cred = c.build(&gate);
    let ctx = gate.context(&cred);
    let digest = cred.digest(&ctx);

    // Stripped: the Context and the Digest change, the notes witness fails.
    let mut stripped = cred.clone();
    stripped.attest.clear();
    assert_ne!(gate.context(&stripped), ctx);
    assert_ne!(stripped.digest(&gate.context(&stripped)), digest);
    assert_eq!(
        gate.process(&stripped, NOW).unwrap_err(),
        ErrorCode::BadCredential
    );

    // Swapped for another valid signature over the same Context (another
    // nonce): the Context holds, the Digest does not.
    let mut swapped = cred.clone();
    let other = Cred {
        nonce: "n2",
        ..c.clone()
    };
    set_body(&mut swapped, other.sign("a", &ctx, AUTHORITY).to_bytes());
    assert_eq!(gate.context(&swapped), ctx);
    assert_ne!(swapped.digest(&ctx), digest);
    assert!(gate.verify(&swapped, NOW).is_ok());
    assert_eq!(
        gate.process(&swapped, NOW).unwrap_err(),
        ErrorCode::BadCredential
    );

    // A flipped bit anywhere in the body.
    let body = cred.attest[0].body.clone();
    for i in [3, body.len() / 3, body.len() / 2, body.len() - 3] {
        let mut b = body.clone();
        b[i] ^= 0x01;
        let mut flipped = cred.clone();
        set_body(&mut flipped, b);
        assert_ne!(flipped.digest(&ctx), digest);
        assert!(gate.verify(&flipped, NOW).is_err(), "byte {i}");
        assert_eq!(
            gate.process(&flipped, NOW).unwrap_err(),
            ErrorCode::BadCredential
        );
    }
    assert_eq!(new(gate.process(&cred, NOW)).admission().price(), 1680);
}

#[test]
fn a_quota_counts_down_and_refuses_past_its_limit() {
    let gate = Gate::with(
        NOW + 7200,
        Some(21),
        vec![AttestEntry::quota(ID, 2, 3600)],
        directory(),
    );
    let counter = |now: u64| {
        let id = ids::use_id(ID, &thumbprint(&public("a")));
        block_on(
            gate.store
                .counter(&ids::quota_key(&id, 2, 3600, now).unwrap()),
        )
        .unwrap()
    };
    for (n, nonce) in ["q1", "q2"].into_iter().enumerate() {
        let p = new(gate.process(&Cred::bot("a", nonce).build(&gate), NOW));
        assert_eq!(p.admission().price(), 0);
        assert_eq!(counter(NOW), n as u64 + 1);
        gate.settle_ok(&p, b"answer", NOW);
    }
    let third = Cred::bot("a", "q3").build(&gate);
    assert_eq!(gate.process(&third, NOW).unwrap_err(), ErrorCode::Underpaid);
    assert_eq!(counter(NOW), 2);
    let paying = Cred::bot("a", "q4").with_notes("a", 21).build(&gate);
    assert_eq!(new(gate.process(&paying, NOW)).admission().price(), 21);
    // Per key: bot b has its own quota.
    let b = Cred::bot("b", "b1").build(&gate);
    assert_eq!(new(gate.process(&b, NOW)).admission().price(), 0);
    // The first replays from its record although the quota is full.
    let first = Cred::bot("a", "q1").build(&gate);
    assert!(replayed(gate.process(&first, NOW + 5)).replayed());
    // The next epoch has room.
    let mut later = Cred::bot("a", "q5");
    later.created = NOW + 3600;
    later.expires = NOW + 7200;
    assert_eq!(
        new(gate.process(&later.build(&gate), NOW + 3600))
            .admission()
            .price(),
        0
    );
}

#[test]
fn the_same_attestation_under_another_replay_key_follows_its_use_model() {
    // One signature, two credentials with different notes: two ReplayKeys.
    let build = |gate: &Gate, tag: &'static str| {
        let first = Cred::bot("a", "n1").with_notes("a", 1680).build(gate);
        let mut c = Cred::bot("a", "n1").with_notes(tag, 1680).build(gate);
        c.attest = first.attest.clone();
        sign_notes(gate, &mut c);
        c
    };
    let gate = discount_gate();
    let (one, two) = (build(&gate, "a"), build(&gate, "b"));
    assert_eq!(one.attest, two.attest);
    let p1 = new(gate.process(&one, NOW));
    let p2 = new(gate.process(&two, NOW));
    assert_ne!(p1.replay_key(), p2.replay_key());
    // Under the single model the second would be SPENT.
    let gate = discount_gate();
    gate.model.set(Some(UseModel::Single));
    let (one, two) = (build(&gate, "a"), build(&gate, "b"));
    let _p = new(gate.process(&one, NOW));
    assert_eq!(gate.process(&two, NOW).unwrap_err(), ErrorCode::Spent);
}

#[test]
fn keys_resolve_on_the_agent_and_keyid_pair() {
    let gate = waive_gate();
    // Bot a's key, claimed at another agent URL, or with no URL: the
    // directory lists it only at its own URL.
    for agent in [Some("https://other.example"), None] {
        let c = Cred {
            agent,
            ..Cred::bot("a", "n1")
        };
        rejected_with(gate.verify(&c.build(&gate), NOW), codes::UNKNOWN_KEY);
    }
    // A directory that answers with another key than keyid names.
    let lying = Gate::with(
        NOW + 300,
        None,
        vec![AttestEntry::new(ID, Effect::Waive)],
        Arc::new(Lying(public("b"))),
    );
    rejected_with(
        lying.verify(&Cred::bot("a", "n1").build(&lying), NOW),
        codes::KEYID_MISMATCH,
    );
    // A directory that cannot be reached fails closed.
    let down = Gate::with(
        NOW + 300,
        None,
        vec![AttestEntry::new(ID, Effect::Waive)],
        Arc::new(Down),
    );
    let cred = Cred::bot("a", "n1").build(&down);
    assert!(matches!(
        down.verify(&cred, NOW),
        Err(SchemeError::Unavailable(_))
    ));
    assert_eq!(
        down.process(&cred, NOW).unwrap_err(),
        ErrorCode::Unavailable
    );
}

#[test]
fn signatures_live_from_created_to_expires() {
    let gate = waive_gate();
    let at = |created: u64, expires: u64| {
        Cred {
            created,
            expires,
            ..Cred::bot("a", "n1")
        }
        .build(&gate)
    };
    assert!(gate.verify(&at(NOW + 60, NOW + 600), NOW).is_ok());
    rejected_with(
        gate.verify(&at(NOW + 61, NOW + 600), NOW),
        codes::STALE_SIGNATURE,
    );
    let short = at(NOW - 100, NOW - 60);
    assert!(gate.verify(&short, NOW).is_ok());
    rejected_with(gate.verify(&short, NOW + 1), codes::STALE_SIGNATURE);
    rejected_with(
        gate.verify(&at(NOW, NOW - 1), NOW),
        codes::BAD_SIGNATURE_INPUT,
    );
    rejected_with(
        gate.verify(&at(NOW, NOW + 86_401), NOW),
        codes::LIFETIME_TOO_LONG,
    );
    let lax = Gate {
        wba: WebBotAuthScheme::new(AUTHORITY, directory()).with_max_lifetime(None),
        ..waive_gate()
    };
    let long = Cred {
        expires: NOW + 10 * 86_400,
        ..Cred::bot("a", "n1")
    }
    .build(&lax);
    assert!(lax.verify(&long, NOW).is_ok());
}

/// Verifies `cred` with one body field edited, and expects `code`.
fn refused_after(gate: &Gate, cred: &Credential, edit: impl Fn(&mut WbaBody), code: &str) {
    rejected_with(gate.verify(&with_field(cred, edit), NOW), code);
}

/// Replaces the first `from` in `Signature-Input` with `to`.
fn input_edit(from: &'static str, to: &'static str) -> impl Fn(&mut WbaBody) {
    move |b| b.signature_input = b.signature_input.replacen(from, to, 1)
}

#[test]
fn only_the_canonical_body_verifies() {
    let gate = waive_gate();
    let cred = Cred::bot("a", "n1").build(&gate);
    assert!(gate.verify(&cred, NOW).is_ok());
    // Whitespace the strict serialization does not have, a second
    // signature, labels that disagree.
    refused_after(&gate, &cred, input_edit(" ", "  "), codes::BAD_BODY);
    refused_after(
        &gate,
        &cred,
        |b| b.signature.push_str(", sig2=:AAAA:"),
        codes::BAD_BODY,
    );
    refused_after(
        &gate,
        &cred,
        |b| b.signature = b.signature.replacen("sig1", "sig9", 1),
        codes::BAD_BODY,
    );
    // The agent sent but not covered, covered but not sent, over http,
    // keyed to a member the signature does not cover.
    refused_after(
        &gate,
        &cred,
        input_edit(r#" "signature-agent";key="sig1""#, ""),
        codes::BAD_AGENT,
    );
    refused_after(&gate, &cred, |b| b.signature_agent = None, codes::BAD_AGENT);
    for agent in [
        r#"sig1="http://bot.example""#,
        r#"sig2="https://bot.example""#,
    ] {
        refused_after(
            &gate,
            &cred,
            |b| b.signature_agent = Some(agent.into()),
            codes::BAD_AGENT,
        );
    }
    // A witness.
    let mut w = cred.clone();
    w.attest[0].witness = vec![1; 64];
    rejected_with(gate.verify(&w, NOW), codes::BAD_BODY);
}

#[test]
fn only_the_gates_components_and_web_bot_auth_parameters_verify() {
    let gate = waive_gate();
    let cred = Cred::bot("a", "n1").build(&gate);
    let cases = [
        (
            r#""@authority""#,
            r#""@authority" "@path""#,
            codes::UNSUPPORTED_COMPONENT,
        ),
        (
            r#""@authority""#,
            r#""@authority";req"#,
            codes::UNSUPPORTED_COMPONENT,
        ),
        (r#" "bnap-context""#, "", codes::MISSING_COMPONENT),
        (r#""@authority" "#, "", codes::MISSING_COMPONENT),
        (
            r#""bnap-context""#,
            r#""bnap-context" "bnap-context""#,
            codes::BAD_SIGNATURE_INPUT,
        ),
        (
            r#"tag="web-bot-auth""#,
            r#"tag="other""#,
            codes::BAD_SIGNATURE_INPUT,
        ),
        (";created=", ";made=", codes::BAD_SIGNATURE_INPUT),
        (";expires=", ";until=", codes::BAD_SIGNATURE_INPUT),
        (
            r#"tag="web-bot-auth""#,
            r#"tag="web-bot-auth";alg="rsa-pss-sha512""#,
            codes::UNSUPPORTED_ALG,
        ),
    ];
    for (from, to, code) in cases {
        refused_after(&gate, &cred, input_edit(from, to), code);
    }
    // alg="ed25519" is allowed, but it is signed: adding it after the fact
    // breaks the signature.
    refused_after(
        &gate,
        &cred,
        input_edit(
            r#"tag="web-bot-auth""#,
            r#"tag="web-bot-auth";alg="ed25519""#,
        ),
        codes::BAD_SIGNATURE,
    );
    // A keyid that is not a thumbprint.
    let id = keyid(&public("a"));
    refused_after(
        &gate,
        &cred,
        move |b| b.signature_input = b.signature_input.replacen(&id, "not-a-thumbprint", 1),
        codes::BAD_KEYID,
    );
    // The scheme used as a pay entry.
    let entry = PayEntry::new(ID, 0, "sat");
    let ctx = gate.context(&cred);
    let digest = cred.digest(&ctx);
    let view = CappedSigner::verify_only(Arc::new(NoSigner), "sat");
    let r = block_on(gate.wba.verify(
        &cred.attest[0],
        &VerifyCtx {
            now: NOW,
            offer: &gate.offer,
            entry: Entry::Pay(&entry),
            action_scope: &gate.scope,
            context: &ctx,
            digest: &digest,
            signer: &view,
        },
    ));
    rejected_with(r, codes::NOT_AN_ATTESTATION);
}

#[test]
fn the_plug_offers_no_pay_entries() {
    let s = Scope([1; 32]);
    let ctx = |role| OfferCtx {
        now: NOW,
        route_id: "chat",
        scope: &s,
        route_scope: true,
        metered: true,
        expires: NOW + 300,
        role,
    };
    let plug = WebBotAuthScheme::new(AUTHORITY, directory());
    assert_eq!(plug.id(), "httpsig:web-bot-auth");
    assert_eq!(
        block_on(plug.offer(&ctx(OfferRole::Attest {
            effect: Effect::Discount
        })))
        .unwrap(),
        SchemeOffer::default()
    );
    assert_eq!(
        block_on(plug.offer(&ctx(OfferRole::Pay {
            amount: 21,
            unit: "sat"
        }))),
        Err(SchemeError::Unsupported)
    );
}
