//! The scheme through its plug trait, against the fake Lightning rail.

use std::sync::Arc;

use bnap_core::Offer;
use bnap_core::credential::SchemePart;
use bnap_core::hash::{Context, Digest, Scope};
use bnap_core::offer::{AttestEntry, Effect, NativeEntry, OfferFields, PayEntry};
use bnap_core::schnorr::{Signature, SigningKey};
use bnap_core::sign::{CoreMessage, UnsignedOffer};
use bnap_core::test_support::block_on;
use bnap_plug::{BlindSignature, BlindedOutput, ChangeLimit, KeysetId, Point, Signer, SignerError};
use bnap_rail_fake::FakeRail;

use super::*;

const NOW: u64 = 1_791_700_000;
const SECRET: [u8; 32] = [6; 32];

/// Signs offers; checks no notes and signs no change.
struct OfferSigner(SigningKey);

#[async_trait::async_trait]
impl Signer for OfferSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        msg.sign_with(&self.0, &[0; 32])
            .map_err(|e| SignerError::Refused(e.to_string()))
    }

    async fn verify_unblinded(
        &self,
        _: &KeysetId,
        _: &str,
        _: u64,
        _: &[u8],
        _: &Point,
    ) -> Result<Option<Point>, SignerError> {
        Ok(None)
    }

    async fn blind_sign(
        &self,
        _: &KeysetId,
        _: &[BlindedOutput],
        _: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        Err(SignerError::Refused("no change here".into()))
    }
}

struct Fixture {
    fake: Arc<FakeRail>,
    scheme: LightningCharge,
    signer: Arc<OfferSigner>,
}

fn fixture() -> Fixture {
    let fake = Arc::new(FakeRail::new([4; 32]));
    fake.set_now(NOW);
    Fixture {
        scheme: LightningCharge::new(
            ChallengeKeys::new(SECRET).unwrap(),
            "api.example",
            Network::Regtest,
            fake.clone(),
        )
        .unwrap(),
        fake,
        signer: Arc::new(OfferSigner(
            SigningKey::from_secret_bytes(&sha256(b"offer key")).unwrap(),
        )),
    }
}

impl Fixture {
    /// An exact-scope offer for `amount` sat with this scheme's native.
    fn offer(&self, nonce: u8, amount: u64) -> Offer {
        let scope = Scope(sha256(b"GET /thing"));
        let mut f = OfferFields::new(scope, NOW + 300, self.signer.0.public_key(), [nonce; 16]);
        f.pay = vec![PayEntry::new(SCHEME_ID, amount, "sat")];
        let id = f.offer_id().unwrap();
        let native = block_on(self.scheme.native(&NativeCtx {
            now: NOW,
            offer_id: &id,
            entry: &f.pay[0],
            pay_index: 0,
            expires: f.expires,
        }))
        .unwrap()
        .unwrap();
        assert_eq!(native.kind, NATIVE_KIND);
        f.native = vec![NativeEntry::new(0, native.kind, native.data)];
        let u = UnsignedOffer::new(&f, Some(&[3; 32])).unwrap();
        let sig = block_on(self.signer.schnorr(u.message())).unwrap();
        u.finish(&sig).unwrap()
    }

    fn challenge(offer: &Offer) -> Challenge {
        Challenge::parse(std::str::from_utf8(&offer.fields().native[0].data).unwrap()).unwrap()
    }

    /// Pays the challenge's invoice and builds the client's token.
    fn pay(&self, offer: &Offer) -> String {
        let c = Self::challenge(offer);
        let req = ChargeRequest::decode(&c.request).unwrap();
        let preimage = self.fake.pay(&req.payment_hash).unwrap();
        Credential::new(c, preimage).encode()
    }

    fn verify_with(
        &self,
        offer: &Offer,
        entry: Entry<'_>,
        part: &SchemePart,
    ) -> Result<Verified, SchemeError> {
        let view = CappedSigner::verify_only(self.signer.clone(), UNIT);
        let scope = offer.fields().scope;
        block_on(self.scheme.verify(
            part,
            &VerifyCtx {
                now: NOW,
                offer,
                entry,
                action_scope: &scope,
                context: &Context([0; 32]),
                digest: &Digest([0; 32]),
                signer: &view,
            },
        ))
    }

    fn verify(&self, offer: &Offer, body: &[u8]) -> Result<Verified, SchemeError> {
        self.verify_with(
            offer,
            Entry::Pay(&offer.fields().pay[0]),
            &SchemePart::new(SCHEME_ID, body.to_vec()),
        )
    }
}

fn code(e: &SchemeError) -> String {
    match e {
        SchemeError::Rejected { scheme_code, .. } => scheme_code.clone(),
        other => format!("{other:?}"),
    }
}

/// Re-encodes a token's credential after `change`.
fn tamper(token: &str, change: impl FnOnce(&mut Credential)) -> String {
    let mut c = Credential::decode(token.as_bytes()).unwrap();
    change(&mut c);
    c.encode()
}

#[test]
fn the_native_challenge_binds_the_invoice_and_the_offer() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let c = Fixture::challenge(&offer);
    assert_eq!(
        c.to_header().as_bytes(),
        offer.fields().native[0].data.as_slice()
    );
    assert_eq!(
        (c.method.as_str(), c.intent.as_str()),
        ("lightning", "charge")
    );
    assert_eq!(c.realm, "api.example");
    assert_eq!(c.expires.as_deref(), Some("2026-10-11T06:31:40Z"));
    assert!(fx.scheme.keys().verify(&c));
    let req = ChargeRequest::decode(&c.request).unwrap();
    assert_eq!((req.amount, req.network), (21, Network::Regtest));
    let inv = fx.fake.invoice(&req.payment_hash).unwrap();
    assert_eq!(inv.invoice, req.invoice);
    assert_eq!(inv.memo, offer.offer_id().0, "description hash = OfferID");
    let opaque = json::decode(c.opaque.as_deref().unwrap().as_bytes()).unwrap();
    assert_eq!(opaque[OFFER_MEMBER], hex::encode(offer.offer_id().0));
}

#[test]
fn a_paid_credential_verifies_to_the_payment_hash() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let token = fx.pay(&offer);
    let hash = ChargeRequest::decode(&Fixture::challenge(&offer).request)
        .unwrap()
        .payment_hash;
    let v = fx.verify(&offer, token.as_bytes()).unwrap();
    assert_eq!(v.use_ids, vec![hash.to_vec()]);
    assert_eq!(
        v.rail_ids,
        vec![RailRef {
            kind: "ln".into(),
            reference: hash.to_vec(),
        }]
    );
    assert_eq!((v.value, v.quota_id), (21, None));
}

#[test]
fn verification_refuses_what_this_gate_did_not_issue() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let other = fx.offer(2, 21);
    let token = fx.pay(&offer);
    let check = |o: &Offer, t: &str| code(&fx.verify(o, t.as_bytes()).unwrap_err());

    // Under another offer of this gate.
    assert_eq!(
        check(&other, &token),
        "payment:lightning/charge/OFFER_MISMATCH"
    );
    // A wrong preimage.
    assert_eq!(
        check(&offer, &tamper(&token, |c| c.preimage = [0; 32])),
        "payment:lightning/charge/INVALID_PREIMAGE"
    );
    // Any echoed field changed, or one the gate never sets added.
    for change in [
        (|c: &mut Credential| c.challenge.realm = "evil.example".into()) as fn(&mut Credential),
        |c| {
            c.challenge.request = ChargeRequest {
                amount: 1,
                ..ChargeRequest::decode(&c.challenge.request).unwrap()
            }
            .encode();
        },
        |c| c.challenge.opaque = Some(json::encode(&json!({OFFER_MEMBER: "00".repeat(32)}))),
        |c| c.challenge.expires = Some("2099-01-01T00:00:00Z".into()),
        |c| c.challenge.id = "x".into(),
        |c| c.challenge.description = Some("d".into()),
        |c| c.challenge.header = Some("Payment-Authorization".into()),
        |c| c.challenge.digest = Some(String::new()),
    ] {
        assert_eq!(
            check(&offer, &tamper(&token, change)),
            "payment:lightning/charge/UNKNOWN_CHALLENGE"
        );
    }
    // A challenge bound under another secret.
    let foreign = LightningCharge::new(
        ChallengeKeys::new([7; 32]).unwrap(),
        "api.example",
        Network::Regtest,
        fx.fake.clone(),
    )
    .unwrap();
    let forged = tamper(&token, |c| {
        c.challenge = foreign.keys().bind(c.challenge.clone());
    });
    assert_eq!(
        check(&offer, &forged),
        "payment:lightning/charge/UNKNOWN_CHALLENGE"
    );
    // An unverified payer identifier.
    let sourced = tamper(&token, |c| c.source = Some("did:key:z6Mk".into()));
    assert_eq!(check(&offer, &sourced), "payment:lightning/charge/SOURCE");
    // Not a credential at all.
    assert_eq!(check(&offer, "eyJ9"), "payment:lightning/charge/MALFORMED");
}

#[test]
fn a_challenge_for_another_amount_or_network_is_refused() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let token = fx.pay(&offer);
    // A challenge this gate bound for this offer but for 20 sat (as a gate
    // whose Pricer changed would): the amount must be the entry's.
    let rebound = |change: fn(&mut ChargeRequest)| {
        tamper(&token, |c| {
            let mut req = ChargeRequest::decode(&c.challenge.request).unwrap();
            change(&mut req);
            c.challenge.request = req.encode();
            c.challenge = fx.scheme.keys().bind(c.challenge.clone());
        })
    };
    for t in [
        rebound(|r| r.amount = 20),
        rebound(|r| r.network = Network::Mainnet),
    ] {
        let e = fx.verify(&offer, t.as_bytes()).unwrap_err();
        assert_eq!(code(&e), "payment:lightning/charge/AMOUNT");
    }
}

#[test]
fn retired_secrets_still_verify() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let token = fx.pay(&offer);
    let rotated = LightningCharge::new(
        ChallengeKeys::new([9; 32])
            .unwrap()
            .with_retired([SECRET.to_vec()]),
        "api.example",
        Network::Regtest,
        fx.fake.clone(),
    )
    .unwrap();
    let view = CappedSigner::verify_only(fx.signer.clone(), UNIT);
    let scope = offer.fields().scope;
    let v = block_on(rotated.verify(
        &SchemePart::new(SCHEME_ID, token.into_bytes()),
        &VerifyCtx {
            now: NOW,
            offer: &offer,
            entry: Entry::Pay(&offer.fields().pay[0]),
            action_scope: &scope,
            context: &Context([0; 32]),
            digest: &Digest([0; 32]),
            signer: &view,
        },
    ));
    assert!(v.is_ok());
}

#[test]
fn verification_needs_a_sat_pay_entry_and_no_witness() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let body = fx.pay(&offer).into_bytes();
    let mut part = SchemePart::new(SCHEME_ID, body.clone());
    part.witness = vec![1];
    let pay = Entry::Pay(&offer.fields().pay[0]);
    assert_eq!(
        code(&fx.verify_with(&offer, pay, &part).unwrap_err()),
        "payment:lightning/charge/WITNESS"
    );
    let attest = AttestEntry::new(SCHEME_ID, Effect::Waive);
    let part = SchemePart::new(SCHEME_ID, body);
    assert_eq!(
        code(
            &fx.verify_with(&offer, Entry::Attest(&attest), &part)
                .unwrap_err()
        ),
        "payment:lightning/charge/NOT_PAY"
    );
    let msat = PayEntry::new(SCHEME_ID, 21_000, "msat");
    assert_eq!(
        code(
            &fx.verify_with(&offer, Entry::Pay(&msat), &part)
                .unwrap_err()
        ),
        "payment:lightning/charge/UNIT"
    );
}

#[test]
fn a_native_credential_recovers_its_offer_without_state() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let token = fx.pay(&offer);
    let header = authorization(&token);
    let native = credential_from_authorization(&header).unwrap();
    let n = block_on(fx.scheme.recover_native(native.as_bytes(), NOW)).unwrap();
    assert_eq!(n.offer_id, offer.offer_id());
    assert_eq!(
        n.part,
        SchemePart::new(SCHEME_ID, token.clone().into_bytes())
    );
    assert!(fx.verify(&offer, &n.part.body).is_ok());
    let forged = tamper(&token, |c| c.challenge.id = "x".into());
    let e = block_on(fx.scheme.recover_native(forged.as_bytes(), NOW)).unwrap_err();
    assert_eq!(code(&e), "payment:lightning/charge/UNKNOWN_CHALLENGE");
}

#[test]
fn settle_returns_the_payment_receipt_on_ok_only() {
    let fx = fixture();
    let offer = fx.offer(1, 21);
    let token = fx.pay(&offer);
    let part = SchemePart::new(SCHEME_ID, token.clone().into_bytes());
    let v = fx.verify(&offer, &part.body).unwrap();
    let view = CappedSigner::verify_only(fx.signer.clone(), UNIT);
    let settle = |status| {
        block_on(fx.scheme.settle(
            &part,
            &v,
            &SettleCtx {
                now: NOW + 5,
                status,
                charged: 21,
                entry: &offer.fields().pay[0],
                context: &Context([0; 32]),
                digest: &Digest([0; 32]),
            },
            &view,
        ))
        .unwrap()
    };
    let receipt = settle(Status::Ok).unwrap();
    let want = Receipt {
        challenge_id: Credential::decode(token.as_bytes()).unwrap().challenge.id,
        payment_hash: v.use_ids[0].as_slice().try_into().unwrap(),
        timestamp: NOW + 5,
    };
    assert_eq!(receipt, want.encode().into_bytes());
    assert_eq!(settle(Status::Failed), None);
}

#[test]
fn offers_must_be_exact_scope_non_metered_sat() {
    let fx = fixture();
    let scope = Scope([0; 32]);
    let cx = |route_scope, metered, unit| OfferCtx {
        now: NOW,
        route_id: "r",
        scope: &scope,
        route_scope,
        metered,
        expires: NOW + 60,
        role: OfferRole::Pay { amount: 21, unit },
    };
    assert!(block_on(fx.scheme.offer(&cx(false, false, "sat"))).is_ok());
    for (r, m, u) in [
        (true, false, "sat"),
        (false, true, "sat"),
        (false, false, "msat"),
    ] {
        assert_eq!(
            block_on(fx.scheme.offer(&cx(r, m, u))),
            Err(SchemeError::Unsupported)
        );
    }
}

#[test]
fn an_invoice_that_outlives_the_offer_is_never_offered() {
    // The gate takes a credential until the offer, or the entry's quote,
    // expires, with 60 s of skew (4.4 step 4). An invoice still payable
    // after that takes a payment the gate refuses STALE, and the lightning
    // method refunds nothing.
    let id = OfferId([1; 32]);
    let native = |ttl: u64, entry: &PayEntry| {
        let fake = FakeRail::new([4; 32]).with_ttl(ttl);
        fake.set_now(NOW);
        let rail: Arc<dyn FundingRail> = Arc::new(fake);
        let scheme = LightningCharge::new(
            ChallengeKeys::new(SECRET).unwrap(),
            "api.example",
            Network::Regtest,
            rail,
        )
        .unwrap();
        block_on(scheme.native(&NativeCtx {
            now: NOW,
            offer_id: &id,
            entry,
            pay_index: 0,
            expires: NOW + 300,
        }))
    };
    let outlives = |r: Result<Option<NativeArtifact>, SchemeError>| match r {
        Err(SchemeError::Unavailable(m)) => m.contains("outlives the offer"),
        _ => false,
    };
    let entry = PayEntry::new(SCHEME_ID, 21, "sat");
    // The invoice may end with the offer, or within the skew after it.
    assert!(native(300, &entry).unwrap().is_some());
    assert!(native(360, &entry).unwrap().is_some());
    // Not later: the rail defaults of the past (600 s, 3600 s) included.
    for ttl in [361, 600, 3_600] {
        assert!(outlives(native(ttl, &entry)), "ttl {ttl}");
    }
    // A shorter quote bounds it too.
    let mut quoted = entry.clone();
    quoted.quote_expires = Some(NOW + 120);
    assert!(native(180, &quoted).unwrap().is_some());
    assert!(outlives(native(181, &quoted)));
}

#[test]
fn construction_checks_the_secret_and_the_realm() {
    let fake: Arc<dyn FundingRail> = Arc::new(FakeRail::new([0; 32]));
    assert!(ChallengeKeys::new([0; 31]).is_err());
    let keys = ChallengeKeys::new([0; 32]).unwrap();
    for realm in ["", "a\"b", "a\\b", "a\nb"] {
        assert!(
            LightningCharge::new(keys.clone(), realm, Network::Mainnet, fake.clone()).is_err(),
            "{realm:?}"
        );
    }
}
