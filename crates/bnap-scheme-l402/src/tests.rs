//! The scheme through its plug trait, against the fake Lightning rail.

use std::sync::Arc;

use bnap_core::Offer;
use bnap_core::credential::SchemePart;
use bnap_core::hash::{Context, Digest, Scope, sha256};
use bnap_core::offer::{AttestEntry, Effect, NativeEntry, OfferFields, PayEntry};
use bnap_core::schnorr::{Signature, SigningKey};
use bnap_core::sign::{CoreMessage, UnsignedOffer};
use bnap_core::test_support::block_on;
use bnap_plug::{
    BlindSignature, BlindedOutput, CappedSigner, ChangeLimit, KeysetId, Point, Signer, SignerError,
};
use bnap_rail_fake::FakeRail;

use super::*;

const NOW: u64 = 1_791_700_000;

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
    scheme: L402,
    signer: Arc<OfferSigner>,
}

fn fixture() -> Fixture {
    let fake = Arc::new(FakeRail::new([4; 32]));
    fake.set_now(NOW);
    let rail: Arc<dyn FundingRail> = Arc::new(OfferInvoices::new(fake.clone()));
    Fixture {
        fake,
        scheme: L402::new(MacaroonKeys::new([1; 32]), rail),
        signer: Arc::new(OfferSigner(
            SigningKey::from_secret_bytes(&sha256(b"offer key")).unwrap(),
        )),
    }
}

impl Fixture {
    /// An exact-scope offer for 21 sat with this scheme's native artifact.
    fn offer(&self, nonce: u8, amount: u64, unit: &str) -> Offer {
        let scope = Scope(sha256(b"GET /thing"));
        let mut f = OfferFields::new(scope, NOW + 300, self.signer.0.public_key(), [nonce; 16]);
        f.pay = vec![PayEntry::new(SCHEME_ID, amount, unit)];
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
        let offer = u.finish(&sig).unwrap();
        assert_eq!(offer.offer_id(), id, "natives do not change the OfferID");
        offer
    }

    /// The challenge an offer carries.
    fn challenge(offer: &Offer) -> Challenge {
        let data = &offer.fields().native[0].data;
        Challenge::parse(std::str::from_utf8(data).unwrap()).unwrap()
    }

    /// Pays the offer's invoice and builds the token a client sends.
    fn pay(&self, offer: &Offer) -> Token {
        let c = Self::challenge(offer);
        let hash = self.hash_of(&c);
        let preimage = self.fake.pay(&hash).unwrap();
        Token::new(&c.token, preimage).unwrap()
    }

    fn hash_of(&self, c: &Challenge) -> [u8; 32] {
        let t = Token::new(&c.token, [0; 32]).unwrap();
        self.scheme.keys().open(&t).unwrap().identifier.payment_hash
    }

    fn verify(
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

    fn verify_pay(&self, offer: &Offer, body: &[u8]) -> Result<Verified, SchemeError> {
        let entry = &offer.fields().pay[0];
        self.verify(
            offer,
            Entry::Pay(entry),
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

#[test]
fn a_paid_token_verifies_to_the_payment_hash_and_its_ln_rail_reference() {
    let fx = fixture();
    let offer = fx.offer(1, 21, "sat");
    let c = Fixture::challenge(&offer);
    // The challenge's bytes are the offer's native entry, and its macaroon
    // embeds the OfferID.
    assert_eq!(
        c.to_header().as_bytes(),
        offer.fields().native[0].data.as_slice()
    );
    let hash = fx.hash_of(&c);
    let minted = fx
        .scheme
        .keys()
        .open(&Token::new(&c.token, [0; 32]).unwrap())
        .unwrap();
    assert_eq!(minted.offer_id, offer.offer_id());
    assert_eq!(minted.expires, offer.fields().expires);
    // The invoice commits to the OfferID as its description hash.
    let inv = fx.fake.invoice(&hash).unwrap();
    assert_eq!(inv.memo, offer.offer_id().0);
    assert_eq!(inv.invoice, c.invoice);
    assert_eq!((inv.amount, inv.unit.as_str()), (21, "sat"));

    let token = fx.pay(&offer);
    let v = fx.verify_pay(&offer, token.to_string().as_bytes()).unwrap();
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
fn verification_checks_the_preimage_and_the_offer() {
    let fx = fixture();
    let offer = fx.offer(1, 21, "sat");
    let other = fx.offer(2, 21, "sat");
    let c = Fixture::challenge(&offer);

    // A preimage that does not hash to the payment hash.
    let wrong = Token::new(&c.token, [8; 32]).unwrap();
    let e = fx
        .verify_pay(&offer, wrong.to_string().as_bytes())
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/BAD_PREIMAGE");

    // A real, paid token presented under another offer of the same gate.
    let token = fx.pay(&offer);
    let e = fx
        .verify_pay(&other, token.to_string().as_bytes())
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/OFFER_MISMATCH");
    assert_eq!(e.code(), bnap_core::ErrorCode::BadCredential);

    // A macaroon minted under keys this gate does not hold.
    let foreign = MacaroonKeys::new([2; 32])
        .mint(&offer.offer_id(), &fx.hash_of(&c), offer.fields().expires)
        .unwrap();
    let forged = Token::new(&foreign, *token.preimage()).unwrap();
    let e = fx
        .verify_pay(&offer, forged.to_string().as_bytes())
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/BAD_MACAROON");

    // A macaroon for this offer with another expiry.
    let shifted = fx
        .scheme
        .keys()
        .mint(
            &offer.offer_id(),
            &fx.hash_of(&c),
            offer.fields().expires + 1,
        )
        .unwrap();
    let t = Token::new(&shifted, *token.preimage()).unwrap();
    let e = fx.verify_pay(&offer, t.to_string().as_bytes()).unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/OFFER_MISMATCH");

    // Not a token at all.
    let e = fx.verify_pay(&offer, b"Bearer x").unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/MALFORMED");
}

#[test]
fn verification_needs_a_sat_pay_entry_and_no_witness() {
    let fx = fixture();
    let offer = fx.offer(1, 21, "sat");
    let token = fx.pay(&offer);
    let body = token.to_string().into_bytes();
    let mut part = SchemePart::new(SCHEME_ID, body.clone());
    part.witness = vec![1];
    let e = fx
        .verify(&offer, Entry::Pay(&offer.fields().pay[0]), &part)
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/WITNESS");
    let attest = AttestEntry::new(SCHEME_ID, Effect::Waive);
    let e = fx
        .verify(
            &offer,
            Entry::Attest(&attest),
            &SchemePart::new(SCHEME_ID, body.clone()),
        )
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/NOT_PAY");
    let msat = PayEntry::new(SCHEME_ID, 21_000, "msat");
    let e = fx
        .verify(&offer, Entry::Pay(&msat), &SchemePart::new(SCHEME_ID, body))
        .unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/UNIT");
}

#[test]
fn a_native_token_recovers_its_offer_without_state() {
    let fx = fixture();
    let offer = fx.offer(1, 21, "sat");
    let token = fx.pay(&offer);
    let header = authorization(&token);
    let native = credential_from_authorization(&header).unwrap();
    let n = block_on(fx.scheme.recover_native(native.as_bytes(), NOW)).unwrap();
    assert_eq!(n.offer_id, offer.offer_id());
    assert_eq!(n.offer, None);
    assert_eq!(
        n.part,
        SchemePart::new(SCHEME_ID, native.as_bytes().to_vec())
    );
    // The part it returns verifies as a credential body would.
    assert!(fx.verify_pay(&offer, &n.part.body).is_ok());
    // A forged macaroon recovers nothing.
    let foreign = MacaroonKeys::new([2; 32])
        .mint(&offer.offer_id(), &[0; 32], offer.fields().expires)
        .unwrap();
    let forged = Token::new(&foreign, [0; 32]).unwrap().to_string();
    let e = block_on(fx.scheme.recover_native(forged.as_bytes(), NOW)).unwrap_err();
    assert_eq!(code(&e), "httpauth:L402/BAD_MACAROON");
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
    assert_eq!(
        block_on(fx.scheme.offer(&cx(false, false, "sat"))).unwrap(),
        SchemeOffer::default()
    );
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
    let attest = OfferCtx {
        role: OfferRole::Attest {
            effect: Effect::Waive,
        },
        ..cx(false, false, "sat")
    };
    assert_eq!(
        block_on(fx.scheme.offer(&attest)),
        Err(SchemeError::Unsupported)
    );
}

#[test]
fn natives_need_sat_and_a_live_rail() {
    let fx = fixture();
    let entry = PayEntry::new(SCHEME_ID, 21_000, "msat");
    let id = bnap_core::hash::OfferId([1; 32]);
    let cx = NativeCtx {
        now: NOW,
        offer_id: &id,
        entry: &entry,
        pay_index: 0,
        expires: NOW + 60,
    };
    assert_eq!(
        block_on(fx.scheme.native(&cx)),
        Err(SchemeError::Unsupported)
    );
    fx.fake.set_unavailable(true);
    let sat = PayEntry::new(SCHEME_ID, 21, "sat");
    let e = block_on(fx.scheme.native(&NativeCtx { entry: &sat, ..cx })).unwrap_err();
    assert!(matches!(e, SchemeError::Unavailable(_)));
}

#[test]
fn an_invoice_that_outlives_the_offer_is_never_offered() {
    // The gate takes a credential until the offer, or the entry's quote,
    // expires, with 60 s of skew (4.4 step 4). An invoice still payable
    // after that takes a payment the gate refuses STALE, and L402 refunds
    // nothing.
    let id = bnap_core::hash::OfferId([1; 32]);
    let native = |ttl: u64, entry: &PayEntry| {
        let fake = FakeRail::new([4; 32]).with_ttl(ttl);
        fake.set_now(NOW);
        let rail: Arc<dyn FundingRail> = Arc::new(fake);
        let scheme = L402::new(MacaroonKeys::new([1; 32]), rail);
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
fn settle_signs_nothing_and_returns_nothing() {
    let fx = fixture();
    let offer = fx.offer(1, 21, "sat");
    let token = fx.pay(&offer);
    let part = SchemePart::new(SCHEME_ID, token.to_string().into_bytes());
    let v = fx.verify_pay(&offer, &part.body).unwrap();
    let view = CappedSigner::verify_only(fx.signer.clone(), UNIT);
    let r = block_on(fx.scheme.settle(
        &part,
        &v,
        &bnap_plug::SettleCtx {
            now: NOW,
            status: bnap_core::response::Status::Ok,
            charged: 21,
            entry: &offer.fields().pay[0],
            context: &Context([0; 32]),
            digest: &Digest([0; 32]),
        },
        &view,
    ));
    assert_eq!(r, Ok(None));
}
