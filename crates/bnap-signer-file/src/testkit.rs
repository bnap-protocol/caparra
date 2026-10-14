//! The [`Signer`] behaviour suite, with the `test-support` feature.
//!
//! Every signer implementation in this workspace runs the same checks:
//! `bnap-signer-file` against [`FileSigner`] in process, and
//! `bnap-signer-process` against its client talking to the `bnap-signer`
//! binary over a Unix socket. Each check is an `async fn` over an
//! `Arc<dyn Signer>` loaded from [`KEY_FILE`]; [`run`] runs them all. They
//! panic on failure, so they are for tests only.
//!
//! [`KEY_FILE`] holds the draft-00 test offer and receipt keys
//! (`SHA-256("bnap test offer key")`, `SHA-256("bnap test receipt key")`)
//! and two notes keysets derived from one test seed: index 0 active with an
//! input fee of 100 ppk, index 1 inactive (inputs only), 16 amounts each.
//! Never use any of it outside tests.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bnap_core::hash::{Context, Digest, OfferId, ReplayKey, Scope, sha256};
use bnap_core::limits::Limits;
use bnap_core::note::hash_to_curve;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, Pending, Request};
use bnap_core::pricing::{Backing, BackingSource, PayValue, Refund};
use bnap_core::response::{ResponseFields, Status};
use bnap_core::schnorr::Key;
use bnap_core::secp256k1::rand::{RngCore, thread_rng};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{SchemeUses, UseModel};
use bnap_core::test_support::{MemoryStore, unsigned_response};
use bnap_plug::{
    BlindSignature, BlindedOutput, CappedSigner, ChangeLimit, KeysetId, Point, Signer, SignerError,
    UseStore,
};
use cashu::dhke::{blind_message, unblind_message};
use cashu::nuts::{BlindSignature as CashuBlindSignature, BlindSignatureDleq, Id};
use cashu::{Amount, PublicKey, SecretKey};

use crate::FileSigner;

/// The test key file. See the module docs; test material only.
pub const KEY_FILE: &str = r#"# Test material only: the draft-00 test keys and a fixed test seed.
[[key]]
use = "offer"
secret = "bda3aea2a2aae7f8373847fa9ea2937fa8befc1da0d83a3071da3c458f13a6b6"

[[key]]
use = "receipt"
secret = "03cd229c5c5926c3fba5ce72f70d3ac6d632506b9a461c12201b4e8849d9b494"

[[keyset]]
seed = "4a7627233f8531b73f6cd8d2b708fede917ebf29f7a518537cc7e0ac5a77c998"
index = 0
input_fee_ppk = 100
final_expiry = 4102444800
active = true
orders = 16

[[keyset]]
seed = "4a7627233f8531b73f6cd8d2b708fede917ebf29f7a518537cc7e0ac5a77c998"
index = 1
final_expiry = 4102444800
active = false
orders = 16
"#;

/// Far in the future: 2100-01-01.
const FAR: u64 = 4_102_444_800;

/// The public side of a keyset in [`KEY_FILE`].
#[derive(Debug, Clone)]
pub struct KeysetPublic {
    /// Its full ID.
    pub id: KeysetId,
    /// `A` by amount.
    pub keys: BTreeMap<u64, [u8; 33]>,
}

/// What a test needs to know about [`KEY_FILE`]: public data only.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// The offer key.
    pub offer_key: Key,
    /// The receipt key.
    pub receipt_key: Key,
    /// Keyset index 0: active, 100 ppk.
    pub active: KeysetPublic,
    /// Keyset index 1: inputs only.
    pub inactive: KeysetPublic,
}

/// The fixture of [`KEY_FILE`].
///
/// # Panics
///
/// If [`KEY_FILE`] does not load.
#[must_use]
pub fn fixture() -> Fixture {
    let s = FileSigner::from_toml(KEY_FILE).expect("the test key file loads");
    let public = |i: usize| KeysetPublic {
        id: KeysetId(s.keysets()[i].id().to_vec()),
        keys: s.keysets()[i].public_keys(),
    };
    Fixture {
        offer_key: s.keys()[0].public_key(),
        receipt_key: s.keys()[1].public_key(),
        active: public(0),
        inactive: public(1),
    }
}

/// A signer over [`KEY_FILE`] with both keysets active: the test's own
/// issuer, to mint notes on the inactive keyset.
///
/// # Panics
///
/// If [`KEY_FILE`] does not load.
#[must_use]
pub fn issuer() -> FileSigner {
    FileSigner::from_toml(&KEY_FILE.replace("active = false", "active = true"))
        .expect("the test key file loads")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A `ReplayKey` no other check uses.
#[must_use]
pub fn fresh_replay_key() -> ReplayKey {
    let mut b = [0u8; 32];
    thread_rng().fill_bytes(&mut b);
    ReplayKey(b)
}

/// A settlement in `sat` with `cap`, for a fresh outcome.
#[must_use]
pub fn limit(status: Status, cap: u64) -> ChangeLimit {
    ChangeLimit {
        replay_key: fresh_replay_key(),
        status,
        unit: "sat".into(),
        cap,
        keep_until: FAR,
    }
}

/// One output the test can unblind: its secret, blinding factor and `B'`.
pub struct TestOutput {
    /// The note's secret.
    pub secret: Vec<u8>,
    /// The blinding factor `r`.
    pub r: SecretKey,
    /// The output as the signer gets it.
    pub output: BlindedOutput,
}

/// A fresh output of `amount` through the `cashu` crate's NUT-00
/// `blind_message`.
///
/// # Panics
///
/// Never, in practice (a random point off the curve).
#[must_use]
pub fn output(amount: u64) -> TestOutput {
    let mut raw = [0u8; 32];
    thread_rng().fill_bytes(&mut raw);
    let secret = hex::encode(raw).into_bytes();
    let (b, r) = blind_message(&secret, None).expect("blinding works");
    TestOutput {
        secret,
        r,
        output: BlindedOutput {
            amount,
            blinded: Point(b.to_bytes()),
        },
    }
}

/// Fresh outputs of these amounts.
#[must_use]
pub fn outputs(amounts: &[u64]) -> Vec<TestOutput> {
    amounts.iter().map(|a| output(*a)).collect()
}

fn plain(outs: &[TestOutput]) -> Vec<BlindedOutput> {
    outs.iter().map(|o| o.output).collect()
}

/// Checks a blind signature's NUT-12 DLEQ proof with the `cashu` crate and
/// unblinds it, returning the note's `C`.
///
/// # Panics
///
/// When the proof does not verify.
#[must_use]
pub fn check_and_unblind(ks: &KeysetPublic, out: &TestOutput, sig: &BlindSignature) -> Point {
    let a = PublicKey::from_slice(&ks.keys[&out.output.amount]).expect("a keyset key");
    let b = PublicKey::from_slice(&out.output.blinded.0).expect("a point");
    let signed = CashuBlindSignature {
        amount: Amount::from(sig.amount),
        keyset_id: Id::from_bytes(&ks.id.0).expect("a keyset ID"),
        c: PublicKey::from_slice(&sig.signature.0).expect("C' is a point"),
        dleq: Some(BlindSignatureDleq {
            e: SecretKey::from_slice(&sig.dleq.e).expect("e is a scalar"),
            s: SecretKey::from_slice(&sig.dleq.s).expect("s is a scalar"),
        }),
    };
    signed
        .verify_dleq(a, b)
        .expect("the DLEQ proof verifies with the cashu crate");
    Point(
        unblind_message(&signed.c, &out.r, &a)
            .expect("unblinds")
            .to_bytes(),
    )
}

/// An outcome committed in a [`MemoryStore`] the way a gate commits one: a
/// `bnap:notes` credential backed by one signer-verified note worth `value`
/// sat, on an entry priced `price` sat, refund atomic.
///
/// # Panics
///
/// When the commit fails.
#[must_use]
pub fn commit(store: &dyn UseStore, value: u64, price: u64) -> Pending {
    let now = now();
    let mut n = [0u8; 32];
    thread_rng().fill_bytes(&mut n);
    let mut offer = OfferFields::new(Scope([1; 32]), now + 300, Key([9; 32]), [0; 16]);
    offer.pay.push(PayEntry::new("bnap:notes", price, "sat"));
    let y = [&[2u8][..], &sha256(&n)].concat();
    let ids = [y.clone()];
    let schemes = [SchemeUses {
        scheme: "bnap:notes",
        model: UseModel::Single,
        local_ids: &ids,
    }];
    let admitted = bnap_core::test_support::block_on(outcome::process(
        store,
        &Request {
            offer: &offer,
            context: &Context(sha256(&n)),
            pay_body: &n,
            attest_bodies: &[],
            schemes: &schemes,
            rail_ids: &[],
            pay: Some(PayValue {
                scheme: "bnap:notes",
                claimed: value,
                backing: vec![Backing {
                    source: BackingSource::Note(y),
                    amount: value,
                    unit: "sat".into(),
                }],
                refund: Refund::Atomic,
            }),
            attest: &[],
            now,
        },
        &Limits::default(),
    ));
    match admitted {
        Ok(Admitted::New(p)) => p,
        other => panic!("expected a commit, got {other:?}"),
    }
}

/// Offers sign under the offer key and acks under the receipt key, and the
/// objects finish (each signature verifies under the object's own key).
///
/// # Panics
///
/// On any failure.
pub async fn signs_offers_and_acks_with_the_key_for_their_use(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let mut f = OfferFields::new(Scope([1; 32]), now() + 300, fx.offer_key, [3; 16]);
    f.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).expect("an offer");
    let sig = signer
        .schnorr(unsigned.message())
        .await
        .expect("offer signed");
    unsigned
        .finish(&sig)
        .expect("the offer finishes")
        .verify_signature()
        .expect("offer_sig verifies");

    let unsigned = unsigned_response(&response(fx.receipt_key)).expect("a response");
    let sig = signer
        .schnorr(unsigned.message())
        .await
        .expect("ack signed");
    unsigned
        .finish(&sig)
        .expect("the response finishes")
        .verify_ack()
        .expect("the ack verifies");
}

fn response(receipt_key: Key) -> ResponseFields {
    ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 21,
        unit: Some("sat".into()),
        offer_id: OfferId([5; 32]),
        digest: Digest([6; 32]),
        metered_units: None,
        scheme_result: Some(b"change".to_vec()),
        receipt_key,
        settled_at: now(),
        unknown: Vec::new(),
    }
}

/// Messages under a key the signer does not hold, or holds for the other
/// use, are refused.
///
/// # Panics
///
/// When one is signed.
pub async fn refuses_foreign_messages(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let stranger = Key(
        bnap_core::schnorr::SigningKey::from_secret_bytes(&sha256(b"someone else"))
            .expect("a key")
            .public_key()
            .0,
    );
    for key in [fx.receipt_key, stranger] {
        let mut f = OfferFields::new(Scope([1; 32]), now() + 300, key, [3; 16]);
        f.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
        let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).expect("an offer");
        assert!(
            matches!(
                signer.schnorr(unsigned.message()).await,
                Err(SignerError::Refused(_))
            ),
            "an offer under {key} must be refused"
        );
    }
    for key in [fx.offer_key, stranger] {
        let unsigned = unsigned_response(&response(key)).expect("a response");
        assert!(
            matches!(
                signer.schnorr(unsigned.message()).await,
                Err(SignerError::Refused(_))
            ),
            "an ack under {key} must be refused"
        );
    }
}

/// Blind signatures carry a NUT-12 DLEQ proof the `cashu` crate verifies,
/// unblind to notes the signer then accepts, and are deterministic.
///
/// # Panics
///
/// On any failure.
pub async fn blind_signatures_verify_with_the_cashu_crate(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let outs = outputs(&[1, 8, 1024]);
    let lim = limit(Status::Ok, 2000);
    let sigs = signer
        .blind_sign(&fx.active.id, &plain(&outs), &lim)
        .await
        .expect("signed");
    assert_eq!(sigs.len(), 3);
    for (out, sig) in outs.iter().zip(&sigs) {
        assert_eq!(sig.amount, out.output.amount);
        let c = check_and_unblind(&fx.active, out, sig);
        let y = hash_to_curve(&out.secret).expect("Y");
        assert_eq!(
            signer
                .verify_unblinded(&fx.active.id, "sat", out.output.amount, &out.secret, &c)
                .await,
            Ok(Some(Point(y))),
            "the unblinded note verifies"
        );
        // A tampered proof fails.
        let mut bad = *sig;
        bad.dleq.s[31] ^= 1;
        let a = PublicKey::from_slice(&fx.active.keys[&out.output.amount]).expect("A");
        let tampered = CashuBlindSignature {
            amount: Amount::from(bad.amount),
            keyset_id: Id::from_bytes(&fx.active.id.0).expect("ID"),
            c: PublicKey::from_slice(&bad.signature.0).expect("C'"),
            dleq: SecretKey::from_slice(&bad.dleq.e)
                .ok()
                .zip(SecretKey::from_slice(&bad.dleq.s).ok())
                .map(|(e, s)| BlindSignatureDleq { e, s }),
        };
        assert!(
            tampered
                .verify_dleq(a, PublicKey::from_slice(&out.output.blinded.0).expect("B'"))
                .is_err()
        );
    }
    // The same outputs again, for the same outcome: the same notes, the
    // same proofs, and nothing counted twice.
    let again = signer
        .blind_sign(&fx.active.id, &plain(&outs), &lim)
        .await
        .expect("re-signed");
    assert_eq!(again, sigs);
}

/// A note is accepted only for its own secret, amount, keyset and unit; a
/// note on an inactive keyset is still accepted as an input.
///
/// # Panics
///
/// On any failure.
pub async fn notes_are_checked_against_their_secret(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let issuer: Arc<dyn Signer> = Arc::new(issuer());
    let outs = outputs(&[4, 4]);
    let sigs = issuer
        .blind_sign(&fx.inactive.id, &plain(&outs), &limit(Status::Ok, 8))
        .await
        .expect("the test issuer signs");
    let c0 = check_and_unblind(&fx.inactive, &outs[0], &sigs[0]);
    let c1 = check_and_unblind(&fx.inactive, &outs[1], &sigs[1]);
    let y0 = Point(hash_to_curve(&outs[0].secret).expect("Y"));
    let id = &fx.inactive.id;
    let check = |unit: &'static str, amount: u64, secret: Vec<u8>, c: Point, ks: KeysetId| {
        let signer = signer.clone();
        async move {
            signer
                .verify_unblinded(&ks, unit, amount, &secret, &c)
                .await
        }
    };
    assert_eq!(
        check("sat", 4, outs[0].secret.clone(), c0, id.clone()).await,
        Ok(Some(y0)),
        "a note on an inactive keyset is still an input"
    );
    assert_eq!(
        check("sat", 8, outs[0].secret.clone(), c0, id.clone()).await,
        Ok(None)
    );
    assert_eq!(
        check("msat", 4, outs[0].secret.clone(), c0, id.clone()).await,
        Ok(None)
    );
    assert_eq!(
        check("sat", 4, outs[0].secret.clone(), c0, fx.active.id.clone()).await,
        Ok(None)
    );
    assert_eq!(
        check("sat", 4, outs[0].secret.clone(), c0, KeysetId(vec![1; 33])).await,
        Ok(None)
    );
    assert_eq!(
        check("sat", 4, outs[0].secret.clone(), c1, id.clone()).await,
        Ok(None)
    );
    let mut other = outs[0].secret.clone();
    other[0] ^= 1;
    assert_eq!(check("sat", 4, other, c0, id.clone()).await, Ok(None));
}

/// Outputs that would take the outcome's total past the cap are refused,
/// across calls; outputs signed before for the same outcome count nothing.
///
/// # Panics
///
/// On any failure.
pub async fn refuses_outputs_over_the_cap(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let lim = limit(Status::Ok, 10);
    let [eight, four, two, one] = [output(8), output(4), output(2), output(1)];
    let sign = |outs: Vec<BlindedOutput>| {
        let signer = signer.clone();
        let (id, lim) = (fx.active.id.clone(), lim.clone());
        async move { signer.blind_sign(&id, &outs, &lim).await }
    };
    assert!(matches!(
        sign(vec![eight.output, four.output]).await,
        Err(SignerError::OverCap { .. })
    ));
    sign(vec![eight.output]).await.expect("8 of 10");
    assert!(matches!(
        sign(vec![four.output]).await,
        Err(SignerError::OverCap { .. })
    ));
    sign(vec![eight.output]).await.expect("the same 8 again");
    sign(vec![two.output]).await.expect("10 of 10");
    assert!(matches!(
        sign(vec![one.output]).await,
        Err(SignerError::OverCap { .. })
    ));
    // A larger cap named later for the same outcome and status does not
    // raise the first one.
    let mut raised = lim.clone();
    raised.cap = 1000;
    assert!(matches!(
        signer
            .blind_sign(&fx.active.id, &[one.output], &raised)
            .await,
        Err(SignerError::OverCap { .. })
    ));
}

/// Empty batches and outputs of amount 0 are refused, and consume nothing.
///
/// # Panics
///
/// On any failure.
pub async fn refuses_zero_amounts_and_empty_batches(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let lim = limit(Status::Ok, 8);
    let mut zero = output(1).output;
    zero.amount = 0;
    for batch in [vec![], vec![zero], vec![output(1).output, zero]] {
        assert!(
            matches!(
                signer.blind_sign(&fx.active.id, &batch, &lim).await,
                Err(SignerError::Refused(_))
            ),
            "batch of {} must be refused",
            batch.len()
        );
    }
    signer
        .blind_sign(&fx.active.id, &[output(8).output], &lim)
        .await
        .expect("the whole cap is still there");
}

/// Outputs the signer must not sign: another unit, an inactive or unknown
/// keyset, an amount without a key, a point off the curve, an outcome past
/// its record, too many outputs.
///
/// # Panics
///
/// When one is signed.
pub async fn refuses_outputs_it_must_not_sign(signer: &Arc<dyn Signer>) {
    let fx = fixture();
    let refused =
        |r: Result<Vec<BlindSignature>, SignerError>| matches!(r, Err(SignerError::Refused(_)));
    let one = [output(1).output];
    let mut msat = limit(Status::Ok, 100);
    msat.unit = "msat".into();
    assert!(refused(signer.blind_sign(&fx.active.id, &one, &msat).await));
    let lim = limit(Status::Ok, 1 << 40);
    assert!(refused(
        signer.blind_sign(&fx.inactive.id, &one, &lim).await
    ));
    assert!(refused(
        signer.blind_sign(&KeysetId(vec![1; 33]), &one, &lim).await
    ));
    for amount in [3, 1 << 20] {
        let mut o = output(1).output;
        o.amount = amount;
        assert!(refused(signer.blind_sign(&fx.active.id, &[o], &lim).await));
    }
    let off_curve = BlindedOutput {
        amount: 1,
        blinded: Point([0; 33]),
    };
    assert!(refused(
        signer.blind_sign(&fx.active.id, &[off_curve], &lim).await
    ));
    let mut gone = limit(Status::Failed, 100);
    gone.keep_until = 1;
    assert!(refused(signer.blind_sign(&fx.active.id, &one, &gone).await));
    let many: Vec<BlindedOutput> = (0..=crate::MAX_OUTPUTS_PER_CALL)
        .map(|_| output(1).output)
        .collect();
    assert!(refused(signer.blind_sign(&fx.active.id, &many, &lim).await));
}

/// Change signed the way a gate signs it: through
/// `CappedSigner::for_change` over the use store that committed the
/// outcome, which reserves every output in the outcome's record before the
/// signer signs it.
///
/// # Panics
///
/// On any failure.
pub async fn change_goes_through_the_store_ledger(signer: Arc<dyn Signer>) {
    let fx = fixture();
    let store: Arc<dyn UseStore> = Arc::new(MemoryStore::new());
    let pending = commit(&*store, 64, 21);
    let charge = pending.charge(Status::Ok, 0);
    assert_eq!(charge.cap().get(), 43);
    let (capped, guard) = CappedSigner::for_change(signer, store.clone(), charge.cap());
    let outs = outputs(&[32, 8, 2, 1]);
    let sigs = capped
        .blind_sign(&fx.active.id, &plain(&outs))
        .await
        .expect("the change is signed");
    for (out, sig) in outs.iter().zip(&sigs) {
        let _ = check_and_unblind(&fx.active, out, sig);
    }
    let record = store
        .outcome(pending.replay_key())
        .await
        .expect("the store answers")
        .expect("the outcome has a record");
    assert_eq!(record.change_total, 43, "every output was reserved first");
    assert!(matches!(
        capped.blind_sign(&fx.active.id, &[output(1).output]).await,
        Err(SignerError::OverCap { .. })
    ));
    guard.close();
    assert!(matches!(
        capped.blind_sign(&fx.active.id, &[output(1).output]).await,
        Err(SignerError::Refused(_))
    ));
}

/// Runs every check of this module against `signer`.
///
/// # Panics
///
/// On the first failure.
pub async fn run(signer: Arc<dyn Signer>) {
    signs_offers_and_acks_with_the_key_for_their_use(&signer).await;
    refuses_foreign_messages(&signer).await;
    blind_signatures_verify_with_the_cashu_crate(&signer).await;
    notes_are_checked_against_their_secret(&signer).await;
    refuses_outputs_over_the_cap(&signer).await;
    refuses_zero_amounts_and_empty_batches(&signer).await;
    refuses_outputs_it_must_not_sign(&signer).await;
    change_goes_through_the_store_ledger(signer).await;
}
