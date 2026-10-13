//! The plug traits driven end to end through `dyn` objects: mock schemes, a
//! fake Lightning rail, a key-holding test signer and the in-memory store.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::hash::{Context, Digest, RailId, ReplayKey, Scope, sha256};
use bnap_core::ids::{rail, rail_id};
use bnap_core::limits::Limits;
use bnap_core::manifest::KeyUse;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, CommitError, ReceiptInput, SettleError};
use bnap_core::pricing::{Admission, AdmitInput, Backing, BackingSource, Charge, PayValue, Refund};
use bnap_core::response::{Response, Status};
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::{UnsignedOffer, UnsignedResponse};
use bnap_core::store::{CommitPlan, PlanInput, Settlement, UseModel};
use bnap_core::test_support::{MemoryStore, block_on};
use bnap_core::{ErrorCode, Offer};
use bnap_plug::{
    Action, BlindSignature, BlindedOutput, Budget, CappedSigner, Carrier, Challenge, ChangeLedger,
    ChangeLimit, Confirmed, CoreMessage, CredentialScheme, Decision, Dleq, Entry, FundingRail,
    KeysetId, OfferCtx, PayId, PayRequest, PayState, Point, RailError, RailPayment, RailRef,
    RawCredential, SchemeError, SchemeOffer, SettleCtx, Signer, SignerError, UseStore, Verified,
    VerifyCtx, confirm_rail_id,
};

const NOW: u64 = 1_791_700_000;
const AUX0: [u8; 32] = [0; 32];

// ---------------------------------------------------------------- signer

/// A signer that holds keys by use, keeps the running change total per
/// settlement in a [`ChangeLedger`], and records every blind-sign call.
struct TestSigner {
    offer: SigningKey,
    receipt: SigningKey,
    blind_calls: Mutex<Vec<u64>>,
    ledger: ChangeLedger,
    signed: AtomicU64,
    short_answer: bool,
}

impl TestSigner {
    fn new() -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(&sha256(b"test offer key")).unwrap(),
            receipt: SigningKey::from_secret_bytes(&sha256(b"test receipt key")).unwrap(),
            blind_calls: Mutex::new(Vec::new()),
            ledger: ChangeLedger::new(),
            signed: AtomicU64::new(0),
            short_answer: false,
        }
    }

    /// The cap of every blind-sign call that reached the signer.
    fn calls(&self) -> Vec<u64> {
        self.blind_calls.lock().unwrap().clone()
    }

    /// What the signer signed, over every settlement.
    fn signed(&self) -> u64 {
        self.signed.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let key = match msg.purpose().key_use() {
            KeyUse::Offer => &self.offer,
            KeyUse::Receipt => &self.receipt,
            KeyUse::Other(_) => return Err(SignerError::Refused("no such use".into())),
        };
        msg.sign_with(key, &AUX0)
            .map_err(|_| SignerError::Refused("key not held for this use".into()))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        unit: &str,
        _amount: u64,
        y: &Point,
        c: &Point,
    ) -> Result<bool, SignerError> {
        // Stand-in for C == k·Y; the test keyset is in sat.
        Ok(unit == "sat" && y == c)
    }

    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        self.blind_calls.lock().unwrap().push(limit.cap);
        if limit.unit != "sat" {
            return Err(SignerError::Refused("the keyset is in sat".into()));
        }
        self.ledger.reserve(keyset, outputs, limit)?;
        self.signed.fetch_add(
            outputs.iter().map(|o| o.amount).sum::<u64>(),
            Ordering::SeqCst,
        );
        let n = if self.short_answer {
            outputs.len().saturating_sub(1)
        } else {
            outputs.len()
        };
        Ok(outputs[..n]
            .iter()
            .map(|o| BlindSignature {
                amount: o.amount,
                signature: o.blinded,
                dleq: Dleq {
                    e: [0; 32],
                    s: [0; 32],
                },
            })
            .collect())
    }
}

/// Blinded outputs of these amounts; `tag` keeps the points of one batch
/// apart from every other batch's.
fn outputs(tag: u16, amounts: &[u64]) -> Vec<BlindedOutput> {
    amounts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let mut p = [2; 33];
            p[1..3].copy_from_slice(&tag.to_be_bytes());
            p[3..5].copy_from_slice(&u16::try_from(i).unwrap().to_be_bytes());
            BlindedOutput {
                amount: *a,
                blinded: Point(p),
            }
        })
        .collect()
}

fn rk(n: u8) -> ReplayKey {
    ReplayKey([n; 32])
}

fn ks() -> KeysetId {
    KeysetId(vec![0, 1, 2, 3, 4, 5, 6, 7])
}

/// A change cap the way the gate gets one: from bnap-core's settlement of
/// notes worth `value` that the signer verified.
fn cap_of(value: u64, price: u64) -> bnap_plug::ChangeCap {
    settled_cap(value, price, "sat", Status::Ok)
}

/// The same, for a pay entry in `unit` and a settlement of `status`.
fn settled_cap(value: u64, price: u64, unit: &str, status: Status) -> bnap_plug::ChangeCap {
    let mut o = OfferFields::new(Scope([1; 32]), NOW + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", price, unit));
    let adm = bnap_core::pricing::admit(
        &AdmitInput {
            offer: &o,
            pay: Some(PayValue {
                scheme: "bnap:notes",
                claimed: value,
                backing: vec![Backing {
                    source: BackingSource::Note(vec![3; 33]),
                    amount: value,
                    unit: unit.into(),
                }],
                refund: Refund::Atomic,
            }),
            attest: &[],
            now: NOW,
        },
        |_| 0,
    )
    .unwrap();
    adm.settle(status, 0).cap
}

#[test]
fn the_capped_signer_refuses_outputs_above_the_cap() {
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = CappedSigner::for_change(inner.clone(), &cap_of(150, 50), rk(1));
    assert_eq!((capped.cap(), capped.remaining()), (Some(100), Some(100)));
    // 64 + 32 + 8 = 104: refused before the signer is called.
    let err = block_on(capped.blind_sign(&ks(), &outputs(1, &[64, 32, 8]))).unwrap_err();
    assert_eq!(err, SignerError::OverCap { sum: 104, cap: 100 });
    assert_eq!(err.code(), ErrorCode::Unavailable);
    // An amount sum that overflows u64 is above any cap.
    let err = block_on(capped.blind_sign(&ks(), &outputs(2, &[u64::MAX, 1]))).unwrap_err();
    assert_eq!(
        err,
        SignerError::OverCap {
            sum: u64::MAX,
            cap: 100
        }
    );
    assert_eq!(inner.calls(), Vec::<u64>::new());
    // 64 + 32 + 4 = 100: signed, and the signer gets the settlement's
    // whole cap.
    let sigs = block_on(capped.blind_sign(&ks(), &outputs(3, &[64, 32, 4]))).unwrap();
    assert_eq!(sigs.len(), 3);
    assert_eq!(inner.calls(), vec![100]);
    assert_eq!(capped.remaining(), Some(0));
    guard.close();
}

#[test]
fn two_calls_whose_sum_exceeds_the_cap_are_refused() {
    // The review's probe signed the full cap twice inside one settle.
    let inner = Arc::new(TestSigner::new());
    let (capped, _guard) = CappedSigner::for_change(inner.clone(), &cap_of(150, 50), rk(1));
    block_on(capped.blind_sign(&ks(), &outputs(1, &[64]))).unwrap();
    assert_eq!(
        block_on(capped.blind_sign(&ks(), &outputs(2, &[64]))),
        Err(SignerError::OverCap { sum: 64, cap: 36 })
    );
    block_on(capped.blind_sign(&ks(), &outputs(3, &[32, 4]))).unwrap();
    assert_eq!(capped.remaining(), Some(0));
    assert_eq!(
        block_on(capped.blind_sign(&ks(), &outputs(4, &[1]))),
        Err(SignerError::OverCap { sum: 1, cap: 0 })
    );
    assert_eq!(inner.signed(), 100);
    assert_eq!(inner.ledger.total(&rk(1), Status::Ok), 100);
}

#[test]
fn zero_amount_outputs_and_empty_batches_are_refused() {
    // The checker's probe: a hostile scheme asked for 1,000 outputs of 0
    // sat under a 29 sat cap. They carry no value on a standard keyset, but
    // each one is signer work, so they are refused before the budget is
    // touched, and the signer's own ledger refuses them as well.
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = CappedSigner::for_change(inner.clone(), &cap_of(50, 21), rk(1));
    assert_eq!(capped.remaining(), Some(29));
    let zeros = outputs(1, &[0; 1_000]);
    assert!(matches!(
        block_on(capped.blind_sign(&ks(), &zeros)),
        Err(SignerError::Refused(_))
    ));
    // One zero among valued outputs is refused too, and so is an empty
    // batch.
    assert!(matches!(
        block_on(capped.blind_sign(&ks(), &outputs(2, &[8, 0, 4]))),
        Err(SignerError::Refused(_))
    ));
    assert!(matches!(
        block_on(capped.blind_sign(&ks(), &[])),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(capped.remaining(), Some(29), "the budget was not touched");
    assert_eq!(
        inner.calls(),
        Vec::<u64>::new(),
        "the signer was not called"
    );
    guard.close();

    // An out-of-process signer gets the same answer from its ledger, whoever
    // calls it.
    let ledger = ChangeLedger::new();
    let limit = ChangeLimit {
        replay_key: rk(2),
        status: Status::Ok,
        unit: "sat".into(),
        cap: 29,
    };
    assert!(matches!(
        ledger.reserve(&ks(), &zeros, &limit),
        Err(SignerError::Refused(_))
    ));
    assert!(matches!(
        ledger.reserve(&ks(), &[], &limit),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(ledger.total(&rk(2), Status::Ok), 0);
    ledger
        .reserve(&ks(), &outputs(3, &[16, 8]), &limit)
        .unwrap();
    assert_eq!(ledger.total(&rk(2), Status::Ok), 24);
}

#[test]
fn concurrent_clones_never_exceed_the_cap_in_total() {
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = CappedSigner::for_change(inner.clone(), &cap_of(150, 50), rk(1));
    let barrier = Barrier::new(16);
    let signed = AtomicU64::new(0);
    std::thread::scope(|s| {
        for t in 0..16u16 {
            let clone = capped.clone();
            let (barrier, signed) = (&barrier, &signed);
            s.spawn(move || {
                barrier.wait();
                for i in 0..20u16 {
                    let batch = outputs(t * 20 + i, &[3]);
                    if let Ok(sigs) = block_on(clone.blind_sign(&ks(), &batch)) {
                        let sum: u64 = sigs.iter().map(|s| s.amount).sum();
                        signed.fetch_add(sum, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    // 320 attempts of 3 sat against a cap of 100: 33 are signed.
    assert_eq!(signed.load(Ordering::SeqCst), 99);
    assert_eq!(inner.signed(), 99);
    assert_eq!(capped.remaining(), Some(1));
    drop(guard);
}

#[test]
fn a_clone_used_after_settle_returns_is_refused() {
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = CappedSigner::for_change(inner.clone(), &cap_of(150, 50), rk(1));
    let kept = capped.clone();
    block_on(kept.blind_sign(&ks(), &outputs(1, &[10]))).unwrap();
    // settle returned: the gate drops the guard.
    drop(guard);
    assert_eq!(kept.remaining(), Some(0));
    for (i, s) in [&kept, &capped].into_iter().enumerate() {
        let batch = outputs(2 + u16::try_from(i).unwrap(), &[1]);
        assert!(matches!(
            block_on(s.blind_sign(&ks(), &batch)),
            Err(SignerError::Refused(_))
        ));
    }
    // Dropping the guard at once fails closed: nothing can be signed.
    let (unguarded, _) = CappedSigner::for_change(inner.clone(), &cap_of(150, 50), rk(2));
    assert!(matches!(
        block_on(unguarded.blind_sign(&ks(), &outputs(4, &[1]))),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(inner.signed(), 10);
}

#[test]
fn the_signer_keeps_a_running_total_per_settlement() {
    let inner = Arc::new(TestSigner::new());
    let cap = cap_of(150, 50);
    // Two budgets for one settlement: the signer's total bounds them
    // together, whatever each budget has left.
    let (first, _g1) = CappedSigner::for_change(inner.clone(), &cap, rk(1));
    let (second, _g2) = CappedSigner::for_change(inner.clone(), &cap, rk(1));
    block_on(first.blind_sign(&ks(), &outputs(1, &[64, 16]))).unwrap();
    assert_eq!(
        block_on(second.blind_sign(&ks(), &outputs(2, &[64]))),
        Err(SignerError::OverCap { sum: 144, cap: 100 })
    );
    // The same outputs again make the same notes: they count nothing.
    let (again, _g3) = CappedSigner::for_change(inner.clone(), &cap, rk(1));
    block_on(again.blind_sign(&ks(), &outputs(1, &[64, 16]))).unwrap();
    assert_eq!(inner.ledger.total(&rk(1), Status::Ok), 80);
    // The refund of the same ReplayKey and another outcome have their own
    // totals.
    let refund = settled_cap(150, 50, "sat", Status::Failed);
    assert_eq!((refund.get(), refund.status()), (150, Status::Failed));
    let (refunds, _g4) = CappedSigner::for_change(inner.clone(), &refund, rk(1));
    block_on(refunds.blind_sign(&ks(), &outputs(3, &[128, 16]))).unwrap();
    let (other, _g5) = CappedSigner::for_change(inner.clone(), &cap, rk(2));
    block_on(other.blind_sign(&ks(), &outputs(4, &[64]))).unwrap();
    assert_eq!(
        (
            inner.ledger.total(&rk(1), Status::Ok),
            inner.ledger.total(&rk(1), Status::Failed),
            inner.ledger.total(&rk(2), Status::Ok)
        ),
        (80, 144, 64)
    );
    // A later call naming the same settlement with a larger cap does not
    // raise it.
    let bigger = cap_of(1_000, 50);
    let (raised, _g7) = CappedSigner::for_change(inner.clone(), &bigger, rk(1));
    assert_eq!(
        block_on(raised.blind_sign(&ks(), &outputs(6, &[64]))),
        Err(SignerError::OverCap { sum: 144, cap: 100 })
    );
    inner.ledger.forget(&rk(1));
    assert_eq!(inner.ledger.total(&rk(1), Status::Failed), 0);
    // The signer refuses a settlement in a unit its keyset is not in.
    let msat = settled_cap(150, 50, "msat", Status::Ok);
    let (in_msat, _g6) = CappedSigner::for_change(inner.clone(), &msat, rk(3));
    assert_eq!(in_msat.unit(), "msat");
    assert!(matches!(
        block_on(in_msat.blind_sign(&ks(), &outputs(5, &[1]))),
        Err(SignerError::Refused(_))
    ));
}

#[test]
fn concurrent_refunds_of_one_outcome_sign_its_value_once() {
    // Two replays that both found the refund missing: a deterministic
    // settle signs the same outputs twice, which makes the same notes.
    let inner = Arc::new(TestSigner::new());
    let refund = settled_cap(150, 50, "sat", Status::Failed);
    let (a, _ga) = CappedSigner::for_change(inner.clone(), &refund, rk(9));
    let (b, _gb) = CappedSigner::for_change(inner.clone(), &refund, rk(9));
    let same = outputs(1, &[128, 16, 4, 2]);
    block_on(a.blind_sign(&ks(), &same)).unwrap();
    block_on(b.blind_sign(&ks(), &same)).unwrap();
    // A settle that signs other outputs for the same refund is refused.
    let (c, _gc) = CappedSigner::for_change(inner.clone(), &refund, rk(9));
    assert_eq!(
        block_on(c.blind_sign(&ks(), &outputs(2, &[1]))),
        Err(SignerError::OverCap { sum: 151, cap: 150 })
    );
    assert_eq!(inner.ledger.total(&rk(9), Status::Failed), 150);
}

#[test]
fn the_verify_only_view_signs_nothing() {
    let inner = Arc::new(TestSigner::new());
    let view = CappedSigner::verify_only(inner.clone(), "sat");
    assert_eq!((view.cap(), view.remaining()), (None, None));
    assert!(block_on(view.verify_unblinded(&ks(), 8, &Point([3; 33]), &Point([3; 33]))).unwrap());
    assert!(matches!(
        block_on(view.blind_sign(&ks(), &[])),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(inner.calls(), Vec::<u64>::new());
}

#[test]
fn a_signer_answer_that_does_not_match_the_outputs_is_refused() {
    let mut s = TestSigner::new();
    s.short_answer = true;
    let (capped, _guard) = CappedSigner::for_change(Arc::new(s), &cap_of(100, 0), rk(1));
    assert!(matches!(
        block_on(capped.blind_sign(&ks(), &outputs(1, &[1, 2]))),
        Err(SignerError::Refused(_))
    ));
}

#[test]
fn the_signer_signs_core_messages_with_the_key_for_their_use() {
    let signer: Arc<dyn Signer> = Arc::new(TestSigner::new());
    let t = TestSigner::new();
    let mut f = OfferFields::new(Scope([1; 32]), NOW + 300, t.offer.public_key(), [0; 16]);
    f.pay.push(PayEntry::new("httpauth:L402", 21, "sat"));
    let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
    let sig = block_on(signer.schnorr(unsigned.message())).unwrap();
    unsigned.finish(&sig).unwrap().verify_signature().unwrap();
    // An offer that names the receipt key: the signer holds that key only
    // for receipts, so it refuses.
    let mut wrong = f.clone();
    wrong.offer_key = t.receipt.public_key();
    let unsigned = UnsignedOffer::new(&wrong, Some(&[7; 32])).unwrap();
    assert!(matches!(
        block_on(signer.schnorr(unsigned.message())),
        Err(SignerError::Refused(_))
    ));
}

// ------------------------------------------------------- schemes and rail

#[test]
fn the_verify_only_view_keeps_each_accepted_note_once() {
    let view = CappedSigner::verify_only(Arc::new(TestSigner::new()), "sat");
    let (y1, y2, bad) = (Point([3; 33]), Point([4; 33]), Point([5; 33]));
    for (amount, y, c) in [
        (64, &y1, &y1),
        (32, &y2, &y2),
        (64, &y1, &y1),
        (1_000, &bad, &y1),
    ] {
        let _ = block_on(view.verify_unblinded(&ks(), amount, y, c)).unwrap();
    }
    // A clone adds to the same notes.
    let clone = view.clone();
    assert!(block_on(clone.verify_unblinded(&ks(), 64, &y1, &y1)).unwrap());
    let notes = view.notes();
    assert_eq!(
        notes
            .iter()
            .map(|b| (b.amount, b.unit.as_str()))
            .collect::<Vec<_>>(),
        vec![(64, "sat"), (32, "sat")],
        "Y1 counts once, the bad note not at all"
    );
    assert_eq!(notes[0].source, BackingSource::Note(y1.0.to_vec()));
    // A view in another unit: the signer accepts no sat keyset for it.
    let msat = CappedSigner::verify_only(Arc::new(TestSigner::new()), "msat");
    assert!(!block_on(msat.verify_unblinded(&ks(), 64, &y1, &y1)).unwrap());
    assert_eq!(msat.notes(), Vec::<Backing>::new());
}

/// A class O scheme whose local ID is its payment hash, like L402, or a
/// challenge ID, like MPP; both refer to the Lightning payment. `claim`
/// overrides the value it reports, as a dishonest scheme would.
struct LnScheme {
    id: &'static str,
    local: fn(&[u8; 32]) -> Vec<u8>,
    claim: Option<u64>,
}

#[async_trait::async_trait]
impl CredentialScheme for LnScheme {
    fn id(&self) -> &str {
        self.id
    }

    async fn offer(&self, _cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        Ok(SchemeOffer::default())
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let Entry::Pay(entry) = cx.entry else {
            return Err(SchemeError::rejected(self.id, "NOT_PAY", "attest entry"));
        };
        let hash: [u8; 32] = part
            .body
            .as_slice()
            .try_into()
            .map_err(|_| SchemeError::rejected(self.id, "BAD_BODY", "not 32 bytes"))?;
        Ok(Verified {
            use_ids: vec![(self.local)(&hash)],
            rail_ids: vec![RailRef {
                kind: rail::LN.into(),
                reference: hash.to_vec(),
            }],
            value: self.claim.unwrap_or(entry.amount),
            quota_id: None,
        })
    }

    async fn settle(
        &self,
        _part: &SchemePart,
        _verified: &Verified,
        cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        // A class O scheme returns no change; it may not sign anything.
        assert_eq!(signer.cap(), Some(0));
        Ok(Some(format!("settled {}", cx.charged).into_bytes()))
    }
}

/// A Lightning rail that knows which payment hashes were paid, and reports
/// each as `amount` in `unit`, in `state`.
struct FakeLn {
    paid: BTreeSet<[u8; 32]>,
    amount: u64,
    unit: &'static str,
    state: PayState,
}

impl FakeLn {
    fn paid(hash: [u8; 32]) -> Self {
        Self {
            paid: BTreeSet::from([hash]),
            amount: 21,
            unit: "sat",
            state: PayState::Paid,
        }
    }
}

#[async_trait::async_trait]
impl FundingRail for FakeLn {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        Ok(PayRequest {
            id: PayId(memo.to_vec()),
            rail_kind: rail::LN.into(),
            request: "lnbc-test".into(),
            amount,
            unit: unit.into(),
            expires: NOW + 600,
        })
    }

    async fn status(&self, _id: &PayId) -> Result<PayState, RailError> {
        Ok(PayState::Paid)
    }

    async fn confirm(&self, r: &RailRef) -> Result<Confirmed, RailError> {
        let hash: [u8; 32] = r
            .reference
            .as_slice()
            .try_into()
            .map_err(|_| RailError::NotConfirmed("not a payment hash".into()))?;
        if !self.paid.contains(&hash) {
            return Err(RailError::NotConfirmed("unpaid".into()));
        }
        Ok(Confirmed {
            canonical: rail::ln(&hash),
            state: self.state,
            amount: self.amount,
            unit: self.unit.into(),
        })
    }
}

fn l402() -> Arc<dyn CredentialScheme> {
    Arc::new(LnScheme {
        id: "httpauth:L402",
        local: |h| h.to_vec(),
        claim: None,
    })
}

fn mpp() -> Arc<dyn CredentialScheme> {
    Arc::new(LnScheme {
        id: "payment:lightning/charge",
        local: |h| sha256(&[&b"mpp id "[..], h].concat()).to_vec(),
        claim: None,
    })
}

/// A notes scheme: the body is notes of 74 bytes each (amount, `Y`, `C`),
/// each checked through the verify-only view. It reports `claim` as its
/// value, which may be more than the notes are worth. Its `settle` returns
/// the cap it was given; a greedy one also tries to sign the whole cap
/// twice and keeps a clone of its signer for later. `id` is `bnap:notes`,
/// or another value scheme over the same operator notes, such as a Cashu
/// NUT-24 adapter.
struct Notes {
    id: &'static str,
    claim: u64,
    greedy: bool,
    kept: Mutex<Option<CappedSigner>>,
}

impl Notes {
    fn claiming(claim: u64) -> Self {
        Self {
            id: "bnap:notes",
            claim,
            greedy: false,
            kept: Mutex::new(None),
        }
    }
}

fn notes_body(notes: &[(u64, u8)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (amount, y) in notes {
        b.extend_from_slice(&amount.to_be_bytes());
        b.extend_from_slice(&[*y; 33]);
        b.extend_from_slice(&[*y; 33]);
    }
    b
}

#[async_trait::async_trait]
impl CredentialScheme for Notes {
    fn id(&self) -> &'static str {
        self.id
    }

    async fn offer(&self, _cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        Ok(SchemeOffer::default())
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let mut ys = Vec::new();
        for n in part.body.chunks(74) {
            let amount = u64::from_be_bytes(n[..8].try_into().unwrap());
            let y = Point(n[8..41].try_into().unwrap());
            let c = Point(n[41..74].try_into().unwrap());
            if !cx
                .signer
                .verify_unblinded(&ks(), amount, &y, &c)
                .await
                .unwrap()
            {
                return Err(SchemeError::rejected(self.id, "BAD_NOTE", "C != kY"));
            }
            ys.push(y.0.to_vec());
        }
        Ok(Verified {
            use_ids: ys,
            rail_ids: Vec::new(),
            value: self.claim,
            quota_id: None,
        })
    }

    async fn settle(
        &self,
        _part: &SchemePart,
        _verified: &Verified,
        _cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        let cap = signer.cap().unwrap();
        if !self.greedy {
            return Ok(Some(format!("cap {cap}").into_bytes()));
        }
        let first = signer.blind_sign(&ks(), &outputs(1, &[cap])).await;
        let second = signer.blind_sign(&ks(), &outputs(2, &[cap])).await;
        *self.kept.lock().unwrap() = Some(signer.clone());
        Ok(Some(
            format!("first {} second {}", first.is_ok(), second.is_ok()).into_bytes(),
        ))
    }
}

#[test]
fn the_rail_supplies_the_rail_id() {
    let hash = sha256(b"preimage");
    let ln = FakeLn::paid(hash);
    let r = RailRef {
        kind: "ln".into(),
        reference: hash.to_vec(),
    };
    assert_eq!(
        block_on(confirm_rail_id(&ln, &r)).unwrap(),
        RailPayment {
            rail_id: rail_id(rail::LN, &hash),
            amount: 21,
            unit: "sat".into(),
        }
    );
    // A scheme cannot point an ln payment at another rail kind's space.
    let lie = RailRef {
        kind: "onchain".into(),
        reference: hash.to_vec(),
    };
    let err = block_on(confirm_rail_id(&ln, &lie)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadCredential);
    let unpaid = RailRef {
        kind: "ln".into(),
        reference: sha256(b"other").to_vec(),
    };
    assert!(matches!(
        block_on(confirm_rail_id(&ln, &unpaid)),
        Err(RailError::NotConfirmed(_))
    ));
    // A payment the rail knows but that is not final backs nothing.
    for state in [PayState::Pending, PayState::Expired, PayState::Failed] {
        let ln = FakeLn {
            state,
            ..FakeLn::paid(hash)
        };
        let err = block_on(confirm_rail_id(&ln, &r)).unwrap_err();
        assert!(matches!(err, RailError::NotConfirmed(_)), "{state:?}");
        assert_eq!(err.code(), ErrorCode::BadCredential);
    }
}

// ------------------------------------------------------------------ gate

/// Each test scheme's registered `refund` property, as the registry states
/// it; the gate passes it to admission, never asking the plug.
fn registered_refund(scheme: &str) -> Refund {
    match scheme {
        "bnap:notes" | "cashu:nut24" => Refund::Atomic,
        "payment:lightning/charge" => Refund::OutOfBand,
        _ => Refund::None,
    }
}

struct Gate {
    store: MemoryStore,
    signer: Arc<TestSigner>,
    rail: FakeLn,
    offer: Offer,
    scope: Scope,
    limits: Limits,
    /// The next action outlives `pending_timeout`: the sweep runs while it
    /// is still running.
    slow_action: std::cell::Cell<bool>,
    /// The gate crashes right after the next commit.
    crash_after_commit: std::cell::Cell<bool>,
}

impl Gate {
    fn new(paid: [u8; 32]) -> Self {
        Self::with_rail(FakeLn::paid(paid))
    }

    fn with_rail(rail: FakeLn) -> Self {
        let signer = Arc::new(TestSigner::new());
        let scope = Scope(sha256(b"POST /v1/thing"));
        let mut f = OfferFields::new(scope, NOW + 300, signer.offer.public_key(), [5; 16]);
        f.pay = vec![
            PayEntry::new("httpauth:L402", 21, "sat"),
            PayEntry::new("payment:lightning/charge", 21, "sat"),
            PayEntry::new("bnap:notes", 50, "sat"),
            PayEntry::new("cashu:nut24", 50, "sat"),
        ];
        let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
        let sig = block_on(signer.schnorr(unsigned.message())).unwrap();
        let offer = unsigned.finish(&sig).unwrap();
        Self {
            store: MemoryStore::new(),
            signer,
            rail,
            offer,
            scope,
            limits: Limits::default(),
            slow_action: std::cell::Cell::new(false),
            crash_after_commit: std::cell::Cell::new(false),
        }
    }

    /// Verify, confirm rails and price: the scheme's verified part, the
    /// `RailId`s and the admission.
    fn verify_and_admit(
        &self,
        scheme: &dyn CredentialScheme,
        part: &SchemePart,
        ctx: &Context,
        digest: &Digest,
        now: u64,
    ) -> Result<(Verified, Vec<RailId>, Admission), ErrorCode> {
        let (_, entry) = self.offer.fields().pay_entry(scheme.id()).unwrap();
        let view = CappedSigner::verify_only(self.signer.clone(), &entry.unit);
        let verified = block_on(scheme.verify(
            part,
            &VerifyCtx {
                now,
                offer: &self.offer,
                entry: Entry::Pay(entry),
                action_scope: &self.scope,
                context: ctx,
                digest,
                signer: &view,
            },
        ))
        .map_err(|e| e.code())?;
        // The rails confirm every payment; the view kept every note the
        // signer accepted. Admission counts those, not the scheme's claim.
        let payments = verified
            .rail_ids
            .iter()
            .map(|r| block_on(confirm_rail_id(&self.rail, r)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.code())?;
        let rail_ids: Vec<_> = payments.iter().map(|p| p.rail_id).collect();
        let mut backing: Vec<_> = payments.iter().map(RailPayment::backing).collect();
        backing.extend(view.notes());
        let store: &dyn UseStore = &self.store;
        let admission = block_on(outcome::admit(
            store,
            &AdmitInput {
                offer: self.offer.fields(),
                pay: Some(PayValue {
                    scheme: scheme.id(),
                    claimed: verified.value,
                    backing,
                    refund: registered_refund(scheme.id()),
                }),
                attest: &[],
                now,
            },
        ))
        .map_err(|e| e.code())?;
        Ok((verified, rail_ids, admission))
    }

    /// Verify, confirm rails, price, commit, run, settle and sign the
    /// receipt, all through `dyn` plugs.
    fn handle(
        &self,
        scheme: &dyn CredentialScheme,
        cred: &Credential,
        now: u64,
    ) -> Result<Response, ErrorCode> {
        let offer_id = self.offer.offer_id();
        let ctx = cred.context(&offer_id, &self.scope);
        let digest = cred.digest(&ctx);
        let part = cred.pay.as_ref().unwrap();
        let (_, entry) = self.offer.fields().pay_entry(scheme.id()).unwrap();
        let (verified, rail_ids, admission) =
            self.verify_and_admit(scheme, part, &ctx, &digest, now)?;
        let store: &dyn UseStore = &self.store;
        let plan = CommitPlan::build(&PlanInput {
            context: &ctx,
            pay_body: &part.body,
            attest_bodies: &[],
            schemes: &[verified.uses(scheme.id(), UseModel::Single)],
            rail_ids: &rail_ids,
            admission: &admission,
            offer_expires: self.offer.fields().expires,
            now,
            replay_window: self.limits.replay_window,
        })
        .map_err(|e| e.code())?;
        let receipt_input = ReceiptInput {
            offer_id,
            digest,
            unit: Some(entry.unit.clone()),
            metered: false,
            receipt_key: self.signer.receipt.public_key(),
        };
        let rk = *plan.replay_key();
        // The scheme's settle for a charge, inside one change budget.
        let run_settle = |charge: &Charge| {
            let (capped, guard) = CappedSigner::for_change(self.signer.clone(), &charge.cap, rk);
            let result = block_on(scheme.settle(
                part,
                &verified,
                &SettleCtx {
                    now,
                    status: charge.status,
                    charged: charge.charged,
                    entry,
                    context: &ctx,
                    digest: &digest,
                },
                &capped,
            ));
            // settle returned: no clone of its signer signs from here.
            guard.close();
            result.map_err(|e| e.code())
        };
        // A timed-out outcome's refund: settle FAILED, record it once, and
        // answer from the record the store returns.
        let refund = || {
            let result = run_settle(&admission.settle(Status::Failed, 0))?;
            block_on(outcome::record_refund(store, &rk, result.as_deref()))
                .map_err(|_| ErrorCode::Unavailable)
        };
        let fields = match block_on(outcome::commit(store, &plan, &self.limits)) {
            Err(e) => return Err(e.code()),
            Ok(Admitted::Replay(r)) if r.needs_refund() => {
                assert_eq!(r.receipt(&receipt_input), None, "no refund, no receipt");
                outcome::receipt(&refund()?, &receipt_input, true).unwrap()
            }
            Ok(Admitted::Replay(r)) => r.receipt(&receipt_input).unwrap(),
            Ok(Admitted::New) => {
                if self.crash_after_commit.take() {
                    return Err(ErrorCode::Unavailable);
                }
                // The action runs here.
                if self.slow_action.take() {
                    let late = now + self.limits.pending_timeout + 1;
                    block_on(outcome::sweep(store, late, &self.limits)).unwrap();
                }
                let charge = admission.settle(Status::Ok, 0);
                let result = run_settle(&charge)?;
                let s = Settlement::new(&charge, now).with_scheme_result(result);
                match block_on(outcome::settle(store, &rk, &s, &self.limits)) {
                    Ok(rec) => outcome::receipt(&rec, &receipt_input, false).unwrap(),
                    // The timeout won: the OK result and its change are
                    // discarded, and the answer is the FAILED record, with
                    // its refund.
                    Err(SettleError::AlreadySettled(rec)) => {
                        let rec = if rec.needs_refund() { refund()? } else { *rec };
                        outcome::receipt(&rec, &receipt_input, false).unwrap()
                    }
                    Err(_) => return Err(ErrorCode::Unavailable),
                }
            }
        };
        let unsigned = UnsignedResponse::new(&fields).unwrap();
        let signer: &dyn Signer = &*self.signer;
        let ack = block_on(signer.schnorr(unsigned.message())).unwrap();
        Ok(unsigned.finish(&ack).unwrap())
    }
}

fn credential(scheme: &str, hash: [u8; 32], gate: &Gate) -> Credential {
    let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    c.pay = Some(SchemePart::new(scheme, hash.to_vec()));
    c
}

#[test]
fn one_lightning_payment_under_two_schemes_admits_one_action() {
    let hash = sha256(b"preimage");
    let gate = Gate::new(hash);
    let (l402, mpp) = (l402(), mpp());
    let first = credential(l402.id(), hash, &gate);
    let receipt = gate.handle(&*l402, &first, NOW).unwrap();
    assert_eq!(receipt.fields().status, Status::Ok);
    assert_eq!(receipt.fields().charged, 21);
    assert_eq!(
        receipt.fields().scheme_result.as_deref(),
        Some(&b"settled 21"[..])
    );
    receipt.verify_ack().unwrap();

    // The same payment presented through MPP: its own use ID is new, but
    // the RailId is the same, so it is SPENT.
    let second = credential(mpp.id(), hash, &gate);
    assert_eq!(gate.handle(&*mpp, &second, NOW + 1), Err(ErrorCode::Spent));

    // The L402 credential again: a replay, signed afresh with replayed.
    let again = gate.handle(&*l402, &first, NOW + 2).unwrap();
    assert!(again.fields().replayed);
    assert_eq!(again.fields().settled_at, NOW);
    assert_eq!(again.fields().charged, 21);
    again.verify_ack().unwrap();
}

#[test]
fn an_underpaying_rail_reference_is_underpaid() {
    // The review's probe: the rail confirmed 21 msat, the scheme claimed
    // 1,000,000 sat. Admission counts the rail's 0 sat.
    let hash = sha256(b"preimage");
    let gate = Gate::with_rail(FakeLn {
        amount: 21,
        unit: "msat",
        ..FakeLn::paid(hash)
    });
    let liar = LnScheme {
        id: "httpauth:L402",
        local: |h| h.to_vec(),
        claim: Some(1_000_000),
    };
    let cred = credential(liar.id(), hash, &gate);
    assert_eq!(gate.handle(&liar, &cred, NOW), Err(ErrorCode::Underpaid));
    gate.store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
    // 20 sat confirmed for a 21 sat entry: still underpaid.
    let gate = Gate::with_rail(FakeLn {
        amount: 20,
        ..FakeLn::paid(hash)
    });
    let cred = credential(liar.id(), hash, &gate);
    assert_eq!(gate.handle(&liar, &cred, NOW), Err(ErrorCode::Underpaid));
}

#[test]
fn a_payment_in_another_unit_is_refused() {
    let hash = sha256(b"preimage");
    let gate = Gate::with_rail(FakeLn {
        amount: 21,
        unit: "USD",
        ..FakeLn::paid(hash)
    });
    let l402 = l402();
    let cred = credential(l402.id(), hash, &gate);
    assert_eq!(
        gate.handle(&*l402, &cred, NOW),
        Err(ErrorCode::BadCredential)
    );
    gate.store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
}

#[test]
fn a_payment_that_is_not_final_never_reaches_commit() {
    let hash = sha256(b"preimage");
    let gate = Gate::with_rail(FakeLn {
        state: PayState::Pending,
        ..FakeLn::paid(hash)
    });
    let l402 = l402();
    let cred = credential(l402.id(), hash, &gate);
    assert_eq!(
        gate.handle(&*l402, &cred, NOW),
        Err(ErrorCode::BadCredential)
    );
    gate.store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
}

#[test]
fn a_notes_value_larger_than_the_verified_notes_is_cut_to_them() {
    let gate = Gate::new([0; 32]);
    let liar = Notes::claiming(1_000);
    // Notes of 64 and 32 sat, the first listed twice, for a 50 sat entry:
    // the value is 96, so the change cap is 46, never 950.
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4), (64, 3)]),
    ));
    let r = gate.handle(&liar, &cred, NOW).unwrap();
    assert_eq!(r.fields().charged, 50);
    assert_eq!(r.fields().scheme_result.as_deref(), Some(&b"cap 46"[..]));
    // Notes worth 32 sat for the same entry: UNDERPAID, whatever it claims.
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new("bnap:notes", notes_body(&[(32, 5)])));
    assert_eq!(gate.handle(&liar, &cred, NOW), Err(ErrorCode::Underpaid));
}

#[test]
fn one_note_is_spent_once_whichever_value_scheme_carries_it() {
    // The review's probe: bnap:notes and a Cashu adapter both check notes
    // through the gate's one signer. One note Y = [7; 33] worth 64 sat is
    // admitted under bnap:notes; the same note under cashu:nut24 is SPENT,
    // although the adapter's own UseId for it is new (ERRATA N3b-19).
    for (first, second) in [("bnap:notes", "cashu:nut24"), ("cashu:nut24", "bnap:notes")] {
        let gate = Gate::new([0; 32]);
        let (a, b) = (
            Notes {
                id: first,
                ..Notes::claiming(64)
            },
            Notes {
                id: second,
                ..Notes::claiming(64)
            },
        );
        let note = |scheme: &str| {
            let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
            c.pay = Some(SchemePart::new(scheme, notes_body(&[(64, 7)])));
            c
        };
        let r = gate.handle(&a, &note(first), NOW).unwrap();
        assert_eq!((r.fields().status, r.fields().charged), (Status::Ok, 50));
        assert_eq!(
            gate.handle(&b, &note(second), NOW + 1),
            Err(ErrorCode::Spent)
        );
        gate.store
            .inspect(|t| assert_eq!(t.outcomes_len(), 1, "one note, one action"));
        // The first credential is still a replay of its own outcome.
        assert!(
            gate.handle(&a, &note(first), NOW + 2)
                .unwrap()
                .fields()
                .replayed
        );
    }
}

#[test]
fn a_scheme_cannot_sign_past_its_cap_or_after_settle() {
    // The review's probe through the gate: a settle that signs the whole
    // cap twice and keeps its signer. Notes of 64 and 32 sat for a 50 sat
    // entry: the cap is 46.
    let gate = Gate::new([0; 32]);
    let greedy = Notes {
        greedy: true,
        ..Notes::claiming(96)
    };
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    let r = gate.handle(&greedy, &cred, NOW).unwrap();
    assert_eq!(
        r.fields().scheme_result.as_deref(),
        Some(&b"first true second false"[..])
    );
    let kept = greedy.kept.lock().unwrap().take().unwrap();
    assert_eq!(kept.remaining(), Some(0));
    for i in 0..10 {
        assert!(matches!(
            block_on(kept.blind_sign(&ks(), &outputs(10 + i, &[1]))),
            Err(SignerError::Refused(_))
        ));
    }
    assert_eq!(gate.signer.signed(), 46);
}

#[test]
fn an_action_that_outlives_the_timeout_answers_failed_with_its_refund() {
    // Notes of 64 and 32 sat for a 50 sat entry. The action finishes after
    // pending_timeout: its OK change (cap 46) is discarded, and the client
    // gets FAILED, charged 0, with the refund (cap 96).
    let gate = Gate::new([0; 32]);
    let notes = Notes::claiming(96);
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    gate.slow_action.set(true);
    let r = gate.handle(&notes, &cred, NOW).unwrap();
    let f = r.fields();
    assert_eq!(
        (f.status, f.charged, f.replayed),
        (Status::Failed, 0, false)
    );
    assert_eq!(f.scheme_result.as_deref(), Some(&b"cap 96"[..]));
    r.verify_ack().unwrap();
    // A replay gets the same recorded refund, never a second one.
    let again = gate.handle(&notes, &cred, NOW + 1).unwrap();
    assert!(again.fields().replayed);
    assert_eq!(
        again.fields().scheme_result.as_deref(),
        Some(&b"cap 96"[..])
    );
}

#[test]
fn a_replay_after_the_timeout_collects_the_refund_first() {
    // The gate crashes after commit: the outcome stays PENDING until the
    // client replays past pending_timeout, and that replay gets the refund.
    let gate = Gate::new([0; 32]);
    let notes = Notes::claiming(96);
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    gate.crash_after_commit.set(true);
    assert_eq!(gate.handle(&notes, &cred, NOW), Err(ErrorCode::Unavailable));
    assert_eq!(gate.handle(&notes, &cred, NOW + 1), Err(ErrorCode::Pending));
    let late = NOW + gate.limits.pending_timeout + 1;
    let r = gate.handle(&notes, &cred, late).unwrap();
    let f = r.fields();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Failed, 0, true));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"cap 96"[..]));
    assert_eq!(
        gate.signer.calls(),
        Vec::<u64>::new(),
        "notes sign nothing here"
    );
}

#[test]
fn a_scheme_without_atomic_refund_mints_no_change_or_refund() {
    // The review's probe: httpauth:L402 at 21 sat, backed by a confirmed
    // 1,000 sat Lightning payment. L402 registers refund = "none": the
    // excess is kept, and neither the OK settle nor the refund of a
    // timed-out outcome gets a change budget (LnScheme::settle asserts a
    // cap of 0), so nothing is signed in the operator's notes.
    let hash = sha256(b"preimage");
    let gate = Gate::with_rail(FakeLn {
        amount: 1_000,
        ..FakeLn::paid(hash)
    });
    let l402 = l402();
    let cred = credential(l402.id(), hash, &gate);
    let r = gate.handle(&*l402, &cred, NOW).unwrap();
    assert_eq!((r.fields().status, r.fields().charged), (Status::Ok, 21));

    let other = sha256(b"other preimage");
    let gate = Gate::with_rail(FakeLn {
        amount: 1_000,
        ..FakeLn::paid(other)
    });
    let cred = credential(l402.id(), other, &gate);
    gate.crash_after_commit.set(true);
    assert_eq!(gate.handle(&*l402, &cred, NOW), Err(ErrorCode::Unavailable));
    let late = NOW + gate.limits.pending_timeout + 1;
    let r = gate.handle(&*l402, &cred, late).unwrap();
    let f = r.fields();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Failed, 0, true));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"settled 0"[..]));
    assert_eq!(gate.signer.signed(), 0, "minted nothing on FAILED");
    assert_eq!(gate.signer.calls(), Vec::<u64>::new());
}

#[test]
fn an_unpaid_payment_never_reaches_commit() {
    let gate = Gate::new(sha256(b"paid"));
    let l402 = l402();
    let cred = credential(l402.id(), sha256(b"not paid"), &gate);
    assert_eq!(
        gate.handle(&*l402, &cred, NOW),
        Err(ErrorCode::BadCredential)
    );
    gate.store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
}

#[test]
fn a_store_outage_fails_closed() {
    let hash = sha256(b"preimage");
    let gate = Gate::new(hash);
    gate.store.set_unavailable(true);
    let l402 = l402();
    let cred = credential(l402.id(), hash, &gate);
    // admit reads no counter here (no quota), so the commit is where it
    // fails, closed.
    assert_eq!(gate.handle(&*l402, &cred, NOW), Err(ErrorCode::Unavailable));
    let err = CommitError::Store(bnap_plug::StoreError("down".into()));
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

// ------------------------------------------------- carrier, judge, wallet

/// A carrier over plain strings: request "METHOD path [credential hex]".
struct LineCarrier;

impl Carrier for LineCarrier {
    type Request = String;
    type Response = Vec<String>;

    fn name(&self) -> &'static str {
        "line"
    }

    fn action_scope(&self, req: &String) -> Result<Scope, bnap_core::Error> {
        let line = req.rsplit_once(' ').map_or(req.as_str(), |(head, _)| head);
        Ok(Scope(sha256(line.as_bytes())))
    }

    fn route_scope(&self, route_id: &str) -> Scope {
        Scope(sha256(route_id.as_bytes()))
    }

    fn extract(&self, req: &String) -> Result<Option<RawCredential>, bnap_core::Error> {
        let parts: Vec<&str> = req.split(' ').collect();
        Ok(parts
            .get(2)
            .and_then(|h| hex::decode(h).ok())
            .map(RawCredential::Bnap))
    }

    fn offer(&self, c: &Challenge<'_>, out: &mut Vec<String>) {
        out.extend(c.offers.iter().map(|o| hex::encode(o.bytes())));
        out.extend(c.natives.iter().map(|n| n.value.clone()));
    }

    fn receipt(&self, r: &Response, out: &mut Vec<String>) {
        out.push(hex::encode(r.bytes()));
    }

    fn error(&self, e: &bnap_core::ErrorObject, out: &mut Vec<String>) {
        out.push(format!("error {}", e.code));
    }
}

#[test]
fn carriers_judges_and_budgets() {
    let carrier: &dyn Carrier<Request = String, Response = Vec<String>> = &LineCarrier;
    assert_eq!(carrier.name(), "line");
    let req = "POST /x 0001".to_owned();
    assert_eq!(
        carrier.extract(&req).unwrap(),
        Some(RawCredential::Bnap(vec![0, 1]))
    );
    let gate = Gate::new([0; 32]);
    let mut out = Vec::new();
    carrier.offer(
        &Challenge {
            offers: std::slice::from_ref(&gate.offer),
            natives: &[],
            error: None,
        },
        &mut out,
    );
    assert_eq!(out.len(), 1);

    assert_eq!(Decision::Admit.error(), None);
    let q = Decision::Queue { retry_after: 7 }.error().unwrap();
    assert_eq!(
        (q.socket_code(), q.retry_after),
        (Some(ErrorCode::RateLimited), Some(7))
    );
    let r = Decision::Refuse {
        detail: "abuse".into(),
    }
    .error()
    .unwrap();
    assert_eq!(r.socket_code(), Some(ErrorCode::Policy));

    let req = PayRequest {
        id: PayId(vec![1]),
        rail_kind: "ln".into(),
        request: "lnbc-test".into(),
        amount: 21,
        unit: "sat".into(),
        expires: NOW,
    };
    let budget = |max, unit: &str| Budget {
        max,
        unit: unit.into(),
    };
    assert!(bnap_plug::pay::within_budget(&req, &budget(21, "sat")));
    assert!(!bnap_plug::pay::within_budget(&req, &budget(20, "sat")));
    assert!(!bnap_plug::pay::within_budget(&req, &budget(21, "msat")));

    let action = Action {
        route_id: "chat".into(),
        carrier: "line".into(),
        scope: Scope([0; 32]),
        route_scope: true,
        metered: true,
        meter: Some("tokens".into()),
    };
    assert_eq!(action.meter.as_deref(), Some("tokens"));
}

#[test]
fn scheme_errors_carry_a_namespaced_code() {
    let e = SchemeError::rejected("bnap:notes", "BAD_SIGNATURE", "input 2");
    assert_eq!(e.code(), ErrorCode::BadCredential);
    let obj = e.to_error_object();
    assert_eq!(obj.scheme_code.as_deref(), Some("bnap:notes/BAD_SIGNATURE"));
    assert_eq!(obj.detail, None, "the detail stays in the logs");
    assert_eq!(
        SchemeError::Unavailable("facilitator".into()).code(),
        ErrorCode::Unavailable
    );
    // The default native path is unsupported.
    let s = l402();
    assert_eq!(
        block_on(s.recover_native(b"token", NOW)),
        Err(SchemeError::Unsupported)
    );
}
