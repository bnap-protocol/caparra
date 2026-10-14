//! The plug traits driven end to end through `dyn` objects: mock schemes, a
//! fake Lightning rail, a key-holding test signer and the in-memory store.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, LazyLock, Mutex};

use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::hash::{Context, Digest, RailId, ReplayKey, Scope, sha256};
use bnap_core::ids::{rail, rail_id};
use bnap_core::limits::Limits;
use bnap_core::manifest::KeyUse;
use bnap_core::note::hash_to_curve;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::outcome::{
    self, Admitted, ProcessError, ReceiptInput, Recorded, Request, SettleError,
};
use bnap_core::pricing::{Backing, BackingSource, PayValue, Refund};
use bnap_core::response::{Response, Status};
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::secp256k1::{All, PublicKey, Scalar, Secp256k1};
use bnap_core::sign::UnsignedOffer;
use bnap_core::store::{Settlement, UseModel};
use bnap_core::test_support::{MemoryStore, block_on};
use bnap_core::{ErrorCode, Offer};
use bnap_plug::{
    Action, BlindSignature, BlindedOutput, Budget, CappedSigner, Carrier, Challenge, ChangeCap,
    ChangeLedger, ChangeLimit, Confirmed, CoreMessage, CredentialScheme, Decision, Dleq, Entry,
    FundingRail, KeysetId, OfferCtx, PayId, PayRequest, PayState, Point, RailError, RailPayment,
    RailRef, RawCredential, SchemeError, SchemeOffer, SettleCtx, SettleGuard, Signer, SignerError,
    UseStore, Verified, VerifyCtx, confirm_rail_id,
};

const NOW: u64 = 1_791_700_000;
const AUX0: [u8; 32] = [0; 32];

// ---------------------------------------------------------------- signer

static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// The scalar `m`.
fn scalar(m: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&m.to_be_bytes());
    Scalar::from_be_bytes(b).unwrap()
}

/// `s·P` for a compressed point; `None` for bytes that are not a point.
fn times(p: &[u8; 33], s: &Scalar) -> Option<[u8; 33]> {
    let p = PublicKey::from_slice(p).ok()?;
    Some(p.mul_tweak(&SECP, s).ok()?.serialize())
}

/// `-P`.
fn negated(p: &[u8; 33]) -> [u8; 33] {
    PublicKey::from_slice(p).unwrap().negate(&SECP).serialize()
}

/// The test issuer's key `k`, for every amount of the test keyset.
fn issuer_key() -> Scalar {
    Scalar::from_be_bytes(sha256(b"test issuer key")).unwrap()
}

/// A note secret as `bnap:notes` writes one: 64 lowercase hex characters.
fn secret(tag: u8) -> Vec<u8> {
    hex::encode(sha256(&[b"note key ", &[tag][..]].concat())).into_bytes()
}

/// The unblinded signature of a note: `C = k·hash_to_curve(secret)`.
fn mint(secret: &[u8]) -> Point {
    Point(times(&hash_to_curve(secret).unwrap(), &issuer_key()).unwrap())
}

/// A signer that holds keys by use, checks notes with real BDHKE math
/// (`C = k·Y` for the `Y` it derives from the secret), keeps the running
/// change total per settlement in a [`ChangeLedger`], and records every
/// blind-sign call.
struct TestSigner {
    offer: SigningKey,
    receipt: SigningKey,
    blind_calls: Mutex<Vec<u64>>,
    ledger: ChangeLedger,
    signed: AtomicU64,
    minted: Mutex<BTreeSet<Minted>>,
    short_answer: bool,
}

/// One output as the test signer signed it: keyset, amount and `B'`.
type Minted = (Vec<u8>, u64, [u8; 33]);

impl TestSigner {
    fn new() -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(&sha256(b"test offer key")).unwrap(),
            receipt: SigningKey::from_secret_bytes(&sha256(b"test receipt key")).unwrap(),
            blind_calls: Mutex::new(Vec::new()),
            ledger: ChangeLedger::new(),
            signed: AtomicU64::new(0),
            minted: Mutex::new(BTreeSet::new()),
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

    /// The value of the distinct notes the signer made: an output signed
    /// twice makes the same note, so it counts once.
    fn minted(&self) -> u64 {
        self.minted.lock().unwrap().iter().map(|o| o.1).sum()
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
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        // Y from the secret, never from the caller; the keyset is in sat.
        let Some(y) = hash_to_curve(secret) else {
            return Ok(None);
        };
        let ok = unit == "sat" && times(&y, &issuer_key()) == Some(c.0);
        Ok(ok.then_some(Point(y)))
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
        self.minted.lock().unwrap().extend(
            outputs
                .iter()
                .map(|o| (keyset.0.clone(), o.amount, o.blinded.0)),
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

/// A committed outcome the way a gate gets one, and the store whose record
/// of it keeps its change ledger.
struct Outcome {
    store: Arc<dyn UseStore>,
    pending: bnap_core::Pending,
}

impl Outcome {
    /// `process`, on a store of its own, for a credential backed by a note
    /// worth `value` that the signer verified, on a `bnap:notes` entry of
    /// `price` in `unit`. Every call makes a new `ReplayKey`; the outcome's
    /// charges give change caps bound to it.
    fn new(value: u64, price: u64, unit: &str) -> Self {
        let store: Arc<dyn UseStore> = Arc::new(MemoryStore::new());
        let pending = commit_in(&*store, value, price, unit);
        Self { store, pending }
    }

    /// The change cap of a settlement of this outcome with `status`.
    fn cap(&self, status: Status) -> ChangeCap {
        self.pending.charge(status, 0).cap().clone()
    }

    /// A change view of `signer` under `cap`, reserving in this outcome's
    /// store.
    fn view(&self, signer: &Arc<TestSigner>, cap: &ChangeCap) -> (CappedSigner, SettleGuard) {
        CappedSigner::for_change(signer.clone(), self.store.clone(), cap)
    }

    /// The change view of this outcome's OK settlement.
    fn change(&self, signer: &Arc<TestSigner>) -> (CappedSigner, SettleGuard) {
        self.view(signer, &self.cap(Status::Ok))
    }

    /// What the store reserved for this outcome, change and refund
    /// together.
    fn reserved(&self) -> u64 {
        block_on(self.store.outcome(self.pending.replay_key()))
            .unwrap()
            .unwrap()
            .change_total
    }
}

/// Commits a new credential in `store` (see [`Outcome::new`]).
fn commit_in(store: &dyn UseStore, value: u64, price: u64, unit: &str) -> bnap_core::Pending {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let mut o = OfferFields::new(Scope([1; 32]), NOW + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", price, unit));
    let y = [&[2u8][..], &sha256(&n)].concat();
    let ids = [y.clone()];
    let schemes = [bnap_core::store::SchemeUses {
        scheme: "bnap:notes",
        model: UseModel::Single,
        local_ids: &ids,
    }];
    let admitted = block_on(outcome::process(
        store,
        &Request {
            offer: &o,
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
                    unit: unit.into(),
                }],
                refund: Refund::Atomic,
            }),
            attest: &[],
            now: NOW,
        },
        &Limits::default(),
    ));
    match admitted {
        Ok(Admitted::New(p)) => p,
        other => panic!("expected a commit, got {other:?}"),
    }
}

/// A new outcome: notes worth `value` sat for a `price` in sat.
fn sat(value: u64, price: u64) -> Outcome {
    Outcome::new(value, price, "sat")
}

#[test]
fn the_capped_signer_refuses_outputs_above_the_cap() {
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = sat(150, 50).change(&inner);
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
    let o = sat(150, 50);
    let cap = o.cap(Status::Ok);
    let (capped, _guard) = o.view(&inner, &cap);
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
    assert_eq!(inner.ledger.total(cap.replay_key()), 100);
    assert_eq!(o.reserved(), 100);
}

#[test]
fn zero_amount_outputs_and_empty_batches_are_refused() {
    // The checker's probe: a hostile scheme asked for 1,000 outputs of 0
    // sat under a 29 sat cap. They carry no value on a standard keyset, but
    // each one is signer work, so they are refused before the budget is
    // touched, and the signer's own ledger refuses them as well.
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = sat(50, 21).change(&inner);
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
        keep_until: NOW,
    };
    assert!(matches!(
        ledger.reserve(&ks(), &zeros, &limit),
        Err(SignerError::Refused(_))
    ));
    assert!(matches!(
        ledger.reserve(&ks(), &[], &limit),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(ledger.total(&rk(2)), 0);
    ledger
        .reserve(&ks(), &outputs(3, &[16, 8]), &limit)
        .unwrap();
    assert_eq!(ledger.total(&rk(2)), 24);
}

#[test]
fn concurrent_clones_never_exceed_the_cap_in_total() {
    let inner = Arc::new(TestSigner::new());
    let (capped, guard) = sat(150, 50).change(&inner);
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
    let (capped, guard) = sat(150, 50).change(&inner);
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
    let (unguarded, _) = sat(150, 50).change(&inner);
    assert!(matches!(
        block_on(unguarded.blind_sign(&ks(), &outputs(4, &[1]))),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(inner.signed(), 10);
}

#[test]
fn the_signer_keeps_a_running_total_per_settlement() {
    let inner = Arc::new(TestSigner::new());
    let p = sat(150, 50);
    let cap = p.cap(Status::Ok);
    let rk1 = *cap.replay_key();
    assert_eq!(&rk1, p.pending.replay_key(), "the cap names its outcome");
    // Two budgets for one settlement: the outcome's total bounds them
    // together, whatever each budget has left.
    let (first, _g1) = p.view(&inner, &cap);
    let (second, _g2) = p.view(&inner, &cap);
    block_on(first.blind_sign(&ks(), &outputs(1, &[64, 16]))).unwrap();
    assert_eq!(
        block_on(second.blind_sign(&ks(), &outputs(2, &[64]))),
        Err(SignerError::OverCap { sum: 144, cap: 100 })
    );
    // The same outputs again make the same notes: they count nothing.
    let (again, _g3) = p.view(&inner, &cap);
    block_on(again.blind_sign(&ks(), &outputs(1, &[64, 16]))).unwrap();
    assert_eq!((inner.ledger.total(&rk1), p.reserved()), (80, 80));
    // The refund of the same outcome shares its total: under its cap of
    // 150 it re-signs the 80 of change for nothing and adds 70, and
    // nothing beyond. Another outcome has its own total.
    let refund = p.cap(Status::Failed);
    assert_eq!(
        (refund.get(), refund.status(), *refund.replay_key()),
        (150, Status::Failed, rk1)
    );
    let (refunds, _g4) = p.view(&inner, &refund);
    let mut superset = outputs(1, &[64, 16]);
    superset.extend(outputs(3, &[64, 4, 2]));
    block_on(refunds.blind_sign(&ks(), &superset)).unwrap();
    let (more, _g8) = p.view(&inner, &refund);
    assert_eq!(
        block_on(more.blind_sign(&ks(), &outputs(7, &[1]))),
        Err(SignerError::OverCap { sum: 151, cap: 150 })
    );
    let other = sat(150, 50);
    let (others, _g5) = other.change(&inner);
    block_on(others.blind_sign(&ks(), &outputs(4, &[64]))).unwrap();
    assert_eq!(
        (
            inner.ledger.total(&rk1),
            inner.ledger.total(other.pending.replay_key())
        ),
        (150, 64)
    );
    // The signer drops an outcome's total only once the outcome can no
    // longer be settled: its record window from commit, plus a clock skew.
    assert_eq!(cap.keep_until(), NOW + 86_400);
    assert_eq!(inner.ledger.forget_expired(cap.keep_until() + 60), 0);
    assert_eq!(inner.ledger.total(&rk1), 150);
    assert_eq!(inner.ledger.forget_expired(cap.keep_until() + 61), 2);
    assert_eq!(inner.ledger.total(&rk1), 0);
    // The signer forgot, the store did not: a fresh refund output for the
    // same outcome is still refused before the signer is called.
    let calls = inner.calls().len();
    let (after, _g9) = p.view(&inner, &refund);
    assert_eq!(
        block_on(after.blind_sign(&ks(), &outputs(8, &[1]))),
        Err(SignerError::OverCap { sum: 151, cap: 150 })
    );
    assert_eq!(inner.calls().len(), calls);
    // The signer refuses a settlement in a unit its keyset is not in.
    let msat = Outcome::new(150, 50, "msat");
    let (in_msat, _g6) = msat.change(&inner);
    assert_eq!(in_msat.unit(), "msat");
    assert!(matches!(
        block_on(in_msat.blind_sign(&ks(), &outputs(5, &[1]))),
        Err(SignerError::Refused(_))
    ));
}

#[test]
fn the_ledger_bounds_change_and_refund_together() {
    // The hostile-scheme finding at the signer: the OK change of a late
    // settle (cap value - charged = 46) and the FAILED refund (cap value =
    // 96) of one ReplayKey. Before, each status had its own total and 142
    // was signed; now the refund may add only what keeps the total at 96,
    // whichever settlement came first.
    let ledger = ChangeLedger::new();
    let limit = |status, cap| ChangeLimit {
        replay_key: rk(4),
        status,
        unit: "sat".into(),
        cap,
        keep_until: NOW,
    };
    ledger
        .reserve(&ks(), &outputs(1, &[32, 8, 4, 2]), &limit(Status::Ok, 46))
        .unwrap();
    assert_eq!(
        ledger.reserve(&ks(), &outputs(2, &[64, 32]), &limit(Status::Failed, 96)),
        Err(SignerError::OverCap { sum: 142, cap: 96 })
    );
    let mut superset = outputs(1, &[32, 8, 4, 2]);
    superset.extend(outputs(3, &[32, 16, 2]));
    ledger
        .reserve(&ks(), &superset, &limit(Status::Failed, 96))
        .unwrap();
    assert_eq!(ledger.total(&rk(4)), 96);
    // A later call naming the same settlement with a larger cap does not
    // raise it: the first cap named for (rk, OK) bounds every OK call.
    let pinned = ChangeLedger::new();
    let ok = |cap| ChangeLimit {
        replay_key: rk(5),
        ..limit(Status::Ok, cap)
    };
    pinned.reserve(&ks(), &outputs(4, &[32]), &ok(46)).unwrap();
    assert_eq!(
        pinned.reserve(&ks(), &outputs(5, &[32]), &ok(1_000)),
        Err(SignerError::OverCap { sum: 64, cap: 46 })
    );
    // The refund first, then a late OK settle: its change outputs are
    // already in the refund, so they cost nothing, and fresh ones are
    // refused.
    let ledger = ChangeLedger::new();
    ledger
        .reserve(&ks(), &superset, &limit(Status::Failed, 96))
        .unwrap();
    ledger
        .reserve(&ks(), &outputs(1, &[32, 8, 4, 2]), &limit(Status::Ok, 46))
        .unwrap();
    assert!(matches!(
        ledger.reserve(&ks(), &outputs(9, &[1]), &limit(Status::Ok, 46)),
        Err(SignerError::OverCap { .. })
    ));
    assert_eq!(ledger.total(&rk(4)), 96);
}

#[test]
fn concurrent_refunds_of_one_outcome_sign_its_value_once() {
    // Two replays that both found the refund missing: a deterministic
    // settle signs the same outputs twice, which makes the same notes.
    let inner = Arc::new(TestSigner::new());
    let o = sat(150, 50);
    let refund = o.cap(Status::Failed);
    let (a, _ga) = o.view(&inner, &refund);
    let (b, _gb) = o.view(&inner, &refund);
    let same = outputs(1, &[128, 16, 4, 2]);
    block_on(a.blind_sign(&ks(), &same)).unwrap();
    block_on(b.blind_sign(&ks(), &same)).unwrap();
    // A settle that signs other outputs for the same refund is refused.
    let (c, _gc) = o.view(&inner, &refund);
    assert_eq!(
        block_on(c.blind_sign(&ks(), &outputs(2, &[1]))),
        Err(SignerError::OverCap { sum: 151, cap: 150 })
    );
    assert_eq!(inner.ledger.total(refund.replay_key()), 150);
    assert_eq!(o.reserved(), 150);
}

#[test]
fn no_change_is_signed_after_the_settle_is_recorded() {
    // The checker's probe (change_can_be_signed_after_the_settle_is_recorded):
    // an OK cap used after the store recorded the settle signed 46 sat of
    // change while the record kept scheme_result None, so every replay
    // answered without it, against 6.4 ("The scheme MUST NOT pay out
    // anything beyond that recorded result"). Fresh outputs are now
    // reserved only while the outcome is PENDING.
    let inner = Arc::new(TestSigner::new());
    let o = sat(96, 50);
    let charge = o.pending.charge(Status::Ok, 0);
    let s = Settlement::new(&charge, NOW);
    let rec = block_on(outcome::settle(
        &*o.store,
        &o.pending,
        &s,
        &Limits::default(),
    ))
    .unwrap();
    assert_eq!(rec.record().scheme_result, None);
    let (late, _g1) = o.view(&inner, charge.cap());
    assert!(matches!(
        block_on(late.blind_sign(&ks(), &outputs(1, &[32, 8, 4, 2]))),
        Err(SignerError::Refused(_))
    ));
    let (refund, _g2) = o.view(&inner, &o.cap(Status::Failed));
    assert!(matches!(
        block_on(refund.blind_sign(&ks(), &outputs(2, &[64]))),
        Err(SignerError::Refused(_))
    ));
    assert_eq!((inner.minted(), o.reserved()), (0, 0));
    assert!(inner.calls().is_empty(), "refused before the signer");
    // Change reserved before the settle, as an honest gate does, can be
    // signed again after it: the same notes, nothing fresh.
    let honest = sat(96, 50);
    let charge = honest.pending.charge(Status::Ok, 0);
    let reserved = outputs(3, &[32, 8, 4, 2]);
    let (before, _g3) = honest.view(&inner, charge.cap());
    block_on(before.blind_sign(&ks(), &reserved)).unwrap();
    let s = Settlement::new(&charge, NOW);
    block_on(outcome::settle(
        &*honest.store,
        &honest.pending,
        &s,
        &Limits::default(),
    ))
    .unwrap();
    let (again, _g4) = honest.view(&inner, charge.cap());
    block_on(again.blind_sign(&ks(), &reserved)).unwrap();
    let (fresh, _g5) = honest.view(&inner, charge.cap());
    assert!(matches!(
        block_on(fresh.blind_sign(&ks(), &outputs(4, &[1]))),
        Err(SignerError::Refused(_))
    ));
    assert_eq!((inner.minted(), honest.reserved()), (46, 46));
}

#[test]
fn a_refund_cap_signs_nothing_after_the_refund_is_recorded() {
    // The checker's probe (a_refund_cap_signs_after_the_refund_is_recorded):
    // two replays of a timed-out outcome both took its refund cap; one
    // signed 10 sat and recorded "refund 10", then the other signed 86
    // more, 96 minted against a recorded refund of 10. Fresh refund
    // outputs are now reserved only while the refund is due.
    let inner = Arc::new(TestSigner::new());
    let o = sat(96, 50);
    let l = Limits::default();
    let late = Settlement::new(
        &o.pending.charge(Status::Ok, 0),
        NOW + l.pending_timeout + 1,
    );
    let Err(SettleError::AlreadySettled(due)) =
        block_on(outcome::settle(&*o.store, &o.pending, &late, &l))
    else {
        panic!("the late settle loses to the timeout");
    };
    assert!(due.needs_refund());
    let cap = due.refund_cap().unwrap();
    let (first, _g1) = o.view(&inner, &cap);
    let (second, _g2) = o.view(&inner, &cap);
    let refund = outputs(1, &[8, 2]);
    block_on(first.blind_sign(&ks(), &refund)).unwrap();
    let rec = block_on(outcome::record_refund(&*o.store, &due, Some(b"refund 10"))).unwrap();
    assert!(!rec.needs_refund());
    assert!(matches!(
        block_on(second.blind_sign(&ks(), &outputs(2, &[64, 16, 4, 2]))),
        Err(SignerError::Refused(_))
    ));
    // The recorded refund's own outputs make the same notes again.
    block_on(second.blind_sign(&ks(), &refund)).unwrap();
    assert_eq!((inner.minted(), o.reserved()), (10, 10));
}

#[test]
fn the_verify_only_view_signs_nothing() {
    let inner = Arc::new(TestSigner::new());
    let view = CappedSigner::verify_only(inner.clone(), "sat");
    assert_eq!((view.cap(), view.remaining()), (None, None));
    let s = secret(3);
    assert!(
        block_on(view.verify_unblinded(&ks(), 8, &s, &mint(&s)))
            .unwrap()
            .is_some()
    );
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
    let (capped, _guard) = sat(100, 0).change(&Arc::new(s));
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
    let (s1, s2, s3) = (secret(3), secret(4), secret(5));
    let (y1, y2) = (hash_to_curve(&s1).unwrap(), hash_to_curve(&s2).unwrap());
    for (amount, s, c) in [
        (64, &s1, mint(&s1)),
        (32, &s2, mint(&s2)),
        (64, &s1, mint(&s1)),
        (1_000, &s3, mint(&s1)),
    ] {
        let _ = block_on(view.verify_unblinded(&ks(), amount, s, &c)).unwrap();
    }
    // A clone adds to the same notes, and gets the Y it derived back.
    let clone = view.clone();
    assert_eq!(
        block_on(clone.verify_unblinded(&ks(), 64, &s1, &mint(&s1))).unwrap(),
        Some(Point(y1))
    );
    let mut notes: Vec<_> = view
        .notes()
        .into_iter()
        .map(|b| (b.source, b.amount, b.unit))
        .collect();
    notes.sort();
    let mut want = vec![
        (BackingSource::Note(y1.to_vec()), 64, "sat".to_owned()),
        (BackingSource::Note(y2.to_vec()), 32, "sat".to_owned()),
    ];
    want.sort();
    assert_eq!(notes, want, "Y1 counts once, the bad note not at all");
    // A view in another unit: the signer accepts no sat keyset for it.
    let msat = CappedSigner::verify_only(Arc::new(TestSigner::new()), "msat");
    assert_eq!(
        block_on(msat.verify_unblinded(&ks(), 64, &s1, &mint(&s1))).unwrap(),
        None
    );
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

/// A notes scheme: the body is notes of 105 bytes each (amount, the
/// 64-character secret, `C`), each checked through the verify-only view.
/// It reports `claim` as its value, which may be more than the notes are
/// worth. What its `settle` does is its [`Settles`]. `id` is `bnap:notes`,
/// or another value scheme over the same operator notes, such as a Cashu
/// NUT-24 adapter.
struct Notes {
    id: &'static str,
    claim: u64,
    settles: Settles,
    kept: Mutex<Option<CappedSigner>>,
    stash: Mutex<Vec<BlindSignature>>,
    /// The next tag of a fresh output, for [`Settles::HoardAndFail`].
    next_tag: std::sync::atomic::AtomicU16,
    /// [`Settles::HoardAndFail`] lets its settle succeed from now on.
    cash_out: std::sync::atomic::AtomicBool,
}

/// How a test notes scheme settles.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Settles {
    /// Signs nothing and returns the cap it was given.
    Report,
    /// Tries to sign the whole cap twice and keeps a clone of its signer.
    Greedy,
    /// Hostile: signs the whole cap with fresh outputs in every settlement,
    /// keeps every signature it got, and returns them all, so a late OK
    /// settle's change reaches the client inside the refund.
    Hoard,
    /// As `bnap:notes` does: the change outputs (worth value - price) on
    /// OK; the change outputs again and the refund outputs (worth the
    /// price) on FAILED, so the refund is a superset of the change.
    Honest,
    /// Hostile, against a signer that restarts or runs twice: every settle
    /// signs as many fresh outputs as it is let (one of each power of two up
    /// to its cap, largest first), keeps every signature, and returns an
    /// error, so the gate records no refund and every replay opens a new
    /// refund budget. Once told to cash out, it returns all it kept.
    HoardAndFail,
}

impl Notes {
    fn claiming(claim: u64) -> Self {
        Self {
            id: "bnap:notes",
            claim,
            settles: Settles::Report,
            kept: Mutex::new(None),
            stash: Mutex::new(Vec::new()),
            next_tag: std::sync::atomic::AtomicU16::new(1_000),
            cash_out: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn settling(claim: u64, settles: Settles) -> Self {
        Self {
            settles,
            ..Self::claiming(claim)
        }
    }
}

/// The powers of two that add up to `n`, largest first.
fn powers(n: u64) -> Vec<u64> {
    (0..64)
        .rev()
        .map(|b| 1u64 << b)
        .filter(|p| n & p != 0)
        .collect()
}

/// A notes body: per note its amount, the secret `secret(tag)` and the
/// issuer's `C` for it.
fn notes_body(notes: &[(u64, u8)]) -> Vec<u8> {
    let notes: Vec<_> = notes
        .iter()
        .map(|(amount, tag)| {
            let s = secret(*tag);
            let c = mint(&s);
            (*amount, s, c)
        })
        .collect();
    raw_notes_body(&notes)
}

/// A notes body of exactly these (amount, secret, `C`) triples; the
/// secrets must be 64 bytes.
fn raw_notes_body(notes: &[(u64, Vec<u8>, Point)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (amount, s, c) in notes {
        assert_eq!(s.len(), 64);
        b.extend_from_slice(&amount.to_be_bytes());
        b.extend_from_slice(s);
        b.extend_from_slice(&c.0);
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
        for n in part.body.chunks(105) {
            let amount = u64::from_be_bytes(n[..8].try_into().unwrap());
            let secret = &n[8..72];
            let c = Point(n[72..105].try_into().unwrap());
            let Some(y) = cx
                .signer
                .verify_unblinded(&ks(), amount, secret, &c)
                .await
                .unwrap()
            else {
                return Err(SchemeError::rejected(self.id, "BAD_NOTE", "C != kY"));
            };
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
        verified: &Verified,
        cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        let cap = signer.cap().unwrap();
        match self.settles {
            Settles::Report => Ok(Some(format!("cap {cap}").into_bytes())),
            Settles::Greedy => {
                let first = signer.blind_sign(&ks(), &outputs(1, &[cap])).await;
                let second = signer.blind_sign(&ks(), &outputs(2, &[cap])).await;
                *self.kept.lock().unwrap() = Some(signer.clone());
                Ok(Some(
                    format!("first {} second {}", first.is_ok(), second.is_ok()).into_bytes(),
                ))
            }
            Settles::Hoard => {
                let tag = if cx.status == Status::Ok { 10 } else { 11 };
                if let Ok(sigs) = signer.blind_sign(&ks(), &outputs(tag, &[cap])).await {
                    self.stash.lock().unwrap().extend(sigs);
                }
                let all: u64 = self.stash.lock().unwrap().iter().map(|s| s.amount).sum();
                Ok(Some(format!("hoard {all}").into_bytes()))
            }
            Settles::HoardAndFail => {
                for bit in (0..64).rev() {
                    let amount = 1u64 << bit;
                    if amount > cap {
                        continue;
                    }
                    let tag = self.next_tag.fetch_add(1, Ordering::SeqCst);
                    if let Ok(sigs) = signer.blind_sign(&ks(), &outputs(tag, &[amount])).await {
                        self.stash.lock().unwrap().extend(sigs);
                    }
                }
                let all: u64 = self.stash.lock().unwrap().iter().map(|s| s.amount).sum();
                if self.cash_out.load(Ordering::SeqCst) {
                    Ok(Some(format!("hoard {all}").into_bytes()))
                } else {
                    Err(SchemeError::rejected(
                        self.id,
                        "HOARD",
                        "kept its signatures",
                    ))
                }
            }
            Settles::Honest => {
                let price = cx.entry.amount;
                let mut out = outputs(1, &powers(verified.value - price));
                if cx.status == Status::Failed {
                    out.extend(outputs(2, &powers(price)));
                }
                let sigs = if out.is_empty() {
                    Vec::new()
                } else {
                    signer
                        .blind_sign(&ks(), &out)
                        .await
                        .map_err(|e| SchemeError::rejected(self.id, "SIGNER", e.to_string()))?
                };
                let sum: u64 = sigs.iter().map(|s| s.amount).sum();
                Ok(Some(format!("signed {sum}").into_bytes()))
            }
        }
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
    store: Arc<MemoryStore>,
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
    /// The next action settles after `pending_timeout`, and no sweep ran.
    late_settle: std::cell::Cell<bool>,
}

impl Gate {
    fn new(paid: [u8; 32]) -> Self {
        Self::with_rail(FakeLn::paid(paid))
    }

    fn with_rail(rail: FakeLn) -> Self {
        Self::on(Arc::new(MemoryStore::new()), rail)
    }

    /// A gate instance with a signer of its own (a fresh process: its
    /// ledger is empty) on the store `store`, which other instances may
    /// share or which a restart reloaded.
    fn on(store: Arc<MemoryStore>, rail: FakeLn) -> Self {
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
            store,
            signer,
            rail,
            offer,
            scope,
            limits: Limits::default(),
            slow_action: std::cell::Cell::new(false),
            crash_after_commit: std::cell::Cell::new(false),
            late_settle: std::cell::Cell::new(false),
        }
    }

    /// Verify and confirm rails: the scheme's verified part, the
    /// `RailId`s, and the backing the rails and the signer confirmed.
    fn verify(
        &self,
        scheme: &dyn CredentialScheme,
        part: &SchemePart,
        ctx: &Context,
        digest: &Digest,
        now: u64,
    ) -> Result<(Verified, Vec<RailId>, Vec<Backing>), ErrorCode> {
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
        Ok((verified, rail_ids, backing))
    }

    /// Verify, confirm rails, then `process` (replay detection, pricing and
    /// commit in bnap-core's order), run, settle and sign the receipt, all
    /// through `dyn` plugs.
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
        let (verified, rail_ids, backing) = self.verify(scheme, part, &ctx, &digest, now)?;
        let store: &dyn UseStore = &*self.store;
        let schemes = [verified.uses(scheme.id(), UseModel::Single)];
        let admitted = block_on(outcome::process(
            store,
            &Request {
                offer: self.offer.fields(),
                context: &ctx,
                pay_body: &part.body,
                attest_bodies: &[],
                schemes: &schemes,
                rail_ids: &rail_ids,
                pay: Some(PayValue {
                    scheme: scheme.id(),
                    claimed: verified.value,
                    backing,
                    refund: registered_refund(scheme.id()),
                }),
                attest: &[],
                now,
            },
            &self.limits,
        ))
        .map_err(|e| e.code())?;
        let receipt_input = ReceiptInput {
            offer_id,
            digest,
            unit: Some(entry.unit.clone()),
            metered: false,
            receipt_key: self.signer.receipt.public_key(),
        };
        // The scheme's settle inside one change budget.
        let run_settle = |cap: &ChangeCap, charged: u64| {
            let (capped, guard) =
                CappedSigner::for_change(self.signer.clone(), self.store.clone(), cap);
            let result = block_on(scheme.settle(
                part,
                &verified,
                &SettleCtx {
                    now,
                    status: cap.status(),
                    charged,
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
        // A timed-out outcome's refund: settle FAILED under the cap the
        // commit recorded, record it once, and answer from what the store
        // returns.
        let refund = |r: &Recorded| {
            assert_eq!(r.receipt(&receipt_input), None, "no refund, no receipt");
            assert!(r.unsigned_receipt(&receipt_input).is_none());
            let cap = r.refund_cap().unwrap();
            let result = run_settle(&cap, 0)?;
            block_on(outcome::record_refund(store, r, result.as_deref()))
                .map_err(|_| ErrorCode::Unavailable)
        };
        let answer = match admitted {
            Admitted::Replay(r) if r.needs_refund() => refund(&r)?,
            Admitted::Replay(r) => r,
            Admitted::New(pending) => {
                if self.crash_after_commit.take() {
                    return Err(ErrorCode::Unavailable);
                }
                // The action runs here.
                let mut settled_at = now;
                if self.slow_action.take() {
                    let late = now + self.limits.pending_timeout + 1;
                    block_on(outcome::sweep(store, late, &self.limits)).unwrap();
                }
                if self.late_settle.take() {
                    // No sweep runs; the settle itself comes too late.
                    settled_at = now + self.limits.pending_timeout + 1;
                }
                let charge = pending.charge(Status::Ok, 0);
                let result = run_settle(charge.cap(), charge.charged())?;
                let s = Settlement::new(&charge, settled_at).with_scheme_result(result);
                match block_on(outcome::settle(store, &pending, &s, &self.limits)) {
                    Ok(rec) => rec,
                    // The timeout won: the OK result and its change are
                    // discarded, and the answer is the FAILED record, with
                    // its refund.
                    Err(SettleError::AlreadySettled(rec)) if rec.needs_refund() => refund(&rec)?,
                    Err(SettleError::AlreadySettled(rec)) => *rec,
                    Err(_) => return Err(ErrorCode::Unavailable),
                }
            }
        };
        // The receipt is signed from the recorded outcome, the only way.
        let unsigned = answer.unsigned_receipt(&receipt_input).unwrap().unwrap();
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
fn a_scaled_or_negated_note_never_counts_and_one_note_admits_one_action() {
    // The checker's HIGH probe, with real BDHKE math. From one real 50 sat
    // note (secret s, C = k·Y), the old trait let a scheme name (m·Y, m·C),
    // which passes C == k·y; through process, one note admitted 5 actions,
    // and 20 scaled copies backed a claim of 1,000 sat on a 21 sat entry,
    // with 979 sat of change. Now the scheme names only the secret and the
    // signer derives Y = hash_to_curve(s) itself.
    let signer: Arc<dyn Signer> = Arc::new(TestSigner::new());
    let s = secret(1);
    let y = hash_to_curve(&s).unwrap();
    let c = mint(&s);
    let view = CappedSigner::verify_only(signer.clone(), "sat");
    for m in 2..=20 {
        let (ym, cm) = (
            times(&y, &scalar(m)).unwrap(),
            times(&c.0, &scalar(m)).unwrap(),
        );
        // A scaled point cannot be named: taken as a secret, its bytes map
        // to another point.
        assert_eq!(
            block_on(view.verify_unblinded(&ks(), 50, &ym, &Point(cm))).unwrap(),
            None
        );
        // The real secret with a scaled C is refused.
        assert_eq!(
            block_on(view.verify_unblinded(&ks(), 50, &s, &Point(cm))).unwrap(),
            None
        );
    }
    // So is the negated pair (-Y, -C), whose -C has the other prefix.
    assert_eq!(
        block_on(view.verify_unblinded(&ks(), 50, &s, &Point(negated(&c.0)))).unwrap(),
        None
    );
    assert_eq!(view.notes(), Vec::<Backing>::new());

    // Five credentials, each carrying the real note and twenty scaled
    // copies, claiming 1,000 sat on a 21 sat entry.
    let store = Arc::new(MemoryStore::new());
    let mut o = OfferFields::new(Scope([1; 32]), NOW + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    let mut answers = Vec::new();
    for n in 1..=5u8 {
        let view = CappedSigner::verify_only(signer.clone(), "sat");
        let mut ys = Vec::new();
        for m in 1..=20 {
            let cm = Point(times(&c.0, &scalar(m)).unwrap());
            if let Some(p) = block_on(view.verify_unblinded(&ks(), 50, &s, &cm)).unwrap() {
                ys.push(p.0.to_vec());
            }
        }
        assert_eq!(ys, vec![y.to_vec()], "only the real note verifies");
        let notes = view.notes();
        assert_eq!(notes.len(), 1);
        assert_eq!(
            (notes[0].source.clone(), notes[0].amount),
            (BackingSource::Note(y.to_vec()), 50)
        );
        let schemes = [bnap_core::store::SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &ys,
        }];
        answers.push(block_on(outcome::process(
            &*store,
            &Request {
                offer: &o,
                context: &Context([n; 32]),
                pay_body: &[n],
                attest_bodies: &[],
                schemes: &schemes,
                rail_ids: &[],
                pay: Some(PayValue {
                    scheme: "bnap:notes",
                    claimed: 1_000,
                    backing: notes,
                    refund: Refund::Atomic,
                }),
                attest: &[],
                now: NOW,
            },
            &Limits::default(),
        )));
    }
    let Ok(Admitted::New(pending)) = &answers[0] else {
        panic!("the first credential commits: {:?}", answers[0]);
    };
    for a in &answers[1..] {
        assert_eq!(a, &Err(ProcessError::Spent), "one note, one action");
    }
    store.inspect(|t| assert_eq!(t.outcomes_len(), 1));
    // Admitted for the one 50 sat note: the change cap is 29, never 979.
    let charge = pending.charge(Status::Ok, 0);
    assert_eq!(charge.cap().get(), 29);
    let (capped, guard) = CappedSigner::for_change(signer, store, charge.cap());
    assert_eq!(
        block_on(capped.blind_sign(&ks(), &outputs(1, &[512, 256, 128, 64, 16, 2, 1]))),
        Err(SignerError::OverCap { sum: 979, cap: 29 })
    );
    guard.close();
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
    let greedy = Notes::settling(96, Settles::Greedy);
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
fn an_action_that_settles_after_the_timeout_loses_to_it_without_a_sweep() {
    // The checker's LOW probe through the gate: no sweep and no replay ran,
    // but the action settles OK after pending_timeout. The settle loses to
    // the timeout, so the client gets FAILED, charged 0, with the refund
    // (cap 96), exactly as a replay at that moment would.
    let gate = Gate::new([0; 32]);
    let notes = Notes::claiming(96);
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    gate.late_settle.set(true);
    let r = gate.handle(&notes, &cred, NOW).unwrap();
    let f = r.fields();
    assert_eq!(
        (f.status, f.charged, f.replayed),
        (Status::Failed, 0, false)
    );
    assert_eq!(f.scheme_result.as_deref(), Some(&b"cap 96"[..]));
}

#[test]
fn a_hostile_atomic_scheme_never_gets_more_than_the_value_signed() {
    // The checker's finding: an atomic scheme whose outcome opens an OK
    // change budget and then ends FAILED (its own OK settle, or the action,
    // outlived pending_timeout) signed both budgets in full, the change
    // (value - charged = 46) and the refund (value = 96), kept the change
    // signatures and returned them inside the refund's scheme_result: 142
    // sat of notes for 96 sat paid. The signer's total is now one per
    // ReplayKey across both settlements, bounded by the larger cap.
    for late in [true, false] {
        let gate = Gate::new([0; 32]);
        let hoarder = Notes::settling(96, Settles::Hoard);
        let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
        cred.pay = Some(SchemePart::new(
            "bnap:notes",
            notes_body(&[(64, 3), (32, 4)]),
        ));
        if late {
            gate.late_settle.set(true);
        } else {
            gate.slow_action.set(true);
        }
        let r = gate.handle(&hoarder, &cred, NOW).unwrap();
        let f = r.fields();
        assert_eq!((f.status, f.charged), (Status::Failed, 0));
        assert!(
            gate.signer.minted() <= 96,
            "minted {}",
            gate.signer.minted()
        );
        // A late settle signed its 46 sat of change while the outcome was
        // still PENDING, and the refund could add nothing fresh past 96.
        // After the sweep, the OK settle signs nothing (the outcome's FAILED
        // result is recorded) and the refund signs the whole 96.
        let want: &[u8] = if late { b"hoard 46" } else { b"hoard 96" };
        assert_eq!(f.scheme_result.as_deref(), Some(want));
    }
}

#[test]
fn an_honest_refund_that_re_signs_its_change_is_paid_in_full() {
    // An honest atomic scheme makes its refund a superset of its change, as
    // bnap:notes does (FAILED signs outputs and refund_outputs). After a
    // late OK settle signed the 46 sat of change, the refund re-signs those
    // outputs for nothing and adds the 50 sat of refund outputs: the client
    // gets the whole 96 sat, and 96 sat of notes exist in all.
    let gate = Gate::new([0; 32]);
    let honest = Notes::settling(96, Settles::Honest);
    let mut cred = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    cred.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    gate.late_settle.set(true);
    let r = gate.handle(&honest, &cred, NOW).unwrap();
    let f = r.fields();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"signed 96"[..]));
    assert_eq!(gate.signer.minted(), 96);
    // On time, the same scheme signs its 46 sat of change and no more.
    let gate = Gate::new([0; 32]);
    let r = gate.handle(&honest, &cred, NOW).unwrap();
    assert_eq!((r.fields().status, r.fields().charged), (Status::Ok, 50));
    assert_eq!(r.fields().scheme_result.as_deref(), Some(&b"signed 46"[..]));
    assert_eq!(gate.signer.minted(), 46);
}

/// The distinct notes minted by `signers` together: one output signed by
/// two signer instances makes one note.
fn minted_by(signers: &[Arc<TestSigner>]) -> u64 {
    let all: BTreeSet<Minted> = signers
        .iter()
        .flat_map(|s| s.minted.lock().unwrap().clone())
        .collect();
    all.iter().map(|o| o.1).sum()
}

/// The credential of the hoarding probes: notes of 64 and 32 sat for the
/// 50 sat `bnap:notes` entry of `gate`'s offer.
fn hoard_credential(gate: &Gate) -> Credential {
    let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    c.pay = Some(SchemePart::new(
        "bnap:notes",
        notes_body(&[(64, 3), (32, 4)]),
    ));
    c
}

/// What `gate`'s store reserved for the one outcome it holds, change and
/// refund together.
fn reserved_in(gate: &Gate) -> u64 {
    use bnap_core::store::UseTable;
    gate.store.inspect(|t| {
        let keys = t.outcome_keys();
        assert_eq!(keys.len(), 1, "one outcome");
        t.outcome(&keys[0]).unwrap().change_total
    })
}

#[test]
fn a_hoarding_scheme_never_mints_more_than_the_value_across_signer_instances() {
    // The checker's probe: two gate instances, each with its own signer
    // process, share one store (two gates on one Postgres). The scheme
    // signs its OK change, keeps it and fails, so the outcome stays
    // PENDING; each replay past the timeout opens a refund budget of the
    // whole value, and the scheme signs into it, keeps it and fails again,
    // so no refund is recorded. Before the store kept the outcome's total,
    // each signer's own ledger allowed the whole value: 174 sat minted for
    // 96 paid.
    let store = Arc::new(MemoryStore::new());
    let a = Gate::on(store.clone(), FakeLn::paid([0; 32]));
    let b = Gate::on(store, FakeLn::paid([0; 32]));
    let hoarder = Notes::settling(96, Settles::HoardAndFail);
    assert!(a.handle(&hoarder, &hoard_credential(&a), NOW).is_err());
    let late = NOW + a.limits.pending_timeout + 1;
    for (i, gate) in [&a, &b, &a].into_iter().enumerate() {
        let now = late + u64::try_from(i).unwrap();
        assert!(gate.handle(&hoarder, &hoard_credential(gate), now).is_err());
    }
    // It cashes out on B: everything it kept, in one refund.
    hoarder.cash_out.store(true, Ordering::SeqCst);
    let r = b
        .handle(&hoarder, &hoard_credential(&b), late + 10)
        .unwrap();
    let f = r.fields();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    let minted = minted_by(&[a.signer.clone(), b.signer.clone()]);
    assert!(minted <= 96, "96 sat paid, {minted} sat minted");
    assert_eq!(
        f.scheme_result.as_deref(),
        Some(format!("hoard {minted}").as_bytes())
    );
    assert_eq!(
        reserved_in(&b),
        minted,
        "every minted note was reserved first"
    );
}

#[test]
fn a_hoarding_scheme_never_mints_more_than_the_value_across_signer_restarts() {
    // The same scheme against one gate whose signer restarts between
    // replays: each restart is a new signer process with an empty ledger,
    // and a gate that reloads its store as it was persisted. Before the
    // store kept the outcome's total, every restart allowed the whole value
    // again: 366 sat minted for 96 paid after three restarts.
    let mut gate = Gate::new([0; 32]);
    let hoarder = Notes::settling(96, Settles::HoardAndFail);
    let mut signers = vec![gate.signer.clone()];
    assert!(
        gate.handle(&hoarder, &hoard_credential(&gate), NOW)
            .is_err()
    );
    let late = NOW + gate.limits.pending_timeout + 1;
    for i in 0..4u64 {
        gate = Gate::on(Arc::new(gate.store.reloaded()), FakeLn::paid([0; 32]));
        signers.push(gate.signer.clone());
        if i == 3 {
            hoarder.cash_out.store(true, Ordering::SeqCst);
            break;
        }
        assert!(
            gate.handle(&hoarder, &hoard_credential(&gate), late + i)
                .is_err()
        );
    }
    let r = gate
        .handle(&hoarder, &hoard_credential(&gate), late + 10)
        .unwrap();
    assert_eq!(r.fields().status, Status::Failed);
    let minted = minted_by(&signers);
    assert!(minted <= 96, "96 sat paid, {minted} sat minted");
    assert_eq!(
        reserved_in(&gate),
        minted,
        "every minted note was reserved first"
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
    // The outcome lookup comes first, before any pricing, and fails closed.
    assert_eq!(gate.handle(&*l402, &cred, NOW), Err(ErrorCode::Unavailable));
    let err = ProcessError::Store(bnap_plug::StoreError("down".into()));
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
