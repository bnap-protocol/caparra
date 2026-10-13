//! State machine tests against the in-memory store, all through
//! [`process`], the one entry point a gate has.

use std::sync::Barrier;

use super::*;
use crate::class::BindingClass;
use crate::credential::{Credential, OfferRef, SchemePart};
use crate::hash::{RailId, Scope, UseId, sha256};
use crate::ids::{self, rail};
use crate::offer::{AttestEntry, PayEntry};
use crate::pricing::{Backing, BackingSource, Refund};
use crate::store::{Commit, Settle, UseModel};
use crate::test_support::{MemoryStore, block_on};

const T0: u64 = 1_791_700_000;

fn limits() -> Limits {
    Limits::default()
}

fn ctx(n: u8) -> Context {
    Context([n; 32])
}

/// One request as a gate hands it to [`process`], owned so tests can vary
/// one field at a time.
#[derive(Debug, Clone)]
struct Req {
    offer: OfferFields,
    ctx: Context,
    pay_body: Vec<u8>,
    attest_bodies: Vec<Vec<u8>>,
    uses: Vec<(&'static str, UseModel, Vec<Vec<u8>>)>,
    rails: Vec<RailId>,
    pay: Option<PayValue<'static>>,
    attest: Vec<VerifiedAttest>,
    now: u64,
}

impl Req {
    /// A `bnap:notes` credential at a price of 0, naming one note under the
    /// single model: the store alone decides what happens to it.
    fn note(c: u8, y: &[u8], now: u64) -> Self {
        let mut offer = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
        offer.pay.push(PayEntry::new("bnap:notes", 0, "sat"));
        Self {
            offer,
            ctx: ctx(c),
            pay_body: b"notes body".to_vec(),
            attest_bodies: Vec::new(),
            uses: vec![("bnap:notes", UseModel::Single, vec![y.to_vec()])],
            rails: Vec::new(),
            pay: Some(PayValue {
                scheme: "bnap:notes",
                claimed: 0,
                backing: Vec::new(),
                refund: Refund::Atomic,
            }),
            attest: Vec::new(),
            now,
        }
    }

    fn at(&self, now: u64) -> Self {
        Self {
            now,
            ..self.clone()
        }
    }

    fn with_uses(mut self, uses: Vec<(&'static str, UseModel, Vec<Vec<u8>>)>) -> Self {
        self.uses = uses;
        self
    }

    fn process_in<S: UseStore + ?Sized>(
        &self,
        store: &S,
        l: &Limits,
    ) -> Result<Admitted, ProcessError> {
        let bodies: Vec<&[u8]> = self.attest_bodies.iter().map(Vec::as_slice).collect();
        let schemes: Vec<SchemeUses<'_>> = self
            .uses
            .iter()
            .map(|(scheme, model, ids)| SchemeUses {
                scheme,
                model: *model,
                local_ids: ids,
            })
            .collect();
        block_on(process(
            store,
            &Request {
                offer: &self.offer,
                context: &self.ctx,
                pay_body: &self.pay_body,
                attest_bodies: &bodies,
                schemes: &schemes,
                rail_ids: &self.rails,
                pay: self.pay.clone(),
                attest: &self.attest,
                now: self.now,
            },
            l,
        ))
    }

    fn process(&self, store: &MemoryStore) -> Result<Admitted, ProcessError> {
        self.process_in(store, &limits())
    }

    /// The `ReplayKey` of 6.1, computed here from the same inputs.
    fn rk(&self) -> ReplayKey {
        let bodies: Vec<&[u8]> = self.attest_bodies.iter().map(Vec::as_slice).collect();
        let mut all: Vec<[u8; 32]> = self
            .uses
            .iter()
            .flat_map(|(s, _, ids)| ids.iter().map(|l| ids::use_id(s, l).0))
            .collect();
        all.extend(self.rails.iter().map(|r| r.0));
        ids::replay_key(&self.ctx, &self.pay_body, &bodies, &all)
    }
}

fn new(r: Result<Admitted, ProcessError>) -> Pending {
    match r {
        Ok(Admitted::New(p)) => p,
        other => panic!("expected New, got {other:?}"),
    }
}

fn replay(r: Result<Admitted, ProcessError>) -> Recorded {
    match r {
        Ok(Admitted::Replay(r)) => r,
        other => panic!("expected a replay, got {other:?}"),
    }
}

fn settlement(status: Status, charged: u64, at: u64) -> Settlement {
    Settlement {
        status,
        charged,
        metered_units: Some(850),
        scheme_result: Some(b"change signatures".to_vec()),
        response: Some(b"stored response".to_vec()),
        settled_at: at,
    }
}

fn settle_ok(store: &MemoryStore, p: &Pending, charged: u64, at: u64) -> Recorded {
    block_on(settle(
        store,
        p,
        &settlement(Status::Ok, charged, at),
        &limits(),
    ))
    .unwrap()
}

fn failed(at: u64, result: Option<&[u8]>) -> Settlement {
    Settlement {
        status: Status::Failed,
        charged: 0,
        metered_units: None,
        scheme_result: result.map(<[u8]>::to_vec),
        response: None,
        settled_at: at,
    }
}

fn receipt_input(digest: Digest) -> ReceiptInput {
    ReceiptInput {
        offer_id: OfferId([7; 32]),
        digest,
        unit: Some("sat".into()),
        metered: true,
        receipt_key: Key([2; 32]),
    }
}

/// A store whose pricing reads always see empty counters, as reads taken
/// before a burst of concurrent commits would. Only the commit's re-check
/// can then keep a quota or rate counter within its limit.
struct StaleReads(MemoryStore);

#[async_trait::async_trait]
impl UseStore for StaleReads {
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
        self.0.commit(plan).await
    }

    async fn counter(&self, _key: &CounterKey) -> Result<u64, StoreError> {
        Ok(0)
    }

    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
        self.0.outcome(rk).await
    }

    async fn settle(
        &self,
        rk: &ReplayKey,
        s: &Settlement,
        pending_timeout: u64,
    ) -> Result<Settle, StoreError> {
        self.0.settle(rk, s, pending_timeout).await
    }

    async fn expire_pending(
        &self,
        created_before: u64,
        now: u64,
    ) -> Result<Vec<ReplayKey>, StoreError> {
        self.0.expire_pending(created_before, now).await
    }

    async fn record_refund(
        &self,
        rk: &ReplayKey,
        scheme_result: Option<&[u8]>,
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        self.0.record_refund(rk, scheme_result).await
    }

    async fn purge(&self, created_before: u64, now: u64) -> Result<u64, StoreError> {
        self.0.purge(created_before, now).await
    }
}

// ------------------------------------------------------------ the basics

#[test]
fn process_is_new_then_a_retry_is_pending() {
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y1", T0);
    let p = new(r.process(&store));
    assert_eq!(p.replay_key(), &r.rk(), "the ReplayKey of 6.1");
    let rec = block_on(store.outcome(p.replay_key())).unwrap().unwrap();
    assert_eq!(rec.status, OutcomeStatus::Pending);
    assert_eq!(rec.created, T0);
    assert_eq!(rec.keep_until, T0 + 300 + 60);

    let err = r.at(T0 + 10).process(&store).unwrap_err();
    assert_eq!(err, ProcessError::Pending { retry_after: 290 });
    assert_eq!(err.code(), ErrorCode::Pending);
    assert_eq!(err.to_error_object().retry_after, Some(290));
}

#[test]
fn replay_returns_the_recorded_outcome_with_replayed() {
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y1", T0);
    let p = new(r.process(&store));
    let fresh = settle_ok(&store, &p, 340, T0 + 5);
    assert!(!fresh.replayed());
    let first = fresh.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert!(!first.replayed);

    let again = replay(r.at(T0 + 100).process(&store));
    assert!(again.replayed() && !again.needs_refund());
    assert_eq!(again.refund_cap(), None);
    assert_eq!(
        again.record().response.as_deref(),
        Some(&b"stored response"[..])
    );
    let fields = again.receipt(&receipt_input(Digest([9; 32]))).unwrap();
    assert!(fields.replayed);
    assert_eq!(fields.status, Status::Ok);
    assert_eq!(fields.charged, 340);
    assert_eq!(fields.metered_units, Some(850));
    assert_eq!(
        fields.settled_at,
        T0 + 5,
        "a replay keeps the original settled_at"
    );
    assert_eq!(
        fields.scheme_result.as_deref(),
        Some(&b"change signatures"[..])
    );
    assert_eq!(
        fields.digest,
        Digest([9; 32]),
        "signed over the replaying request"
    );
    // The replay wrote nothing.
    assert_eq!(
        block_on(store.outcome(p.replay_key())).unwrap().unwrap(),
        *fresh.record()
    );
}

#[test]
fn status_flip_on_replay_is_impossible() {
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y1", T0);
    let p = new(r.process(&store));
    let ok = settle_ok(&store, &p, 340, T0 + 5);

    let flip = failed(T0 + 6, Some(b"refund"));
    let err = block_on(settle(&store, &p, &flip, &limits())).unwrap_err();
    let SettleError::AlreadySettled(rec) = err else {
        panic!("expected AlreadySettled");
    };
    assert_eq!(rec.record(), ok.record());
    // A second OK settle with another charge is refused as well.
    let again = Settlement {
        status: Status::Ok,
        charged: 1,
        ..flip
    };
    assert!(matches!(
        block_on(settle(&store, &p, &again, &limits())),
        Err(SettleError::AlreadySettled(_))
    ));
    // The timeout never touches a settled outcome, and a timed-out refund
    // is never recorded on it.
    let swept = block_on(sweep(&store, T0 + 10_000, &limits())).unwrap();
    assert_eq!(swept.timed_out, Vec::<ReplayKey>::new());
    let after = block_on(record_refund(&store, &ok, Some(b"x"))).unwrap();
    assert_eq!(after.record(), ok.record());
    // A replay still reports OK.
    let later = replay(r.at(T0 + 20_000).process(&store));
    assert_eq!(later.record(), ok.record());
}

#[test]
fn concurrent_double_spend_has_exactly_one_winner() {
    const N: u8 = 16;
    let store = MemoryStore::new();
    let barrier = Barrier::new(usize::from(N));
    let results: Vec<Result<Admitted, ProcessError>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (store, barrier) = (&store, &barrier);
                s.spawn(move || {
                    // N different credentials spending the same note.
                    let r = Req::note(i, b"the one note", T0);
                    barrier.wait();
                    r.process(store)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let wins = results
        .iter()
        .filter(|r| matches!(r, Ok(Admitted::New(_))))
        .count();
    let spent = results
        .iter()
        .filter(|r| **r == Err(ProcessError::Spent))
        .count();
    assert_eq!((wins, spent), (1, usize::from(N) - 1));
    store.inspect(|t| {
        assert_eq!(t.used_len(), 1);
        assert_eq!(t.outcomes_len(), 1);
    });
}

#[test]
fn concurrent_retries_of_one_credential_run_once() {
    const N: usize = 12;
    let store = MemoryStore::new();
    let barrier = Barrier::new(N);
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let (store, barrier) = (&store, &barrier);
                s.spawn(move || {
                    let r = Req::note(3, b"Y", T0);
                    barrier.wait();
                    r.process(store)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(Admitted::New(_))))
            .count(),
        1
    );
    assert!(
        results
            .iter()
            .filter(|r| !matches!(r, Ok(Admitted::New(_))))
            .all(|r| matches!(r, Err(ProcessError::Pending { .. })))
    );
}

#[test]
fn same_use_ids_under_another_replay_key_are_spent() {
    let store = MemoryStore::new();
    let a = Req::note(1, b"Y1", T0);
    let pa = new(a.process(&store));
    settle_ok(&store, &pa, 21, T0 + 1);
    // The same note in another credential (another Context, so another
    // ReplayKey): SPENT, never the other credential's outcome.
    let b = Req::note(2, b"Y1", T0 + 2);
    assert_ne!(a.rk(), b.rk());
    assert_eq!(b.process(&store), Err(ProcessError::Spent));
    // Same Context but a body changed on the path: another ReplayKey, SPENT.
    let c = Req {
        pay_body: b"notes body, altered".to_vec(),
        ..a.at(T0 + 3)
    };
    assert_eq!(c.process(&store), Err(ProcessError::Spent));
}

#[test]
fn a_replay_names_only_its_own_record() {
    // Security review, store lead (b): a replay is answered from
    // outcome[rk] without checking that every single the request names is
    // used under rk. That holds by construction: the ReplayKey covers every
    // UseId and RailId, so a request that shares one single with a
    // committed credential but differs in any other has another ReplayKey
    // and is SPENT. Backing notes are not in the ReplayKey (6.1), so a
    // replay may name one the commit never saw: it is answered from the
    // record, consumes nothing, and its refund is the one the commit fixed.
    let store = MemoryStore::new();
    let mut a = Req::note(1, b"Y1", T0);
    a.offer.pay[0].amount = 50;
    a.pay = Some(PayValue {
        scheme: "bnap:notes",
        claimed: 64,
        backing: vec![Backing {
            source: BackingSource::Note(b"Y1".to_vec()),
            amount: 64,
            unit: "sat".into(),
        }],
        refund: Refund::Atomic,
    });
    let pa = new(a.process(&store));
    // One single shared with A, one new: another ReplayKey, SPENT, and the
    // new note is not consumed.
    let b = Req::note(1, b"Y1", T0 + 1).with_uses(vec![(
        "bnap:notes",
        UseModel::Single,
        vec![b"Y1".to_vec(), b"Y2".to_vec()],
    )]);
    assert_ne!(b.rk(), a.rk());
    assert_eq!(b.process(&store), Err(ProcessError::Spent));
    let y2 = ids::use_id("bnap:notes", b"Y2");
    store.inspect(|t| assert!(t.used_by(&y2.0).is_none()));
    // A's request again after a crash, now also backed by a note worth 100
    // sat that the commit never saw: the same ReplayKey, a replay, and the
    // refund cap is the 64 sat the commit consumed, not 164.
    let mut again = a.at(T0 + limits().pending_timeout + 1);
    if let Some(p) = &mut again.pay {
        p.backing.push(Backing {
            source: BackingSource::Note(b"N9".to_vec()),
            amount: 100,
            unit: "sat".into(),
        });
        p.claimed = 164;
    }
    assert_eq!(again.rk(), *pa.replay_key());
    let r = replay(again.process(&store));
    assert!(r.needs_refund());
    let cap = r.refund_cap().unwrap();
    assert_eq!(
        (cap.get(), cap.unit(), cap.status()),
        (64, "sat", Status::Failed)
    );
    let n9 = crate::pricing::note_id(b"N9");
    store.inspect(|t| {
        assert!(t.used_by(&n9).is_none(), "the replay consumed nothing");
        assert_eq!(t.used_by(&crate::pricing::note_id(b"Y1")), Some(a.rk()));
    });
}

#[test]
fn one_payment_through_two_schemes_is_a_conflict() {
    let store = MemoryStore::new();
    let hash = sha256(b"preimage");
    let payment = ids::rail_id(rail::LN, &rail::ln(&hash));
    let first = Req {
        pay_body: b"l402 token".to_vec(),
        rails: vec![payment],
        ..Req::note(1, b"", T0).with_uses(vec![(
            "httpauth:L402",
            UseModel::Single,
            vec![hash.to_vec()],
        )])
    };
    let second = Req {
        pay_body: b"mpp credential".to_vec(),
        rails: vec![payment],
        ..Req::note(2, b"", T0).with_uses(vec![(
            "payment:lightning/charge",
            UseModel::Single,
            vec![b"mpp challenge id".to_vec()],
        )])
    };
    // The schemes' use IDs differ; only the RailId is shared.
    assert_ne!(
        ids::use_id("httpauth:L402", &hash),
        ids::use_id("payment:lightning/charge", b"mpp challenge id")
    );
    new(first.process(&store));
    assert_eq!(second.process(&store), Err(ProcessError::Spent));
    // The failed commit consumed nothing: its own use ID is still free.
    let mpp_use = ids::use_id("payment:lightning/charge", b"mpp challenge id");
    store.inspect(|t| {
        assert!(t.used_by(&mpp_use.0).is_none());
        assert_eq!(t.used_by(&payment.0), Some(first.rk()));
    });
}

#[test]
fn rail_ids_are_single_whatever_the_scheme_model() {
    // Security review, store lead (d): one payment admits one action even
    // when the scheme that cites it counts its own IDs as rate or reusable
    // (6.2: RailIds are always single).
    for model in [UseModel::Reusable, UseModel::Rate { k: 100, epoch: 60 }] {
        let store = MemoryStore::new();
        let payment = RailId([5; 32]);
        let cite = |c: u8| Req {
            rails: vec![payment],
            ..Req::note(c, b"", T0).with_uses(vec![(
                "vnd.example",
                model,
                vec![b"client".to_vec()],
            )])
        };
        new(cite(1).process(&store));
        assert_eq!(
            cite(2).process(&store),
            Err(ProcessError::Spent),
            "{model:?}"
        );
        store.inspect(|t| assert_eq!(t.used_by(&payment.0), Some(cite(1).rk())));
    }
}

#[test]
fn an_abort_consumes_nothing() {
    let store = MemoryStore::new();
    new(Req::note(1, b"B", T0).process(&store));
    let both = Req::note(2, b"", T0).with_uses(vec![(
        "bnap:notes",
        UseModel::Single,
        vec![b"A".to_vec(), b"B".to_vec()],
    )]);
    assert_eq!(both.process(&store), Err(ProcessError::Spent));
    // The client keeps note A.
    new(Req::note(3, b"A", T0).process(&store));
}

fn rate_req(c: u8, key_id: &[u8], k: u64, now: u64) -> Req {
    Req {
        pay_body: b"arc presentation".to_vec(),
        ..Req::note(c, b"", now).with_uses(vec![(
            "vnd.cfrg.arc",
            UseModel::Rate { k, epoch: 60 },
            vec![key_id.to_vec()],
        )])
    }
}

fn rate_counter(key_id: &[u8], k: u64, epoch: u64, now: u64) -> CounterKey {
    ids::rate_key(&ids::use_id("vnd.cfrg.arc", key_id), k, epoch, now).unwrap()
}

#[test]
fn rate_counters_limit_and_failed_gives_them_back() {
    let store = MemoryStore::new();
    let now = 120 * 60 + 15;
    let mut first = rate_req(1, b"client", 1, now);
    let mut second = rate_req(2, b"client", 1, now);
    // An offer that lives as long as the record may.
    for r in [&mut first, &mut second] {
        r.offer.expires = now + 300;
    }
    let p = new(first.process(&store));
    store.inspect(|t| assert_eq!(t.used_len(), 0, "a rate ID is no single use"));
    assert_eq!(
        block_on(store.counter(&rate_counter(b"client", 1, 60, now))).unwrap(),
        1
    );
    assert_eq!(
        second.process(&store),
        Err(ProcessError::RateLimited { retry_after: 45 })
    );
    // FAILED gives the counter back, so the second credential now fits.
    block_on(settle(&store, &p, &failed(now + 1, None), &limits())).unwrap();
    new(second.process(&store));
}

#[test]
fn failed_keeps_single_uses_spent() {
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y1", T0);
    let p = new(r.process(&store));
    let rec = block_on(settle(
        &store,
        &p,
        &failed(T0 + 1, Some(b"refund outputs")),
        &limits(),
    ))
    .unwrap();
    assert_eq!(rec.record().status, OutcomeStatus::Failed);
    assert_eq!(rec.record().charged, Some(0));
    assert_eq!(
        Req::note(2, b"Y1", T0 + 2).process(&store),
        Err(ProcessError::Spent)
    );
    // The same credential replays its FAILED outcome and its refund.
    let again = replay(r.at(T0 + 3).process(&store));
    let f = again.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"refund outputs"[..]));
}

#[test]
fn pending_timeout_moves_to_failed_and_the_replay_collects_the_refund() {
    let store = MemoryStore::new();
    let l = limits();
    let r = Req::note(1, b"", T0).with_uses(vec![
        (
            "vnd.cfrg.arc",
            UseModel::Rate { k: 5, epoch: 3600 },
            vec![b"client".to_vec()],
        ),
        ("bnap:notes", UseModel::Single, vec![b"note".to_vec()]),
    ]);
    let p = new(r.process(&store));
    let key = ids::rate_key(&ids::use_id("vnd.cfrg.arc", b"client"), 5, 3600, T0).unwrap();
    assert_eq!(block_on(store.counter(&key)).unwrap(), 1);

    // Still inside pending_timeout: nothing happens.
    let swept = block_on(sweep(&store, T0 + l.pending_timeout, &l)).unwrap();
    assert_eq!(swept.timed_out, Vec::<ReplayKey>::new());
    // Past it: FAILED, charge 0, counters back, single uses kept.
    let swept = block_on(sweep(&store, T0 + l.pending_timeout + 1, &l)).unwrap();
    assert_eq!(swept.timed_out, vec![*p.replay_key()]);
    let rec = block_on(store.outcome(p.replay_key())).unwrap().unwrap();
    assert_eq!(rec.status, OutcomeStatus::Failed);
    assert_eq!(rec.charged, Some(0));
    assert!(rec.timed_out && rec.needs_refund());
    assert_eq!(block_on(store.counter(&key)).unwrap(), 0);

    // The action finished late: its settle is refused, no double payout.
    let late = Settlement {
        status: Status::Ok,
        charged: 21,
        metered_units: None,
        scheme_result: Some(b"change".to_vec()),
        response: None,
        settled_at: T0 + 400,
    };
    assert!(matches!(
        block_on(settle(&store, &p, &late, &l)),
        Err(SettleError::AlreadySettled(_))
    ));

    // The client replays to collect its refund, which is recorded once. No
    // receipt is made before it is.
    let again = replay(r.at(T0 + 400).process_in(&store, &l));
    assert!(again.needs_refund());
    assert!(again.refund_cap().is_some());
    assert_eq!(again.receipt(&receipt_input(Digest([4; 32]))), None);
    let rec = block_on(record_refund(&store, &again, Some(b"refund 1"))).unwrap();
    assert!(rec.replayed());
    assert_eq!(
        rec.record().scheme_result.as_deref(),
        Some(&b"refund 1"[..])
    );
    let rec = block_on(record_refund(&store, &again, Some(b"refund 2"))).unwrap();
    assert_eq!(
        rec.record().scheme_result.as_deref(),
        Some(&b"refund 1"[..]),
        "the first recorded refund wins"
    );
    let again = replay(r.at(T0 + 401).process_in(&store, &l));
    assert!(!again.needs_refund());
    assert_eq!(again.refund_cap(), None);
    let f = again.receipt(&receipt_input(Digest([4; 32]))).unwrap();
    assert_eq!(f.metered_units, Some(0));
    assert_eq!(f.settled_at, T0 + l.pending_timeout + 1);
}

#[test]
fn a_replay_past_the_timeout_times_out_at_once() {
    let store = MemoryStore::new();
    let l = limits();
    let r = Req::note(1, b"Y", T0);
    new(r.process(&store));
    let again = replay(r.at(T0 + l.pending_timeout + 5).process(&store));
    assert!(again.needs_refund());
    assert_eq!(again.record().settled_at, Some(T0 + l.pending_timeout + 5));
}

#[test]
fn replay_window_expiry() {
    let store = MemoryStore::new();
    let l = limits();
    let r = Req::note(1, b"Y", T0);
    let p = new(r.process(&store));
    settle_ok(&store, &p, 21, T0 + 1);
    // Last second inside the window: a replay.
    replay(r.at(T0 + l.replay_window - 1).process(&store));
    // At the window's end the record no longer answers: SPENT.
    assert_eq!(
        r.at(T0 + l.replay_window).process(&store),
        Err(ProcessError::Spent)
    );
    // The sweep deletes the record but keeps the single use.
    let swept = block_on(sweep(&store, T0 + l.replay_window + 1, &l)).unwrap();
    assert_eq!(swept.purged, 1);
    store.inspect(|t| {
        assert_eq!(t.outcomes_len(), 0);
        assert_eq!(t.used_len(), 1);
    });
    // A later replay of the long-expired offer: the record is gone, so it
    // is a new credential on an expired offer, refused before any commit.
    // The note stays spent either way.
    assert_eq!(
        r.at(T0 + l.replay_window + 2).process(&store),
        Err(ProcessError::Stale(Stale::Expired))
    );
    let mut fresh = r.at(T0 + l.replay_window + 2);
    fresh.offer.expires = T0 + l.replay_window + 300;
    fresh.ctx = ctx(9);
    assert_eq!(fresh.process(&store), Err(ProcessError::Spent));
}

#[test]
fn the_sweep_never_purges_pending() {
    let store = MemoryStore::new();
    let l = Limits {
        pending_timeout: 200_000,
        ..Limits::default()
    };
    let r = Req::note(1, b"Y", T0);
    let p = new(r.process_in(&store, &l));
    let swept = block_on(sweep(&store, T0 + l.replay_window + 10, &l)).unwrap();
    assert_eq!(swept.purged, 0);
    assert!(block_on(store.outcome(p.replay_key())).unwrap().is_some());
}

#[test]
fn credentials_without_single_ids_must_not_outlive_their_record() {
    let l = limits();
    let bot = |expires: u64| {
        let mut r = Req::note(1, b"", T0).with_uses(vec![(
            "httpsig:web-bot-auth",
            UseModel::Reusable,
            vec![b"bot key".to_vec()],
        )]);
        r.pay_body = Vec::new();
        r.offer.expires = expires;
        r
    };
    // expires + 60 <= now + replay_window is admitted.
    new(bot(T0 + l.replay_window - 60).process(&MemoryStore::new()));
    let err = bot(T0 + l.replay_window - 59)
        .process(&MemoryStore::new())
        .unwrap_err();
    assert_eq!(err, ProcessError::Plan(PlanError::OutlivesRecord));
    assert_eq!(err.code(), ErrorCode::Policy);
    // A rail ID is a single use, so the rule does not apply.
    let with_rail = Req {
        rails: vec![RailId([5; 32])],
        ..bot(T0 + 10 * l.replay_window)
    };
    new(with_rail.process(&MemoryStore::new()));
}

#[test]
fn reusable_ids_enter_the_replay_key_but_are_not_consumed() {
    let store = MemoryStore::new();
    let bot = |c: u8| {
        Req::note(c, b"", T0).with_uses(vec![(
            "httpsig:web-bot-auth",
            UseModel::Reusable,
            vec![b"bot key".to_vec()],
        )])
    };
    let a = bot(1);
    let id = ids::use_id("httpsig:web-bot-auth", b"bot key");
    assert_eq!(
        a.rk(),
        ids::replay_key(&ctx(1), b"notes body", &[], &[id.0]),
        "the ReplayKey covers the reusable ID"
    );
    // Two requests with the same reusable attestation both run, and nothing
    // is consumed.
    assert_eq!(*new(a.process(&store)).replay_key(), a.rk());
    new(bot(2).process(&store));
    store.inspect(|t| assert_eq!(t.used_len(), 0));
}

#[test]
fn duplicate_ids_in_one_credential_commit_once() {
    let store = MemoryStore::new();
    let r = Req::note(1, b"", T0).with_uses(vec![(
        "bnap:notes",
        UseModel::Single,
        vec![b"Y".to_vec(), b"Y".to_vec()],
    )]);
    let p = new(r.process(&store));
    store.inspect(|t| assert_eq!(t.used_len(), 1));
    let y = ids::use_id("bnap:notes", b"Y").0;
    assert_eq!(
        *p.replay_key(),
        ids::replay_key(&ctx(1), b"notes body", &[], &[y, y]),
        "the ReplayKey keeps both (ERRATA N3a-9)"
    );
}

#[test]
fn an_unreachable_store_fails_closed() {
    let store = MemoryStore::new();
    store.set_unavailable(true);
    let err = Req::note(1, b"Y", T0).process(&store).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    store.set_unavailable(false);
    new(Req::note(1, b"Y", T0).process(&store));
}

#[test]
fn settle_of_an_unknown_outcome_is_refused() {
    // A Pending from one store settled in another: no record there.
    let p = new(Req::note(1, b"Y", T0).process(&MemoryStore::new()));
    assert_eq!(
        block_on(settle(
            &MemoryStore::new(),
            &p,
            &settlement(Status::Ok, 0, T0),
            &limits()
        )),
        Err(SettleError::Unknown)
    );
}

#[test]
fn a_replay_on_a_new_connection_shares_the_replay_key() {
    // Draft-00 5.3: binding is in the Digest, not the Context.
    let mut cred = Credential::new(OfferRef::Id(OfferId([3; 32])));
    cred.pay = Some(SchemePart::new("bnap:notes", b"body".to_vec()));
    cred.binding = Some(sha256(b"connection 1"));
    let scope = Scope([4; 32]);
    let c1 = cred.context(&OfferId([3; 32]), &scope);
    let d1 = cred.digest(&c1);
    let mut retry = cred.clone();
    retry.binding = Some(sha256(b"connection 2"));
    let c2 = retry.context(&OfferId([3; 32]), &scope);
    assert_eq!(c1, c2);
    let d2 = retry.digest(&c2);
    assert_ne!(d1, d2);

    let store = MemoryStore::new();
    let first = Req {
        ctx: c1,
        ..Req::note(1, b"Y", T0)
    };
    let p = new(first.process(&store));
    settle_ok(&store, &p, 21, T0 + 1);
    let second = Req {
        ctx: c2,
        ..first.at(T0 + 2)
    };
    let r = replay(second.process(&store));
    assert_eq!(r.replay_key(), p.replay_key());
    assert_eq!(r.receipt(&receipt_input(d2)).unwrap().digest, d2);
}

#[test]
fn use_ids_are_prefixed_by_the_scheme() {
    // The same local ID under two schemes gives two UseIds (6.1).
    let a: UseId = ids::use_id("bnap:notes", b"x");
    let b: UseId = ids::use_id("httpauth:L402", b"x");
    assert_ne!(a, b);
}

#[test]
fn an_unreachable_store_never_admits_a_replay_or_a_new_credential() {
    // The lookup comes first, so an outage fails closed before pricing.
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y", T0);
    let p = new(r.process(&store));
    settle_ok(&store, &p, 0, T0 + 1);
    store.set_unavailable(true);
    for at in [T0 + 2, T0 + 400] {
        assert_eq!(
            r.at(at).process(&store).unwrap_err().code(),
            ErrorCode::Unavailable
        );
    }
}

// ------------------------------------------------------- quota and replay

/// An offer of 21 sat for `bnap:notes`, with an `httpauth:DPoP` quota of `limit` per
/// hour.
fn quota_offer(limit: u64) -> OfferFields {
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    o.attest
        .push(AttestEntry::quota("httpauth:DPoP", limit, 3600));
    o
}

/// A request under the quota offer: the `httpauth:DPoP` attestation (class A, quota
/// identity "jwk thumbprint"), and, with `notes`, a pay part backed by a
/// signer-verified note worth `notes` sat.
fn quota_req(c: u8, limit: u64, notes: Option<u64>, now: u64) -> Req {
    let client = ids::use_id("httpauth:DPoP", b"jwk thumbprint");
    let mut uses = vec![(
        "httpauth:DPoP",
        UseModel::Reusable,
        vec![b"jwk thumbprint".to_vec()],
    )];
    let y = [c; 33];
    if notes.is_some() {
        uses.push(("bnap:notes", UseModel::Single, vec![y.to_vec()]));
    }
    Req {
        offer: quota_offer(limit),
        ctx: ctx(c),
        pay_body: if notes.is_some() {
            b"notes".to_vec()
        } else {
            Vec::new()
        },
        attest_bodies: vec![b"dpop proof".to_vec()],
        uses,
        rails: Vec::new(),
        pay: notes.map(|amount| PayValue {
            scheme: "bnap:notes",
            claimed: amount,
            backing: vec![Backing {
                source: BackingSource::Note(y.to_vec()),
                amount,
                unit: "sat".into(),
            }],
            refund: Refund::Atomic,
        }),
        attest: vec![VerifiedAttest::new("httpauth:DPoP", BindingClass::A).with_quota_id(client)],
        now,
    }
}

#[test]
fn a_quota_priced_attestation_replays_after_its_commit_filled_the_quota() {
    // The checker's probe (a), MEDIUM: an attestation-only credential under
    // a quota of 1 per hour on a 21 sat entry, settled OK. Its own commit
    // filled the quota, so pricing the replay now finds no room and would
    // ask 2^64 - 1 of a credential without pay. Before the re-cut the replay
    // got Price(Underpaid { price: u64::MAX, value: 0 }); the lookup now
    // comes before pricing and it is a replay (6.4).
    let store = MemoryStore::new();
    let r = quota_req(1, 1, None, T0);
    let p = new(r.process(&store));
    assert_eq!(p.admission().price(), 0);
    let charge = p.charge(Status::Ok, 0);
    assert_eq!((charge.charged, charge.cap.get()), (0, 0));
    let s = Settlement::new(&charge, T0 + 1).with_response(Some(b"the answer".to_vec()));
    block_on(settle(&store, &p, &s, &limits())).unwrap();
    // Another client of the same identity is refused: the quota is full.
    let other = Req {
        ctx: ctx(2),
        ..r.at(T0 + 5)
    };
    assert_eq!(
        other.process(&store),
        Err(ProcessError::Price(PriceError::Underpaid {
            price: u64::MAX,
            value: 0
        }))
    );
    // The replay is answered from the record.
    let again = replay(r.at(T0 + 10).process(&store));
    assert_eq!(again.record().response.as_deref(), Some(&b"the answer"[..]));
    let f = again.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Ok, 0, true));
}

#[test]
fn a_quota_priced_payment_replays_its_recorded_change() {
    // The checker's probe (b), MEDIUM: notes worth 10 sat on a 21 sat entry,
    // priced 0 by the quota, settled OK with the 10 sat of atomic change in
    // scheme_result; the response was lost. Before the re-cut the replay
    // got Price(Underpaid { price: 21, value: 10 }) and the change was
    // unreachable; now it is a replay with the recorded scheme_result.
    let store = MemoryStore::new();
    let r = quota_req(1, 1, Some(10), T0);
    let p = new(r.process(&store));
    let charge = p.charge(Status::Ok, 0);
    assert_eq!((charge.charged, charge.cap.get()), (0, 10));
    let s = Settlement::new(&charge, T0 + 1).with_scheme_result(Some(b"change 10".to_vec()));
    block_on(settle(&store, &p, &s, &limits())).unwrap();
    let again = replay(r.at(T0 + 10).process(&store));
    let f = again.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert!(f.replayed);
    assert_eq!(f.scheme_result.as_deref(), Some(&b"change 10"[..]));
}

#[test]
fn a_quota_priced_payment_collects_its_refund_after_a_crash() {
    // The checker's probe (c), MEDIUM: the same credential, but the gate
    // crashed after the commit. The replay past pending_timeout must time
    // the outcome out and collect the 10 sat refund. Before the re-cut it
    // got Price(Underpaid { price: 21, value: 10 }) until a sweep gave the
    // counter back. The refund cap is the one the commit recorded.
    let store = MemoryStore::new();
    let l = limits();
    let r = quota_req(1, 1, Some(10), T0);
    new(r.process(&store));
    let late = replay(r.at(T0 + l.pending_timeout + 1).process(&store));
    assert!(late.needs_refund());
    let cap = late.refund_cap().unwrap();
    assert_eq!(
        (cap.get(), cap.unit(), cap.status()),
        (10, "sat", Status::Failed)
    );
    assert_eq!(late.receipt(&receipt_input(Digest([1; 32]))), None);
    let rec = block_on(record_refund(&store, &late, Some(b"refund 10"))).unwrap();
    let f = rec.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!((f.status, f.charged, f.replayed), (Status::Failed, 0, true));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"refund 10"[..]));
    // The timeout gave the quota back, so the identity has room again.
    new(quota_req(2, 1, Some(10), T0 + l.pending_timeout + 2).process(&store));
}

#[test]
fn a_stale_quota_read_never_admits_past_the_limit() {
    // Security review, outcome lead (a), and draft-00 7: a quota that had
    // room at pricing but is full at commit aborts with RATE_LIMITED and
    // consumes nothing. Every pricing read here is stale (it sees room), so
    // only the commit's atomic re-check holds the limit.
    let store = StaleReads(MemoryStore::new());
    let answers: Vec<_> = (1..=5u8)
        .map(|c| quota_req(c, 1, None, T0).process_in(&store, &limits()))
        .collect();
    assert!(matches!(answers[0], Ok(Admitted::New(_))));
    for a in &answers[1..] {
        assert!(matches!(a, Err(ProcessError::RateLimited { .. })), "{a:?}");
    }
    // With pay: the second note is not consumed by the aborted commit.
    let store = StaleReads(MemoryStore::new());
    new(quota_req(1, 1, Some(10), T0).process_in(&store, &limits()));
    let err = quota_req(2, 1, Some(10), T0)
        .process_in(&store, &limits())
        .unwrap_err();
    assert!(matches!(err, ProcessError::RateLimited { .. }));
    let n2 = crate::pricing::note_id(&[2; 33]);
    store.0.inspect(|t| {
        assert!(t.used_by(&n2).is_none());
        assert_eq!(t.outcomes_len(), 1);
    });
    // Pricing that sees the full quota charges the full price.
    let real = &store.0;
    assert_eq!(
        quota_req(3, 1, Some(10), T0).process(real),
        Err(ProcessError::Price(PriceError::Underpaid {
            price: 21,
            value: 10
        }))
    );
}

#[test]
fn concurrent_quota_admissions_never_exceed_the_limit() {
    // Security review, outcome lead (a), concurrently: 16 credentials of one
    // identity under a quota of 3, started together, all priced on stale
    // reads. Exactly 3 run.
    const N: u8 = 16;
    let store = StaleReads(MemoryStore::new());
    let barrier = Barrier::new(usize::from(N));
    let answers: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|c| {
                let (store, barrier) = (&store, &barrier);
                s.spawn(move || {
                    let r = quota_req(c, 3, None, T0);
                    barrier.wait();
                    r.process_in(store, &limits())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let new = answers
        .iter()
        .filter(|a| matches!(a, Ok(Admitted::New(_))))
        .count();
    let limited = answers
        .iter()
        .filter(|a| matches!(a, Err(ProcessError::RateLimited { .. })))
        .count();
    assert_eq!((new, limited), (3, usize::from(N) - 3));
    store.0.inspect(|t| assert_eq!(t.outcomes_len(), 3));
}

#[test]
fn concurrent_replays_after_a_crash_refund_once() {
    // Security review, outcome lead (b): a crash leaves a quota-priced
    // payment PENDING; 12 replays arrive together past pending_timeout.
    // None runs the action again, the outcome times out once, and every
    // answer carries the one refund recorded first, whatever each replay's
    // own refund computation returned.
    const N: usize = 12;
    let store = MemoryStore::new();
    let l = limits();
    let r = quota_req(1, 1, Some(10), T0);
    new(r.process(&store));
    let late = r.at(T0 + l.pending_timeout + 1);
    let barrier = Barrier::new(N);
    let answers: Vec<Recorded> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (store, barrier, late) = (&store, &barrier, &late);
                s.spawn(move || {
                    barrier.wait();
                    let got = replay(late.process(store));
                    if got.needs_refund() {
                        assert_eq!(got.refund_cap().unwrap().get(), 10);
                        let own = format!("refund by {i}").into_bytes();
                        block_on(record_refund(store, &got, Some(&own))).unwrap()
                    } else {
                        got
                    }
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let first = answers[0].record().clone();
    assert!(first.refund_recorded && first.timed_out);
    for a in &answers {
        assert_eq!(a.record(), &first, "one refund, the first recorded");
        assert!(a.receipt(&receipt_input(Digest([1; 32]))).is_some());
    }
    store.inspect(|t| assert_eq!(t.outcomes_len(), 1));
}

#[test]
fn settle_and_the_timeout_race_to_one_transition() {
    // Security review, outcome lead (d): the action's settle and the
    // timeout reach one PENDING outcome together. Exactly one wins, the
    // status changes once, and the outcome's counter is given back at most
    // once: another credential of the same client holds the same counter,
    // so a double give-back would show.
    for round in 0..20u8 {
        let store = MemoryStore::new();
        let l = limits();
        let other = rate_req(200, b"client", 5, T0);
        let mine = rate_req(round, b"client", 5, T0);
        let mut both = [other, mine];
        for r in &mut both {
            r.offer.expires = T0 + 300;
            r.uses
                .push(("bnap:notes", UseModel::Single, vec![vec![r.ctx.0[0]]]));
        }
        // The other credential settled OK long ago; it keeps its count.
        let o = new(both[0].process(&store));
        settle_ok(&store, &o, 21, T0 + 1);
        let p = new(both[1].process(&store));
        let key = rate_counter(b"client", 5, 60, T0);
        assert_eq!(block_on(store.counter(&key)).unwrap(), 2);
        let barrier = Barrier::new(8);
        let settled: Vec<bool> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let (store, barrier, p, l) = (&store, &barrier, &p, &l);
                    s.spawn(move || {
                        barrier.wait();
                        if i % 2 == 0 {
                            let s = settlement(Status::Ok, 21, T0 + 5);
                            block_on(settle(store, p, &s, l)).is_ok()
                        } else {
                            block_on(sweep(store, T0 + l.pending_timeout + 1, l)).unwrap();
                            false
                        }
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let wins = settled.iter().filter(|w| **w).count();
        let rec = block_on(store.outcome(p.replay_key())).unwrap().unwrap();
        let counter = block_on(store.counter(&key)).unwrap();
        match wins {
            1 => assert_eq!(
                (rec.status, rec.timed_out, counter),
                (OutcomeStatus::Ok, false, 2)
            ),
            0 => assert_eq!(
                (rec.status, rec.timed_out, counter),
                (OutcomeStatus::Failed, true, 1)
            ),
            n => panic!("{n} settles won"),
        }
    }
}

#[test]
fn a_record_is_kept_while_its_offer_can_be_presented() {
    // Security review, store lead (a) and outcome lead (c): a credential
    // without single uses (a reusable attestation) on an offer that lives a
    // day. The operator lowers replay_window and the sweep runs with the
    // new limits while the gate still checks with the old ones. Before the
    // fix the sweep deleted the record and the same credential was admitted
    // again as New. The record now carries keep_until = expires + 60 and the
    // store never purges it before then; once the offer is stale, a fresh
    // commit is refused as STALE.
    let long = limits();
    let short = Limits {
        replay_window: 420,
        ..long
    };
    let store = MemoryStore::new();
    let mut r = Req::note(1, b"", T0).with_uses(vec![(
        "httpsig:web-bot-auth",
        UseModel::Reusable,
        vec![b"bot key".to_vec()],
    )]);
    r.offer.expires = T0 + long.replay_window - 60;
    let p = new(r.process_in(&store, &long));
    block_on(settle(
        &store,
        &p,
        &settlement(Status::Ok, 0, T0 + 1),
        &long,
    ))
    .unwrap();
    let swept = block_on(sweep(&store, T0 + 1_000, &short)).unwrap();
    assert_eq!(swept.purged, 0, "the offer is still valid");
    // The gate on the old limits replays it; on the new ones it is SPENT.
    // Never New.
    replay(r.at(T0 + 1_000).process_in(&store, &long));
    assert_eq!(
        r.at(T0 + 1_000).process_in(&store, &short),
        Err(ProcessError::Spent)
    );
    // Past keep_until the record goes, and the offer is stale.
    let after = r.offer.expires + 61;
    assert_eq!(block_on(sweep(&store, after, &short)).unwrap().purged, 1);
    assert_eq!(
        r.at(after).process_in(&store, &long),
        Err(ProcessError::Stale(Stale::Expired))
    );
    store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
}

#[test]
fn a_new_credential_on_an_expired_offer_is_stale_but_a_known_one_is_answered() {
    // A fresh commit needs a valid offer and quote; a replay is answered
    // from its outcome even after the offer expired (the core side of
    // ERRATA N3b-22).
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y", T0);
    let p = new(r.process(&store));
    settle_ok(&store, &p, 0, T0 + 1);
    let past = T0 + 300 + 61;
    replay(r.at(past).process(&store));
    let stranger = Req::note(2, b"Y2", past);
    assert_eq!(
        stranger.process(&store),
        Err(ProcessError::Stale(Stale::Expired))
    );
    assert_eq!(ProcessError::Stale(Stale::Expired).code(), ErrorCode::Stale);
    // The chosen entry's quote expired, the offer not yet.
    let mut quote = Req::note(3, b"Y3", T0 + 200);
    quote.offer.pay[0].quote_expires = Some(T0 + 100);
    assert_eq!(
        quote.process(&store),
        Err(ProcessError::Stale(Stale::QuoteExpired))
    );
    store.inspect(|t| assert_eq!(t.outcomes_len(), 1, "no commit for either"));
}

#[test]
fn every_payment_and_note_counted_as_value_is_consumed() {
    // A scheme that counts notes and a payment as value but names none of
    // them as use IDs: the commit consumes them anyway.
    let store = MemoryStore::new();
    let with = |c: u8, backing: Vec<Backing>| {
        let mut r = Req::note(c, b"", T0).with_uses(Vec::new());
        r.offer.pay[0].amount = 50;
        r.pay = Some(PayValue {
            scheme: "bnap:notes",
            claimed: 1_000,
            backing,
            refund: Refund::Atomic,
        });
        r
    };
    let note = |y: &[u8], amount| Backing {
        source: BackingSource::Note(y.to_vec()),
        amount,
        unit: "sat".into(),
    };
    let rail_pay = Backing {
        source: BackingSource::Rail(RailId([4; 32])),
        amount: 10,
        unit: "sat".into(),
    };
    let first = with(1, vec![note(b"Y1", 64), rail_pay.clone()]);
    assert_eq!(
        first.rk(),
        ids::replay_key(&ctx(1), b"notes body", &[], &[]),
        "the ReplayKey keeps what 6.1 names"
    );
    let p = new(first.process(&store));
    store.inspect(|t| {
        assert_eq!(t.used_len(), 2);
        assert_eq!(t.used_by(&crate::pricing::note_id(b"Y1")), Some(first.rk()));
        assert_eq!(t.used_by(&[4; 32]), Some(first.rk()));
    });
    assert_eq!(p.charge(Status::Ok, 0).cap.get(), 24);
    // The same note, or the same payment, counted again: SPENT.
    assert_eq!(
        with(2, vec![note(b"Y1", 64)]).process(&store),
        Err(ProcessError::Spent)
    );
    assert_eq!(
        with(3, vec![note(b"Y2", 64), rail_pay]).process(&store),
        Err(ProcessError::Spent)
    );
}

#[test]
fn one_signer_verified_note_is_spent_once_across_value_schemes() {
    // An offer lists bnap:notes and a Cashu adapter at 50 sat each, and both
    // check notes through the gate's one signer. One note worth 64 sat is
    // admitted under one scheme, then presented under the other. Each
    // scheme names the note in its own UseId space, so only the scheme-free
    // note ID can catch it (ERRATA N3b-19). Either order.
    let y = [7u8; 33];
    let attempt = |store: &MemoryStore, scheme: &'static str, c: u8| {
        let mut r =
            Req::note(c, b"", T0).with_uses(vec![(scheme, UseModel::Single, vec![y.to_vec()])]);
        r.offer.pay = vec![
            PayEntry::new("bnap:notes", 50, "sat"),
            PayEntry::new("cashu:nut24", 50, "sat"),
        ];
        r.pay_body = b"one note".to_vec();
        r.pay = Some(PayValue {
            scheme,
            claimed: 64,
            backing: vec![Backing {
                source: BackingSource::Note(y.to_vec()),
                amount: 64,
                unit: "sat".into(),
            }],
            refund: Refund::Atomic,
        });
        r.process(store)
    };
    for (first, second) in [("bnap:notes", "cashu:nut24"), ("cashu:nut24", "bnap:notes")] {
        let store = MemoryStore::new();
        new(attempt(&store, first, 1));
        // The scheme's own UseId stays a single, next to the note ID.
        store.inspect(|t| {
            assert!(t.used_by(&ids::use_id(first, &y).0).is_some());
            assert!(t.used_by(&crate::pricing::note_id(&y)).is_some());
        });
        assert_eq!(attempt(&store, second, 2), Err(ProcessError::Spent));
        store.inspect(|t| assert_eq!(t.outcomes_len(), 1, "one note, one action"));
    }
}

#[test]
fn a_refund_with_nothing_to_return_is_recorded_too() {
    // A scheme whose FAILED settle returns no scheme_result (nothing to
    // refund): the refund is still recorded once, and the receipt follows.
    let store = MemoryStore::new();
    let l = limits();
    let r = Req::note(1, b"Y", T0);
    new(r.process(&store));
    let late = replay(r.at(T0 + l.pending_timeout + 5).process(&store));
    assert!(late.needs_refund());
    assert_eq!(late.refund_cap().unwrap().get(), 0, "nothing was paid");
    assert_eq!(late.receipt(&receipt_input(Digest([1; 32]))), None);
    let rec = block_on(record_refund(&store, &late, None)).unwrap();
    assert!(rec.record().refund_recorded && !rec.needs_refund());
    let f = rec.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!(
        (f.status, f.charged, f.scheme_result),
        (Status::Failed, 0, None)
    );
    // A later refund cannot overwrite it.
    let rec = block_on(record_refund(&store, &late, Some(b"more"))).unwrap();
    assert_eq!(rec.record().scheme_result, None);
}

#[test]
fn a_late_settle_answers_from_the_recorded_failed_outcome() {
    // The action outlived pending_timeout: the sweep made it FAILED, and its
    // settle is refused with the record, which still needs its refund.
    let store = MemoryStore::new();
    let l = limits();
    let r = Req::note(1, b"Y", T0);
    let p = new(r.process(&store));
    block_on(sweep(&store, T0 + l.pending_timeout + 1, &l)).unwrap();
    let ok = Settlement {
        status: Status::Ok,
        charged: 21,
        metered_units: None,
        scheme_result: Some(b"change for OK".to_vec()),
        response: None,
        settled_at: T0 + 400,
    };
    let Err(SettleError::AlreadySettled(rec)) = block_on(settle(&store, &p, &ok, &l)) else {
        panic!("expected AlreadySettled");
    };
    assert!(rec.needs_refund() && !rec.replayed());
    assert_eq!(rec.receipt(&receipt_input(Digest([1; 32]))), None);
    let rec = block_on(record_refund(&store, &rec, Some(b"refund"))).unwrap();
    let f = rec.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"refund"[..]));
    assert!(!f.replayed);
}

#[test]
fn a_settle_after_the_pending_timeout_times_the_outcome_out() {
    // The checker's probe, LOW: commit at T0, no sweep and no replay, then
    // the action settles OK at T0 + pending_timeout + 100. A replay at that
    // moment would have timed the outcome out, so the settle must as well:
    // the answer cannot depend on when the sweep runs (6.4).
    let store = MemoryStore::new();
    let l = limits();
    let mut r = rate_req(1, b"client", 5, T0);
    r.uses
        .push(("bnap:notes", UseModel::Single, vec![b"n".to_vec()]));
    let p = new(r.process(&store));
    let key = rate_counter(b"client", 5, 60, T0);
    let late = Settlement {
        status: Status::Ok,
        charged: 21,
        metered_units: None,
        scheme_result: Some(b"change for OK".to_vec()),
        response: None,
        settled_at: T0 + l.pending_timeout + 100,
    };
    let Err(SettleError::AlreadySettled(rec)) = block_on(settle(&store, &p, &late, &l)) else {
        panic!("a settle past pending_timeout must lose to the timeout");
    };
    let rec = rec.record();
    assert_eq!(rec.status, OutcomeStatus::Failed);
    assert!(rec.timed_out && rec.needs_refund());
    assert_eq!(rec.charged, Some(0));
    assert_eq!(rec.scheme_result, None, "the OK result is discarded");
    assert_eq!(rec.settled_at, Some(T0 + l.pending_timeout + 100));
    assert_eq!(
        block_on(store.counter(&key)).unwrap(),
        0,
        "counter given back"
    );
    assert_eq!(
        block_on(store.outcome(p.replay_key())).unwrap().as_ref(),
        Some(rec)
    );

    // At the deadline itself the settle still wins.
    let store = MemoryStore::new();
    let p = new(r.process(&store));
    let on_time = Settlement {
        settled_at: T0 + l.pending_timeout,
        ..late
    };
    let rec = block_on(settle(&store, &p, &on_time, &l)).unwrap();
    assert_eq!(rec.record().status, OutcomeStatus::Ok);
}

// ---------------------------------------------------------------- limits

#[test]
fn limits_refuse_a_replay_window_that_loses_the_refund() {
    use crate::limits::{LimitsError, REFUND_MARGIN};
    use crate::manifest::ManifestLimits;
    let m = |rw: Option<u64>, pt: Option<u64>| ManifestLimits {
        replay_window: rw,
        pending_timeout: pt,
        ..ManifestLimits::default()
    };
    assert_eq!(REFUND_MARGIN, 120);
    // The defaults, and the minimum: pending_timeout + 120.
    assert_eq!(Limits::from_manifest(&m(None, None)), Ok(Limits::default()));
    let min = Limits::from_manifest(&m(Some(420), Some(300))).unwrap();
    assert_eq!(min.record_window(), 420);
    // Shorter windows are refused, the review's probe (window <= timeout)
    // among them, and so is a short window under the default timeout.
    for (rw, pt) in [
        (Some(419), Some(300)),
        (Some(300), Some(300)),
        (Some(100), Some(300)),
        (Some(100), None),
        (None, Some(86_400)),
    ] {
        let e = Limits::from_manifest(&m(rw, pt)).unwrap_err();
        assert!(
            matches!(
                e,
                LimitsError::ReplayWindowTooShort {
                    offer_lifetime: 0,
                    ..
                }
            ),
            "{rw:?} {pt:?}: {e}"
        );
    }
    // The offer lifetime check: every replay an offer allows finds its
    // record, past the timeout included.
    let d = Limits::default();
    assert_eq!(d.check_offer_lifetime(3_600), Ok(()));
    assert_eq!(d.check_offer_lifetime(86_400 - 420), Ok(()));
    assert_eq!(
        d.check_offer_lifetime(86_400 - 419),
        Err(LimitsError::ReplayWindowTooShort {
            replay_window: 86_400,
            pending_timeout: 300,
            offer_lifetime: 85_981,
            min: 86_401,
        })
    );
    assert!(d.check_offer_lifetime(u64::MAX).is_err(), "saturates");
}

#[test]
fn a_timed_out_refund_stays_collectable_under_the_minimum_window() {
    // A crash leaves the outcome PENDING. Under the shortest window the
    // limits allow (pending_timeout 300, replay_window 420), every replay
    // from the timeout to the window's end collects the refund, and the
    // sweep keeps the record until then (6.4: the crash costs the
    // operator, never the client).
    let l = Limits::from_manifest(&crate::manifest::ManifestLimits {
        replay_window: Some(420),
        pending_timeout: Some(300),
        ..Default::default()
    })
    .unwrap();
    for at in [T0 + 301, T0 + 419] {
        let store = MemoryStore::new();
        let r = Req::note(1, b"Y", T0);
        new(r.process_in(&store, &l));
        // The gate crashed. The sweep runs, then the client replays.
        let swept = block_on(sweep(&store, at, &l)).unwrap();
        assert_eq!((swept.timed_out.len(), swept.purged), (1, 0));
        let late = replay(r.at(at).process_in(&store, &l));
        assert!(late.needs_refund());
        let rec = block_on(record_refund(&store, &late, Some(b"refund"))).unwrap();
        let f = rec.receipt(&receipt_input(Digest([1; 32]))).unwrap();
        assert_eq!((f.status, f.charged), (Status::Failed, 0));
        assert_eq!(f.scheme_result.as_deref(), Some(&b"refund"[..]));
    }
    // At the window's end the record no longer answers, as for any outcome.
    let store = MemoryStore::new();
    let r = Req::note(1, b"Y", T0);
    new(r.process_in(&store, &l));
    assert_eq!(
        r.at(T0 + 420).process_in(&store, &l),
        Err(ProcessError::Spent)
    );
}

#[test]
fn hand_built_limits_never_lose_a_timed_out_refund() {
    // Limits built by hand, not from a manifest: replay_window 300 =
    // pending_timeout 300. The record window has a floor of
    // pending_timeout + 120, so the refund is collected.
    let l = Limits {
        replay_window: 300,
        pending_timeout: 300,
        ..Limits::default()
    };
    assert!(l.validate().is_err());
    assert_eq!(l.record_window(), 420);
    let store = MemoryStore::new();
    let mut r = Req::note(1, b"Y", T0);
    r.offer.expires = T0 + 200;
    new(r.process_in(&store, &l));
    let late = T0 + 301;
    assert_eq!(block_on(sweep(&store, late, &l)).unwrap().purged, 0);
    assert!(replay(r.at(late).process_in(&store, &l)).needs_refund());
}
