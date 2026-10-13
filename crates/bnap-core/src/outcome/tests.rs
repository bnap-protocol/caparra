//! State machine tests against the in-memory store.

use std::sync::Barrier;

use super::*;
use crate::class::BindingClass;
use crate::credential::{Credential, OfferRef, SchemePart};
use crate::hash::{Context, RailId, Scope, UseId, sha256};
use crate::ids::{self, rail};
use crate::offer::{AttestEntry, OfferFields, PayEntry};
use crate::pricing::{AdmitInput, Backing, BackingSource, PayValue, VerifiedAttest};
use crate::response::Status;
use crate::store::{PlanInput, SchemeUses, UseModel};
use crate::test_support::{MemoryStore, block_on};

const T0: u64 = 1_791_700_000;

fn limits() -> Limits {
    Limits::default()
}

fn ctx(n: u8) -> Context {
    Context([n; 32])
}

/// An admission at price 0 without a quota, for plans that test the store
/// alone.
fn no_quota() -> Admission {
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 0, "sat"));
    let input = AdmitInput {
        offer: &o,
        pay: Some(PayValue {
            scheme: "bnap:notes",
            claimed: 0,
            backing: Vec::new(),
        }),
        attest: &[],
        now: T0,
    };
    let a = pricing::admit(&input, |_| 0).unwrap();
    assert!(a.decision().quota.is_none());
    a
}

/// A plan for one credential: `ctx` tells credentials apart, `schemes`
/// carries their verified uses.
fn plan_at(
    ctx: &Context,
    pay_body: &[u8],
    schemes: &[SchemeUses<'_>],
    rails: &[RailId],
    now: u64,
) -> CommitPlan {
    CommitPlan::build(&PlanInput {
        context: ctx,
        pay_body,
        attest_bodies: &[],
        schemes,
        rail_ids: rails,
        admission: &no_quota(),
        offer_expires: now + 300,
        now,
        replay_window: limits().replay_window,
    })
    .unwrap()
}

fn note_plan(ctx: &Context, note: &[u8], now: u64) -> CommitPlan {
    let ids = [note.to_vec()];
    plan_at(
        ctx,
        b"notes body",
        &[SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &ids,
        }],
        &[],
        now,
    )
}

fn settle_ok(store: &MemoryStore, rk: &ReplayKey, charged: u64, at: u64) -> OutcomeRecord {
    let s = Settlement {
        status: Status::Ok,
        charged,
        metered_units: Some(850),
        scheme_result: Some(b"change signatures".to_vec()),
        response: Some(b"stored response".to_vec()),
        settled_at: at,
    };
    block_on(settle(store, rk, &s)).unwrap()
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

#[test]
fn commit_is_new_then_a_retry_is_pending() {
    let store = MemoryStore::new();
    let plan = note_plan(&ctx(1), b"Y1", T0);
    assert_eq!(
        block_on(commit(&store, &plan, &limits())),
        Ok(Admitted::New)
    );
    let rec = block_on(store.outcome(plan.replay_key())).unwrap().unwrap();
    assert_eq!(rec.status, OutcomeStatus::Pending);
    assert_eq!(rec.created, T0);

    let retry = note_plan(&ctx(1), b"Y1", T0 + 10);
    let err = block_on(commit(&store, &retry, &limits())).unwrap_err();
    assert_eq!(err, CommitError::Pending { retry_after: 290 });
    assert_eq!(err.code(), ErrorCode::Pending);
    assert_eq!(err.to_error_object().retry_after, Some(290));
}

#[test]
fn replay_returns_the_recorded_outcome_with_replayed() {
    let store = MemoryStore::new();
    let plan = note_plan(&ctx(1), b"Y1", T0);
    block_on(commit(&store, &plan, &limits())).unwrap();
    let fresh = settle_ok(&store, plan.replay_key(), 340, T0 + 5);
    let first = receipt(&fresh, &receipt_input(Digest([1; 32])), false).unwrap();
    assert!(!first.replayed);

    let again = note_plan(&ctx(1), b"Y1", T0 + 100);
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &again, &limits())) else {
        panic!("expected a replay");
    };
    assert!(!r.needs_refund());
    assert_eq!(
        r.record().response.as_deref(),
        Some(&b"stored response"[..])
    );
    let fields = r.receipt(&receipt_input(Digest([9; 32]))).unwrap();
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
        block_on(store.outcome(plan.replay_key())).unwrap().unwrap(),
        fresh
    );
}

#[test]
fn status_flip_on_replay_is_impossible() {
    let store = MemoryStore::new();
    let plan = note_plan(&ctx(1), b"Y1", T0);
    block_on(commit(&store, &plan, &limits())).unwrap();
    let ok = settle_ok(&store, plan.replay_key(), 340, T0 + 5);

    let flip = Settlement {
        status: Status::Failed,
        charged: 0,
        metered_units: None,
        scheme_result: Some(b"refund".to_vec()),
        response: None,
        settled_at: T0 + 6,
    };
    let err = block_on(settle(&store, plan.replay_key(), &flip)).unwrap_err();
    assert_eq!(err, SettleError::AlreadySettled(Box::new(ok.clone())));
    // A second OK settle with another charge is refused as well.
    let mut again = flip.clone();
    again.status = Status::Ok;
    again.charged = 1;
    assert!(matches!(
        block_on(settle(&store, plan.replay_key(), &again)),
        Err(SettleError::AlreadySettled(_))
    ));
    // The timeout never touches a settled outcome, and a timed-out refund
    // is never recorded on it.
    let swept = block_on(sweep(&store, T0 + 10_000, &limits())).unwrap();
    assert_eq!(swept.timed_out, Vec::<ReplayKey>::new());
    let after = block_on(record_refund(&store, plan.replay_key(), Some(b"x"))).unwrap();
    assert_eq!(after, ok);
    // A replay still reports OK.
    let replay = note_plan(&ctx(1), b"Y1", T0 + 20_000);
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &replay, &limits())) else {
        panic!("expected a replay");
    };
    assert_eq!(r.record(), &ok);
}

#[test]
fn concurrent_double_spend_has_exactly_one_winner() {
    const N: u8 = 16;
    let store = MemoryStore::new();
    let barrier = Barrier::new(usize::from(N));
    let results: Vec<Result<Admitted, CommitError>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (store, barrier) = (&store, &barrier);
                s.spawn(move || {
                    // N different credentials spending the same note.
                    let plan = note_plan(&ctx(i), b"the one note", T0);
                    barrier.wait();
                    block_on(commit(store, &plan, &limits()))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let wins = results.iter().filter(|r| **r == Ok(Admitted::New)).count();
    let spent = results
        .iter()
        .filter(|r| **r == Err(CommitError::Spent))
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
                    let plan = note_plan(&ctx(3), b"Y", T0);
                    barrier.wait();
                    block_on(commit(store, &plan, &limits()))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        results.iter().filter(|r| **r == Ok(Admitted::New)).count(),
        1
    );
    assert!(
        results
            .iter()
            .filter(|r| **r != Ok(Admitted::New))
            .all(|r| matches!(r, Err(CommitError::Pending { .. })))
    );
}

#[test]
fn same_use_ids_under_another_replay_key_are_spent() {
    let store = MemoryStore::new();
    let a = note_plan(&ctx(1), b"Y1", T0);
    block_on(commit(&store, &a, &limits())).unwrap();
    settle_ok(&store, a.replay_key(), 21, T0 + 1);
    // The same note in another credential (another Context, so another
    // ReplayKey): SPENT, never the other credential's outcome.
    let b = note_plan(&ctx(2), b"Y1", T0 + 2);
    assert_ne!(a.replay_key(), b.replay_key());
    assert_eq!(
        block_on(commit(&store, &b, &limits())),
        Err(CommitError::Spent)
    );
    // Same Context but a body changed on the path: another ReplayKey, SPENT.
    let ids = [b"Y1".to_vec()];
    let c = plan_at(
        &ctx(1),
        b"notes body, altered",
        &[SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &ids,
        }],
        &[],
        T0 + 3,
    );
    assert_eq!(
        block_on(commit(&store, &c, &limits())),
        Err(CommitError::Spent)
    );
}

#[test]
fn one_payment_through_two_schemes_is_a_conflict() {
    let store = MemoryStore::new();
    let hash = sha256(b"preimage");
    let payment = ids::rail_id(rail::LN, &rail::ln(&hash));
    let l402 = [hash.to_vec()];
    let first = plan_at(
        &ctx(1),
        b"l402 token",
        &[SchemeUses {
            scheme: "httpauth:L402",
            model: UseModel::Single,
            local_ids: &l402,
        }],
        &[payment],
        T0,
    );
    let mpp = [b"mpp challenge id".to_vec()];
    let second = plan_at(
        &ctx(2),
        b"mpp credential",
        &[SchemeUses {
            scheme: "payment:lightning/charge",
            model: UseModel::Single,
            local_ids: &mpp,
        }],
        &[payment],
        T0,
    );
    // The schemes' use IDs differ; only the RailId is shared.
    assert_ne!(
        ids::use_id("httpauth:L402", &hash),
        ids::use_id("payment:lightning/charge", b"mpp challenge id")
    );
    assert_eq!(
        block_on(commit(&store, &first, &limits())),
        Ok(Admitted::New)
    );
    assert_eq!(
        block_on(commit(&store, &second, &limits())),
        Err(CommitError::Spent)
    );
    // The failed commit consumed nothing: its own use ID is still free.
    let mpp_use = ids::use_id("payment:lightning/charge", b"mpp challenge id");
    store.inspect(|t| {
        assert!(t.used_by(&mpp_use.0).is_none());
        assert_eq!(t.used_by(&payment.0), Some(*first.replay_key()));
    });
}

#[test]
fn an_abort_consumes_nothing() {
    let store = MemoryStore::new();
    block_on(commit(&store, &note_plan(&ctx(1), b"B", T0), &limits())).unwrap();
    let ids = [b"A".to_vec(), b"B".to_vec()];
    let both = plan_at(
        &ctx(2),
        b"two notes",
        &[SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &ids,
        }],
        &[],
        T0,
    );
    assert_eq!(
        block_on(commit(&store, &both, &limits())),
        Err(CommitError::Spent)
    );
    // The client keeps note A.
    assert_eq!(
        block_on(commit(&store, &note_plan(&ctx(3), b"A", T0), &limits())),
        Ok(Admitted::New)
    );
}

fn rate_plan(ctx: &Context, key_id: &[u8], k: u64, now: u64) -> CommitPlan {
    let ids = [key_id.to_vec()];
    plan_at(
        ctx,
        b"arc presentation",
        &[SchemeUses {
            scheme: "vnd.cfrg.arc",
            model: UseModel::Rate { k, epoch: 60 },
            local_ids: &ids,
        }],
        &[],
        now,
    )
}

#[test]
fn rate_counters_limit_and_failed_gives_them_back() {
    let store = MemoryStore::new();
    let now = 120 * 60 + 15;
    let first = rate_plan(&ctx(1), b"client", 1, now);
    assert_eq!(first.singles().len(), 0);
    assert_eq!(first.counters().len(), 1);
    assert_eq!(
        block_on(commit(&store, &first, &limits())),
        Ok(Admitted::New)
    );
    let second = rate_plan(&ctx(2), b"client", 1, now);
    assert_eq!(
        block_on(commit(&store, &second, &limits())),
        Err(CommitError::RateLimited { retry_after: 45 })
    );
    // FAILED gives the counter back, so the second credential now fits.
    let failed = Settlement {
        status: Status::Failed,
        charged: 0,
        metered_units: None,
        scheme_result: None,
        response: None,
        settled_at: now + 1,
    };
    block_on(settle(&store, first.replay_key(), &failed)).unwrap();
    assert_eq!(
        block_on(commit(&store, &second, &limits())),
        Ok(Admitted::New)
    );
}

#[test]
fn failed_keeps_single_uses_spent() {
    let store = MemoryStore::new();
    let plan = note_plan(&ctx(1), b"Y1", T0);
    block_on(commit(&store, &plan, &limits())).unwrap();
    let failed = Settlement {
        status: Status::Failed,
        charged: 0,
        metered_units: None,
        scheme_result: Some(b"refund outputs".to_vec()),
        response: None,
        settled_at: T0 + 1,
    };
    let rec = block_on(settle(&store, plan.replay_key(), &failed)).unwrap();
    assert_eq!(rec.status, OutcomeStatus::Failed);
    assert_eq!(rec.charged, Some(0));
    let other = note_plan(&ctx(2), b"Y1", T0 + 2);
    assert_eq!(
        block_on(commit(&store, &other, &limits())),
        Err(CommitError::Spent)
    );
    // The same credential replays its FAILED outcome and its refund.
    let replay = note_plan(&ctx(1), b"Y1", T0 + 3);
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &replay, &limits())) else {
        panic!("expected a replay");
    };
    let f = r.receipt(&receipt_input(Digest([1; 32]))).unwrap();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"refund outputs"[..]));
}

#[test]
fn pending_timeout_moves_to_failed_and_the_replay_collects_the_refund() {
    let store = MemoryStore::new();
    let l = limits();
    let ids = [b"client".to_vec(), b"note".to_vec()];
    let plan = CommitPlan::build(&PlanInput {
        context: &ctx(1),
        pay_body: b"body",
        attest_bodies: &[],
        schemes: &[
            SchemeUses {
                scheme: "vnd.cfrg.arc",
                model: UseModel::Rate { k: 5, epoch: 3600 },
                local_ids: &ids[..1],
            },
            SchemeUses {
                scheme: "bnap:notes",
                model: UseModel::Single,
                local_ids: &ids[1..],
            },
        ],
        rail_ids: &[],
        admission: &no_quota(),
        offer_expires: T0 + 300,
        now: T0,
        replay_window: l.replay_window,
    })
    .unwrap();
    block_on(commit(&store, &plan, &l)).unwrap();
    let key = plan.counters()[0].key;
    assert_eq!(block_on(store.counter(&key)).unwrap(), 1);

    // Still inside pending_timeout: nothing happens.
    let swept = block_on(sweep(&store, T0 + l.pending_timeout, &l)).unwrap();
    assert_eq!(swept.timed_out, Vec::<ReplayKey>::new());
    // Past it: FAILED, charge 0, counters back, single uses kept.
    let swept = block_on(sweep(&store, T0 + l.pending_timeout + 1, &l)).unwrap();
    assert_eq!(swept.timed_out, vec![*plan.replay_key()]);
    let rec = block_on(store.outcome(plan.replay_key())).unwrap().unwrap();
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
        block_on(settle(&store, plan.replay_key(), &late)),
        Err(SettleError::AlreadySettled(_))
    ));

    // The client replays to collect its refund, which is recorded once. No
    // receipt is made before it is.
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &plan, &l)) else {
        panic!("expected a replay");
    };
    assert!(r.needs_refund());
    assert_eq!(r.receipt(&receipt_input(Digest([4; 32]))), None);
    assert_eq!(
        receipt(r.record(), &receipt_input(Digest([4; 32])), false),
        None
    );
    let rec = block_on(record_refund(&store, plan.replay_key(), Some(b"refund 1"))).unwrap();
    assert_eq!(rec.scheme_result.as_deref(), Some(&b"refund 1"[..]));
    let rec = block_on(record_refund(&store, plan.replay_key(), Some(b"refund 2"))).unwrap();
    assert_eq!(
        rec.scheme_result.as_deref(),
        Some(&b"refund 1"[..]),
        "the first recorded refund wins"
    );
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &plan, &l)) else {
        panic!("expected a replay");
    };
    assert!(!r.needs_refund());
    let f = r.receipt(&receipt_input(Digest([4; 32]))).unwrap();
    assert_eq!(f.metered_units, Some(0));
    assert_eq!(f.settled_at, T0 + l.pending_timeout + 1);
}

#[test]
fn a_replay_past_the_timeout_times_out_at_once() {
    let store = MemoryStore::new();
    let l = limits();
    let plan = note_plan(&ctx(1), b"Y", T0);
    block_on(commit(&store, &plan, &l)).unwrap();
    let late = note_plan(&ctx(1), b"Y", T0 + l.pending_timeout + 5);
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &late, &l)) else {
        panic!("expected a replay");
    };
    assert!(r.needs_refund());
    assert_eq!(r.record().settled_at, Some(T0 + l.pending_timeout + 5));
}

#[test]
fn replay_window_expiry() {
    let store = MemoryStore::new();
    let l = limits();
    let plan = note_plan(&ctx(1), b"Y", T0);
    block_on(commit(&store, &plan, &l)).unwrap();
    settle_ok(&store, plan.replay_key(), 21, T0 + 1);
    // Last second inside the window: a replay.
    let inside = note_plan(&ctx(1), b"Y", T0 + l.replay_window - 1);
    assert!(matches!(
        block_on(commit(&store, &inside, &l)),
        Ok(Admitted::Replay(_))
    ));
    // At the window's end the record no longer answers: SPENT.
    let edge = note_plan(&ctx(1), b"Y", T0 + l.replay_window);
    assert_eq!(block_on(commit(&store, &edge, &l)), Err(CommitError::Spent));
    // The sweep deletes the record but keeps the single use.
    let swept = block_on(sweep(&store, T0 + l.replay_window + 1, &l)).unwrap();
    assert_eq!(swept.purged, 1);
    store.inspect(|t| {
        assert_eq!(t.outcomes_len(), 0);
        assert_eq!(t.used_len(), 1);
    });
    let later = note_plan(&ctx(1), b"Y", T0 + l.replay_window + 2);
    assert_eq!(
        block_on(commit(&store, &later, &l)),
        Err(CommitError::Spent)
    );
}

#[test]
fn the_sweep_never_purges_pending() {
    let store = MemoryStore::new();
    let l = Limits {
        pending_timeout: 200_000,
        ..Limits::default()
    };
    let plan = note_plan(&ctx(1), b"Y", T0);
    block_on(commit(&store, &plan, &l)).unwrap();
    let swept = block_on(sweep(&store, T0 + l.replay_window + 10, &l)).unwrap();
    assert_eq!(swept.purged, 0);
    assert!(
        block_on(store.outcome(plan.replay_key()))
            .unwrap()
            .is_some()
    );
}

#[test]
fn credentials_without_single_ids_must_not_outlive_their_record() {
    let l = limits();
    let ids = [b"bot key".to_vec()];
    let uses = [SchemeUses {
        scheme: "httpsig:web-bot-auth",
        model: UseModel::Reusable,
        local_ids: &ids,
    }];
    let c = ctx(1);
    let adm = no_quota();
    let input = |expires| PlanInput {
        context: &c,
        pay_body: b"",
        attest_bodies: &[],
        schemes: &uses,
        rail_ids: &[],
        admission: &adm,
        offer_expires: expires,
        now: T0,
        replay_window: l.replay_window,
    };
    // expires + 60 <= now + replay_window is admitted.
    assert!(CommitPlan::build(&input(T0 + l.replay_window - 60)).is_ok());
    let err = CommitPlan::build(&input(T0 + l.replay_window - 59)).unwrap_err();
    assert_eq!(err, crate::store::PlanError::OutlivesRecord);
    assert_eq!(err.code(), ErrorCode::Policy);
    // A rail ID is a single use, so the rule does not apply.
    let rail = [RailId([5; 32])];
    let mut with_rail = input(T0 + 10 * l.replay_window);
    with_rail.rail_ids = &rail;
    assert!(CommitPlan::build(&with_rail).is_ok());
}

#[test]
fn reusable_ids_enter_the_replay_key_but_are_not_consumed() {
    let store = MemoryStore::new();
    let bot = [b"bot key".to_vec()];
    let uses = [SchemeUses {
        scheme: "httpsig:web-bot-auth",
        model: UseModel::Reusable,
        local_ids: &bot,
    }];
    let a = plan_at(&ctx(1), b"", &uses, &[], T0);
    let b = plan_at(&ctx(2), b"", &uses, &[], T0);
    assert_eq!(
        a.ids(),
        &[ids::use_id("httpsig:web-bot-auth", b"bot key").0]
    );
    assert_eq!((a.singles().len(), a.counters().len()), (0, 0));
    // Two requests with the same reusable attestation both run.
    assert_eq!(block_on(commit(&store, &a, &limits())), Ok(Admitted::New));
    assert_eq!(block_on(commit(&store, &b, &limits())), Ok(Admitted::New));
}

#[test]
fn duplicate_ids_in_one_credential_commit_once() {
    let ids = [b"Y".to_vec(), b"Y".to_vec()];
    let plan = plan_at(
        &ctx(1),
        b"body",
        &[SchemeUses {
            scheme: "bnap:notes",
            model: UseModel::Single,
            local_ids: &ids,
        }],
        &[],
        T0,
    );
    assert_eq!(plan.singles().len(), 1);
    assert_eq!(
        plan.ids().len(),
        2,
        "the ReplayKey keeps both (ERRATA N3a-9)"
    );
}

#[test]
fn an_unreachable_store_fails_closed() {
    let store = MemoryStore::new();
    store.set_unavailable(true);
    let err = block_on(commit(&store, &note_plan(&ctx(1), b"Y", T0), &limits())).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    store.set_unavailable(false);
    assert_eq!(
        block_on(commit(&store, &note_plan(&ctx(1), b"Y", T0), &limits())),
        Ok(Admitted::New)
    );
}

#[test]
fn settle_of_an_unknown_outcome_is_refused() {
    let store = MemoryStore::new();
    let s = Settlement {
        status: Status::Ok,
        charged: 0,
        metered_units: None,
        scheme_result: None,
        response: None,
        settled_at: T0,
    };
    assert_eq!(
        block_on(settle(&store, &ReplayKey([1; 32]), &s)),
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
    let ctx = cred.context(&OfferId([3; 32]), &scope);
    let d1 = cred.digest(&ctx);
    let mut retry = cred.clone();
    retry.binding = Some(sha256(b"connection 2"));
    let ctx2 = retry.context(&OfferId([3; 32]), &scope);
    assert_eq!(ctx, ctx2);
    let d2 = retry.digest(&ctx2);
    assert_ne!(d1, d2);

    let store = MemoryStore::new();
    let first = note_plan(&ctx, b"Y", T0);
    block_on(commit(&store, &first, &limits())).unwrap();
    settle_ok(&store, first.replay_key(), 21, T0 + 1);
    let second = note_plan(&ctx2, b"Y", T0 + 2);
    assert_eq!(first.replay_key(), second.replay_key());
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &second, &limits())) else {
        panic!("expected a replay");
    };
    assert_eq!(r.receipt(&receipt_input(d2)).unwrap().digest, d2);
}

fn quota_offer() -> OfferFields {
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    o.attest.push(AttestEntry::quota("httpauth:DPoP", 1, 3600));
    o
}

#[test]
fn a_quota_with_room_at_pricing_but_full_at_commit_is_rate_limited() {
    let store = MemoryStore::new();
    let offer = quota_offer();
    let client = ids::use_id("httpauth:DPoP", b"jwk thumbprint");
    let att = [VerifiedAttest::new("httpauth:DPoP", BindingClass::A).with_quota_id(client)];
    let input = AdmitInput {
        offer: &offer,
        pay: Some(PayValue {
            scheme: "bnap:notes",
            claimed: 0,
            backing: Vec::new(),
        }),
        attest: &att,
        now: T0,
    };
    // Two requests price at the same time; both see room.
    let a1 = block_on(admit(&store, &input)).unwrap();
    let a2 = block_on(admit(&store, &input)).unwrap();
    assert_eq!((a1.price(), a2.price()), (0, 0));
    let dpop = [b"jwk thumbprint".to_vec()];
    let plan = |c: u8, note: &[u8]| {
        let note = [note.to_vec()];
        CommitPlan::build(&PlanInput {
            context: &ctx(c),
            pay_body: b"",
            attest_bodies: &[&b"dpop proof"[..]],
            schemes: &[
                SchemeUses {
                    scheme: "bnap:notes",
                    model: UseModel::Single,
                    local_ids: &note,
                },
                SchemeUses {
                    scheme: "httpauth:DPoP",
                    model: UseModel::Reusable,
                    local_ids: &dpop,
                },
            ],
            rail_ids: &[],
            admission: &a1,
            offer_expires: T0 + 300,
            now: T0,
            replay_window: limits().replay_window,
        })
        .unwrap()
    };
    assert_eq!(
        block_on(commit(&store, &plan(1, b"n1"), &limits())),
        Ok(Admitted::New)
    );
    let err = block_on(commit(&store, &plan(2, b"n2"), &limits())).unwrap_err();
    assert!(matches!(err, CommitError::RateLimited { .. }));
    // Nothing consumed: the second note is still free.
    let n2 = ids::use_id("bnap:notes", b"n2");
    store.inspect(|t| assert!(t.used_by(&n2.0).is_none()));
    // Now pricing sees the full quota and charges the full price.
    let a3 = block_on(admit(&store, &input));
    assert_eq!(
        a3,
        Err(AdmitError::Price(PriceError::Underpaid {
            price: 21,
            value: 0
        }))
    );
}

#[test]
fn use_ids_are_prefixed_by_the_scheme() {
    // The same local ID under two schemes gives two UseIds (6.1).
    let a: UseId = ids::use_id("bnap:notes", b"x");
    let b: UseId = ids::use_id("httpauth:L402", b"x");
    assert_ne!(a, b);
}

#[test]
fn a_quota_priced_admission_always_commits_its_counter() {
    // The review's probe: an attestation-only credential under a quota of
    // 1 per hour, priced at 0 by the quota. The plan takes the counter from
    // the admission, so no gate can commit it without consuming the quota.
    let store = MemoryStore::new();
    let offer = quota_offer();
    let client = ids::use_id("httpauth:DPoP", b"jwk thumbprint");
    let att = [VerifiedAttest::new("httpauth:DPoP", BindingClass::A).with_quota_id(client)];
    let dpop = [b"jwk thumbprint".to_vec()];
    let mut answers = Vec::new();
    for c in 1..=5u8 {
        let input = AdmitInput {
            offer: &offer,
            pay: None,
            attest: &att,
            now: T0,
        };
        // Price before the commits: every request sees room.
        let a = pricing::admit(&input, |_| 0).unwrap();
        assert_eq!(a.price(), 0);
        let counter = *a.decision().quota_counter().unwrap();
        let plan = CommitPlan::build(&PlanInput {
            context: &ctx(c),
            pay_body: b"",
            attest_bodies: &[&b"dpop proof"[..]],
            schemes: &[SchemeUses {
                scheme: "httpauth:DPoP",
                model: UseModel::Reusable,
                local_ids: &dpop,
            }],
            rail_ids: &[],
            admission: &a,
            offer_expires: offer.expires,
            now: T0,
            replay_window: limits().replay_window,
        })
        .unwrap();
        assert_eq!(plan.counters(), &[counter]);
        answers.push(block_on(commit(&store, &plan, &limits())));
    }
    assert_eq!(answers[0], Ok(Admitted::New));
    for a in &answers[1..] {
        assert!(matches!(a, Err(CommitError::RateLimited { .. })), "{a:?}");
    }
}

#[test]
fn every_payment_and_note_counted_as_value_is_consumed() {
    // A scheme that counts notes and a payment as value but names none of
    // them as use IDs: the plan consumes them anyway.
    let store = MemoryStore::new();
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 50, "sat"));
    let admit_with = |backing: Vec<Backing>| {
        let input = AdmitInput {
            offer: &o,
            pay: Some(PayValue {
                scheme: "bnap:notes",
                claimed: 1_000,
                backing,
            }),
            attest: &[],
            now: T0,
        };
        pricing::admit(&input, |_| 0).unwrap()
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
    let first = admit_with(vec![note(b"Y1", 64), rail_pay.clone()]);
    let plan = |c: u8, a: &Admission| {
        CommitPlan::build(&PlanInput {
            context: &ctx(c),
            pay_body: b"body",
            attest_bodies: &[],
            schemes: &[],
            rail_ids: &[],
            admission: a,
            offer_expires: T0 + 300,
            now: T0,
            replay_window: limits().replay_window,
        })
        .unwrap()
    };
    let p1 = plan(1, &first);
    let y1 = pricing::note_id(b"Y1");
    let mut want = [y1, [4; 32]];
    want.sort_unstable();
    assert_eq!(p1.singles(), &want[..]);
    assert!(p1.ids().is_empty(), "the ReplayKey keeps what 6.1 names");
    assert_eq!(block_on(commit(&store, &p1, &limits())), Ok(Admitted::New));
    // The same note, or the same payment, counted again: SPENT.
    let again = admit_with(vec![note(b"Y1", 64)]);
    assert_eq!(
        block_on(commit(&store, &plan(2, &again), &limits())),
        Err(CommitError::Spent)
    );
    let again = admit_with(vec![note(b"Y2", 64), rail_pay]);
    assert_eq!(
        block_on(commit(&store, &plan(3, &again), &limits())),
        Err(CommitError::Spent)
    );
}

#[test]
fn one_signer_verified_note_is_spent_once_across_value_schemes() {
    // The review's probe: an offer lists bnap:notes and a Cashu adapter at
    // 50 sat each, and both check notes through the gate's one signer. One
    // note worth 64 sat is admitted under one scheme, then presented under
    // the other. Each scheme names the note in its own UseId space, so only
    // the scheme-free note ID can catch it (ERRATA N3b-19). Either order.
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", 50, "sat"));
    o.pay.push(PayEntry::new("cashu:nut24", 50, "sat"));
    let y = [7u8; 33];
    let local = [y.to_vec()];
    let attempt = |store: &MemoryStore, scheme: &str, c: u8| {
        let input = AdmitInput {
            offer: &o,
            pay: Some(PayValue {
                scheme,
                claimed: 64,
                backing: vec![Backing {
                    source: BackingSource::Note(y.to_vec()),
                    amount: 64,
                    unit: "sat".into(),
                }],
            }),
            attest: &[],
            now: T0,
        };
        let admission = pricing::admit(&input, |_| 0).unwrap();
        let plan = CommitPlan::build(&PlanInput {
            context: &ctx(c),
            pay_body: b"one note",
            attest_bodies: &[],
            schemes: &[SchemeUses {
                scheme,
                model: UseModel::Single,
                local_ids: &local,
            }],
            rail_ids: &[],
            admission: &admission,
            offer_expires: o.expires,
            now: T0,
            replay_window: limits().replay_window,
        })
        .unwrap();
        // The scheme's own UseId stays a single, next to the note ID.
        assert!(plan.singles().contains(&ids::use_id(scheme, &y).0));
        assert!(plan.singles().contains(&pricing::note_id(&y)));
        block_on(commit(store, &plan, &limits()))
    };
    for (first, second) in [("bnap:notes", "cashu:nut24"), ("cashu:nut24", "bnap:notes")] {
        let store = MemoryStore::new();
        assert_eq!(attempt(&store, first, 1), Ok(Admitted::New));
        assert_eq!(attempt(&store, second, 2), Err(CommitError::Spent));
        store.inspect(|t| assert_eq!(t.outcomes_len(), 1, "one note, one action"));
    }
}

#[test]
fn a_refund_with_nothing_to_return_is_recorded_too() {
    // A scheme whose FAILED settle returns no scheme_result (nothing to
    // refund): the refund is still recorded once, and the receipt follows.
    let store = MemoryStore::new();
    let l = limits();
    let plan = note_plan(&ctx(1), b"Y", T0);
    block_on(commit(&store, &plan, &l)).unwrap();
    let late = note_plan(&ctx(1), b"Y", T0 + l.pending_timeout + 5);
    let Ok(Admitted::Replay(r)) = block_on(commit(&store, &late, &l)) else {
        panic!("expected a replay");
    };
    assert!(r.needs_refund());
    assert_eq!(r.receipt(&receipt_input(Digest([1; 32]))), None);
    let rec = block_on(record_refund(&store, plan.replay_key(), None)).unwrap();
    assert!(rec.refund_recorded && !rec.needs_refund());
    let f = receipt(&rec, &receipt_input(Digest([1; 32])), true).unwrap();
    assert_eq!(
        (f.status, f.charged, f.scheme_result),
        (Status::Failed, 0, None)
    );
    // A later refund cannot overwrite it.
    let rec = block_on(record_refund(&store, plan.replay_key(), Some(b"more"))).unwrap();
    assert_eq!(rec.scheme_result, None);
}

#[test]
fn a_late_settle_answers_from_the_recorded_failed_outcome() {
    // The action outlived pending_timeout: the sweep made it FAILED, and its
    // settle is refused with the record, which still needs its refund.
    let store = MemoryStore::new();
    let l = limits();
    let plan = note_plan(&ctx(1), b"Y", T0);
    block_on(commit(&store, &plan, &l)).unwrap();
    block_on(sweep(&store, T0 + l.pending_timeout + 1, &l)).unwrap();
    let ok = Settlement {
        status: Status::Ok,
        charged: 21,
        metered_units: None,
        scheme_result: Some(b"change for OK".to_vec()),
        response: None,
        settled_at: T0 + 400,
    };
    let Err(SettleError::AlreadySettled(rec)) = block_on(settle(&store, plan.replay_key(), &ok))
    else {
        panic!("expected AlreadySettled");
    };
    assert!(rec.needs_refund());
    assert_eq!(receipt(&rec, &receipt_input(Digest([1; 32])), false), None);
    let rec = block_on(record_refund(&store, plan.replay_key(), Some(b"refund"))).unwrap();
    let f = receipt(&rec, &receipt_input(Digest([1; 32])), false).unwrap();
    assert_eq!((f.status, f.charged), (Status::Failed, 0));
    assert_eq!(f.scheme_result.as_deref(), Some(&b"refund"[..]));
    assert!(!f.replayed);
}
