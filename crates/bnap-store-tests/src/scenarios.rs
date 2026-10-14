//! Concurrency scenarios through the whole socket flow, for any
//! [`UseStore`].
//!
//! Each scenario starts many calls behind a barrier, round after round, on
//! a store whose pool gives each call its own connection, and drives the
//! store only through bnap-core's public flow (`process`, `settle`,
//! `sweep`, `record_refund`, `reserve_change`), as several gate instances
//! sharing one store would. Where bnap-core's conformance suite checks the
//! store's methods one by one, these check what a gate sees: one action per
//! single use, one transition per outcome, one refund per timed-out outcome,
//! counters within their limits and one change total per outcome.
//!
//! # Panics
//!
//! Every scenario panics, as a test does, when the store breaks the rule it
//! checks or fails.
#![allow(clippy::missing_panics_doc)]

use bnap_core::class::BindingClass;
use bnap_core::hash::{Context, RailId, Scope};
use bnap_core::ids;
use bnap_core::limits::Limits;
use bnap_core::offer::{AttestEntry, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, Pending, ProcessError, Recorded, Request, SettleError};
use bnap_core::pricing::{Backing, BackingSource, PayValue, PriceError, Refund};
use bnap_core::schnorr::Key;
use bnap_core::store::{
    ChangeOutput, OutcomeRecord, OutcomeStatus, Reserve, SchemeUses, Settlement, UseModel, UseStore,
};
use bnap_core::test_support::conformance::Executor;
use bnap_core::{ReplayKey, Status, VerifiedAttest};

use crate::{Tried, race};

/// The clock every scenario starts at.
pub const T0: u64 = 1_791_700_000;
/// Calls each round releases together.
pub const TASKS: usize = 16;
/// Rounds of each scenario.
pub const ROUNDS: u8 = 6;

/// The limits every scenario runs under: the defaults (`pending_timeout`
/// 300 s, `replay_window` one day).
#[must_use]
pub fn limits() -> Limits {
    Limits::default()
}

/// One verified request, owned, as a gate hands it to
/// [`outcome::process`].
#[derive(Debug, Clone)]
pub struct Req {
    /// The checked offer.
    pub offer: OfferFields,
    /// The credential's Context.
    pub ctx: Context,
    /// The pay body.
    pub pay_body: Vec<u8>,
    /// Attest bodies.
    pub attest_bodies: Vec<Vec<u8>>,
    /// Every scheme's local IDs under its model.
    pub uses: Vec<(&'static str, UseModel, Vec<Vec<u8>>)>,
    /// Confirmed rail IDs.
    pub rails: Vec<RailId>,
    /// The pay claim.
    pub pay: Option<PayValue<'static>>,
    /// Verified attestations.
    pub attest: Vec<VerifiedAttest>,
    /// The gate's clock.
    pub now: u64,
}

fn offer(pay: &[(&str, u64)]) -> OfferFields {
    let mut o = OfferFields::new(Scope([1; 32]), T0 + 300, Key([9; 32]), [0; 16]);
    for (scheme, price) in pay {
        o.pay.push(PayEntry::new(*scheme, *price, "sat"));
    }
    o
}

impl Req {
    /// A `bnap:notes` credential (Context `c`) paying with one
    /// signer-verified note `y` worth `value` sat for an entry of `price`
    /// sat, refund atomic. With `rate`, it also names the identity `who`
    /// under a rate of `rate` per minute.
    #[must_use]
    pub fn note(c: u32, y: &[u8], value: u64, price: u64, rate: Option<(u64, &[u8])>) -> Self {
        let mut uses = vec![("bnap:notes", UseModel::Single, vec![y.to_vec()])];
        if let Some((k, who)) = rate {
            uses.push((
                "vnd.client",
                UseModel::Rate { k, epoch: 60 },
                vec![who.to_vec()],
            ));
        }
        Self {
            offer: offer(&[("bnap:notes", price)]),
            ctx: ctx(c),
            pay_body: b"notes".to_vec(),
            attest_bodies: Vec::new(),
            uses,
            rails: Vec::new(),
            pay: Some(PayValue {
                scheme: "bnap:notes",
                claimed: value,
                backing: vec![Backing {
                    source: BackingSource::Note(y.to_vec()),
                    amount: value,
                    unit: "sat".into(),
                }],
                refund: Refund::Atomic,
            }),
            attest: Vec::new(),
            now: T0,
        }
    }

    /// A credential (Context `c`) of `scheme` (`l402` or `mpp`, both
    /// offered at 21 sat) relying on the Lightning payment `hash`, which
    /// the rail confirmed for 21 sat.
    #[must_use]
    pub fn lightning(c: u32, scheme: &'static str, hash: &[u8; 32]) -> Self {
        let rail = ids::rail_id("ln", &ids::rail::ln(hash));
        Self {
            offer: offer(&[("l402", 21), ("mpp", 21)]),
            ctx: ctx(c),
            pay_body: scheme.as_bytes().to_vec(),
            attest_bodies: Vec::new(),
            uses: vec![(scheme, UseModel::Single, vec![c.to_be_bytes().to_vec()])],
            rails: vec![rail],
            pay: Some(PayValue {
                scheme,
                claimed: 21,
                backing: vec![Backing {
                    source: BackingSource::Rail(rail),
                    amount: 21,
                    unit: "sat".into(),
                }],
                refund: Refund::None,
            }),
            attest: Vec::new(),
            now: T0,
        }
    }

    /// An attestation-only credential (Context `c`) of the identity `who`
    /// on an offer of 21 sat with an `httpauth:DPoP` quota of `limit` per
    /// hour: admitted, at price 0, only while the quota has room.
    #[must_use]
    pub fn quota(c: u32, who: &[u8], limit: u64) -> Self {
        let mut o = offer(&[("bnap:notes", 21)]);
        o.attest
            .push(AttestEntry::quota("httpauth:DPoP", limit, 3600));
        let id = ids::use_id("httpauth:DPoP", who);
        Self {
            offer: o,
            ctx: ctx(c),
            pay_body: Vec::new(),
            attest_bodies: vec![c.to_be_bytes().to_vec()],
            uses: vec![("httpauth:DPoP", UseModel::Reusable, vec![who.to_vec()])],
            rails: Vec::new(),
            pay: None,
            attest: vec![VerifiedAttest::new("httpauth:DPoP", BindingClass::A).with_quota_id(id)],
            now: T0,
        }
    }

    /// The same request at `now`.
    #[must_use]
    pub fn at(&self, now: u64) -> Self {
        Self {
            now,
            ..self.clone()
        }
    }

    /// [`outcome::process`] on `store`.
    ///
    /// # Errors
    ///
    /// What `process` refuses.
    pub async fn process<S: UseStore + ?Sized>(&self, store: &S) -> Result<Admitted, ProcessError> {
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
        let req = Request {
            offer: &self.offer,
            context: &self.ctx,
            pay_body: &self.pay_body,
            attest_bodies: &bodies,
            schemes: &schemes,
            rail_ids: &self.rails,
            pay: self.pay.clone(),
            attest: &self.attest,
            now: self.now,
        };
        outcome::process(store, &req, &limits()).await
    }

    /// The `ReplayKey` (6.1) and every single the commit consumes: each
    /// single-model `UseId`, each `RailId` and each backing note.
    #[must_use]
    pub fn tried(&self) -> Tried {
        let bodies: Vec<&[u8]> = self.attest_bodies.iter().map(Vec::as_slice).collect();
        let mut all = Vec::new();
        let mut singles = Vec::new();
        for (scheme, model, locals) in &self.uses {
            for l in locals {
                let id = ids::use_id(scheme, l).0;
                all.push(id);
                if *model == UseModel::Single {
                    singles.push(id);
                }
            }
        }
        for r in &self.rails {
            all.push(r.0);
            singles.push(r.0);
        }
        if let Some(pay) = &self.pay {
            singles.extend(pay.backing.iter().map(|b| b.source.single_id()));
        }
        singles.sort_unstable();
        singles.dedup();
        Tried {
            replay_key: ids::replay_key(&self.ctx, &self.pay_body, &bodies, &all),
            singles,
        }
    }
}

/// Context `c`.
#[must_use]
pub fn ctx(c: u32) -> Context {
    let mut b = [0x5a; 32];
    b[..4].copy_from_slice(&c.to_be_bytes());
    Context(b)
}

/// A 33-byte note point for `n`.
#[must_use]
pub fn note(n: u32) -> Vec<u8> {
    let mut y = vec![2; 33];
    y[1..5].copy_from_slice(&n.to_be_bytes());
    y
}

/// The pending outcome of an admission.
///
/// # Panics
///
/// When `r` is not New.
#[must_use]
pub fn new(r: Result<Admitted, ProcessError>) -> Pending {
    match r {
        Ok(Admitted::New(p)) => p,
        other => panic!("expected New, got {other:?}"),
    }
}

/// The recorded outcome of a replay.
///
/// # Panics
///
/// When `r` is not a replay.
#[must_use]
pub fn replay(r: Result<Admitted, ProcessError>) -> Recorded {
    match r {
        Ok(Admitted::Replay(r)) => r,
        other => panic!("expected a replay, got {other:?}"),
    }
}

/// The settlement of `p` with `status`, at `at`, carrying `result`.
#[must_use]
pub fn settlement(p: &Pending, status: Status, at: u64, result: &[u8]) -> Settlement {
    Settlement::new(&p.charge(status, 0), at).with_scheme_result(Some(result.to_vec()))
}

fn record<S: UseStore + ?Sized>(store: &S, exec: &impl Executor, rk: &ReplayKey) -> OutcomeRecord {
    exec.block_on(store.outcome(rk))
        .unwrap()
        .expect("the outcome record exists")
}

/// Outputs of `amount` each, distinct per `(tag, i)`.
#[must_use]
pub fn output(tag: u8, i: usize, amount: u64) -> ChangeOutput {
    let mut blinded = [3; 33];
    blinded[1] = tag;
    blinded[2..10].copy_from_slice(&u64::try_from(i).unwrap().to_be_bytes());
    ChangeOutput {
        keyset: b"keyset-0".to_vec(),
        amount,
        blinded,
    }
}

/// Double spend of one note: [`TASKS`] credentials, each its own Context
/// and so its own `ReplayKey`, all paying with one note, race through
/// `process`. Exactly one is admitted and the rest are SPENT; no loser
/// leaves a record. The note is spent under its scheme's `UseId` and under
/// `H_"bnap/note"(Y)`, so a later credential carrying it under another
/// value scheme is SPENT too.
pub fn one_note_admits_one_action<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
    for round in 0..ROUNDS {
        let y = note(u32::from(round));
        let reqs: Vec<Req> = (0..TASKS)
            .map(|i| Req::note(1000 * u32::from(round) + idx(i), &y, 50, 21, None))
            .collect();
        let answers = race(TASKS, |i| exec.block_on(reqs[i].process(store)));
        let winners: Vec<usize> = (0..TASKS)
            .filter(|i| matches!(answers[*i], Ok(Admitted::New(_))))
            .collect();
        assert_eq!(winners.len(), 1, "one action per note: {answers:?}");
        for (i, a) in answers.iter().enumerate() {
            if i == winners[0] {
                continue;
            }
            assert_eq!(a.as_ref().err(), Some(&ProcessError::Spent), "{a:?}");
            assert!(
                exec.block_on(store.outcome(&reqs[i].tried().replay_key))
                    .unwrap()
                    .is_none()
            );
        }
        // The same note under another value scheme.
        let mut other = Req::note(999_999 - u32::from(round), &y, 50, 21, None);
        other.uses = vec![("cashu:nut24", UseModel::Single, vec![b"proof".to_vec()])];
        other.offer = offer(&[("cashu:nut24", 21)]);
        if let Some(pay) = &mut other.pay {
            pay.scheme = "cashu:nut24";
        }
        assert_eq!(
            exec.block_on(other.process(store)).err(),
            Some(ProcessError::Spent)
        );
    }
}

/// One Lightning payment offered under two schemes: [`TASKS`] credentials,
/// half L402 and half MPP, all relying on one payment hash, race through
/// `process`. The `RailId` does not depend on the scheme, so exactly one
/// action is admitted and every other credential is SPENT.
pub fn one_payment_under_two_schemes_admits_one_action<S: UseStore + ?Sized>(
    store: &S,
    exec: &impl Executor,
) {
    for round in 0..ROUNDS {
        let hash = [round.wrapping_add(1); 32];
        let reqs: Vec<Req> = (0..TASKS)
            .map(|i| {
                let scheme = if i % 2 == 0 { "l402" } else { "mpp" };
                Req::lightning(1000 * u32::from(round) + idx(i), scheme, &hash)
            })
            .collect();
        let answers = race(TASKS, |i| exec.block_on(reqs[i].process(store)));
        let new = answers
            .iter()
            .filter(|a| matches!(a, Ok(Admitted::New(_))))
            .count();
        let spent = answers
            .iter()
            .filter(|a| a.as_ref().err() == Some(&ProcessError::Spent))
            .count();
        assert_eq!((new, spent), (1, TASKS - 1), "{answers:?}");
    }
}

/// What one call of [`settle_and_sweep_race_to_one_transition`] got.
#[derive(Debug)]
enum Moved {
    Settle(Box<Result<Recorded, SettleError>>),
    Sweep(bool),
}

/// Settle against the timeout: an admitted outcome (which also counts
/// against a rate counter) is settled OK at its deadline by half the
/// tasks, as gate instances finishing the action, while the other half
/// sweep past the deadline. Exactly one call moves it: either one settle
/// wins (every other settle gets `AlreadySettled` with that record, and the
/// counter keeps its count), or the timeout wins (every settle gets the
/// FAILED record, which needs its refund, and the counter is given back
/// once).
pub fn settle_and_sweep_race_to_one_transition<S: UseStore + ?Sized>(
    store: &S,
    exec: &impl Executor,
) {
    let l = limits();
    for round in 0..ROUNDS {
        let who = [b'w', round];
        let r = Req::note(
            u32::from(round),
            &note(100 + u32::from(round)),
            50,
            21,
            Some((100, &who)),
        );
        let p = new(exec.block_on(r.process(store)));
        let rk = *p.replay_key();
        let deadline = T0 + l.pending_timeout;
        let answers = race(TASKS, |i| {
            if (i + usize::from(round)) % 2 == 0 {
                let s = settlement(&p, Status::Ok, deadline, b"change");
                Moved::Settle(Box::new(exec.block_on(outcome::settle(store, &p, &s, &l))))
            } else {
                let sw = exec
                    .block_on(outcome::sweep(store, deadline + 1, &l))
                    .unwrap();
                Moved::Sweep(sw.timed_out.contains(&rk))
            }
        });
        let rec = record(store, exec, &rk);
        let settled = answers
            .iter()
            .filter(|a| matches!(a, Moved::Settle(r) if r.is_ok()))
            .count();
        let swept = answers
            .iter()
            .filter(|a| matches!(a, Moved::Sweep(true)))
            .count();
        assert_eq!(settled + swept, 1, "one transition: {answers:?}");
        for a in &answers {
            let Moved::Settle(answer) = a else { continue };
            match &**answer {
                Ok(won) => {
                    assert_eq!(won.record(), &rec);
                    assert_eq!(rec.status, OutcomeStatus::Ok);
                }
                Err(SettleError::AlreadySettled(seen)) => {
                    assert_eq!(seen.record(), &rec, "a losing settle sees the record");
                    assert!(!seen.replayed());
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        if swept == 1 {
            assert!(rec.timed_out && rec.needs_refund(), "{rec:?}");
        }
        let key = rec.counters[0];
        let count = exec.block_on(store.counter(&key)).unwrap();
        assert_eq!(count, u64::from(rec.status == OutcomeStatus::Ok));
    }
}

/// Concurrent replays of one credential, as a client retrying on several
/// connections: [`TASKS`] copies race through `process` and exactly one is
/// admitted, the rest PENDING. Once settled, every copy is answered from the
/// one record, as a replay, and writes nothing. After a crash (an outcome
/// never settled), copies arriving past the timeout all get the timed-out
/// record; they then record their refunds together, each with its own
/// result, and exactly one is kept and returned to every one of them.
pub fn concurrent_replays_get_one_answer<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
    let l = limits();
    for round in 0..ROUNDS {
        let r = Req::note(
            u32::from(round),
            &note(200 + u32::from(round)),
            96,
            50,
            None,
        );
        let answers = race(TASKS, |_| exec.block_on(r.process(store)));
        let mut pending = None;
        for a in answers {
            match a {
                Ok(Admitted::New(p)) => assert!(pending.replace(p).is_none(), "one New"),
                Err(ProcessError::Pending { retry_after }) => {
                    assert_eq!(retry_after, l.pending_timeout);
                }
                other => panic!("{other:?}"),
            }
        }
        let p = pending.expect("one copy is admitted");
        let rk = *p.replay_key();
        if round % 2 == 0 {
            // Settled: every copy replays the one record.
            let s = settlement(&p, Status::Ok, T0 + 1, b"change 46");
            let done = exec.block_on(outcome::settle(store, &p, &s, &l)).unwrap();
            let replays = race(TASKS, |_| exec.block_on(r.at(T0 + 2).process(store)));
            for a in replays {
                let rec = replay(a);
                assert!(rec.replayed());
                assert_eq!(rec.record(), done.record());
            }
            assert_eq!(
                &record(store, exec, &rk),
                done.record(),
                "replays write nothing"
            );
        } else {
            // Crashed: copies after the timeout collect one refund.
            let late = r.at(T0 + l.pending_timeout + 1);
            let replays = race(TASKS, |_| exec.block_on(late.process(store)));
            let recs: Vec<Recorded> = replays.into_iter().map(replay).collect();
            assert!(recs.iter().all(Recorded::needs_refund), "{recs:?}");
            let refunds = race(TASKS, |i| {
                let result = [b'r', round, u8::try_from(i).unwrap()];
                exec.block_on(outcome::record_refund(store, &recs[i], Some(&result)))
                    .unwrap()
            });
            let rec = record(store, exec, &rk);
            assert!(rec.refund_recorded && !rec.needs_refund());
            for a in &refunds {
                assert_eq!(a.record(), &rec, "every copy gets the refund recorded");
            }
        }
    }
}

/// Quota and rate counters never pass their limit. [`TASKS`]
/// attestation-only credentials of one identity under a quota of 3 race
/// through `process`: exactly 3 are admitted (the others are refused at
/// pricing, UNDERPAID once the quota reads full, or at commit,
/// `RATE_LIMITED`), and the quota counter reads 3. The same with a rate of
/// 5 on paid credentials of one identity: exactly 5, the counter reads 5.
pub fn counters_never_pass_their_limit<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
    for round in 0..ROUNDS {
        let who = [b'q', round];
        let reqs: Vec<Req> = (0..TASKS)
            .map(|i| Req::quota(1000 * u32::from(round) + idx(i), &who, 3))
            .collect();
        let answers = race(TASKS, |i| exec.block_on(reqs[i].process(store)));
        let mut admitted = Vec::new();
        for (i, a) in answers.iter().enumerate() {
            match a {
                Ok(Admitted::New(p)) => admitted.push((i, p.clone())),
                Err(
                    ProcessError::RateLimited { .. }
                    | ProcessError::Price(PriceError::Underpaid { .. }),
                ) => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(admitted.len(), 3, "a quota of 3 admits 3: {answers:?}");
        let rec = record(store, exec, admitted[0].1.replay_key());
        let key = *rec.counters.last().expect("the quota counter");
        assert_eq!(exec.block_on(store.counter(&key)).unwrap(), 3);

        let who = [b'r', round];
        let reqs: Vec<Req> = (0..TASKS)
            .map(|i| {
                let c = 1000 * u32::from(round) + idx(i);
                Req::note(c, &note(10_000 + c), 30, 21, Some((5, &who)))
            })
            .collect();
        let answers = race(TASKS, |i| exec.block_on(reqs[i].process(store)));
        let new: Vec<&Pending> = answers
            .iter()
            .filter_map(|a| match a {
                Ok(Admitted::New(p)) => Some(p),
                Err(ProcessError::RateLimited { retry_after }) => {
                    assert!(*retry_after >= 1);
                    None
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(new.len(), 5, "a rate of 5 admits 5: {answers:?}");
        let rec = record(store, exec, new[0].replay_key());
        assert_eq!(exec.block_on(store.counter(&rec.counters[0])).unwrap(), 5);
    }
}

/// One change total per outcome, through `reserve_change` under the caps
/// bnap-core computes: on an outcome worth 96 sat for a 50 sat entry
/// (atomic refund), [`TASKS`] tasks reserve a fresh 8 sat output each,
/// half under the OK cap (46) and half under the FAILED cap (96), and then
/// all re-reserve their outputs. The record holds exactly the outputs let
/// through and their total, never more than 96; the OK reservations alone
/// never pass 46 (each was checked against the total when it ran, so at
/// most 5 of 8 sat fit); re-reserving adds nothing.
pub fn change_reservations_keep_one_total<S: UseStore + ?Sized>(store: &S, exec: &impl Executor) {
    for round in 0..ROUNDS {
        let r = Req::note(
            u32::from(round),
            &note(300 + u32::from(round)),
            96,
            50,
            None,
        );
        let p = new(exec.block_on(r.process(store)));
        let rk = *p.replay_key();
        let ok = p.charge(Status::Ok, 0);
        let failed = p.charge(Status::Failed, 0);
        assert_eq!((ok.cap().get(), failed.cap().get()), (46, 96));
        let outs: Vec<ChangeOutput> = (0..TASKS).map(|i| output(round, i, 8)).collect();
        let cap = |i: usize| {
            if i.is_multiple_of(2) {
                ok.cap()
            } else {
                failed.cap()
            }
        };
        let answers = race(TASKS, |i| {
            exec.block_on(outcome::reserve_change(store, cap(i), &outs[i..=i]))
                .unwrap()
        });
        let through: Vec<usize> = (0..TASKS)
            .filter(|i| matches!(answers[*i], Reserve::Reserved { .. }))
            .collect();
        let rec = record(store, exec, &rk);
        let n = u64::try_from(through.len()).unwrap();
        assert_eq!(rec.change_total, 8 * n, "{answers:?}");
        assert!(rec.change_total <= 96);
        assert_eq!(rec.change_outputs.len(), through.len());
        assert!(
            through
                .iter()
                .all(|i| rec.change_outputs.contains(&outs[*i]))
        );
        let ok_through = through.iter().filter(|i| *i % 2 == 0).count();
        assert!(ok_through <= 5, "the OK cap holds: {answers:?}");
        for (i, a) in answers.iter().enumerate() {
            if let Reserve::OverCap { cap, .. } = a {
                assert_eq!(*cap, if i % 2 == 0 { 46 } else { 96 });
            }
        }
        let again = race(TASKS, |i| {
            exec.block_on(outcome::reserve_change(store, cap(i), &outs[i..=i]))
                .unwrap()
        });
        for i in &through {
            assert_eq!(
                again[*i],
                Reserve::Reserved {
                    total: rec.change_total
                }
            );
        }
        assert_eq!(record(store, exec, &rk), rec, "re-reserving adds nothing");
    }
}

/// Every scenario of this module, each on a store from `make`.
pub fn run<S: UseStore>(make: impl Fn() -> S, exec: &impl Executor) {
    one_note_admits_one_action(&make(), exec);
    one_payment_under_two_schemes_admits_one_action(&make(), exec);
    settle_and_sweep_race_to_one_transition(&make(), exec);
    concurrent_replays_get_one_answer(&make(), exec);
    counters_never_pass_their_limit(&make(), exec);
    change_reservations_keep_one_total(&make(), exec);
}

fn idx(i: usize) -> u32 {
    u32::try_from(i).unwrap()
}
