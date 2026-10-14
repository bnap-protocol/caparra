//! `bnap-store-sqlite` against bnap-core's conformance suite, the
//! concurrency scenarios and a pool dropped mid-transaction.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bnap_core::ReplayKey;
use bnap_core::outcome;
use bnap_core::store::UseStore;
use bnap_core::test_support::conformance::{self, Executor};
use bnap_core::{CounterKey, Status};
use bnap_store_sqlite::{SqliteConfig, SqliteStore};
use bnap_store_tests::scenarios::{self, Req, T0, limits, note, settlement};
use bnap_store_tests::{Dump, Held, Tokio, check_consistent};
use sqlx::{Connection, Row};

/// Enough connections for every task of a scenario to hold its own.
fn config() -> SqliteConfig {
    SqliteConfig {
        max_connections: 32,
        busy_timeout: Duration::from_secs(60),
        acquire_timeout: Duration::from_secs(60),
    }
}

fn open(exec: &Tokio, path: &Path) -> SqliteStore {
    exec.block_on(SqliteStore::open_with(path, &config()))
        .expect("the store opens")
}

/// A store on a new database file in a temporary directory.
fn fresh(exec: &Tokio) -> Held<SqliteStore> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = open(exec, &dir.path().join("uses.sqlite"));
    Held::new(store, dir)
}

fn key32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// Every row, read through the raw tables and the store.
fn dump(exec: &Tokio, store: &SqliteStore) -> Dump {
    exec.block_on(async {
        let pool = store.pool();
        let used = sqlx::query("SELECT use_id, replay_key FROM used")
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|r| {
                let id: Vec<u8> = r.get(0);
                let rk: Vec<u8> = r.get(1);
                (key32(&id), ReplayKey(key32(&rk)))
            })
            .collect();
        let counters = sqlx::query("SELECT counter_key, value FROM counter")
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|r| {
                let k: Vec<u8> = r.get(0);
                let v: i64 = r.get(1);
                (
                    CounterKey(key32(&k)),
                    u64::try_from(v).expect("small counts"),
                )
            })
            .collect();
        let keys: Vec<Vec<u8>> = sqlx::query_scalar("SELECT replay_key FROM outcome")
            .fetch_all(pool)
            .await
            .unwrap();
        let mut outcomes = Vec::new();
        for k in keys {
            let rk = ReplayKey(key32(&k));
            let rec = store.outcome(&rk).await.unwrap().expect("listed");
            outcomes.push((rk, rec));
        }
        let orphans: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM outcome_counter \
                     WHERE replay_key NOT IN (SELECT replay_key FROM outcome)) \
                  + (SELECT count(*) FROM change_output \
                     WHERE replay_key NOT IN (SELECT replay_key FROM outcome))",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        Dump {
            used,
            counters,
            outcomes,
            orphans: u64::try_from(orphans).unwrap(),
        }
    })
}

#[test]
fn passes_the_conformance_suite() {
    let exec = Tokio::new();
    conformance::run(|| fresh(&exec), &exec);
}

#[test]
fn one_note_admits_one_action() {
    let exec = Tokio::new();
    scenarios::one_note_admits_one_action(&fresh(&exec), &exec);
}

#[test]
fn one_payment_under_two_schemes_admits_one_action() {
    let exec = Tokio::new();
    scenarios::one_payment_under_two_schemes_admits_one_action(&fresh(&exec), &exec);
}

#[test]
fn settle_and_sweep_race_to_one_transition() {
    let exec = Tokio::new();
    scenarios::settle_and_sweep_race_to_one_transition(&fresh(&exec), &exec);
}

#[test]
fn concurrent_replays_get_one_answer() {
    let exec = Tokio::new();
    scenarios::concurrent_replays_get_one_answer(&fresh(&exec), &exec);
}

#[test]
fn counters_never_pass_their_limit() {
    let exec = Tokio::new();
    scenarios::counters_never_pass_their_limit(&fresh(&exec), &exec);
}

#[test]
fn change_reservations_keep_one_total() {
    let exec = Tokio::new();
    scenarios::change_reservations_keep_one_total(&fresh(&exec), &exec);
}

#[test]
fn the_schema_is_applied_once_and_a_store_reopens_its_file() {
    let exec = Tokio::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uses.sqlite");
    let r = Req::note(1, &note(1), 96, 50, Some((10, b"who")));
    let store = open(&exec, &path);
    let p = scenarios::new(exec.block_on(r.process(&store)));
    let done = exec
        .block_on(outcome::settle(
            &store,
            &p,
            &settlement(&p, Status::Ok, T0 + 1, b"kept"),
            &limits(),
        ))
        .unwrap();
    exec.block_on(store.close());
    drop(store);
    let again = open(&exec, &path);
    let rec = scenarios::replay(exec.block_on(r.at(T0 + 2).process(&again)));
    assert_eq!(rec.record(), done.record());
    let mode: String = exec
        .block_on(sqlx::query_scalar("PRAGMA journal_mode").fetch_one(again.pool()))
        .unwrap();
    assert_eq!(mode, "wal");
    let sync: i64 = exec
        .block_on(sqlx::query_scalar("PRAGMA synchronous").fetch_one(again.pool()))
        .unwrap();
    assert_eq!(sync, 2, "synchronous = FULL");
}

/// True while another connection holds the write lock: a write
/// transaction is open.
fn writer_active(exec: &Tokio, path: &Path) -> bool {
    exec.block_on(async {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .busy_timeout(Duration::ZERO);
        let mut probe = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let busy = sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut probe)
            .await
            .is_err();
        if !busy {
            sqlx::query("ROLLBACK").execute(&mut probe).await.unwrap();
        }
        probe.close().await.unwrap();
        busy
    })
}

#[test]
fn a_pool_dropped_mid_transaction_leaves_a_consistent_store() {
    let exec = Tokio::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uses.sqlite");
    for round in 0..3 {
        let store = Arc::new(open(&exec, &path));
        let tried = Arc::new(Mutex::new(Vec::new()));
        let acked = Arc::new(Mutex::new(Vec::new()));
        let gates: Vec<_> = (0..8)
            .map(|w| {
                exec.runtime().spawn(scenarios::gate(
                    Arc::clone(&store),
                    round * 8 + w,
                    Arc::clone(&tried),
                    Arc::clone(&acked),
                ))
            })
            .collect();
        // Let the gates write, then cut them off while one holds a write
        // transaction open, and drop the pool with it.
        std::thread::sleep(Duration::from_millis(150));
        let mut seen = false;
        for _ in 0..1_000 {
            if writer_active(&exec, &path) {
                seen = true;
                break;
            }
        }
        for g in &gates {
            g.abort();
        }
        assert!(seen, "a write transaction was open when the gates stopped");
        for g in gates {
            let e = exec.block_on(g).expect_err("aborted");
            assert!(e.is_cancelled(), "a gate failed: {e:?}");
        }
        drop(Arc::into_inner(store).expect("the gates let go of the store"));

        let store = open(&exec, &path);
        let d = dump(&exec, &store);
        let tried = tried.lock().unwrap().clone();
        check_consistent(&d, &tried);
        let committed: Vec<ReplayKey> = d.outcomes.iter().map(|(rk, _)| *rk).collect();
        for rk in acked.lock().unwrap().iter() {
            assert!(committed.contains(rk), "an acknowledged commit survives");
        }
        assert!(acked.lock().unwrap().len() >= 8, "the gates got going");
        // The reopened store keeps working.
        let r = Req::note(900_000 + round, &note(900_000 + round), 96, 50, None);
        let p = scenarios::new(exec.block_on(r.process(&store)));
        exec.block_on(outcome::settle(
            &store,
            &p,
            &settlement(&p, Status::Ok, T0 + 1, b"after"),
            &limits(),
        ))
        .unwrap();
        exec.block_on(store.close());
    }
}
