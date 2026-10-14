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
use bnap_store_tests::scenarios::Log;
use bnap_store_tests::scenarios::{self, Req, T0, limits, note, settlement};
use bnap_store_tests::{Dump, Held, Tokio, Tried, check_consistent};
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
fn change_outputs_are_matched_whole() {
    let exec = Tokio::new();
    scenarios::change_outputs_are_matched_whole(&fresh(&exec), &exec);
}

#[test]
fn mixed_load_moves_each_outcome_once() {
    let exec = Tokio::new();
    scenarios::mixed_load_moves_each_outcome_once(&fresh(&exec), &exec);
}

#[test]
fn pruning_spares_live_counters() {
    let exec = Tokio::new();
    let held = fresh(&exec);
    let store = &held.store;
    scenarios::pruning_spares_live_counters(
        store,
        &exec,
        |now| exec.block_on(store.prune_counters(now)).unwrap(),
        |key, resets_at| {
            exec.block_on(
                sqlx::query("INSERT INTO counter (counter_key, value, resets_at) VALUES (?, 1, ?)")
                    .bind(&key.0[..])
                    .bind(resets_at.map(u64::cast_signed))
                    .execute(store.pool()),
            )
            .unwrap();
        },
    );
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
        let pool = store.pool().clone();
        let log = Arc::new(Mutex::new(Log::default()));
        let gates: Vec<_> = (0..8)
            .map(|w| {
                let (store, log) = (Arc::clone(&store), Arc::clone(&log));
                exec.runtime().spawn(async move {
                    scenarios::gate(&*store, round * 8 + w, u32::MAX, &log).await;
                })
            })
            .collect();
        // Let the gates write, then cut them off while one holds a write
        // transaction open, and drop the pool with it.
        let start = std::time::Instant::now();
        while log.lock().unwrap().acked.len() < 24 && start.elapsed() < Duration::from_secs(60) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            gates.iter().all(|g| !g.is_finished()),
            "no gate stopped on its own"
        );
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
        // Connections the aborted calls dropped are still being closed in
        // the background (their transactions rolled back, or a COMMIT that
        // was already sent finishing); wait for that before reading, so the
        // check sees one quiet state.
        exec.block_on(pool.close());
        drop(pool);

        let store = open(&exec, &path);
        let d = dump(&exec, &store);
        let log = log.lock().unwrap().clone();
        check_consistent(&d, &log.tried);
        let committed: Vec<ReplayKey> = d.outcomes.iter().map(|(rk, _)| *rk).collect();
        for rk in &log.acked {
            assert!(committed.contains(rk), "an acknowledged commit survives");
        }
        assert!(log.acked.len() >= 24, "the gates got going");
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

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

/// The writer process of [`a_killed_writer_loses_nothing_it_acknowledged`]:
/// four gate loops on the database `BNAP_N5_CHILD_DB` names, printing
/// `tried <rk> <single>,<single>..` before each credential and `acked <rk>`
/// once `process` admitted it, until it is killed. Without the variable it
/// does nothing, so running ignored tests by hand is harmless.
#[test]
#[ignore = "the writer process a_killed_writer_loses_nothing_it_acknowledged starts"]
fn killed_writer_child() {
    use std::io::Write;
    let Ok(path) = std::env::var("BNAP_N5_CHILD_DB") else {
        return;
    };
    let base: u32 = std::env::var("BNAP_N5_CHILD_BASE")
        .ok()
        .and_then(|b| b.parse().ok())
        .unwrap_or(0);
    let exec = Tokio::new();
    let store = Arc::new(open(&exec, Path::new(&path)));
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let say = move |line: String| {
        let mut o = out.lock().unwrap();
        writeln!(o, "{line}").unwrap();
        o.flush().unwrap();
    };
    let lim = limits();
    bnap_store_tests::race(4, |w| {
        for n in 0..u32::MAX {
            let cred = base + u32::try_from(w).unwrap() * 1_000_000 + n;
            let r = Req::note(cred, &note(cred), 96, 50, Some((u64::MAX, b"everyone")));
            let t = r.tried();
            let singles: Vec<String> = t.singles.iter().map(|s| hex(s)).collect();
            say(format!(
                "tried {} {}",
                hex(&t.replay_key.0),
                singles.join(",")
            ));
            let p = scenarios::new(exec.block_on(r.process(&*store)));
            say(format!("acked {}", hex(&p.replay_key().0)));
            let status = if n % 3 == 0 {
                Status::Failed
            } else {
                Status::Ok
            };
            if n % 3 != 2 {
                let s = settlement(&p, status, T0 + 1, b"settled");
                exec.block_on(outcome::settle(&*store, &p, &s, &lim))
                    .unwrap();
            }
        }
    });
}

#[test]
fn a_killed_writer_loses_nothing_it_acknowledged() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let exec = Tokio::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("uses.sqlite");
    for round in 0..3u32 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "killed_writer_child", "--ignored", "--nocapture"])
            .env("BNAP_N5_CHILD_DB", &path)
            .env("BNAP_N5_CHILD_BASE", (round * 10_000).to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the writer starts");
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let (mut tried, mut acked) = (Vec::new(), Vec::new());
        while acked.len() < 60 {
            let Some(Ok(line)) = lines.next() else {
                panic!(
                    "the writer stopped on its own after {} admissions",
                    acked.len()
                );
            };
            if let Some(rest) = line.strip_prefix("tried ") {
                let (rk, singles) = rest.split_once(' ').unwrap();
                tried.push(Tried {
                    replay_key: ReplayKey(unhex32(rk)),
                    singles: singles.split(',').map(unhex32).collect(),
                });
            } else if let Some(rk) = line.strip_prefix("acked ") {
                acked.push(ReplayKey(unhex32(rk)));
            }
        }
        // SIGKILL: no destructor, no rollback, mid-write for some threads.
        child.kill().unwrap();
        child.wait().unwrap();

        let store = open(&exec, &path);
        let d = dump(&exec, &store);
        check_consistent(&d, &tried);
        let committed: Vec<ReplayKey> = d.outcomes.iter().map(|(rk, _)| *rk).collect();
        for rk in &acked {
            assert!(
                committed.contains(rk),
                "an acknowledged commit survives a kill"
            );
        }
        exec.block_on(store.close());
    }
}
