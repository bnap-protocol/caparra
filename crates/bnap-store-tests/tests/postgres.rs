//! `bnap-store-postgres` against bnap-core's conformance suite, the
//! concurrency scenarios and a pool dropped mid-transaction.
//!
//! Needs a Postgres server: set `DATABASE_URL` (for example
//! `postgres://postgres:test@127.0.0.1:55432/postgres`). Without it every
//! test here passes at once and says it skipped. Each store lives in a
//! schema of its own, created for the test and dropped after it.

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bnap_core::outcome;
use bnap_core::store::UseStore;
use bnap_core::test_support::conformance::{self, Executor};
use bnap_core::{CounterKey, ReplayKey, Status};
use bnap_store_postgres::{PostgresConfig, PostgresStore};
use bnap_store_tests::scenarios::{self, Req, T0, limits, note, settlement};
use bnap_store_tests::{Dump, Held, Tokio, check_consistent};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Row};

/// `DATABASE_URL`, or `None` (and a note on stderr) to skip.
fn database_url() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty());
    if url.is_none() {
        eprintln!(
            "skipped: DATABASE_URL is not set, so the Postgres store is not tested here \
             (see notes/n5-stores.md)"
        );
    }
    url
}

/// Enough connections for every task of a scenario to hold its own.
fn config() -> PostgresConfig {
    PostgresConfig {
        max_connections: 24,
        acquire_timeout: Duration::from_secs(60),
        max_retries: 1_000,
    }
}

/// A schema name no other test uses.
fn schema_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!(
        "bnap_n5_{}_{}_{}",
        std::process::id(),
        nanos,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Drops its schema when dropped.
struct Schema {
    url: String,
    name: String,
    handle: tokio::runtime::Handle,
}

impl Schema {
    fn create(exec: &Tokio, url: &str) -> Self {
        let name = schema_name();
        exec.block_on(async {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(url)
                .await
                .expect("DATABASE_URL connects");
            sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {name}")))
                .execute(&admin)
                .await
                .unwrap();
            admin.close().await;
        });
        Self {
            url: url.to_owned(),
            name,
            handle: exec.runtime().handle().clone(),
        }
    }

    /// Connection options whose `search_path` and application name are the
    /// schema.
    fn options(&self) -> PgConnectOptions {
        PgConnectOptions::from_str(&self.url)
            .unwrap()
            .options([("search_path", &self.name)])
            .application_name(&self.name)
    }

    fn open(&self, exec: &Tokio) -> PostgresStore {
        exec.block_on(PostgresStore::connect_with(self.options(), &config()))
            .expect("the store connects")
    }

    /// Runs `sql` with `$1` bound to the schema name, on a connection
    /// outside the schema, and returns how many rows it returned.
    fn admin(&self, exec: &Tokio, sql: &'static str) -> usize {
        exec.block_on(async {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.url)
                .await
                .unwrap();
            let n = sqlx::query(sql)
                .bind(&self.name)
                .fetch_all(&admin)
                .await
                .unwrap()
                .len();
            admin.close().await;
            n
        })
    }
}

impl Drop for Schema {
    fn drop(&mut self) {
        let (url, name) = (self.url.clone(), self.name.clone());
        let _ = self.handle.block_on(async move {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await?;
            sqlx::query(AssertSqlSafe(format!(
                "DROP SCHEMA IF EXISTS {name} CASCADE"
            )))
            .execute(&admin)
            .await?;
            admin.close().await;
            Ok::<_, sqlx::Error>(())
        });
    }
}

/// A store in a new, empty schema, dropped with it.
fn fresh(exec: &Tokio, url: &str) -> Held<PostgresStore> {
    let schema = Schema::create(exec, url);
    let store = schema.open(exec);
    Held::new(store, schema)
}

fn key32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// Every row, read through the raw tables and the store.
fn dump(exec: &Tokio, store: &PostgresStore) -> Dump {
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
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    conformance::run(|| fresh(&exec, &url), &exec);
}

#[test]
fn one_note_admits_one_action() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::one_note_admits_one_action(&fresh(&exec, &url), &exec);
}

#[test]
fn one_payment_under_two_schemes_admits_one_action() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::one_payment_under_two_schemes_admits_one_action(&fresh(&exec, &url), &exec);
}

#[test]
fn settle_and_sweep_race_to_one_transition() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::settle_and_sweep_race_to_one_transition(&fresh(&exec, &url), &exec);
}

#[test]
fn concurrent_replays_get_one_answer() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::concurrent_replays_get_one_answer(&fresh(&exec, &url), &exec);
}

#[test]
fn counters_never_pass_their_limit() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::counters_never_pass_their_limit(&fresh(&exec, &url), &exec);
}

#[test]
fn change_reservations_keep_one_total() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    scenarios::change_reservations_keep_one_total(&fresh(&exec, &url), &exec);
}

#[test]
fn the_schema_is_applied_once_and_a_store_reconnects() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    let schema = Schema::create(&exec, &url);
    let r = Req::note(1, &note(1), 96, 50, Some((10, b"who")));
    let store = schema.open(&exec);
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
    let again = schema.open(&exec);
    let rec = scenarios::replay(exec.block_on(r.at(T0 + 2).process(&again)));
    assert_eq!(rec.record(), done.record());
    let sync: String = exec
        .block_on(sqlx::query_scalar("SHOW synchronous_commit").fetch_one(again.pool()))
        .unwrap();
    assert_eq!(sync, "on");
    exec.block_on(again.close());
}

#[test]
fn a_pool_dropped_mid_transaction_leaves_a_consistent_store() {
    let Some(url) = database_url() else { return };
    let exec = Tokio::new();
    let schema = Schema::create(&exec, &url);
    for round in 0..3 {
        let store = Arc::new(schema.open(&exec));
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
        // Let the gates write, then cut them off while transactions are
        // open, kill their server sessions and drop the pool.
        std::thread::sleep(Duration::from_millis(300));
        let mut seen = false;
        for _ in 0..1_000 {
            let open = schema.admin(
                &exec,
                "SELECT pid FROM pg_stat_activity WHERE application_name = $1 \
                 AND xact_start IS NOT NULL AND state <> 'idle'",
            );
            if open > 0 {
                seen = true;
                break;
            }
        }
        for g in &gates {
            g.abort();
        }
        schema.admin(
            &exec,
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
        );
        assert!(seen, "a transaction was open when the gates stopped");
        for g in gates {
            if let Err(e) = exec.block_on(g) {
                assert!(e.is_cancelled(), "a gate failed: {e:?}");
            }
        }
        drop(Arc::into_inner(store).expect("the gates let go of the store"));

        let store = schema.open(&exec);
        let d = dump(&exec, &store);
        let tried = tried.lock().unwrap().clone();
        check_consistent(&d, &tried);
        let committed: Vec<ReplayKey> = d.outcomes.iter().map(|(rk, _)| *rk).collect();
        for rk in acked.lock().unwrap().iter() {
            assert!(committed.contains(rk), "an acknowledged commit survives");
        }
        assert!(acked.lock().unwrap().len() >= 8, "the gates got going");
        // The reconnected store keeps working.
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
