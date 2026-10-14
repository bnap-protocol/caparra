//! A durable BNAP use store on PostgreSQL: [`PostgresStore`], an
//! implementation of [`bnap_core::store::UseStore`] (draft-00 sections 6.2
//! to 6.4).
//!
//! # Guarantees
//!
//! - **One serializable transaction per method.** Every write method runs
//!   in a `SERIALIZABLE` transaction. Inside it the method loads the rows
//!   that the `bnap_core::store::logic` function of the same name reads,
//!   runs that function, and writes back what it changed. Postgres's
//!   serializable isolation (SSI) aborts any transaction whose outcome
//!   would differ from some serial order, with a serialization failure
//!   (`40001`); the store then runs the whole method again, from a fresh
//!   transaction, up to [`PostgresConfig::max_retries`] times with jittered
//!   backoff. Deadlocks (`40P01`) and a unique violation from a concurrent
//!   insert of the same key (`23505`) are retried the same way. The store
//!   therefore behaves exactly as `logic` run atomically, which
//!   `bnap-store-tests` checks with bnap-core's conformance suite and with
//!   concurrency tests on separate connections.
//! - **Durable before it returns.** Every connection runs with
//!   `synchronous_commit = on`, whatever the server's default, so a commit
//!   that returned is flushed to the write-ahead log (draft-00 section 12,
//!   "Durability"). A transaction cut off by a crash or a dropped connection
//!   is rolled back by the server.
//! - **Fail closed.** Any other database error, retries exhausted, or a row
//!   that does not decode, is a [`StoreError`], which the gate answers with
//!   UNAVAILABLE. A connection lost while `COMMIT` was in flight is reported
//!   as an error although the write may have committed; the client's retry
//!   then finds the outcome (a replay, or PENDING), never a second action.
//!
//! [`UseStore::outcome`] reads in one `REPEATABLE READ, READ ONLY`
//! snapshot and [`UseStore::counter`] in one statement; neither blocks a
//! writer.
//!
//! The schema is embedded and applied by [`PostgresStore::connect`]; see
//! `migrations/` in this crate. It lives in the connection's `search_path`
//! (`public` by default), so one database can hold several stores in
//! separate schemas.
//!
//! ```no_run
//! # async fn demo() -> Result<(), bnap_core::StoreError> {
//! let store = bnap_store_postgres::PostgresStore::connect("postgres://gate@db/uses").await?;
//! // Give `store` to `bnap_core::outcome::process` and friends.
//! # let _ = store;
//! # Ok(())
//! # }
//! ```

mod sql;
mod table;

use std::future::Future;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::str::FromStr;
use std::time::Duration;

use bnap_core::store::{
    ChangeRequest, Commit, CommitPlan, OutcomeRecord, RefundRequest, Reserve, Settle,
    SettleRequest, SweepWindow, UseStore, logic,
};
use bnap_core::{CounterKey, ReplayKey, StoreError};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Postgres, Transaction};

use crate::table::{Load, TxTable};

/// The schema, embedded at compile time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SQLSTATEs after which the whole method runs again: a serialization
/// failure, a deadlock, and a unique violation from a concurrent insert of
/// the same key (which Postgres reports as `23505` rather than `40001` in
/// some interleavings).
const RETRY: [&str; 3] = ["40001", "40P01", "23505"];

/// Pool and retry settings for [`PostgresStore::connect_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresConfig {
    /// Connections in the pool.
    pub max_connections: u32,
    /// How long a call waits for a free connection before it fails closed.
    pub acquire_timeout: Duration,
    /// How many times a method runs again after a serialization failure,
    /// a deadlock or a concurrent insert, before it fails closed.
    pub max_retries: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            acquire_timeout: Duration::from_secs(10),
            max_retries: 64,
        }
    }
}

/// A [`UseStore`] in a Postgres database. Cheap to clone: clones share the
/// connection pool.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
    max_retries: u32,
}

/// What can go wrong inside a method; every case fails closed.
#[derive(Debug)]
enum Error {
    /// The database refused or failed.
    Db(sqlx::Error),
    /// A row that does not decode.
    Corrupt(String),
    /// A store bug caught before anything was written.
    Unsupported(&'static str),
}

impl Error {
    /// True for a transaction Postgres aborted because of a concurrent
    /// one: running the method again is safe, since nothing was written.
    fn retryable(&self) -> bool {
        match self {
            Self::Db(sqlx::Error::Database(e)) => e.code().is_some_and(|c| RETRY.contains(&&*c)),
            _ => false,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<table::Unsupported> for Error {
    fn from(e: table::Unsupported) -> Self {
        Self::Unsupported(e.0)
    }
}

impl From<Error> for StoreError {
    fn from(e: Error) -> Self {
        StoreError(match e {
            Error::Db(e) => format!("postgres: {e}"),
            Error::Corrupt(what) => format!("postgres: corrupt row: {what}"),
            Error::Unsupported(what) => format!("postgres store bug: {what}"),
        })
    }
}

/// A random pause before attempt `n + 1`: up to 2^n ms, at most 128 ms
/// (full jitter), so retries of conflicting methods spread out.
fn backoff(n: u32) -> Duration {
    let mut h = RandomState::new().build_hasher();
    h.write_u32(n);
    let cap_us = 1_000u64 << n.min(7);
    Duration::from_micros(h.finish() % (cap_us + 1))
}

impl PostgresStore {
    /// Connects to the database at `url` with the default
    /// [`PostgresConfig`] and applies the schema.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = PgConnectOptions::from_str(url)
            .map_err(|e| StoreError(format!("postgres: bad database URL: {e}")))?;
        Self::connect_with(options, &PostgresConfig::default()).await
    }

    /// Connects with `options` (host, credentials, TLS, `search_path`,
    /// application name) and applies the schema. `synchronous_commit` is
    /// forced on for every connection.
    pub async fn connect_with(
        options: PgConnectOptions,
        config: &PostgresConfig,
    ) -> Result<Self, StoreError> {
        let options = options.options([("synchronous_commit", "on")]);
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections.max(1))
            .acquire_timeout(config.acquire_timeout)
            .connect_with(options)
            .await
            .map_err(Error::Db)?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| StoreError(format!("postgres: schema migration failed: {e}")))?;
        Ok(Self {
            pool,
            max_retries: config.max_retries,
        })
    }

    /// The connection pool, for health checks and inspection. Writing to
    /// the store's tables through it bypasses every rule of the store.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Closes every connection, waiting for calls in flight to finish.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Deletes rate and quota counters whose epoch ended more than a clock
    /// skew before `now`, and returns how many.
    ///
    /// Not part of [`UseStore`]: `logic` never deletes a counter, so a
    /// counter key of every past epoch stays forever unless the operator
    /// prunes them. A commit always counts in the epoch of its own clock,
    /// so a counter whose epoch ended is never read or incremented again by
    /// a gate whose clock is within the skew; giving one back after it is
    /// pruned changes nothing. Run it with the sweep.
    pub async fn prune_counters(&self, now: u64) -> Result<u64, StoreError> {
        let Some(ended_by) = sql::below(now.saturating_sub(bnap_core::limits::CLOCK_SKEW)) else {
            return Ok(0);
        };
        self.retry(|| async {
            let mut tx = self.write().await?;
            let n = sql::prune_counters(&mut tx, ended_by).await?;
            tx.commit().await?;
            Ok(n)
        })
        .await
    }

    /// Runs `attempt` until it succeeds, fails for a reason other than a
    /// concurrent transaction, or has been retried `max_retries` times.
    async fn retry<R, F, Fut>(&self, mut attempt: F) -> Result<R, StoreError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<R, Error>>,
    {
        let mut n = 0;
        loop {
            match attempt().await {
                Ok(r) => return Ok(r),
                Err(e) if e.retryable() && n < self.max_retries => {
                    tokio::time::sleep(backoff(n)).await;
                    n += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// A serializable write transaction.
    async fn write(&self) -> Result<Transaction<'static, Postgres>, Error> {
        Ok(self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .await?)
    }

    /// Writes back what `logic` changed in `t` and commits.
    async fn finish(mut tx: Transaction<'static, Postgres>, t: &TxTable) -> Result<(), Error> {
        let writes = t.writes()?;
        if !writes.is_empty() {
            sql::apply(&mut tx, &writes).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Loads `outcome[rk]` as `load` says, and every counter it names.
    async fn load(
        tx: &mut Transaction<'static, Postgres>,
        t: &mut TxTable,
        rk: &ReplayKey,
        load: Load,
    ) -> Result<(), Error> {
        let rec = sql::outcome(tx, rk, load).await?;
        t.load_outcome(*rk, rec);
        Self::load_counters(tx, t).await
    }

    /// Loads every counter the loaded records name.
    async fn load_counters(
        tx: &mut Transaction<'static, Postgres>,
        t: &mut TxTable,
    ) -> Result<(), Error> {
        for key in t.unloaded_counters() {
            let v = sql::counter(tx, &key).await?;
            t.load_counter(key, v, None);
        }
        Ok(())
    }

    async fn commit_tx(&self, plan: &CommitPlan) -> Result<Commit, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        let rk = *plan.replay_key();
        let rec = sql::outcome(&mut tx, &rk, Load::Full).await?;
        t.load_outcome(rk, rec);
        for id in plan.singles() {
            let used = sql::is_used(&mut tx, id).await?;
            t.load_used(*id, used);
        }
        for c in plan.counters() {
            let v = sql::counter(&mut tx, &c.key).await?;
            t.load_counter(c.key, v, Some(c.resets_at));
        }
        let out = logic::commit(&mut t, plan);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn settle_tx(&self, req: &SettleRequest<'_>) -> Result<Settle, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        Self::load(&mut tx, &mut t, req.replay_key(), Load::Full).await?;
        let out = logic::settle(&mut t, req);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn expire_tx(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        for (rk, rec) in sql::pending_before(&mut tx, window.timeout_before()).await? {
            t.load_outcome(rk, Some(rec));
        }
        Self::load_counters(&mut tx, &mut t).await?;
        let out = logic::expire_pending(&mut t, window);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn refund_tx(&self, req: &RefundRequest<'_>) -> Result<Option<OutcomeRecord>, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        Self::load(&mut tx, &mut t, req.replay_key(), Load::Full).await?;
        let out = logic::record_refund(&mut t, req);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn reserve_tx(&self, req: &ChangeRequest<'_>) -> Result<Reserve, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        let rk = req.replay_key();
        Self::load(&mut tx, &mut t, rk, Load::Columns).await?;
        let known = sql::outputs_among(&mut tx, rk, req.outputs()).await?;
        t.load_outputs(rk, &known);
        let out = logic::reserve_change(&mut t, req);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn purge_tx(&self, window: &SweepWindow) -> Result<u64, Error> {
        let mut tx = self.write().await?;
        let mut t = TxTable::default();
        for (rk, rec) in sql::purgeable(&mut tx, window.purge_before(), window.now()).await? {
            t.load_outcome(rk, Some(rec));
        }
        let out = logic::purge(&mut t, window);
        Self::finish(tx, &t).await?;
        Ok(out)
    }

    async fn outcome_tx(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, Error> {
        // One snapshot for the record, its counters and its outputs.
        let mut tx = self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .await?;
        let rec = sql::outcome(&mut tx, rk, Load::Full).await?;
        tx.commit().await?;
        Ok(rec)
    }

    async fn counter_read(&self, key: &CounterKey) -> Result<u64, Error> {
        let mut conn = self.pool.acquire().await?;
        sql::counter(&mut conn, key).await
    }
}

#[async_trait::async_trait]
impl UseStore for PostgresStore {
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
        self.retry(|| self.commit_tx(plan)).await
    }

    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
        self.retry(|| self.counter_read(key)).await
    }

    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
        self.retry(|| self.outcome_tx(rk)).await
    }

    async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
        self.retry(|| self.settle_tx(req)).await
    }

    async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
        self.retry(|| self.expire_tx(window)).await
    }

    async fn record_refund(
        &self,
        req: &RefundRequest<'_>,
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        self.retry(|| self.refund_tx(req)).await
    }

    async fn reserve_change(&self, req: &ChangeRequest<'_>) -> Result<Reserve, StoreError> {
        self.retry(|| self.reserve_tx(req)).await
    }

    async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
        self.retry(|| self.purge_tx(window)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_stays_within_its_cap() {
        for n in 0..20 {
            let cap = Duration::from_micros(1_000 << n.min(7));
            assert!(backoff(n) <= cap);
        }
    }
}
