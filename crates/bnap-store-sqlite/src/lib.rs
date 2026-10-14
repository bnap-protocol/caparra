//! A durable BNAP use store on SQLite: [`SqliteStore`], an implementation
//! of [`bnap_core::store::UseStore`] (draft-00 sections 6.2 to 6.4).
//!
//! # Guarantees
//!
//! - **One serializable transaction per method.** Every write method runs
//!   in a `BEGIN IMMEDIATE` transaction, which takes the database's write
//!   lock before its first read, so no other write interleaves with it.
//!   Inside it the method loads the rows that the `bnap_core::store::logic`
//!   function of the same name reads, runs that function, and writes back
//!   what it changed. The store therefore behaves exactly as `logic` run
//!   atomically, which `bnap-store-tests` checks with bnap-core's
//!   conformance suite and with concurrency tests on separate connections.
//! - **Durable before it returns.** The database runs in WAL mode with
//!   `synchronous = FULL` (and `fullfsync` on macOS), so a commit that
//!   returned survives a crash or a power loss (draft-00 section 12,
//!   "Durability"). A transaction cut off by a crash or a dropped
//!   connection leaves nothing behind.
//! - **Fail closed.** Any database error, a lock not granted within the
//!   busy timeout, or a row that does not decode, is a
//!   [`StoreError`], which the gate answers with UNAVAILABLE.
//!
//! Reads ([`UseStore::outcome`], [`UseStore::counter`]) do not take the
//! write lock: WAL readers see the last committed state.
//!
//! The schema is embedded and applied by [`SqliteStore::open`]; see
//! `migrations/` in this crate.
//!
//! ```no_run
//! # async fn demo() -> Result<(), bnap_core::StoreError> {
//! let store = bnap_store_sqlite::SqliteStore::open("uses.sqlite").await?;
//! // Give `store` to `bnap_core::outcome::process` and friends.
//! # let _ = store;
//! # Ok(())
//! # }
//! ```

mod sql;
mod table;

use std::path::Path;
use std::time::Duration;

use bnap_core::store::{
    ChangeRequest, Commit, CommitPlan, OutcomeRecord, RefundRequest, Reserve, Settle,
    SettleRequest, SweepWindow, UseStore, logic,
};
use bnap_core::{CounterKey, ReplayKey, StoreError};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::{Sqlite, Transaction};

use crate::table::{Load, TxTable};

/// The schema, embedded at compile time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Pool and lock settings for [`SqliteStore::open_with`]. The durability
/// settings (WAL, `synchronous = FULL`, `fullfsync`) are not configurable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteConfig {
    /// Connections in the pool. Writes queue on the database's one write
    /// lock whatever the number; more connections let more reads run.
    pub max_connections: u32,
    /// How long a write waits for the write lock before it fails closed.
    pub busy_timeout: Duration,
    /// How long a call waits for a free connection before it fails closed.
    pub acquire_timeout: Duration,
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            max_connections: 8,
            busy_timeout: Duration::from_secs(10),
            acquire_timeout: Duration::from_secs(10),
        }
    }
}

/// A [`UseStore`] in one SQLite database file. Cheap to clone: clones share
/// the connection pool.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
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
            Error::Db(e) => format!("sqlite: {e}"),
            Error::Corrupt(what) => format!("sqlite: corrupt row: {what}"),
            Error::Unsupported(what) => format!("sqlite store bug: {what}"),
        })
    }
}

impl SqliteStore {
    /// Opens (creating it if missing) the database at `path` with the
    /// default [`SqliteConfig`] and applies the schema.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path, &SqliteConfig::default()).await
    }

    /// Opens (creating it if missing) the database at `path` and applies
    /// the schema.
    pub async fn open_with(
        path: impl AsRef<Path>,
        config: &SqliteConfig,
    ) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .locking_mode(SqliteLockingMode::Normal)
            .foreign_keys(true)
            .busy_timeout(config.busy_timeout)
            .pragma("fullfsync", "ON")
            .pragma("checkpoint_fullfsync", "ON");
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections.max(1))
            .acquire_timeout(config.acquire_timeout)
            .connect_with(options)
            .await
            .map_err(Error::Db)?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| StoreError(format!("sqlite: schema migration failed: {e}")))?;
        Ok(Self { pool })
    }

    /// The connection pool, for health checks and inspection. Writing to
    /// the store's tables through it bypasses every rule of the store.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
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
    /// pruned changes nothing. A counter whose `resets_at` is NULL, or at or
    /// above 2^63 (stored negative), is never pruned, whatever `now`: keeping
    /// a counter is the safe side. Run it with the sweep.
    pub async fn prune_counters(&self, now: u64) -> Result<u64, StoreError> {
        let Some(ended_by) = sql::below(now.saturating_sub(bnap_core::limits::CLOCK_SKEW)) else {
            return Ok(0);
        };
        let mut tx = self.write().await?;
        let n = sql::prune_counters(&mut tx, ended_by).await?;
        tx.commit().await.map_err(Error::Db)?;
        Ok(n)
    }

    /// A write transaction: `BEGIN IMMEDIATE` takes the write lock first.
    async fn write(&self) -> Result<Transaction<'static, Sqlite>, Error> {
        Ok(self.pool.begin_with("BEGIN IMMEDIATE").await?)
    }

    /// Writes back what `logic` changed in `t` and commits.
    async fn finish(mut tx: Transaction<'static, Sqlite>, t: &TxTable) -> Result<(), Error> {
        let writes = t.writes()?;
        if !writes.is_empty() {
            sql::apply(&mut tx, &writes).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Loads `outcome[rk]` as `load` says, and, with `Load::Full` or
    /// `Load::Counters`, every counter it names.
    async fn load(
        tx: &mut Transaction<'static, Sqlite>,
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
        tx: &mut Transaction<'static, Sqlite>,
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
        // A deferred transaction: one WAL snapshot for the record, its
        // counters and its outputs, without the write lock.
        let mut tx = self.pool.begin().await?;
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
impl UseStore for SqliteStore {
    async fn commit(&self, plan: &CommitPlan) -> Result<Commit, StoreError> {
        Ok(self.commit_tx(plan).await?)
    }

    async fn counter(&self, key: &CounterKey) -> Result<u64, StoreError> {
        Ok(self.counter_read(key).await?)
    }

    async fn outcome(&self, rk: &ReplayKey) -> Result<Option<OutcomeRecord>, StoreError> {
        Ok(self.outcome_tx(rk).await?)
    }

    async fn settle(&self, req: &SettleRequest<'_>) -> Result<Settle, StoreError> {
        Ok(self.settle_tx(req).await?)
    }

    async fn expire_pending(&self, window: &SweepWindow) -> Result<Vec<ReplayKey>, StoreError> {
        Ok(self.expire_tx(window).await?)
    }

    async fn record_refund(
        &self,
        req: &RefundRequest<'_>,
    ) -> Result<Option<OutcomeRecord>, StoreError> {
        Ok(self.refund_tx(req).await?)
    }

    async fn reserve_change(&self, req: &ChangeRequest<'_>) -> Result<Reserve, StoreError> {
        Ok(self.reserve_tx(req).await?)
    }

    async fn purge(&self, window: &SweepWindow) -> Result<u64, StoreError> {
        Ok(self.purge_tx(window).await?)
    }
}
