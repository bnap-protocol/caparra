//! The `bnap:notes` issuer tables the gate keeps (notes spec 7.4, 8.6).
//!
//! The keyset table is rebuilt from the signer's keysets at every start, so
//! it lives in memory. Fund quotes and signed-output records must outlive
//! a restart: they go in a SQLite file with the same durability settings
//! as the use store (WAL, `synchronous = FULL`), one transaction per write.
//! `memory` keeps them in a temporary file that is deleted at exit.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use bnap_scheme_notes::issuer::QuoteInsert;
use bnap_scheme_notes::keyset::{BlindSigned, KeysetInfo};
use bnap_scheme_notes::wire::{KeysetIdBytes, PointBytes};
use bnap_scheme_notes::{IssuerError, IssuerStore, QuoteRecord, SignedOutput};
use sqlx::Row as _;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS quotes (
        id TEXT PRIMARY KEY, method TEXT NOT NULL, unit TEXT NOT NULL,
        amount INTEGER NOT NULL, request TEXT NOT NULL, payment_hash BLOB NOT NULL,
        expiry INTEGER NOT NULL, pubkey BLOB, paid INTEGER NOT NULL,
        issued INTEGER NOT NULL, created INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS outputs (
        blinded BLOB NOT NULL, source BLOB NOT NULL, keyset BLOB NOT NULL,
        amount INTEGER NOT NULL, c BLOB NOT NULL, e BLOB NOT NULL, s BLOB NOT NULL,
        PRIMARY KEY (blinded, source))",
    "CREATE INDEX IF NOT EXISTS outputs_source ON outputs (source)",
];

/// The gate's issuer store.
#[derive(Debug)]
pub struct GateIssuerStore {
    keysets: Mutex<BTreeMap<KeysetIdBytes, KeysetInfo>>,
    pool: SqlitePool,
}

fn err(e: impl std::fmt::Display) -> IssuerError {
    IssuerError(format!("issuer store: {e}"))
}

fn to_i64(v: u64) -> Result<i64, IssuerError> {
    i64::try_from(v).map_err(err)
}

fn to_u64(v: i64) -> Result<u64, IssuerError> {
    u64::try_from(v).map_err(err)
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], IssuerError> {
    v.try_into().map_err(|_| err("corrupt row"))
}

impl GateIssuerStore {
    /// Opens (creating it if missing) the issuer tables at `path`.
    pub async fn open(path: &Path) -> Result<Self, IssuerError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(std::time::Duration::from_secs(10))
            .pragma("fullfsync", "ON");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(err)?;
        for s in SCHEMA {
            sqlx::query(*s).execute(&pool).await.map_err(err)?;
        }
        Ok(Self {
            keysets: Mutex::new(BTreeMap::new()),
            pool,
        })
    }

    fn table(&self) -> std::sync::MutexGuard<'_, BTreeMap<KeysetIdBytes, KeysetInfo>> {
        self.keysets.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn quote_of(row: &sqlx::sqlite::SqliteRow) -> Result<QuoteRecord, IssuerError> {
    let pubkey: Option<Vec<u8>> = row.try_get("pubkey").map_err(err)?;
    Ok(QuoteRecord {
        id: row.try_get("id").map_err(err)?,
        method: row.try_get("method").map_err(err)?,
        unit: row.try_get("unit").map_err(err)?,
        amount: to_u64(row.try_get("amount").map_err(err)?)?,
        request: row.try_get("request").map_err(err)?,
        payment_hash: fixed(&row.try_get::<Vec<u8>, _>("payment_hash").map_err(err)?)?,
        expiry: to_u64(row.try_get("expiry").map_err(err)?)?,
        pubkey: pubkey.map(|p| fixed::<33>(&p)).transpose()?,
        paid: row.try_get::<i64, _>("paid").map_err(err)? != 0,
        issued: row.try_get::<i64, _>("issued").map_err(err)? != 0,
        created: to_u64(row.try_get("created").map_err(err)?)?,
    })
}

fn output_of(row: &sqlx::sqlite::SqliteRow) -> Result<SignedOutput, IssuerError> {
    Ok(SignedOutput {
        keyset: fixed(&row.try_get::<Vec<u8>, _>("keyset").map_err(err)?)?,
        amount: to_u64(row.try_get("amount").map_err(err)?)?,
        blinded: fixed(&row.try_get::<Vec<u8>, _>("blinded").map_err(err)?)?,
        source: fixed(&row.try_get::<Vec<u8>, _>("source").map_err(err)?)?,
        signature: BlindSigned {
            c: fixed(&row.try_get::<Vec<u8>, _>("c").map_err(err)?)?,
            e: fixed(&row.try_get::<Vec<u8>, _>("e").map_err(err)?)?,
            s: fixed(&row.try_get::<Vec<u8>, _>("s").map_err(err)?)?,
        },
    })
}

#[async_trait::async_trait]
impl IssuerStore for GateIssuerStore {
    async fn keysets(&self) -> Result<Vec<KeysetInfo>, IssuerError> {
        Ok(self.table().values().cloned().collect())
    }

    async fn put_keyset(&self, keyset: &KeysetInfo) -> Result<(), IssuerError> {
        self.table().insert(keyset.id, keyset.clone());
        Ok(())
    }

    async fn quote(&self, id: &str) -> Result<Option<QuoteRecord>, IssuerError> {
        let row = sqlx::query("SELECT * FROM quotes WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(err)?;
        row.as_ref().map(quote_of).transpose()
    }

    async fn insert_quote(&self, q: &QuoteRecord) -> Result<QuoteInsert, IssuerError> {
        let mut tx = self.pool.begin().await.map_err(err)?;
        let existing = sqlx::query("SELECT * FROM quotes WHERE id = ?")
            .bind(&q.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(err)?;
        if let Some(row) = existing {
            return Ok(QuoteInsert::Exists(quote_of(&row)?));
        }
        sqlx::query(
            "INSERT INTO quotes (id, method, unit, amount, request, payment_hash, expiry, pubkey, paid, issued, created)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&q.id)
        .bind(&q.method)
        .bind(&q.unit)
        .bind(to_i64(q.amount)?)
        .bind(&q.request)
        .bind(q.payment_hash.to_vec())
        .bind(to_i64(q.expiry)?)
        .bind(q.pubkey.map(|p| p.to_vec()))
        .bind(i64::from(q.paid))
        .bind(i64::from(q.issued))
        .bind(to_i64(q.created)?)
        .execute(&mut *tx)
        .await
        .map_err(err)?;
        tx.commit().await.map_err(err)?;
        Ok(QuoteInsert::Inserted)
    }

    async fn mark_quote(&self, id: &str, paid: bool, issued: bool) -> Result<(), IssuerError> {
        sqlx::query("UPDATE quotes SET paid = MAX(paid, ?), issued = MAX(issued, ?) WHERE id = ?")
            .bind(i64::from(paid))
            .bind(i64::from(issued))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn put_outputs(&self, outputs: &[SignedOutput]) -> Result<(), IssuerError> {
        let mut tx = self.pool.begin().await.map_err(err)?;
        for o in outputs {
            sqlx::query(
                "INSERT OR IGNORE INTO outputs (blinded, source, keyset, amount, c, e, s)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(o.blinded.to_vec())
            .bind(o.source.to_vec())
            .bind(o.keyset.to_vec())
            .bind(to_i64(o.amount)?)
            .bind(o.signature.c.to_vec())
            .bind(o.signature.e.to_vec())
            .bind(o.signature.s.to_vec())
            .execute(&mut *tx)
            .await
            .map_err(err)?;
        }
        tx.commit().await.map_err(err)
    }

    async fn outputs_by_source(&self, source: &[u8; 32]) -> Result<Vec<SignedOutput>, IssuerError> {
        let rows = sqlx::query("SELECT * FROM outputs WHERE source = ? ORDER BY rowid")
            .bind(source.to_vec())
            .fetch_all(&self.pool)
            .await
            .map_err(err)?;
        rows.iter().map(output_of).collect()
    }

    async fn outputs_by_blinded(
        &self,
        blinded: &[PointBytes],
    ) -> Result<Vec<SignedOutput>, IssuerError> {
        let mut out = Vec::new();
        for b in blinded {
            let rows = sqlx::query("SELECT * FROM outputs WHERE blinded = ? ORDER BY rowid")
                .bind(b.to_vec())
                .fetch_all(&self.pool)
                .await
                .map_err(err)?;
            for r in &rows {
                out.push(output_of(r)?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(id: &str) -> QuoteRecord {
        QuoteRecord {
            id: id.into(),
            method: "bolt11".into(),
            unit: "sat".into(),
            amount: 21,
            request: "lnbcrt...".into(),
            payment_hash: [7; 32],
            expiry: 100,
            pubkey: Some([2; 33]),
            paid: false,
            issued: false,
            created: 1,
        }
    }

    #[tokio::test]
    async fn quotes_and_outputs_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("issuer.db");
        {
            let s = GateIssuerStore::open(&path).await.unwrap();
            assert_eq!(
                s.insert_quote(&quote("q")).await.unwrap(),
                QuoteInsert::Inserted
            );
            let mut other = quote("q");
            other.amount = 5;
            assert_eq!(
                s.insert_quote(&other).await.unwrap(),
                QuoteInsert::Exists(quote("q")),
                "first write wins"
            );
            s.mark_quote("q", true, false).await.unwrap();
            s.mark_quote("q", false, false).await.unwrap();
            let o = SignedOutput {
                keyset: [1; 33],
                amount: 4,
                blinded: [3; 33],
                source: [9; 32],
                signature: BlindSigned {
                    c: [4; 33],
                    e: [5; 32],
                    s: [6; 32],
                },
            };
            s.put_outputs(&[o.clone(), o]).await.unwrap();
        }
        let s = GateIssuerStore::open(&path).await.unwrap();
        let q = s.quote("q").await.unwrap().unwrap();
        assert!(q.paid, "a flag is never cleared");
        assert!(!q.issued);
        assert_eq!(s.outputs_by_source(&[9; 32]).await.unwrap().len(), 1);
        assert_eq!(s.outputs_by_blinded(&[[3; 33]]).await.unwrap().len(), 1);
        assert_eq!(s.outputs_by_blinded(&[[8; 33]]).await.unwrap(), Vec::new());
    }
}
