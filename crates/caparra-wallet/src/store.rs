//! The wallet's store: one SQLite file, every record encrypted at rest.
//!
//! The key comes from a passphrase through argon2id (salt and parameters
//! in the file), and every record is sealed with XChaCha20-Poly1305 under a
//! fresh random nonce, the record's kind and ID as associated data. Record
//! IDs are keyed hashes of their names, so the file shows how many records
//! of each kind it holds, never which origins, notes or keys they name.
//!
//! Writes that must not race (a budget reservation together with the notes
//! it locks, a counter advance) run in one `BEGIN IMMEDIATE` transaction,
//! which takes SQLite's write lock first: two processes on one wallet (the
//! CLI and the MCP server) serialize there.

use std::path::Path;
use std::sync::Arc;

use bnap_core::hash::hmac_sha256;
use bnap_core::secp256k1::rand::{RngCore, thread_rng};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Row, Sqlite, Transaction};
use zeroize::Zeroizing;

use crate::error::{Code, Refusal, Result};

const CHECK: &[u8] = b"caparra-wallet store v1";

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane.
    fn default() -> Self {
        Self {
            m_kib: 65_536,
            t: 3,
            p: 1,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for tests only.
    #[must_use]
    pub fn insecure_for_tests() -> Self {
        Self {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }
}

struct Keys {
    seal: Zeroizing<[u8; 32]>,
    name: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn derive(passphrase: &str, salt: &[u8], kdf: &KdfParams) -> Result<Self> {
        let params = argon2::Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
            .map_err(|e| Refusal::storage(format!("bad key derivation parameters: {e}")))?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut master = Zeroizing::new([0u8; 32]);
        a.hash_password_into(passphrase.as_bytes(), salt, &mut *master)
            .map_err(|e| Refusal::storage(format!("key derivation failed: {e}")))?;
        Ok(Self {
            seal: Zeroizing::new(hmac_sha256(&*master, b"seal")),
            name: Zeroizing::new(hmac_sha256(&*master, b"name")),
        })
    }

    fn id(&self, kind: &str, name: &str) -> [u8; 32] {
        let mut m = Vec::with_capacity(kind.len() + name.len() + 1);
        m.extend_from_slice(kind.as_bytes());
        m.push(0);
        m.extend_from_slice(name.as_bytes());
        hmac_sha256(&*self.name, &m)
    }

    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0u8; 24];
        thread_rng().fill_bytes(&mut nonce);
        let c = XChaCha20Poly1305::new((&*self.seal).into());
        let ct = c
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad })
            .map_err(|_| Refusal::storage("cannot seal a record"))?;
        Ok((nonce.to_vec(), ct))
    }

    fn open(&self, aad: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if nonce.len() != 24 {
            return None;
        }
        let c = XChaCha20Poly1305::new((&*self.seal).into());
        c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .ok()
            .map(Zeroizing::new)
    }
}

fn aad(kind: &str, id: &[u8]) -> Vec<u8> {
    [kind.as_bytes(), &[0], id].concat()
}

fn db(e: sqlx::Error) -> Refusal {
    Refusal::storage(e)
}

/// The open store.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    keys: Arc<Keys>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

async fn connect(path: &Path, create: bool) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .map_err(db)?;
    sqlx::query("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)")
        .execute(&pool)
        .await
        .map_err(db)?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS record (kind TEXT NOT NULL, id BLOB NOT NULL, \
         nonce BLOB NOT NULL, ct BLOB NOT NULL, PRIMARY KEY (kind, id))",
    )
    .execute(&pool)
    .await
    .map_err(db)?;
    Ok(pool)
}

impl Store {
    /// Creates a new store at `path`. Refuses when a file is already there.
    pub async fn create(path: &Path, passphrase: &str, kdf: KdfParams) -> Result<Self> {
        if path.exists() {
            return Err(Refusal::new(
                Code::WalletExists,
                format!(
                    "A wallet already exists at {}. Use it, or pick another path with --wallet.",
                    path.display()
                ),
            ));
        }
        if passphrase.is_empty() {
            return Err(Refusal::bad_input("The passphrase must not be empty."));
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(Refusal::storage)?;
        }
        let pool = connect(path, true).await?;
        restrict(path);
        let mut salt = [0u8; 16];
        thread_rng().fill_bytes(&mut salt);
        let keys = Keys::derive(passphrase, &salt, &kdf)?;
        let (nonce, ct) = keys.seal(b"check", CHECK)?;
        let kdf_json = serde_json::to_vec(&kdf).map_err(Refusal::storage)?;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        for (k, v) in [
            ("salt", salt.to_vec()),
            ("kdf", kdf_json),
            ("check", [nonce, ct].concat()),
        ] {
            sqlx::query("INSERT INTO meta (k, v) VALUES (?, ?)")
                .bind(k)
                .bind(v)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(Self {
            pool,
            keys: Arc::new(keys),
        })
    }

    /// Opens the store at `path` with its passphrase.
    pub async fn open(path: &Path, passphrase: &str) -> Result<Self> {
        if !path.exists() {
            return Err(Refusal::new(
                Code::NoWallet,
                format!(
                    "No wallet at {}. Create one with `bnap init`.",
                    path.display()
                ),
            ));
        }
        let pool = connect(path, false).await?;
        let meta = |k: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query("SELECT v FROM meta WHERE k = ?")
                    .bind(k)
                    .fetch_optional(&pool)
                    .await
                    .map_err(db)?
                    .map(|r| r.get::<Vec<u8>, _>(0))
                    .ok_or_else(|| Refusal::storage(format!("the wallet file has no {k}")))
            }
        };
        let salt = meta("salt").await?;
        let kdf: KdfParams =
            serde_json::from_slice(&meta("kdf").await?).map_err(Refusal::storage)?;
        let check = meta("check").await?;
        let keys = Keys::derive(passphrase, &salt, &kdf)?;
        let ok = check.len() > 24
            && keys
                .open(b"check", &check[..24], &check[24..])
                .is_some_and(|p| p.as_slice() == CHECK);
        if !ok {
            return Err(Refusal::new(
                Code::Locked,
                "Wrong passphrase. Set BNAP_PASSPHRASE or type it again.",
            ));
        }
        Ok(Self {
            pool,
            keys: Arc::new(keys),
        })
    }

    /// A write transaction that holds SQLite's write lock from the start.
    pub async fn tx(&self) -> Result<Tx> {
        Ok(Tx {
            inner: self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?,
            keys: self.keys.clone(),
        })
    }

    /// Reads one record.
    pub async fn get<T: DeserializeOwned>(&self, kind: &str, name: &str) -> Result<Option<T>> {
        let mut tx = self.tx().await?;
        let v = tx.get(kind, name).await?;
        tx.commit().await?;
        Ok(v)
    }

    /// Writes one record.
    pub async fn put<T: Serialize>(&self, kind: &str, name: &str, v: &T) -> Result<()> {
        let mut tx = self.tx().await?;
        tx.put(kind, name, v).await?;
        tx.commit().await
    }

    /// Every record of a kind.
    pub async fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let mut tx = self.tx().await?;
        let v = tx.list(kind).await?;
        tx.commit().await?;
        Ok(v)
    }

    /// Closes the file.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// A write transaction over the store.
pub struct Tx {
    inner: Transaction<'static, Sqlite>,
    keys: Arc<Keys>,
}

impl Tx {
    /// Reads one record.
    pub async fn get<T: DeserializeOwned>(&mut self, kind: &str, name: &str) -> Result<Option<T>> {
        let id = self.keys.id(kind, name);
        let row = sqlx::query("SELECT nonce, ct FROM record WHERE kind = ? AND id = ?")
            .bind(kind)
            .bind(&id[..])
            .fetch_optional(&mut *self.inner)
            .await
            .map_err(db)?;
        let Some(row) = row else { return Ok(None) };
        let plain = self
            .keys
            .open(
                &aad(kind, &id),
                &row.get::<Vec<u8>, _>(0),
                &row.get::<Vec<u8>, _>(1),
            )
            .ok_or_else(|| Refusal::storage("a record does not decrypt"))?;
        serde_json::from_slice(&plain)
            .map(Some)
            .map_err(Refusal::storage)
    }

    /// Writes one record, replacing any of the same kind and name.
    pub async fn put<T: Serialize>(&mut self, kind: &str, name: &str, v: &T) -> Result<()> {
        let id = self.keys.id(kind, name);
        let plain = Zeroizing::new(serde_json::to_vec(v).map_err(Refusal::storage)?);
        let (nonce, ct) = self.keys.seal(&aad(kind, &id), &plain)?;
        sqlx::query("INSERT OR REPLACE INTO record (kind, id, nonce, ct) VALUES (?, ?, ?, ?)")
            .bind(kind)
            .bind(&id[..])
            .bind(nonce)
            .bind(ct)
            .execute(&mut *self.inner)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Deletes one record.
    pub async fn delete(&mut self, kind: &str, name: &str) -> Result<()> {
        let id = self.keys.id(kind, name);
        sqlx::query("DELETE FROM record WHERE kind = ? AND id = ?")
            .bind(kind)
            .bind(&id[..])
            .execute(&mut *self.inner)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Every record of a kind.
    pub async fn list<T: DeserializeOwned>(&mut self, kind: &str) -> Result<Vec<T>> {
        let rows = sqlx::query("SELECT id, nonce, ct FROM record WHERE kind = ?")
            .bind(kind)
            .fetch_all(&mut *self.inner)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|r| {
                let id: Vec<u8> = r.get(0);
                let plain = self
                    .keys
                    .open(
                        &aad(kind, &id),
                        &r.get::<Vec<u8>, _>(1),
                        &r.get::<Vec<u8>, _>(2),
                    )
                    .ok_or_else(|| Refusal::storage("a record does not decrypt"))?;
                serde_json::from_slice(&plain).map_err(Refusal::storage)
            })
            .collect()
    }

    /// Commits.
    pub async fn commit(self) -> Result<()> {
        self.inner.commit().await.map_err(db)
    }
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_are_sealed_and_need_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.db");
        let s = Store::create(&path, "correct horse", KdfParams::insecure_for_tests())
            .await
            .unwrap();
        s.put(
            "pin",
            "https://secret-origin.example",
            &"value with abandon ability",
        )
        .await
        .unwrap();
        assert_eq!(
            s.get::<String>("pin", "https://secret-origin.example")
                .await
                .unwrap()
                .as_deref(),
            Some("value with abandon ability")
        );
        s.close().await;
        let raw = std::fs::read(&path).unwrap();
        let wal = std::fs::read(path.with_extension("db-wal")).unwrap_or_default();
        for hay in [&raw, &wal] {
            let text = String::from_utf8_lossy(hay);
            assert!(!text.contains("secret-origin"));
            assert!(!text.contains("abandon"));
        }
        let e = Store::open(&path, "wrong").await.unwrap_err();
        assert_eq!(e.code, Code::Locked);
        let s = Store::open(&path, "correct horse").await.unwrap();
        assert_eq!(s.list::<String>("pin").await.unwrap().len(), 1);
        let e = Store::create(&path, "x", KdfParams::insecure_for_tests())
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::WalletExists);
        let e = Store::open(&dir.path().join("none.db"), "x")
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::NoWallet);
    }
}
