//! Reading and parsing the key file (format in the crate docs).
//!
//! [`read`] refuses a file that others could read or change, and
//! [`parse`] turns the TOML into held keys and keysets. Neither ever puts a
//! secret, or a line of the file, into an error: a TOML syntax error is
//! reported by line and column only, and a bad value by its field and the
//! position of its `[[key]]` or `[[keyset]]` table.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use bnap_core::manifest::KeyUse;
use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{HeldKey, KeyError};
use crate::keyset::{DEFAULT_ORDERS, KeysetError, NotesKeyset};

/// The largest key file read, in bytes.
pub const MAX_KEY_FILE: u64 = 1 << 20;

/// Why a key file was not loaded. Its `Display` and `Debug` never show a
/// secret or a line of the file.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file could not be opened or read.
    #[error("cannot read key file {path}: {kind}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        kind: std::io::ErrorKind,
    },
    /// The path is a symbolic link; name the file itself.
    #[error("key file {path} is a symbolic link; name the file itself")]
    Symlink {
        /// The file.
        path: PathBuf,
    },
    /// Not a regular file.
    #[error("key file {path} is not a regular file")]
    NotAFile {
        /// The file.
        path: PathBuf,
    },
    /// The group or others have some access to the file.
    #[error(
        "key file {path} has mode {mode:o}: the group and others must have no access (chmod 600)"
    )]
    Permissions {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Larger than [`MAX_KEY_FILE`].
    #[error("key file {path} is larger than {MAX_KEY_FILE} bytes")]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// Not UTF-8.
    #[error("key file is not UTF-8")]
    NotUtf8,
    /// Not valid TOML, or a field of the wrong type. The line is not shown:
    /// it may hold a secret.
    #[error("key file is not a valid key file at line {line}, column {column}")]
    Syntax {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// A value that is not what its field needs.
    #[error("{table} {index}: {field} {problem}")]
    Field {
        /// `key` or `keyset`.
        table: &'static str,
        /// 1-based position of the table in the file.
        index: usize,
        /// The field.
        field: &'static str,
        /// What is wrong with it (never the value).
        problem: &'static str,
    },
    /// A key that cannot be held.
    #[error("key {index}: {error}")]
    Key {
        /// 1-based position.
        index: usize,
        /// Why.
        error: KeyError,
    },
    /// A keyset that cannot be built.
    #[error("keyset {index}: {error}")]
    Keyset {
        /// 1-based position.
        index: usize,
        /// Why.
        error: KeysetError,
    },
    /// The same secret key listed twice, for one use or for two.
    #[error("key {index}: the same key is listed twice; give each use its own key")]
    DuplicateKey {
        /// 1-based position of the second listing.
        index: usize,
    },
    /// Two keysets with one ID.
    #[error("keyset {index}: another keyset has the same ID")]
    DuplicateKeyset {
        /// 1-based position of the second one.
        index: usize,
    },
    /// No key and no keyset.
    #[error("key file holds no key and no keyset")]
    Empty,
}

/// Reads a key file, refusing it unless it is a regular file, reached
/// without a symbolic link, that neither the group nor others can access
/// (Unix). The mode is read from the opened file, so the check and the read
/// are of the same file. Other platforms are not checked.
pub fn read(path: &Path) -> Result<Zeroizing<String>, LoadError> {
    let io = |e: std::io::Error| LoadError::Io {
        path: path.to_owned(),
        kind: e.kind(),
    };
    if std::fs::symlink_metadata(path)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(LoadError::Symlink {
            path: path.to_owned(),
        });
    }
    let mut file = File::open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(LoadError::NotAFile {
            path: path.to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(LoadError::Permissions {
                path: path.to_owned(),
                mode,
            });
        }
    }
    if meta.len() > MAX_KEY_FILE {
        return Err(LoadError::TooLarge {
            path: path.to_owned(),
        });
    }
    // Reserved up front so reading never reallocates and leaves a copy.
    let len = usize::try_from(meta.len()).unwrap_or(0);
    let mut bytes = Zeroizing::new(Vec::with_capacity(len + 1));
    file.by_ref()
        .take(MAX_KEY_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_KEY_FILE {
        return Err(LoadError::TooLarge {
            path: path.to_owned(),
        });
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(LoadError::NotUtf8)
        }
    }
}

/// A secret string, wiped when dropped.
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileToml {
    #[serde(default)]
    key: Vec<KeyToml>,
    #[serde(default)]
    keyset: Vec<KeysetToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyToml {
    #[serde(rename = "use")]
    key_use: String,
    #[serde(deserialize_with = "secret")]
    secret: Zeroizing<String>,
    not_after: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysetToml {
    #[serde(deserialize_with = "secret")]
    seed: Zeroizing<String>,
    index: u32,
    #[serde(default)]
    input_fee_ppk: u64,
    final_expiry: u64,
    #[serde(default = "yes")]
    active: bool,
    orders: Option<u8>,
}

fn yes() -> bool {
    true
}

// The parsed tables hold secrets: never print them.
impl fmt::Debug for FileToml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileToml { .. }")
    }
}

/// What a key file holds.
pub struct Parsed {
    /// The online keys, in file order.
    pub keys: Vec<HeldKey>,
    /// The notes keysets, in file order.
    pub keysets: Vec<NotesKeyset>,
}

impl fmt::Debug for Parsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parsed")
            .field("keys", &self.keys)
            .field("keysets", &self.keysets)
            .finish()
    }
}

/// 1-based line and column of a byte offset.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let before = &text.as_bytes()[..offset.min(text.len())];
    let line = before.iter().filter(|b| **b == b'\n').count() + 1;
    let column = before.iter().rev().take_while(|b| **b != b'\n').count() + 1;
    (line, column)
}

/// Parses the text of a key file.
pub fn parse(text: &str) -> Result<Parsed, LoadError> {
    let file: FileToml = toml::from_str(text).map_err(|e| {
        // The error's Display quotes the offending line, which may hold a
        // secret, and its message can quote a value: keep the position only.
        let (line, column) = position(text, e.span().map_or(0, |s| s.start));
        LoadError::Syntax { line, column }
    })?;
    if file.key.is_empty() && file.keyset.is_empty() {
        return Err(LoadError::Empty);
    }
    let mut keys: Vec<HeldKey> = Vec::with_capacity(file.key.len());
    for (i, k) in file.key.iter().enumerate() {
        let index = i + 1;
        let key_use = match k.key_use.as_str() {
            "offer" => KeyUse::Offer,
            "receipt" => KeyUse::Receipt,
            _ => {
                return Err(LoadError::Field {
                    table: "key",
                    index,
                    field: "use",
                    problem: "is not \"offer\" or \"receipt\"",
                });
            }
        };
        let mut sk = Zeroizing::new([0u8; 32]);
        if k.secret.len() != 64 || hex::decode_to_slice(k.secret.as_bytes(), &mut sk[..]).is_err() {
            return Err(LoadError::Field {
                table: "key",
                index,
                field: "secret",
                problem: "is not 64 hex characters",
            });
        }
        let held = HeldKey::new(key_use, &sk, k.not_after)
            .map_err(|error| LoadError::Key { index, error })?;
        if keys.iter().any(|h| h.public_key() == held.public_key()) {
            return Err(LoadError::DuplicateKey { index });
        }
        keys.push(held);
    }
    let mut keysets: Vec<NotesKeyset> = Vec::with_capacity(file.keyset.len());
    for (i, ks) in file.keyset.iter().enumerate() {
        let index = i + 1;
        let n = ks.seed.len();
        if n % 2 != 0 {
            return Err(LoadError::Field {
                table: "keyset",
                index,
                field: "seed",
                problem: "is not hex",
            });
        }
        let mut seed = Zeroizing::new(vec![0u8; n / 2]);
        if hex::decode_to_slice(ks.seed.as_bytes(), &mut seed[..]).is_err() {
            return Err(LoadError::Field {
                table: "keyset",
                index,
                field: "seed",
                problem: "is not hex",
            });
        }
        let keyset = NotesKeyset::derive(
            &seed,
            ks.index,
            ks.orders.unwrap_or(DEFAULT_ORDERS),
            ks.input_fee_ppk,
            ks.final_expiry,
            ks.active,
        )
        .map_err(|error| LoadError::Keyset { index, error })?;
        if keysets.iter().any(|k| k.id() == keyset.id()) {
            return Err(LoadError::DuplicateKeyset { index });
        }
        keysets.push(keyset);
    }
    Ok(Parsed { keys, keysets })
}
