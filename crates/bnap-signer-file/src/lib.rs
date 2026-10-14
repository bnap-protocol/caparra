//! An in-process BNAP signer whose keys come from a key file on local disk.
//!
//! [`FileSigner`] implements [`bnap_plug::Signer`]: BIP-340 signatures for
//! offers and Response acks (draft-00 4.2 and 8.1) with the offer and
//! receipt keys, and the blind signatures of `bnap:notes` keysets
//! (`schemes/bnap-notes-draft-00.md`, NUT-00 BDHKE with NUT-12 DLEQ proofs,
//! through the `cashu` crate).
//!
//! # Key file
//!
//! A TOML file, read by [`FileSigner::load`], which refuses it unless it is
//! a regular file (not a symbolic link) that neither the group nor anyone
//! else may read, write or execute (mode `0600` or stricter) on Unix:
//!
//! ```toml
//! # Online offer key (manifest use "offer"); not_after is optional.
//! [[key]]
//! use = "offer"
//! secret = "<32-byte secret key, 64 hex characters>"
//! not_after = 1794000000
//!
//! # Online receipt key (manifest use "receipt").
//! [[key]]
//! use = "receipt"
//! secret = "<64 hex characters>"
//!
//! # One bnap:notes keyset, unit sat, derived from a seed (keyset::derive).
//! [[keyset]]
//! seed = "<16 to 64 bytes, hex>"
//! index = 0
//! input_fee_ppk = 100
//! final_expiry = 1830000000
//! active = true      # signs outputs; false: accepts inputs only
//! orders = 32        # keys for 1, 2, 4, ..., 2^31 sat
//! ```
//!
//! The MAC key `K_mac` of draft-00 4.2 is not here: the [`bnap_plug::Signer`]
//! trait has no MAC operation, and the gate computes offer MACs itself.
//!
//! # Secrets
//!
//! - Secrets are never logged and never appear in `Debug` output, error
//!   messages included: errors name a field and a line, never a value.
//! - The file's bytes and every hex secret are held in zeroizing buffers,
//!   and the secp256k1 keys are erased when the signer drops (as far as
//!   `secp256k1::Keypair::non_secure_erase` and the `cashu` crate's
//!   `SecretKey` drop allow: best effort, as in any Rust program).
//!
//! # Only messages bnap-core built
//!
//! [`FileSigner::sign_object`] is the one signing path, and
//! [`bnap_plug::Signer::schnorr`] goes through it too: it parses the bytes
//! with bnap-core as the object the purpose names (an offer's `S`, or a
//! Response without its ack), checks that the object names the requested
//! key, that this signer holds that key for the purpose's use, and signs the
//! tagged hash it computed itself ([`object::recompute`]). No path signs 32
//! bytes a caller supplies.

pub mod keyfile;
pub mod keys;
pub mod keyset;
pub mod object;
mod signer;
#[cfg(feature = "test-support")]
pub mod testkit;

pub use keyfile::LoadError;
pub use keys::HeldKey;
pub use keyset::{KeysetError, NotesKeyset};
pub use object::ObjectError;
pub use signer::{Clock, FileSigner, MAX_OUTPUTS_PER_CALL};
