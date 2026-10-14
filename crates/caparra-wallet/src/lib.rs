//! Client wallet that holds funds and answers BNAP payment challenges.
//!
//! [`Wallet`] is the whole client: an encrypted store (seed, notes, pins,
//! ledger, receipts), a spend policy enforced in code, the paid fetch of
//! draft-00 (offers checked against the pinned manifest, one value
//! credential chosen by cost, receipts kept and checked), a notes wallet on
//! the bnap:notes client module, and the L402 and MPP clients over a
//! Lightning pay source.

// `Refusal` is the wallet's one error and carries the facts a script needs
// (cap, remaining, scheme, property); every path that returns it does I/O,
// so its size is not worth boxing.
#![allow(clippy::result_large_err)]

pub mod attest;
pub mod error;
pub mod invoice;
pub mod issuer;
pub mod notes_ops;
pub mod pay;
pub mod paysource;
pub mod policy;
pub mod rank;
pub mod records;
pub mod registry;
pub mod store;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod transport;
pub mod wallet;

pub use error::{CapKind, Code, Refusal, Result, Source};
pub use pay::{FetchRequest, FetchResult, Payment, ResumeOutcome};
pub use paysource::{PaySource, PaySourceConfig};
pub use policy::{Caps, Linkability, Policy, SessionCaps};
pub use store::KdfParams;
pub use transport::{HttpRequest, HttpResponse, HttpsTransport, Transport};
pub use wallet::{Options, Wallet, system_clock, verify_receipt};
