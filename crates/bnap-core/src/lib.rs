//! Core BNAP protocol types, encoding and verification logic, free of I/O.
//!
//! This crate is the BNAP socket of `spec/socket-draft-00.md`, byte for byte:
//!
//! | Module | Draft-00 |
//! | --- | --- |
//! | [`encoding`] | Section 2: `BigSize`, `tu64`, `lp(x)` |
//! | [`tlv`] | Section 2: TLV streams, type ranges, even/odd rule, entry lists |
//! | [`hash`] | Section 2: SHA-256, BIP-340 tagged hashes, HMAC-SHA256 |
//! | [`schnorr`] | Section 2: BIP-340 keys and signatures |
//! | [`offer`] | Section 4: the Offer, `OfferID`, `offer_sig`, MAC, checks of 4.4 |
//! | [`credential`] | Section 5: the Credential, Context, Digest, native envelope |
//! | [`ids`] | Section 6.1 and 6.2: `UseId`, `RailId`, `ReplayKey`, counter keys |
//! | [`response`] | Section 8.1: the Response and its ack |
//! | [`error`] | Section 8.2: error codes and the Error object |
//! | [`manifest`] | Section 9: the manifest, JCS, root signature, pinning |
//! | [`http`] | Section 10.1: HTTP action and route scopes |
//! | [`class`] | Binding classes S, A, O and none |
//! | [`limits`] | Size limits, clock skew and timeout defaults |
//! | [`pricing`] | Section 7: `price`, admission, metering, the change cap |
//! | [`note`] | The operator's notes: NUT-00 `hash_to_curve` from a note's secret to its `Y` |
//! | [`policy`] | Section 11: effective property vectors and route `require` |
//! | [`store`] | Sections 6.2 to 6.4: use store records, the `UseStore` trait, commit and settle logic |
//! | [`outcome`] | Section 6: the outcome state machine over any `UseStore` |
//! | [`sign`] | Sealed messages for the online signer (offer signatures and acks) |
//! | `test_support` | With the `test-support` feature: an in-memory `UseStore` |
//!
//! The crate does no I/O and holds no RNG: callers pass the clock, nonces,
//! BIP-340 auxiliary randomness and GREASE randomness in. The use store is a
//! plug; [`outcome`] only drives it.

pub mod class;
pub mod credential;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod http;
pub mod ids;
pub mod limits;
pub mod manifest;
pub mod note;
pub mod offer;
pub mod outcome;
pub mod policy;
pub mod pricing;
pub mod response;
pub mod schnorr;
pub mod sign;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tlv;

pub use class::BindingClass;
pub use credential::{Credential, CredentialParse, OfferRef, SchemePart};
pub use error::{Error, ErrorCode, ErrorObject, MalformedKind, Object};
pub use hash::{Context, CounterKey, Digest, OfferId, RailId, ReplayKey, Scope, UseId};
pub use limits::Limits;
pub use manifest::{Manifest, ManifestKey, SignedManifest};
pub use offer::{AttestEntry, Effect, GateOfferCheck, NativeEntry, Offer, OfferFields, PayEntry};
pub use outcome::{Admitted, Pending, ProcessError, Recorded, SettleError};
pub use policy::{EffectiveVector, Require, RoutePolicy};
pub use pricing::{
    Admission, Backing, BackingSource, Charge, PriceDecision, PriceError, Refund, VerifiedAttest,
};
pub use response::{Response, ResponseFields, Status};
pub use schnorr::{Key, Signature, SigningKey};
pub use sign::{CoreMessage, Purpose, UnsignedOffer, UnsignedResponse};
pub use store::{
    CommitPlan, OutcomeRecord, OutcomeStatus, Settlement, StoreError, UseModel, UseStore,
};

/// The `bitcoin` crate's re-export of secp256k1, the only secp256k1 in the
/// tree.
pub use bitcoin::secp256k1;
