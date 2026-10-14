//! Plug-in traits that connect signers, stores, schemes, rails and carriers to the core.
//!
//! These are the plug points of the overview's "Caparra as a plug host",
//! brought in line with draft-00 (ERRATA rows 2 and 19): schemes split
//! body and witness and return rail references, rails supply canonical
//! payment bytes, and the store commits counters as well as IDs.
//!
//! | Plug | Trait | Trust |
//! | --- | --- | --- |
//! | Credential and attestation schemes | [`CredentialScheme`] | Contained |
//! | Carrier | [`Carrier`] | Contained |
//! | Funding rail | [`FundingRail`] | Operator-trusted |
//! | Use store | [`UseStore`] (defined in `bnap-core`, re-exported) | Operator-trusted |
//! | Signer | [`Signer`], seen by schemes only as a [`CappedSigner`] | Operator-trusted |
//! | Pricer | [`Pricer`] | Contained |
//! | Judge | [`Judge`] | Contained |
//! | Pay source (client) | [`PaySource`] | Client |
//!
//! Only bnap-core computes the `OfferID`, Context, Digest and `ReplayKey`,
//! prefixes use IDs, compares value with price, commits uses and builds
//! every message the signer signs. Plugs get read access to what they need
//! and return data. No plug sees a secret key.
//!
//! Every async trait uses `async-trait`, so plugs can be held as
//! `Arc<dyn Trait>`.

pub mod carrier;
pub mod pay;
pub mod policy;
pub mod rail;
pub mod scheme;
pub mod signer;

pub use carrier::{Carrier, Challenge, NativeChallenge, RawCredential};
pub use pay::{Budget, PayError, PayProof, PaySource};
pub use policy::{Action, Decision, Judge, Pricer, PricerError};
pub use rail::{
    Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailPayment, confirm_rail_id,
};
pub use scheme::{
    CredentialScheme, Entry, LocalId, NativeArtifact, NativeCredential, NativeCtx, OfferCtx,
    OfferRole, RailRef, SchemeError, SchemeOffer, SettleCtx, Verified, VerifyCtx,
};
pub use signer::{
    BlindSignature, BlindedOutput, CappedSigner, ChangeLedger, ChangeLimit, Dleq, KeysetId, Point,
    SettleGuard, Signer, SignerError,
};

/// The use store plug, defined in `bnap-core` so the outcome state machine
/// can be generic over it.
pub use bnap_core::store::{
    ChangeOutput, ChangeRequest, Commit, CommitPlan, OutcomeRecord, RefundRequest, Reserve, Settle,
    SettleRequest, Settlement, StoreError, SweepWindow, UseStore,
};

/// The sealed message type [`Signer::schnorr`] takes.
pub use bnap_core::sign::CoreMessage;

/// The change cap a [`CappedSigner`] enforces, bound to its outcome.
pub use bnap_core::pricing::ChangeCap;

/// A pay entry's effective property vector, as a [`Judge`] sees it.
pub use bnap_core::policy::EffectiveVector as Properties;
