//! The credential scheme plug: value schemes and attestations.
//!
//! A scheme is contained, not trusted. It never computes a socket ID, a
//! Context, a Digest or a `ReplayKey`, never commits, and never signs:
//!
//! - `verify` returns local IDs; bnap-core prefixes each with the scheme ID
//!   ([`bnap_core::ids::use_id`]), so no scheme names an ID in another
//!   scheme's space.
//! - `verify` returns rail references, not rail IDs; the operator-trusted
//!   rail confirms each and supplies the canonical bytes (draft-00 6.1).
//! - The Context and Digest arrive read-only, computed by the gate.
//! - The signer arrives as a [`CappedSigner`].
//!
//! Its properties come from the registry, never from the plug.

use bnap_core::credential::SchemePart;
use bnap_core::error::{ErrorCode, ErrorObject};
use bnap_core::hash::{Context, Digest, OfferId, Scope, UseId};
use bnap_core::ids::use_id;
use bnap_core::offer::{AttestEntry, Effect, Offer, PayEntry};
use bnap_core::response::Status;
use bnap_core::store::{SchemeUses, UseModel};

use crate::signer::CappedSigner;

/// A local ID, as the scheme's registry entry defines it (a note's `Y`, an
/// L402 payment hash).
pub type LocalId = Vec<u8>;

/// A scheme's reference to a payment its credential relies on. The rail
/// of that kind confirms it and returns the canonical payment bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RailRef {
    /// The rail kind, such as `ln`.
    pub kind: String,
    /// The scheme's own reference to the payment, such as a payment hash.
    pub reference: Vec<u8>,
}

/// What a scheme's `verify` returns: `Verified { use_ids, rail_ids, value }`
/// of the overview, with rail references per draft-00 6.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verified {
    /// Local IDs; bnap-core prefixes them with the scheme ID.
    pub use_ids: Vec<LocalId>,
    /// References to every payment the credential relies on, for the rails
    /// to confirm. bnap-core commits the resulting `RailId`s with the use
    /// IDs.
    pub rail_ids: Vec<RailRef>,
    /// The value, in the chosen pay entry's unit; 0 for an attestation.
    pub value: u64,
    /// For an attestation that may carry a quota: the local ID of the
    /// stable identity its registry entry declares as `quota_id`.
    pub quota_id: Option<LocalId>,
}

impl Verified {
    /// The scheme's uses for [`bnap_core::store::CommitPlan::build`], under
    /// the model the registry sets.
    #[must_use]
    pub fn uses<'a>(&'a self, scheme: &'a str, model: UseModel) -> SchemeUses<'a> {
        SchemeUses {
            scheme,
            model,
            local_ids: &self.use_ids,
        }
    }

    /// The `UseId` a quota counts against, for
    /// [`bnap_core::pricing::VerifiedAttest`].
    #[must_use]
    pub fn quota_use_id(&self, scheme: &str) -> Option<UseId> {
        self.quota_id.as_ref().map(|l| use_id(scheme, l))
    }
}

/// The scheme's role in an offer being built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferRole<'a> {
    /// A pay entry with this amount and unit.
    Pay {
        /// The Pricer's amount; the ceiling in a metered offer.
        amount: u64,
        /// The unit.
        unit: &'a str,
    },
    /// An attest entry with this effect.
    Attest {
        /// What the attestation does to the price.
        effect: Effect,
    },
}

/// What a scheme sees while an offer is built, before the `OfferID` exists.
#[derive(Debug, Clone, Copy)]
pub struct OfferCtx<'a> {
    /// The gate's clock.
    pub now: u64,
    /// The manifest route.
    pub route_id: &'a str,
    /// The action or route scope the offer prices.
    pub scope: &'a Scope,
    /// The offer is route scope.
    pub route_scope: bool,
    /// The offer is metered.
    pub metered: bool,
    /// The offer's `expires`.
    pub expires: u64,
    /// The scheme's entry.
    pub role: OfferRole<'a>,
}

/// The scheme's contribution to an entry: its `params` record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemeOffer {
    /// Bytes defined by the scheme's registry entry.
    pub params: Option<Vec<u8>>,
}

/// What a class O scheme sees when it makes a native artifact (4.2 step
/// 3): the `OfferID` is fixed by now.
#[derive(Debug, Clone, Copy)]
pub struct NativeCtx<'a> {
    /// The gate's clock.
    pub now: u64,
    /// The `OfferID` the artifact must embed.
    pub offer_id: &'a OfferId,
    /// The pay entry the artifact is for.
    pub entry: &'a PayEntry,
    /// Index of the entry in `pay`.
    pub pay_index: usize,
    /// The offer's `expires`.
    pub expires: u64,
}

/// A native artifact for one pay entry (Offer record 26).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeArtifact {
    /// The label from the registry entry, such as `bolt11`.
    pub kind: String,
    /// The artifact's bytes.
    pub data: Vec<u8>,
}

/// The scheme's entry in the offer a credential uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry<'a> {
    /// A pay entry.
    Pay(&'a PayEntry),
    /// An attest entry.
    Attest(&'a AttestEntry),
}

/// What a scheme sees in `verify`. Everything is read-only and was checked
/// by the gate first (draft-00 4.4).
#[derive(Debug, Clone, Copy)]
pub struct VerifyCtx<'a> {
    /// The gate's clock.
    pub now: u64,
    /// The offer, authenticated, unexpired and in scope.
    pub offer: &'a Offer,
    /// The scheme's entry in it.
    pub entry: Entry<'a>,
    /// The carrier's action scope of this request.
    pub action_scope: &'a Scope,
    /// The Context the gate computed.
    pub context: &'a Context,
    /// The Digest the gate computed.
    pub digest: &'a Digest,
    /// A verify-only signer, for unblinded-note checks.
    pub signer: &'a CappedSigner,
}

/// What a scheme sees in `settle`.
#[derive(Debug, Clone, Copy)]
pub struct SettleCtx<'a> {
    /// The gate's clock.
    pub now: u64,
    /// OK or FAILED.
    pub status: Status,
    /// What bnap-core charged; 0 on FAILED.
    pub charged: u64,
    /// The pay entry.
    pub entry: &'a PayEntry,
    /// The Context.
    pub context: &'a Context,
    /// The Digest.
    pub digest: &'a Digest,
}

/// A native credential recovered without state (draft-00 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCredential {
    /// The `OfferID` the artifact embeds, authenticated by the adapter.
    pub offer_id: OfferId,
    /// The offer's bytes, when the artifact carries them; otherwise the gate
    /// looks the offer up in its cache of offers issued with natives.
    pub offer: Option<Vec<u8>>,
    /// The native credential bytes the registry entry defines, as the part
    /// `verify` receives (body = those bytes, no witness).
    pub part: SchemePart,
}

/// Why a scheme failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SchemeError {
    /// `BAD_CREDENTIAL` with a namespaced scheme code.
    #[error("{scheme_code}: {detail}")]
    Rejected {
        /// Such as `bnap:notes/BAD_SIGNATURE`.
        scheme_code: String,
        /// For logs only; never shown to a model or a user as instructions.
        detail: String,
    },
    /// UNAVAILABLE: a verifier or facilitator the scheme needs is down.
    #[error("scheme unavailable: {0}")]
    Unavailable(String),
    /// The scheme has no such capability (for example no native path).
    #[error("not supported by this scheme")]
    Unsupported,
}

impl SchemeError {
    /// A rejection with the code `"{scheme}/{code}"`.
    #[must_use]
    pub fn rejected(scheme: &str, code: &str, detail: impl Into<String>) -> Self {
        Self::Rejected {
            scheme_code: format!("{scheme}/{code}"),
            detail: detail.into(),
        }
    }

    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Rejected { .. } | Self::Unsupported => ErrorCode::BadCredential,
            Self::Unavailable(_) => ErrorCode::Unavailable,
        }
    }

    /// The 8.2 Error object, with `scheme_code` for a rejection. The detail
    /// stays out of it: it is for logs only.
    #[must_use]
    pub fn to_error_object(&self) -> ErrorObject {
        let mut e = ErrorObject::new(self.code());
        if let Self::Rejected { scheme_code, .. } = self {
            e.scheme_code = Some(scheme_code.clone());
        }
        e
    }
}

/// A credential scheme (value or attestation).
///
/// `verify` has no side effects and reads no use state: the socket decides
/// use at commit, so a replay of a committed credential always reaches the
/// replay path. `settle` is deterministic: the same verified credential,
/// outcome and charge always give the same `scheme_result` (6.4).
#[async_trait::async_trait]
pub trait CredentialScheme: Send + Sync {
    /// The registered scheme ID. Properties come from the registry, not
    /// from here.
    fn id(&self) -> &str;

    /// The entry's `params` while an offer is built (4.2 steps 1 and 2).
    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError>;

    /// A native artifact that embeds `cx.offer_id`, for class O schemes
    /// (4.2 step 3). The default makes none.
    async fn native(&self, cx: &NativeCtx<'_>) -> Result<Option<NativeArtifact>, SchemeError> {
        let _ = cx;
        Ok(None)
    }

    /// Checks the scheme's part of a credential and returns its local IDs,
    /// rail references and value.
    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError>;

    /// Settles a value scheme: change or refund, within the signer's cap.
    /// Returns the `scheme_result` bytes. The default returns none.
    ///
    /// `signer` is a change budget for this one settlement: every
    /// `blind_sign` call takes from the same cap, clones share it, and it
    /// closes when `settle` returns, so a clone kept for later signs
    /// nothing.
    async fn settle(
        &self,
        part: &SchemePart,
        verified: &Verified,
        cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        let _ = (part, verified, cx, signer);
        Ok(None)
    }

    /// Recovers a native credential (draft-00 5.4): the embedded `OfferID`,
    /// authenticated without state, and the offer if the artifact carries
    /// it. The default has no native path.
    async fn recover_native(
        &self,
        native: &[u8],
        now: u64,
    ) -> Result<NativeCredential, SchemeError> {
        let _ = (native, now);
        Err(SchemeError::Unsupported)
    }
}
