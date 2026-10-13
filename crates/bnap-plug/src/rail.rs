//! The funding rail plug (operator-trusted).
//!
//! Schemes are untrusted, so canonical payment bytes come from the rail,
//! never from the scheme (draft-00 6.1): a scheme names a payment with a
//! [`RailRef`], the rail of that kind confirms it, and bnap-core computes
//! the `RailId` from the rail's own kind and bytes ([`confirm_rail_id`]).

use bnap_core::ErrorCode;
use bnap_core::hash::RailId;
use bnap_core::ids::rail_id;

use crate::scheme::RailRef;

/// A rail's ID for a payment request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PayId(pub Vec<u8>);

/// A payment request a rail made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayRequest {
    /// The rail's ID for it.
    pub id: PayId,
    /// The rail kind, such as `ln`.
    pub rail_kind: String,
    /// The request as a payer reads it, such as a BOLT11 invoice.
    pub request: String,
    /// Amount, in `unit`.
    pub amount: u64,
    /// Unit.
    pub unit: String,
    /// When the request expires, Unix seconds.
    pub expires: u64,
}

/// The state of a payment request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayState {
    /// Not paid yet.
    Pending,
    /// Paid and final for this rail.
    Paid,
    /// Expired unpaid.
    Expired,
    /// Failed.
    Failed,
}

/// A payment the rail confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmed {
    /// The canonical payment bytes of the rail kind (6.1).
    pub canonical: Vec<u8>,
    /// What was paid.
    pub amount: u64,
    /// In this unit.
    pub unit: String,
}

/// Why a rail did not confirm or create a payment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RailError {
    /// The reference names no payment, or one that is not paid.
    #[error("payment not confirmed: {0}")]
    NotConfirmed(String),
    /// A reference of another rail kind.
    #[error("rail kind {got} sent to a {want} rail")]
    WrongKind {
        /// The rail's kind.
        want: String,
        /// The reference's kind.
        got: String,
    },
    /// The rail cannot be reached.
    #[error("rail unavailable: {0}")]
    Unavailable(String),
}

impl RailError {
    /// The draft-00 error code: `BAD_CREDENTIAL` for a payment that is not
    /// there, UNAVAILABLE for a rail that is down (fail closed).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::NotConfirmed(_) | Self::WrongKind { .. } => ErrorCode::BadCredential,
            Self::Unavailable(_) => ErrorCode::Unavailable,
        }
    }
}

/// A funding rail (operator-trusted).
#[async_trait::async_trait]
pub trait FundingRail: Send + Sync {
    /// The rail kind, such as `ln`.
    fn kind(&self) -> &str;

    /// Creates a payment request; `memo` is 32 bytes the request commits
    /// to, such as an invoice description hash.
    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError>;

    /// The state of a request this rail made.
    async fn status(&self, id: &PayId) -> Result<PayState, RailError>;

    /// Confirms a payment a scheme referred to and returns its canonical
    /// bytes.
    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError>;
}

/// Confirms `reference` with `rail` and computes the `RailId` from the
/// rail's own kind and canonical bytes, never from the scheme's.
pub async fn confirm_rail_id(
    rail: &dyn FundingRail,
    reference: &RailRef,
) -> Result<RailId, RailError> {
    if reference.kind != rail.kind() {
        return Err(RailError::WrongKind {
            want: rail.kind().to_owned(),
            got: reference.kind.clone(),
        });
    }
    let c = rail.confirm(reference).await?;
    Ok(rail_id(rail.kind(), &c.canonical))
}
