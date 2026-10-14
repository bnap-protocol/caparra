//! The client's pay source plug.

use crate::rail::PayRequest;

/// What the client's spend policy allows for one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    /// The most to pay, in `unit`.
    pub max: u64,
    /// The unit.
    pub unit: String,
}

/// Proof that a payment was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayProof {
    /// The rail kind it went over, such as `ln`.
    pub rail_kind: String,
    /// The proof, such as a Lightning preimage.
    pub proof: Vec<u8>,
    /// What was paid, in the request's unit, fees excluded.
    pub amount: u64,
}

/// Why a payment was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PayError {
    /// The request is above the budget or in another unit.
    #[error("request for {amount} {unit} is outside the budget")]
    OverBudget {
        /// Requested amount.
        amount: u64,
        /// Requested unit.
        unit: String,
    },
    /// The payment failed.
    #[error("payment failed: {0}")]
    Failed(String),
    /// The wallet cannot be reached.
    #[error("pay source unavailable: {0}")]
    Unavailable(String),
}

/// A pay source (client side): NWC, a Lightning node, a custodial API.
#[async_trait::async_trait]
pub trait PaySource: Send + Sync {
    /// Pays `request` if it fits `budget`. MUST refuse a request above the
    /// budget or in another unit.
    async fn pay(&self, request: &PayRequest, budget: &Budget) -> Result<PayProof, PayError>;
}

/// True when `request` fits `budget`: same unit, amount at most the
/// maximum.
#[must_use]
pub fn within_budget(request: &PayRequest, budget: &Budget) -> bool {
    request.unit == budget.unit && request.amount <= budget.max
}
