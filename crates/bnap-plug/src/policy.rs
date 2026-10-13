//! The pricer and judge plugs, and the action they see.

use bnap_core::ErrorCode;
use bnap_core::error::ErrorObject;
use bnap_core::hash::Scope;
use bnap_core::policy::EffectiveVector;
use bnap_core::store::OutcomeRecord;

/// The action being priced or judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The manifest route ID.
    pub route_id: String,
    /// The carrier name, such as `http`.
    pub carrier: String,
    /// The action scope, or the route scope for a route offer.
    pub scope: Scope,
    /// `scope` is a route scope.
    pub route_scope: bool,
    /// The route is metered.
    pub metered: bool,
    /// The route's meter, such as `tokens`.
    pub meter: Option<String>,
}

/// Why a pricer gave no price.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PricerError {
    /// The pricer cannot price in this unit.
    #[error("no price in unit {0}")]
    NoPrice(String),
    /// A feed the pricer needs is down.
    #[error("pricer unavailable: {0}")]
    Unavailable(String),
}

impl PricerError {
    /// UNAVAILABLE: no offer is made without a price.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::Unavailable
    }
}

/// The pricer: writes one amount per pay entry when the gate builds an
/// offer (section 7). At verification time the gate uses only the offer.
#[async_trait::async_trait]
pub trait Pricer: Send + Sync {
    /// The amount for `action` in `unit`, in its base denomination; the
    /// ceiling for a metered route.
    async fn price(&self, action: &Action, unit: &str) -> Result<u64, PricerError>;
}

/// A judge's answer before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Go on to commit.
    Admit,
    /// Not now; try again after `retry_after` seconds.
    Queue {
        /// Seconds.
        retry_after: u64,
    },
    /// Refused.
    Refuse {
        /// For logs only.
        detail: String,
    },
}

impl Decision {
    /// The error the gate answers with: none for Admit, `RATE_LIMITED` with
    /// `retry_after` for Queue, POLICY for Refuse (draft-00 defines no code
    /// for judges; ERRATA N3b-8).
    #[must_use]
    pub fn error(&self) -> Option<ErrorObject> {
        match self {
            Self::Admit => None,
            Self::Queue { retry_after } => {
                let mut e = ErrorObject::new(ErrorCode::RateLimited);
                e.retry_after = Some(*retry_after);
                Some(e)
            }
            Self::Refuse { .. } => Some(ErrorObject::new(ErrorCode::Policy)),
        }
    }
}

/// The judge: admits, queues or refuses before commit, and sees outcomes
/// after.
#[async_trait::async_trait]
pub trait Judge: Send + Sync {
    /// Decides on an action whose credential verified, given the chosen pay
    /// entry's effective property vector.
    async fn admit(&self, action: &Action, properties: &EffectiveVector) -> Decision;

    /// Sees a settled outcome, for abuse handling. The default does
    /// nothing.
    async fn after(&self, action: &Action, outcome: &OutcomeRecord) {
        let _ = (action, outcome);
    }
}
