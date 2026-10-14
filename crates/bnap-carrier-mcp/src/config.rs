//! What the operator configures: the registry facts of each scheme, the
//! rails, and the price of each tool.

use std::collections::BTreeMap;
use std::sync::Arc;

use bnap_core::BindingClass;
use bnap_core::limits::{Limits, LimitsError};
use bnap_core::offer::AttestEntry;
use bnap_core::policy::{EffectiveVector, Require};
use bnap_core::pricing::Refund;
use bnap_core::schnorr::Key;
use bnap_core::store::{UseModel, UseStore};
use bnap_plug::{CredentialScheme, FundingRail, Signer};

/// A scheme plug with the facts its registry entry states. The gate takes
/// class, use model, refund property and property vector from here, never
/// from the plug (draft-00 11).
#[derive(Clone)]
pub struct SchemeConfig {
    /// The plug.
    pub plug: Arc<dyn CredentialScheme>,
    /// Binding class (registry `binding`).
    pub class: BindingClass,
    /// Use model as the socket enforces it (registry `use`).
    pub model: UseModel,
    /// Refund property (registry `refund`); attestations: [`Refund::None`].
    pub refund: Refund,
    /// The effective property vector of the scheme with its rails and
    /// verifier, for the tools' `require`.
    pub properties: EffectiveVector,
}

impl std::fmt::Debug for SchemeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemeConfig")
            .field("id", &self.plug.id())
            .field("class", &self.class)
            .field("model", &self.model)
            .field("refund", &self.refund)
            .finish_non_exhaustive()
    }
}

impl SchemeConfig {
    /// A scheme with its registry facts and an empty property vector (no
    /// property known, so a tool with a `require` never admits it).
    #[must_use]
    pub fn new(
        plug: Arc<dyn CredentialScheme>,
        class: BindingClass,
        model: UseModel,
        refund: Refund,
    ) -> Self {
        Self {
            plug,
            class,
            model,
            refund,
            properties: EffectiveVector::default(),
        }
    }

    /// With the effective property vector.
    #[must_use]
    pub fn with_properties(mut self, v: EffectiveVector) -> Self {
        self.properties = v;
        self
    }
}

/// One pay entry of a tool's price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    /// Scheme ID.
    pub scheme: String,
    /// Amount in the unit's base denomination.
    pub amount: u64,
    /// Unit, such as `sat`.
    pub unit: String,
}

/// The price of one tool: what its exact-scope offers list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPrice {
    /// Pay entries, in preference order.
    pub pay: Vec<Price>,
    /// Attest entries (required, waive, discount, quota), in offer order.
    pub attest: Vec<AttestEntry>,
    /// The tool's `require`: schemes whose property vector does not meet it
    /// are never offered, and a pay scheme that does not is POLICY.
    pub require: Require,
}

impl ToolPrice {
    /// An empty price; add entries with [`Self::pay`] and [`Self::attest`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pay entry.
    #[must_use]
    pub fn pay(mut self, scheme: &str, amount: u64, unit: &str) -> Self {
        self.pay.push(Price {
            scheme: scheme.to_owned(),
            amount,
            unit: unit.to_owned(),
        });
        self
    }

    /// Adds an attest entry.
    #[must_use]
    pub fn attest(mut self, entry: AttestEntry) -> Self {
        self.attest.push(entry);
        self
    }

    /// Sets the `require`.
    #[must_use]
    pub fn require(mut self, require: Require) -> Self {
        self.require = require;
        self
    }
}

/// A clock: Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// How long the exact-scope offers live by default, in seconds. A
/// Lightning rail's invoices must not live longer (notes N7-6).
pub const DEFAULT_OFFER_LIFETIME: u64 = 300;

/// The largest tool result kept for replays by default, in bytes.
pub const DEFAULT_MAX_KEPT: usize = 64 * 1024;

/// How many issued offers the cache holds at most by default.
pub const DEFAULT_OFFER_CACHE: usize = 4096;

/// Why a configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A tool's price names a scheme that is not configured.
    #[error("tool {tool:?} names the unconfigured scheme {scheme:?}")]
    UnknownScheme {
        /// The tool.
        tool: String,
        /// The scheme.
        scheme: String,
    },
    /// A tool has neither a pay entry nor a waive.
    #[error("tool {0:?} has no pay entry and no waive")]
    NoPay(String),
    /// The limits are inconsistent.
    #[error("limits: {0}")]
    Limits(#[from] LimitsError),
    /// No offer MAC key.
    #[error("no offer MAC key")]
    NoMacKey,
}

/// Everything the gate needs, collected by [`crate::Gate::builder`].
pub struct GateConfig {
    /// The MCP endpoint's URI as the operator publishes it, such as
    /// `https://api.example/mcp`: the first input of every scope.
    pub server_uri: String,
    /// The use store.
    pub store: Arc<dyn UseStore>,
    /// The signer that holds the offer and receipt keys.
    pub signer: Arc<dyn Signer>,
    /// The offer key.
    pub offer_key: Key,
    /// The receipt key.
    pub receipt_key: Key,
    /// `K_mac`: the current key first, then retained ones (4.2).
    pub mac_keys: Vec<[u8; 32]>,
    /// The manifest's limits.
    pub limits: Limits,
    /// Exact-scope offer lifetime, seconds.
    pub offer_lifetime: u64,
    /// Schemes by ID.
    pub schemes: BTreeMap<String, SchemeConfig>,
    /// Rails by kind, to confirm every rail reference (6.1).
    pub rails: BTreeMap<String, Arc<dyn FundingRail>>,
    /// Priced tools by name; every other tool is free.
    pub tools: BTreeMap<String, ToolPrice>,
    /// The clock.
    pub clock: Clock,
    /// The largest tool result kept in the outcome record for replays.
    pub max_kept: usize,
    /// How many issued offers the cache holds at most.
    pub offer_cache: usize,
}
