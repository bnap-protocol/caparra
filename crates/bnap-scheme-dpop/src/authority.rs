//! The operator's word on tokens and keys.
//!
//! A `DPoP` proof shows that the client holds a key; it says nothing about
//! whether the operator should honour that key. Anyone can make a fresh key
//! and sign a perfect proof with it, so a waive, discount or quota granted
//! to any key would be granted to everyone. The [`Authority`] is where the
//! operator decides: an access token its authorization server issued (RFC
//! 9068 JWT validation or RFC 7662 introspection, which report the token's
//! `cnf.jkt`, RFC 9449 section 6), or a `DPoP` key it registered on its own
//! (the "API keys with `DPoP`" of the overview's plug catalogue).
//!
//! An authority is operator-trusted and may be online. It is never asked
//! before the proof's cheap checks and its signature passed.

use std::collections::{HashMap, HashSet};

use crate::jose::Thumbprint;

/// What an authority knows about an active access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenInfo {
    /// The token's `cnf.jkt`: the thumbprint of the `DPoP` key it is bound
    /// to, or `None` for a token that is not sender-constrained (a bearer
    /// token).
    pub jkt: Option<Thumbprint>,
}

impl TokenInfo {
    /// A token bound to the `DPoP` key `jkt`.
    #[must_use]
    pub fn bound_to(jkt: Thumbprint) -> Self {
        Self { jkt: Some(jkt) }
    }

    /// A bearer token: active, bound to no key.
    #[must_use]
    pub fn bearer() -> Self {
        Self { jkt: None }
    }
}

/// An authority's answer about a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenStatus {
    /// The token is valid now.
    Active(TokenInfo),
    /// Unknown, expired, revoked or for another audience.
    Inactive,
}

/// The authority could not answer: the scheme fails closed with
/// UNAVAILABLE (draft-00 section 12, "Fail closed").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("authority unavailable: {0}")]
pub struct AuthorityError(pub String);

/// The operator's check of access tokens and registered keys.
#[async_trait::async_trait]
pub trait Authority: Send + Sync {
    /// Checks an access token at `now`: is it active, and which `DPoP` key
    /// (`cnf.jkt`) is it bound to?
    async fn check_token(&self, token: &str, now: u64) -> Result<TokenStatus, AuthorityError>;

    /// Whether a `DPoP` key presented without an access token is one the
    /// operator registered. The default registers none, so a proof alone
    /// never verifies.
    async fn check_key(&self, jkt: &Thumbprint, now: u64) -> Result<bool, AuthorityError> {
        let _ = (jkt, now);
        Ok(false)
    }
}

/// An authority with a fixed list of tokens and keys, for tests and for
/// small deployments that hand out API keys themselves.
#[derive(Debug, Clone, Default)]
pub struct StaticAuthority {
    tokens: HashMap<String, TokenInfo>,
    keys: HashSet<Thumbprint>,
}

impl StaticAuthority {
    /// An authority that knows nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an active token.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>, info: TokenInfo) -> Self {
        self.tokens.insert(token.into(), info);
        self
    }

    /// Registers a `DPoP` key that is accepted without a token.
    #[must_use]
    pub fn with_key(mut self, jkt: Thumbprint) -> Self {
        self.keys.insert(jkt);
        self
    }
}

#[async_trait::async_trait]
impl Authority for StaticAuthority {
    async fn check_token(&self, token: &str, _now: u64) -> Result<TokenStatus, AuthorityError> {
        Ok(self
            .tokens
            .get(token)
            .map_or(TokenStatus::Inactive, |i| TokenStatus::Active(*i)))
    }

    async fn check_key(&self, jkt: &Thumbprint, _now: u64) -> Result<bool, AuthorityError> {
        Ok(self.keys.contains(jkt))
    }
}
