//! Key discovery, behind a trait so that the scheme itself never touches
//! the network.
//!
//! Web Bot Auth (draft-ietf-webbotauth-httpsig-protocol-00 section 5.5)
//! resolves the agent's `Signature-Agent` URL to a JWK set and picks the
//! key the `keyid` parameter names. Fetching, caching, refreshing and the
//! SSRF rules of section 6.7 are the operator's: a [`KeyDirectory`] does
//! them, online or from a cache, and the scheme only asks it for one key.
//! Lookup is keyed on the pair (URL, `keyid`), never on the key alone
//! (section 5.4), and an agent without a URL resolves only against keys the
//! verifier already holds (section 4.3).
//!
//! The directory is also where trust lives. A valid signature proves that
//! the holder of a key the URL publishes signed this request; it says
//! nothing about whether the operator should discount it (section 4.1).
//! Anyone can publish a directory, so a directory that resolves every URL
//! would grant the attestation's effect to everyone: an operator lists the
//! agents it honours, or resolves only URLs a registry it trusts names.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::hash::sha256;

/// How a `Signature-Agent` member resolves to keys (the member's `type`
/// parameter, section 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentType {
    /// `directory`, the default: the origin's well-known
    /// `http-message-signatures-directory`.
    Directory,
    /// `jwks_uri`: the URL is a JWK set.
    JwksUri,
    /// `cimd`: the URL is a Client ID Metadata Document.
    Cimd,
}

impl AgentType {
    /// Reads the `type` token; `None` for a type this crate does not know,
    /// which a verifier MUST ignore (section 5.2.1).
    #[must_use]
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "directory" => Some(Self::Directory),
            "jwks_uri" => Some(Self::JwksUri),
            "cimd" => Some(Self::Cimd),
            _ => None,
        }
    }
}

/// The `Signature-Agent` member a signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignatureAgent {
    /// The member's URL, `https` only.
    pub url: String,
    /// How it resolves.
    pub kind: AgentType,
}

/// What the scheme asks a directory.
#[derive(Debug, Clone, Copy)]
pub struct KeyQuery<'a> {
    /// The agent the signature covers, or `None` when the request named no
    /// usable URL: then only a key the verifier already holds can match.
    pub agent: Option<&'a SignatureAgent>,
    /// The `keyid` parameter: the base64url JWK SHA-256 thumbprint of the
    /// key.
    pub keyid: &'a str,
    /// The gate's clock, for cache expiry and key validity (`nbf`, `exp`).
    pub now: u64,
}

/// The directory could not answer: the scheme fails closed with
/// UNAVAILABLE (draft-00 section 12, "Fail closed").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("key directory unavailable: {0}")]
pub struct DirectoryError(pub String);

/// Resolves a Web Bot Auth key.
#[async_trait::async_trait]
pub trait KeyDirectory: Send + Sync {
    /// The Ed25519 public key `q.keyid` names at `q.agent`, if the
    /// operator honours that pair; `Ok(None)` when it does not, or when the
    /// directory does not list the key.
    async fn resolve(&self, q: &KeyQuery<'_>) -> Result<Option<[u8; 32]>, DirectoryError>;
}

/// The RFC 7638 input for an Ed25519 key (RFC 8037 appendix A.3).
#[must_use]
pub fn thumbprint_input(key: &[u8; 32]) -> String {
    format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(key)
    )
}

/// The JWK SHA-256 thumbprint of an Ed25519 key: the scheme's local ID.
#[must_use]
pub fn thumbprint(key: &[u8; 32]) -> [u8; 32] {
    sha256(thumbprint_input(key).as_bytes())
}

/// The `keyid` of an Ed25519 key: its thumbprint in base64url (section 5.2).
#[must_use]
pub fn keyid(key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(thumbprint(key))
}

/// A directory with a fixed list of keys, for tests and for operators who
/// pin the agents they honour.
#[derive(Debug, Clone, Default)]
pub struct StaticDirectory {
    agents: HashMap<(String, String), [u8; 32]>,
    held: HashMap<String, [u8; 32]>,
}

impl StaticDirectory {
    /// A directory that knows no key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lists `key` at the agent URL `url`, whatever the member's type.
    #[must_use]
    pub fn with_agent_key(mut self, url: impl Into<String>, key: [u8; 32]) -> Self {
        self.agents.insert((url.into(), keyid(&key)), key);
        self
    }

    /// Holds `key` for requests that name no usable agent URL (section
    /// 4.3).
    #[must_use]
    pub fn with_held_key(mut self, key: [u8; 32]) -> Self {
        self.held.insert(keyid(&key), key);
        self
    }
}

#[async_trait::async_trait]
impl KeyDirectory for StaticDirectory {
    async fn resolve(&self, q: &KeyQuery<'_>) -> Result<Option<[u8; 32]>, DirectoryError> {
        Ok(match q.agent {
            Some(a) => self
                .agents
                .get(&(a.url.clone(), q.keyid.to_owned()))
                .copied(),
            None => self.held.get(q.keyid).copied(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8037_thumbprint() {
        // RFC 8037 appendix A.3.
        let x = URL_SAFE_NO_PAD
            .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            .unwrap();
        let key: [u8; 32] = x.try_into().unwrap();
        assert_eq!(keyid(&key), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn the_web_bot_auth_test_key_has_the_keyid_the_draft_uses() {
        // The Ed25519 test key of the Web Bot Auth drafts and of the
        // web-bot-auth crate's tests, and the keyid they sign with.
        let x = URL_SAFE_NO_PAD
            .decode("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
            .unwrap();
        let key: [u8; 32] = x.try_into().unwrap();
        assert_eq!(keyid(&key), "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
    }
}
