//! `httpsig:web-bot-auth`: Web Bot Auth (HTTP Message Signatures, RFC 9421,
//! profiled by draft-ietf-webbotauth-httpsig-protocol-00) as a BNAP
//! attestation of binding class A.
//!
//! An agent that signs its requests with Web Bot Auth adds one component to
//! what it signs: `bnap-context`, the credential's Context in base64url, as
//! the `BNAP-Context` field carries it (draft-00 10.2). It copies its
//! `Signature`, `Signature-Input` and `Signature-Agent` field values into
//! the attest body ([`body`]). The signature then embeds the Context,
//! which is what class A means: it verifies for this offer, this request,
//! this choice of schemes and these extensions, and for nothing else.
//!
//! [`WebBotAuthScheme`] rebuilds the signature base from the gate's own
//! values (draft-00 5.1), never from the HTTP request: its configured
//! authority for `@authority`, the Context it was handed for
//! `bnap-context`, the body for the agent. Key discovery is behind the
//! [`KeyDirectory`] trait ([`directory`]), so the scheme does no network
//! I/O and tests need none. The signature itself is checked by Cloudflare's
//! `web-bot-auth` crate (Ed25519, pure Rust).
//!
//! It returns one local ID, the signing key's JWK SHA-256 thumbprint (RFC
//! 7638), which is also its quota identity. The registry sets the class
//! (A) and the use model (`reusable`); effects come from the offer.
//!
//! # Scheme codes
//!
//! A refusal is `BAD_CREDENTIAL` with the scheme code
//! `httpsig:web-bot-auth/<code>`, from [`codes`]. A directory that cannot
//! be reached is UNAVAILABLE.

pub mod body;
pub mod client;
pub mod directory;
mod scheme;

pub use directory::{
    AgentType, DirectoryError, KeyDirectory, KeyQuery, SignatureAgent, StaticDirectory, keyid,
    thumbprint,
};
#[doc(hidden)]
pub use scheme::fuzz_check_body;
pub use scheme::{CONTEXT_FIELD, DEFAULT_MAX_LIFETIME, ID, LABEL, TAG, WebBotAuthScheme};

/// Scheme codes, the part after `httpsig:web-bot-auth/`.
pub mod codes {
    /// The body is not canonical: unknown records, fields not in their
    /// strict serialization, more than one signature, a label other than
    /// [`LABEL`](crate::LABEL), a witness.
    pub const BAD_BODY: &str = "BAD_BODY";
    /// `Signature-Input` lacks a parameter, has the wrong `tag`, names a
    /// component twice, or has `expires` before `created`.
    pub const BAD_SIGNATURE_INPUT: &str = "BAD_SIGNATURE_INPUT";
    /// The signature covers a component the gate cannot build from the
    /// Context and its own authority.
    pub const UNSUPPORTED_COMPONENT: &str = "UNSUPPORTED_COMPONENT";
    /// The signature does not cover `@authority` or `bnap-context`.
    pub const MISSING_COMPONENT: &str = "MISSING_COMPONENT";
    /// `alg` is not `ed25519`.
    pub const UNSUPPORTED_ALG: &str = "UNSUPPORTED_ALG";
    /// `Signature-Agent` is malformed, not `https`, not the one member the
    /// signature covers, or not covered.
    pub const BAD_AGENT: &str = "BAD_AGENT";
    /// `keyid` is not a base64url SHA-256 thumbprint.
    pub const BAD_KEYID: &str = "BAD_KEYID";
    /// The directory does not list the key for this agent, or lists one
    /// that is not a usable Ed25519 key (a small-order point included).
    pub const UNKNOWN_KEY: &str = "UNKNOWN_KEY";
    /// The directory's key does not have the thumbprint `keyid` names.
    pub const KEYID_MISMATCH: &str = "KEYID_MISMATCH";
    /// `created` is in the future or the signature has expired.
    pub const STALE_SIGNATURE: &str = "STALE_SIGNATURE";
    /// `expires - created` is above the scheme's limit.
    pub const LIFETIME_TOO_LONG: &str = "LIFETIME_TOO_LONG";
    /// The signature does not verify over the gate's signature base.
    pub const BAD_SIGNATURE: &str = "BAD_SIGNATURE";
    /// The scheme was used as a pay entry.
    pub const NOT_AN_ATTESTATION: &str = "NOT_AN_ATTESTATION";
}
