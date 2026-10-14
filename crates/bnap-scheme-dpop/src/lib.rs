//! Attestation schemes for OAuth access tokens and API keys:
//! `httpauth:DPoP` (RFC 9449), binding class A, and `httpauth:Bearer` (RFC
//! 6750), binding class none.
//!
//! # `httpauth:DPoP`
//!
//! The client copies what it would send in `Authorization: DPoP <token>`
//! and `DPoP: <proof>` into its attest body ([`body`]), and the proof
//! carries one more claim, `bnap_ctx`: the credential's Context (draft-00
//! 5.2) in lowercase hex. The proof therefore embeds the Context, which is
//! what class A means: it verifies for this offer, this request, this
//! choice of schemes and these extensions, and for nothing else.
//! [`DpopScheme`] checks the proof ([`proof`]), then asks the operator's
//! [`Authority`] whether the token is active and bound to the proof's key
//! (or, without a token, whether the key itself is registered), and
//! returns the key's JWK SHA-256 thumbprint (RFC 7638) as its local ID and
//! its quota identity.
//!
//! Signature checks are pure Rust: ES256 with `p256`, `EdDSA` with
//! `ed25519-dalek` ([`jose`]). Nothing in this crate links OpenSSL.
//!
//! # OAuth with DPoP, and without
//!
//! The registry pairs two entries for the same tokens, and the pairing is
//! the whole point of this crate:
//!
//! | Presented as | What binds it to the request | Class | May |
//! | --- | --- | --- | --- |
//! | `httpauth:DPoP` | A DPoP proof whose key the token is bound to (`cnf.jkt`, `ath`), and whose `bnap_ctx` claim is the Context | A | Be required, waive, discount, carry a quota |
//! | `httpauth:Bearer` | Nothing: whoever holds the token can present it | none | Only be required |
//!
//! **Without DPoP binding an access token is class none and never waives
//! or discounts.** Three rules hold that line, each in its own place:
//!
//! - the registry gives `httpauth:Bearer` class none, and the gate never
//!   takes a class from a plug;
//! - bnap-core refuses to build an offer in which a class none attestation
//!   waives, discounts or carries a quota
//!   ([`bnap_core::OfferFields::check_binding_classes`]), and its pricing
//!   ignores such an effect even if one reached it (the
//!   [`bnap_core::pricing::PriceDecision`] `ignored` list);
//! - [`DpopScheme`] refuses a token that is not bound to a key
//!   (`UNBOUND_TOKEN`), so a bearer token can never be dressed up as class
//!   A, and [`BearerScheme`] refuses a token that is bound to one
//!   (`DPOP_BOUND_TOKEN`), so a sender-constrained token is never accepted
//!   without its proof (RFC 9449 section 7.1).
//!
//! # Uses
//!
//! Both schemes are `reusable` in the registry: their local IDs enter the
//! `ReplayKey` but nothing is consumed (draft-00 6.2). Any limit comes from
//! a `quota` attest entry, which only `httpauth:DPoP` can carry. The class,
//! the use model and the properties come from the registry, never from
//! these plugs.
//!
//! # Scheme codes
//!
//! A refusal is `BAD_CREDENTIAL` with a scheme code `httpauth:DPoP/<code>`
//! or `httpauth:Bearer/<code>`, from [`codes`]. An authority that cannot
//! be reached is UNAVAILABLE.

pub mod authority;
pub mod body;
pub mod client;
pub mod jose;
pub mod proof;
mod scheme;

pub use authority::{Authority, AuthorityError, StaticAuthority, TokenInfo, TokenStatus};
pub use jose::Thumbprint;
pub use proof::BNAP_CTX_CLAIM;
pub use scheme::{BEARER, BearerScheme, DPOP, DpopScheme};

/// Scheme codes, the part after `httpauth:DPoP/` or `httpauth:Bearer/`.
pub mod codes {
    /// The body is not the canonical TLV, or the part has a witness.
    pub const BAD_BODY: &str = "BAD_BODY";
    /// The proof is not a well-formed DPoP proof.
    pub const BAD_PROOF: &str = "BAD_PROOF";
    /// The proof's `alg` is not ES256 or `EdDSA`.
    pub const UNSUPPORTED_ALG: &str = "UNSUPPORTED_ALG";
    /// The proof's `jwk` is not a usable public key, or does not fit `alg`.
    pub const BAD_KEY: &str = "BAD_KEY";
    /// The proof's signature does not verify, or is not canonical.
    pub const BAD_SIGNATURE: &str = "BAD_SIGNATURE";
    /// The proof's `bnap_ctx` names another Context.
    pub const WRONG_CONTEXT: &str = "WRONG_CONTEXT";
    /// The proof's `iat` is in the future or too old.
    pub const STALE_PROOF: &str = "STALE_PROOF";
    /// The proof's `ath` does not match the access token.
    pub const ATH_MISMATCH: &str = "ATH_MISMATCH";
    /// The authority does not know the token as active.
    pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
    /// The token is bound to no key: it is a bearer token.
    pub const UNBOUND_TOKEN: &str = "UNBOUND_TOKEN";
    /// The token is bound to another key than the proof's.
    pub const KEY_MISMATCH: &str = "KEY_MISMATCH";
    /// No token, and the authority did not register the key.
    pub const UNKNOWN_KEY: &str = "UNKNOWN_KEY";
    /// The scheme was used as a pay entry.
    pub const NOT_AN_ATTESTATION: &str = "NOT_AN_ATTESTATION";
    /// A DPoP-bound token was presented as a bearer token.
    pub const DPOP_BOUND_TOKEN: &str = "DPOP_BOUND_TOKEN";
}
