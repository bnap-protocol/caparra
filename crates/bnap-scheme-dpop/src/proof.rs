//! Checking a `DPoP` proof (RFC 9449 section 4.3) against a BNAP request.
//!
//! The proof is a JWT the client signs with its `DPoP` key. For BNAP it
//! carries one more claim, [`BNAP_CTX_CLAIM`] (`bnap_ctx`): the lowercase hex
//! of the credential's Context (draft-00 5.2). That claim is what makes the
//! attestation class A: the proof embeds everything the client chose (the
//! offer, the request's action scope, the value scheme, every attestation
//! scheme and the extensions), so it verifies for this one request and no
//! other.
//!
//! What [`check`] does, with RFC 9449 4.3's step numbers:
//!
//! | Step | Check |
//! | --- | --- |
//! | 2 | One well-formed compact JWS, every part canonical ([`crate::jose`]) |
//! | 3 | `jti`, `htm`, `htu`, `iat` and `bnap_ctx` present, with their types |
//! | 4 | `typ` is `dpop+jwt` |
//! | 5 | `alg` is `ES256` or `EdDSA` (`Ed25519`); no `crit` |
//! | 6 | The signature verifies under the `jwk` header |
//! | 7 | The `jwk` has no private key material |
//! | 8, 9 | Not compared with the request: see below |
//! | 10 | Not used: BNAP has no `DPoP-Nonce`; the `OfferID` inside the Context plays its part |
//! | 11 | `iat` is not in the future (60 s of skew), and not older than `max_age` when one is set |
//! | 12 | `ath` is the hash of the access token presented with it, and absent without one |
//!
//! **`htm` and `htu` are not compared with the request.** Draft-00 5.1
//! forbids a scheme to read request fields, and the plug's `VerifyCtx` gives
//! it no method or target. They need no comparison: `bnap_ctx` binds the
//! Context, whose action scope already hashes the method, the target, the
//! content and the listed headers (draft-00 10.1), so a proof made for any
//! other request names another Context and is refused. They stay required
//! so that a proof is an RFC 9449 proof.
//!
//! **No `max_age` by default.** The Context names the offer, whose `expires`
//! the gate checked before any plug ran (draft-00 4.4), so a proof is never
//! older than its offer. A shorter window would refuse the replays a client
//! makes to fetch a receipt it missed (draft-00 6.4): a replay is verified
//! again, and an attestation that no longer verifies drops its use IDs from
//! the `ReplayKey`, so the replay would no longer find its outcome.

use bnap_core::hash::{Context, sha256};
use bnap_core::limits::CLOCK_SKEW;
use serde_json::{Map, Value};

use crate::jose::{self, Alg, JoseError, PublicJwk, Thumbprint};

/// The JWT claim that carries the Context, as lowercase hex.
pub const BNAP_CTX_CLAIM: &str = "bnap_ctx";

/// The `typ` of a `DPoP` proof (RFC 9449 4.2).
pub const DPOP_TYP: &str = "dpop+jwt";

/// The longest `jti` accepted, in bytes.
pub const MAX_JTI: usize = 256;

/// What a proof is checked against.
#[derive(Debug, Clone, Copy)]
pub struct ProofCheck<'a> {
    /// The Context the gate computed for this credential.
    pub context: &'a Context,
    /// The gate's clock.
    pub now: u64,
    /// The oldest `iat` accepted, in seconds before `now` (plus a clock
    /// skew); `None` leaves the age to the offer's expiry.
    pub max_age: Option<u64>,
    /// The access token presented with the proof, if any.
    pub access_token: Option<&'a str>,
}

/// A proof that passed [`check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedProof {
    /// The proof's public key.
    pub jwk: PublicJwk,
    /// Its JWK SHA-256 thumbprint.
    pub jkt: Thumbprint,
    /// The algorithm it was signed with.
    pub alg: Alg,
    /// `jti`.
    pub jti: String,
    /// `htm`.
    pub htm: String,
    /// `htu`.
    pub htu: String,
    /// `iat`.
    pub iat: u64,
}

/// Why a proof was refused. [`ProofError::code`] is the scheme code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// Not a well-formed `DPoP` proof.
    #[error("malformed proof: {0}")]
    Malformed(String),
    /// An algorithm this scheme does not verify.
    #[error("unsupported alg")]
    UnsupportedAlg,
    /// A `jwk` that is not a usable public key.
    #[error("bad key: {0}")]
    BadKey(JoseError),
    /// The signature does not verify, or is not canonical.
    #[error("bad signature: {0}")]
    BadSignature(JoseError),
    /// `bnap_ctx` names another Context.
    #[error("the proof names another Context")]
    WrongContext,
    /// `iat` is in the future, or older than `max_age`.
    #[error("the proof is not fresh")]
    Stale,
    /// `ath` does not match the access token, or is present without one.
    #[error("ath does not match the access token")]
    AthMismatch,
}

impl ProofError {
    /// The scheme code (the part after `httpauth:DPoP/`).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => crate::codes::BAD_PROOF,
            Self::UnsupportedAlg => crate::codes::UNSUPPORTED_ALG,
            Self::BadKey(_) => crate::codes::BAD_KEY,
            Self::BadSignature(_) => crate::codes::BAD_SIGNATURE,
            Self::WrongContext => crate::codes::WRONG_CONTEXT,
            Self::Stale => crate::codes::STALE_PROOF,
            Self::AthMismatch => crate::codes::ATH_MISMATCH,
        }
    }
}

fn malformed(what: impl Into<String>) -> ProofError {
    ProofError::Malformed(what.into())
}

fn string<'a>(o: &'a Map<String, Value>, name: &str) -> Result<&'a str, ProofError> {
    match o.get(name) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        Some(_) => Err(malformed(format!("{name} is not a non-empty string"))),
        None => Err(malformed(format!("{name} is missing"))),
    }
}

/// Checks a `DPoP` proof against the request's Context, the clock and the
/// access token presented with it. Cheap checks run first: the signature is
/// checked only once the claims name this Context.
pub fn check(proof: &[u8], chk: &ProofCheck<'_>) -> Result<CheckedProof, ProofError> {
    let jws = jose::parse_compact(proof).map_err(|e| malformed(e.to_string()))?;
    let h = &jws.header;
    if h.get("typ").and_then(Value::as_str) != Some(DPOP_TYP) {
        return Err(malformed("typ is not dpop+jwt"));
    }
    if h.contains_key("crit") {
        return Err(malformed(
            "crit names extensions this scheme does not understand",
        ));
    }
    let alg = Alg::from_jws(string(h, "alg")?).ok_or(ProofError::UnsupportedAlg)?;
    let jwk = PublicJwk::from_value(h.get("jwk").ok_or_else(|| malformed("jwk is missing"))?)
        .map_err(ProofError::BadKey)?;
    let fits = matches!(
        (alg, jwk),
        (Alg::Es256, PublicJwk::P256 { .. }) | (Alg::EdDsa, PublicJwk::Ed25519 { .. })
    );
    if !fits {
        return Err(ProofError::BadKey(JoseError::AlgMismatch));
    }

    let c = &jws.payload;
    let jti = string(c, "jti")?;
    if jti.len() > MAX_JTI {
        return Err(malformed("jti is too long"));
    }
    let htm = string(c, "htm")?;
    if !htm.bytes().all(is_tchar) {
        return Err(malformed("htm is not an HTTP method"));
    }
    let htu = string(c, "htu")?;
    let iat = c
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("iat is not a non-negative integer"))?;
    // The Context, as the claim names it: exactly the lowercase hex.
    if string(c, BNAP_CTX_CLAIM)? != hex::encode(chk.context.0) {
        return Err(ProofError::WrongContext);
    }
    match (chk.access_token, c.get("ath")) {
        (None, None) => {}
        (Some(t), Some(Value::String(ath))) if *ath == jose::b64u(&sha256(t.as_bytes())) => {}
        _ => return Err(ProofError::AthMismatch),
    }
    if iat > chk.now.saturating_add(CLOCK_SKEW) {
        return Err(ProofError::Stale);
    }
    if let Some(age) = chk.max_age
        && chk.now > iat.saturating_add(age).saturating_add(CLOCK_SKEW)
    {
        return Err(ProofError::Stale);
    }

    jwk.verify(alg, &jws.signing_input, &jws.signature)
        .map_err(ProofError::BadSignature)?;
    Ok(CheckedProof {
        jkt: jwk.thumbprint(),
        jwk,
        alg,
        jti: jti.to_owned(),
        htm: htm.to_owned(),
        htu: htu.to_owned(),
        iat,
    })
}

/// An RFC 9110 `tchar`, the syntax of a method.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
