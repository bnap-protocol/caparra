//! The attest bodies of `httpauth:DPoP` and `httpauth:Bearer`.
//!
//! Each body is a nested TLV stream (draft-00 section 2) holding what the
//! client would otherwise send in HTTP fields, copied into the credential so
//! that the Digest covers it (draft-00 5.1, "Everything verified is in the
//! credential"):
//!
//! | Scheme | Type | Name | Value | Presence |
//! | --- | --- | --- | --- | --- |
//! | `httpauth:DPoP` | 0 | proof | The `DPoP` proof JWT, compact serialization (the `DPoP` field value) | Required |
//! | `httpauth:DPoP` | 2 | `access_token` | The access token, as `Authorization: DPoP <token>` carries it | Optional |
//! | `httpauth:Bearer` | 0 | token | The bearer token or API key | Required |
//!
//! Bodies are canonical (draft-00 5.1): a record of any other type, odd ones
//! included, a record with an empty value, a value over the size limit, or a
//! value with a byte outside its syntax is refused, so nobody on the path
//! can re-encode a body into another one that verifies the same way.

use bnap_core::tlv::{StreamKind, TlvStream, write_record};

/// Record types of the `httpauth:DPoP` body.
pub mod dpop_types {
    /// The `DPoP` proof JWT.
    pub const PROOF: u64 = 0;
    /// The access token.
    pub const ACCESS_TOKEN: u64 = 2;
}

/// Record types of the `httpauth:Bearer` body.
pub mod bearer_types {
    /// The bearer token.
    pub const TOKEN: u64 = 0;
}

/// The largest `DPoP` proof accepted, in bytes.
pub const MAX_PROOF: usize = 4096;

/// The largest access token accepted, in bytes.
pub const MAX_TOKEN: usize = 8192;

/// Why a body was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BodyError {
    /// The TLV framing is broken.
    #[error("bad TLV framing")]
    Framing,
    /// A record of a type the body does not define.
    #[error("record type {0} is not part of the body")]
    UnknownRecord(u64),
    /// A required record is missing.
    #[error("record type {0} is missing")]
    Missing(u64),
    /// A record is present but empty.
    #[error("record type {0} is empty")]
    Empty(u64),
    /// A record is longer than its limit.
    #[error("record type {0} is too long")]
    TooLong(u64),
    /// A record holds a byte outside its syntax.
    #[error("record type {0} has a byte outside its syntax")]
    Syntax(u64),
}

/// The `httpauth:DPoP` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopBody {
    /// The `DPoP` proof JWT, compact serialization.
    pub proof: String,
    /// The access token the proof is presented with, if any.
    pub access_token: Option<String>,
}

impl DpopBody {
    /// Serializes the body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_record(&mut out, dpop_types::PROOF, self.proof.as_bytes());
        if let Some(t) = &self.access_token {
            write_record(&mut out, dpop_types::ACCESS_TOKEN, t.as_bytes());
        }
        out
    }

    /// Parses a body, refusing anything but its one canonical form.
    pub fn parse(bytes: &[u8]) -> Result<Self, BodyError> {
        let s = stream(bytes, &[dpop_types::PROOF, dpop_types::ACCESS_TOKEN])?;
        let proof = s
            .get(dpop_types::PROOF)
            .ok_or(BodyError::Missing(dpop_types::PROOF))?;
        let proof = value(dpop_types::PROOF, proof, MAX_PROOF, is_jws_char)?;
        let access_token = s
            .get(dpop_types::ACCESS_TOKEN)
            .map(|t| token(dpop_types::ACCESS_TOKEN, t))
            .transpose()?;
        Ok(Self {
            proof,
            access_token,
        })
    }
}

/// The `httpauth:Bearer` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerBody {
    /// The bearer token or API key.
    pub token: String,
}

impl BearerBody {
    /// Serializes the body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_record(&mut out, bearer_types::TOKEN, self.token.as_bytes());
        out
    }

    /// Parses a body, refusing anything but its one canonical form.
    pub fn parse(bytes: &[u8]) -> Result<Self, BodyError> {
        let s = stream(bytes, &[bearer_types::TOKEN])?;
        let t = s
            .get(bearer_types::TOKEN)
            .ok_or(BodyError::Missing(bearer_types::TOKEN))?;
        Ok(Self {
            token: token(bearer_types::TOKEN, t)?,
        })
    }
}

/// Parses the stream and refuses every record type not in `known`.
fn stream(bytes: &[u8], known: &[u64]) -> Result<TlvStream, BodyError> {
    let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(|_| BodyError::Framing)?;
    if let Some((t, _)) = s.records().iter().find(|(t, _)| !known.contains(t)) {
        return Err(BodyError::UnknownRecord(*t));
    }
    Ok(s)
}

fn value(typ: u64, v: &[u8], max: usize, ok: fn(u8) -> bool) -> Result<String, BodyError> {
    if v.is_empty() {
        return Err(BodyError::Empty(typ));
    }
    if v.len() > max {
        return Err(BodyError::TooLong(typ));
    }
    if !v.iter().all(|b| ok(*b)) {
        return Err(BodyError::Syntax(typ));
    }
    // Every allowed byte is ASCII.
    String::from_utf8(v.to_vec()).map_err(|_| BodyError::Syntax(typ))
}

/// An RFC 6750 `b64token`: `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" /
/// "+" / "/" ) *"="`.
fn token(typ: u64, v: &[u8]) -> Result<String, BodyError> {
    let t = value(typ, v, MAX_TOKEN, |b| {
        b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b)
    })?;
    let core = t.trim_end_matches('=');
    if core.is_empty() || core.contains('=') {
        return Err(BodyError::Syntax(typ));
    }
    Ok(t)
}

/// The compact JWS alphabet: base64url and the dot.
fn is_jws_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dpop(token: Option<&str>) -> DpopBody {
        DpopBody {
            proof: "aGVhZA.cGF5bG9hZA.c2ln".into(),
            access_token: token.map(Into::into),
        }
    }

    #[test]
    fn bodies_round_trip() {
        for b in [
            dpop(None),
            dpop(Some("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")),
        ] {
            assert_eq!(DpopBody::parse(&b.to_bytes()).unwrap(), b);
        }
        let b = BearerBody {
            token: "mF_9.B5f-4.1JqM".into(),
        };
        assert_eq!(BearerBody::parse(&b.to_bytes()).unwrap(), b);
    }

    #[test]
    fn only_the_canonical_form_is_accepted() {
        // An unknown odd record, an unknown even record, an experimental
        // one: none of them is verified, so none is allowed.
        for t in [1u64, 3, 4, 1_000_000_001] {
            let mut s =
                TlvStream::parse(&dpop(Some("tok")).to_bytes(), StreamKind::Nested).unwrap();
            s.insert(t, b"x".to_vec()).unwrap();
            assert_eq!(
                DpopBody::parse(&s.to_bytes()),
                Err(BodyError::UnknownRecord(t)),
                "{t}"
            );
        }
        // An empty access token record is not the same as no token.
        let mut empty = Vec::new();
        write_record(&mut empty, 0, b"a.b.c");
        write_record(&mut empty, 2, b"");
        assert_eq!(DpopBody::parse(&empty), Err(BodyError::Empty(2)));
        // No proof at all.
        let mut no_proof = Vec::new();
        write_record(&mut no_proof, 2, b"tok");
        assert_eq!(DpopBody::parse(&no_proof), Err(BodyError::Missing(0)));
        // Whitespace or padding inside the JWS, a space in a token.
        let mut ws = Vec::new();
        write_record(&mut ws, 0, b"a.b.c ");
        assert_eq!(DpopBody::parse(&ws), Err(BodyError::Syntax(0)));
        let mut sp = Vec::new();
        write_record(&mut sp, 0, b"tok en");
        assert_eq!(BearerBody::parse(&sp), Err(BodyError::Syntax(0)));
        let mut eq = Vec::new();
        write_record(&mut eq, 0, b"to=ken");
        assert_eq!(BearerBody::parse(&eq), Err(BodyError::Syntax(0)));
        // Records out of order are a framing error.
        let mut order = Vec::new();
        write_record(&mut order, 2, b"tok");
        write_record(&mut order, 0, b"a.b.c");
        assert_eq!(DpopBody::parse(&order), Err(BodyError::Framing));
        // Too long.
        let long = DpopBody {
            proof: "a".repeat(MAX_PROOF + 1),
            access_token: None,
        };
        assert_eq!(
            DpopBody::parse(&long.to_bytes()),
            Err(BodyError::TooLong(0))
        );
    }
}
