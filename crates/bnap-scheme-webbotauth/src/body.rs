//! The `httpsig:web-bot-auth` attest body.
//!
//! A nested TLV stream (draft-00 section 2) holding the three HTTP fields a
//! Web Bot Auth agent sends, copied into the credential so that the Digest
//! covers them (draft-00 5.1, "Everything verified is in the credential"):
//!
//! | Type | Name | Value | Presence |
//! | --- | --- | --- | --- |
//! | 0 | signature | The `Signature` field value (RFC 9421 4.2) | Required |
//! | 2 | `signature_input` | The `Signature-Input` field value (RFC 9421 4.1) | Required |
//! | 4 | `signature_agent` | The `Signature-Agent` field value (draft-ietf-webbotauth-httpsig-protocol-00 5.2.1) | Optional |
//!
//! The body is canonical (draft-00 5.1): a record of any other type, an
//! empty record, a value over [`MAX_FIELD`] bytes, or a byte outside visible
//! ASCII and space is refused here, and the scheme then requires each value
//! to be the strict structured-field serialization of what it parses to
//! (RFC 9651 section 4), so whitespace, member order and number spellings
//! have one form only.

use bnap_core::tlv::{StreamKind, TlvStream, write_record};

/// Record types of the body.
pub mod types {
    /// The `Signature` field value.
    pub const SIGNATURE: u64 = 0;
    /// The `Signature-Input` field value.
    pub const SIGNATURE_INPUT: u64 = 2;
    /// The `Signature-Agent` field value.
    pub const SIGNATURE_AGENT: u64 = 4;
}

/// The longest field value accepted, in bytes.
pub const MAX_FIELD: usize = 4096;

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
    /// A record is longer than [`MAX_FIELD`].
    #[error("record type {0} is too long")]
    TooLong(u64),
    /// A record holds a byte outside visible ASCII and space.
    #[error("record type {0} has a byte outside visible ASCII")]
    Syntax(u64),
}

/// The `httpsig:web-bot-auth` body: three HTTP field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbaBody {
    /// The `Signature` field value.
    pub signature: String,
    /// The `Signature-Input` field value.
    pub signature_input: String,
    /// The `Signature-Agent` field value, if the agent sent one.
    pub signature_agent: Option<String>,
}

impl WbaBody {
    /// Serializes the body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_record(&mut out, types::SIGNATURE, self.signature.as_bytes());
        write_record(
            &mut out,
            types::SIGNATURE_INPUT,
            self.signature_input.as_bytes(),
        );
        if let Some(a) = &self.signature_agent {
            write_record(&mut out, types::SIGNATURE_AGENT, a.as_bytes());
        }
        out
    }

    /// Parses a body, refusing unknown records and bytes outside the field
    /// syntax.
    pub fn parse(bytes: &[u8]) -> Result<Self, BodyError> {
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(|_| BodyError::Framing)?;
        let known = [
            types::SIGNATURE,
            types::SIGNATURE_INPUT,
            types::SIGNATURE_AGENT,
        ];
        if let Some((t, _)) = s.records().iter().find(|(t, _)| !known.contains(t)) {
            return Err(BodyError::UnknownRecord(*t));
        }
        let required = |t: u64| {
            s.get(t)
                .ok_or(BodyError::Missing(t))
                .and_then(|v| field(t, v))
        };
        Ok(Self {
            signature: required(types::SIGNATURE)?,
            signature_input: required(types::SIGNATURE_INPUT)?,
            signature_agent: s
                .get(types::SIGNATURE_AGENT)
                .map(|v| field(types::SIGNATURE_AGENT, v))
                .transpose()?,
        })
    }
}

fn field(typ: u64, v: &[u8]) -> Result<String, BodyError> {
    if v.is_empty() {
        return Err(BodyError::Empty(typ));
    }
    if v.len() > MAX_FIELD {
        return Err(BodyError::TooLong(typ));
    }
    if !v.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(BodyError::Syntax(typ));
    }
    String::from_utf8(v.to_vec()).map_err(|_| BodyError::Syntax(typ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(agent: Option<&str>) -> WbaBody {
        WbaBody {
            signature: "sig1=:AAAA:".into(),
            signature_input: r#"sig1=("@authority");created=1;expires=2"#.into(),
            signature_agent: agent.map(Into::into),
        }
    }

    #[test]
    fn bodies_round_trip() {
        for b in [body(None), body(Some(r#"sig1="https://bot.example""#))] {
            assert_eq!(WbaBody::parse(&b.to_bytes()).unwrap(), b);
        }
    }

    #[test]
    fn unknown_empty_and_non_ascii_records_are_refused() {
        for t in [1u64, 3, 5, 6, 1_000_000_001] {
            let mut s = TlvStream::parse(&body(None).to_bytes(), StreamKind::Nested).unwrap();
            s.insert(t, b"x".to_vec()).unwrap();
            assert_eq!(
                WbaBody::parse(&s.to_bytes()),
                Err(BodyError::UnknownRecord(t))
            );
        }
        let mut b = Vec::new();
        write_record(&mut b, 0, b"sig1=:AAAA:");
        assert_eq!(WbaBody::parse(&b), Err(BodyError::Missing(2)));
        write_record(&mut b, 2, b"x");
        write_record(&mut b, 4, b"");
        assert_eq!(WbaBody::parse(&b), Err(BodyError::Empty(4)));
        let mut nl = Vec::new();
        write_record(&mut nl, 0, b"sig1=:AAAA:\r\n");
        write_record(&mut nl, 2, b"x");
        assert_eq!(WbaBody::parse(&nl), Err(BodyError::Syntax(0)));
        let long = WbaBody {
            signature: "a".repeat(MAX_FIELD + 1),
            ..body(None)
        };
        assert_eq!(WbaBody::parse(&long.to_bytes()), Err(BodyError::TooLong(0)));
    }
}
