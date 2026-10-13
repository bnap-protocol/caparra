//! Socket error codes (draft-00 section 8.2), the Error object, and the typed
//! errors that this crate's checks return.

use std::fmt;
use std::str::FromStr;

use crate::encoding::tu64;
use crate::tlv::{Fields, StreamKind, TlvStream};

/// The socket error codes of draft-00 section 8.2.
///
/// Codes up to 1,000 are reserved for draft-00; the registry assigns the
/// rest, so an [`ErrorObject`] carries its code as a plain `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// 1: unsupported socket version.
    Version,
    /// 2: bad encoding, order or framing.
    Malformed,
    /// 3: over a size limit.
    TooLarge,
    /// 4: offer MAC or signature fails.
    BadOffer,
    /// 5: offer or quote expired.
    Stale,
    /// 6: offer is for another action or route.
    WrongScope,
    /// 7: a scheme the offer does not list.
    NotOffered,
    /// 8: properties or a required attestation missing.
    Policy,
    /// 9: value below the effective price.
    Underpaid,
    /// 10: the scheme rejected the credential; see `scheme_code`.
    BadCredential,
    /// 11: TLS binding mismatch or not checkable.
    Binding,
    /// 12: a use ID is already committed under another `ReplayKey`.
    Spent,
    /// 13: the same credential is still in flight.
    Pending,
    /// 14: a rate counter is full.
    RateLimited,
    /// 15: store, signer or verifier unreachable; the gate fails closed.
    Unavailable,
    /// 16: the route needs a credential and none was sent.
    Required,
}

impl ErrorCode {
    /// Every socket error code, in numeric order.
    pub const ALL: [Self; 16] = [
        Self::Version,
        Self::Malformed,
        Self::TooLarge,
        Self::BadOffer,
        Self::Stale,
        Self::WrongScope,
        Self::NotOffered,
        Self::Policy,
        Self::Underpaid,
        Self::BadCredential,
        Self::Binding,
        Self::Spent,
        Self::Pending,
        Self::RateLimited,
        Self::Unavailable,
        Self::Required,
    ];

    /// The numeric code.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::Version => 1,
            Self::Malformed => 2,
            Self::TooLarge => 3,
            Self::BadOffer => 4,
            Self::Stale => 5,
            Self::WrongScope => 6,
            Self::NotOffered => 7,
            Self::Policy => 8,
            Self::Underpaid => 9,
            Self::BadCredential => 10,
            Self::Binding => 11,
            Self::Spent => 12,
            Self::Pending => 13,
            Self::RateLimited => 14,
            Self::Unavailable => 15,
            Self::Required => 16,
        }
    }

    /// The name as draft-00 writes it, such as `"WRONG_SCOPE"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Version => "VERSION",
            Self::Malformed => "MALFORMED",
            Self::TooLarge => "TOO_LARGE",
            Self::BadOffer => "BAD_OFFER",
            Self::Stale => "STALE",
            Self::WrongScope => "WRONG_SCOPE",
            Self::NotOffered => "NOT_OFFERED",
            Self::Policy => "POLICY",
            Self::Underpaid => "UNDERPAID",
            Self::BadCredential => "BAD_CREDENTIAL",
            Self::Binding => "BINDING",
            Self::Spent => "SPENT",
            Self::Pending => "PENDING",
            Self::RateLimited => "RATE_LIMITED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Required => "REQUIRED",
        }
    }

    /// The HTTP status the HTTP carrier answers with.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::Version | Self::Malformed | Self::Binding => 400,
            Self::TooLarge => 413,
            Self::BadOffer
            | Self::Stale
            | Self::WrongScope
            | Self::NotOffered
            | Self::Underpaid
            | Self::BadCredential
            | Self::Required => 402,
            Self::Policy => 403,
            Self::Spent | Self::Pending => 409,
            Self::RateLimited => 429,
            Self::Unavailable => 503,
        }
    }

    /// True when the answer carries a fresh offer (BAD_OFFER, STALE,
    /// WRONG_SCOPE and REQUIRED).
    #[must_use]
    pub fn sends_fresh_offer(self) -> bool {
        matches!(self, Self::BadOffer | Self::Stale | Self::WrongScope | Self::Required)
    }

    /// True when the answer carries `retry_after` (PENDING and RATE_LIMITED).
    #[must_use]
    pub fn has_retry_after(self) -> bool {
        matches!(self, Self::Pending | Self::RateLimited)
    }

    /// Looks up a numeric code. Codes outside 1 to 16 return `None`.
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }

    /// Looks up a name such as `"SPENT"`. Names are case-sensitive.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ErrorCode {
    type Err = UnknownErrorCode;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or(UnknownErrorCode)
    }
}

impl TryFrom<u64> for ErrorCode {
    type Error = UnknownErrorCode;
    fn try_from(code: u64) -> Result<Self, Self::Error> {
        Self::from_code(code).ok_or(UnknownErrorCode)
    }
}

impl From<ErrorCode> for u64 {
    fn from(c: ErrorCode) -> Self {
        c.code()
    }
}

/// A code or name that is not one of draft-00's sixteen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a draft-00 socket error code")]
pub struct UnknownErrorCode;

/// Which object a check was looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Object {
    /// An Offer (section 4).
    Offer,
    /// A pay entry inside an Offer.
    PayEntry,
    /// An attest entry inside an Offer.
    AttestEntry,
    /// A native entry inside an Offer.
    NativeEntry,
    /// A Credential (section 5).
    Credential,
    /// The `pay` or an `attest` part of a Credential.
    CredentialPart,
    /// The `ext` stream of a Credential.
    Ext,
    /// A Response (section 8.1).
    Response,
    /// An Error object (section 8.2).
    ErrorObject,
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Offer => "offer",
            Self::PayEntry => "pay entry",
            Self::AttestEntry => "attest entry",
            Self::NativeEntry => "native entry",
            Self::Credential => "credential",
            Self::CredentialPart => "credential part",
            Self::Ext => "ext",
            Self::Response => "response",
            Self::ErrorObject => "error object",
        })
    }
}

/// What made an object MALFORMED.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum MalformedKind {
    /// The bytes ended inside a BigSize, a length or a value.
    #[error("truncated")]
    Truncated,
    /// A BigSize was not minimally encoded.
    #[error("non-minimal BigSize")]
    NonMinimalBigSize,
    /// Record types were not strictly increasing.
    #[error("record type {typ} after {prev}: types must strictly increase")]
    TypeOrder {
        /// The previous type.
        prev: u64,
        /// The offending type.
        typ: u64,
    },
    /// An unknown even record type (the even/odd rule).
    #[error("unknown even type {0}")]
    UnknownEvenType(u64),
    /// A nested stream used a type outside 0 to 239, the experimental range
    /// and GREASE.
    #[error("type {0} not allowed in a nested stream")]
    TypeNotAllowed(u64),
    /// A required record is absent.
    #[error("record {0} missing")]
    MissingRecord(u64),
    /// A fixed-length record has the wrong length.
    #[error("record {typ} has length {len}")]
    Length {
        /// The record type.
        typ: u64,
        /// Its length.
        len: usize,
    },
    /// A `tu64` had a leading zero byte.
    #[error("record {0}: non-minimal tu64")]
    NonMinimalTu64(u64),
    /// A `tu64` was longer than eight bytes.
    #[error("record {0}: tu64 longer than 8 bytes")]
    Tu64Overflow(u64),
    /// A UTF-8 record was not valid UTF-8.
    #[error("record {0}: not UTF-8")]
    NotUtf8(u64),
    /// A flag record had a non-empty value.
    #[error("record {0}: flag with a value")]
    FlagNotEmpty(u64),
    /// A scheme ID appeared twice where it must be unique.
    #[error("scheme {0} appears twice")]
    DuplicateScheme(String),
    /// A scheme's binding class does not allow the place it is used in.
    #[error("scheme {scheme}: {rule}")]
    ClassViolation {
        /// The scheme ID.
        scheme: String,
        /// The rule of draft-00 it breaks.
        rule: &'static str,
    },
    /// A rule of draft-00 that the bytes break; the text names it.
    #[error("{0}")]
    Rule(&'static str),
}

/// Why an offer failed the authenticity check (BAD_OFFER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum BadOffer {
    /// The MAC verifies under none of the gate's current or retained keys.
    #[error("MAC does not verify")]
    Mac,
    /// An offer without `mac` lacks `issued_at`.
    #[error("offer without mac lacks issued_at")]
    MissingIssuedAt,
    /// An offer without `mac` names an `offer_key` the gate does not hold.
    #[error("offer key not held by this gate")]
    UnknownKey,
    /// `offer_sig` does not verify.
    #[error("offer_sig does not verify")]
    Signature,
    /// A credential named an OfferID the gate does not cache.
    #[error("unknown OfferID")]
    UnknownOfferId,
    /// Client side: `offer_key` is not in the pinned manifest for use
    /// `offer`, or it has expired.
    #[error("offer key not pinned for use offer")]
    NotPinned,
    /// Client side: `info` is not on the origin the offer came from.
    #[error("info is on another origin")]
    InfoOrigin,
}

/// Why an expiry check failed (STALE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum Stale {
    /// `expires` is past, beyond the 60 s skew.
    #[error("offer expired")]
    Expired,
    /// The chosen entry's `quote_expires` is past, beyond the 60 s skew.
    #[error("quote expired")]
    QuoteExpired,
    /// `issued_at` is in the future, beyond the 60 s skew.
    #[error("issued_at in the future")]
    IssuedInFuture,
}

/// A failed socket check. Each variant maps to one draft-00 error code
/// through [`Error::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// TOO_LARGE: the object is over its size limit.
    #[error("{object} is {len} bytes, over the {max}-byte limit")]
    TooLarge {
        /// The object.
        object: Object,
        /// Its length.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// MALFORMED.
    #[error("malformed {object}: {kind}")]
    Malformed {
        /// The object the fault is in.
        object: Object,
        /// The fault.
        kind: MalformedKind,
    },
    /// VERSION: unsupported socket version.
    #[error("{object} version {version} is not supported")]
    Version {
        /// The object.
        object: Object,
        /// The version it carries.
        version: u64,
    },
    /// BAD_OFFER.
    #[error("bad offer: {0}")]
    BadOffer(BadOffer),
    /// STALE.
    #[error("stale: {0}")]
    Stale(Stale),
    /// WRONG_SCOPE.
    #[error("offer is for another action or route")]
    WrongScope,
    /// NOT_OFFERED: the credential uses a scheme the offer does not list.
    #[error("scheme {0} is not offered")]
    NotOffered(String),
    /// BINDING: the TLS binding does not match or cannot be checked.
    #[error("TLS binding mismatch or not checkable")]
    Binding,
}

impl Error {
    /// The draft-00 error code this failure is answered with.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } => ErrorCode::TooLarge,
            Self::Malformed { .. } => ErrorCode::Malformed,
            Self::Version { .. } => ErrorCode::Version,
            Self::BadOffer(_) => ErrorCode::BadOffer,
            Self::Stale(_) => ErrorCode::Stale,
            Self::WrongScope => ErrorCode::WrongScope,
            Self::NotOffered(_) => ErrorCode::NotOffered,
            Self::Binding => ErrorCode::Binding,
        }
    }

    pub(crate) fn malformed(object: Object) -> impl Fn(MalformedKind) -> Self {
        move |kind| Self::Malformed { object, kind }
    }

    pub(crate) fn rule(object: Object, rule: &'static str) -> Self {
        Self::Malformed { object, kind: MalformedKind::Rule(rule) }
    }
}

/// The version every object of draft-00 carries.
pub const VERSION: u64 = 1;

/// Longest `detail` an Error object may carry, in bytes.
pub const MAX_DETAIL: usize = 256;

/// An Error object (draft-00 section 8.2): a TLV stream of 0 version, 2 code,
/// 4 `scheme_code`, 6 detail and 8 `retry_after`. Errors are not signed, and
/// a client MUST NOT treat one as proof of anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorObject {
    /// The numeric code: one of [`ErrorCode`], or a registry code above 1,000.
    pub code: u64,
    /// Namespaced scheme code, such as `bnap:notes/OUTPUT_REUSED`.
    pub scheme_code: Option<String>,
    /// Text for logs only, at most 256 bytes. It never reaches a model or a
    /// user as instructions.
    pub detail: Option<String>,
    /// Seconds to wait before retrying.
    pub retry_after: Option<u64>,
    /// Unknown odd records, kept as received.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl ErrorObject {
    /// A bare error with a socket code.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self { code: code.code(), scheme_code: None, detail: None, retry_after: None, unknown: Vec::new() }
    }

    /// Sets `detail`, cut at a character boundary to at most 256 bytes.
    #[must_use]
    pub fn with_detail(mut self, detail: &str) -> Self {
        let mut end = detail.len().min(MAX_DETAIL);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        self.detail = Some(detail[..end].to_owned());
        self
    }

    /// The socket code, when the numeric code is one of draft-00's.
    #[must_use]
    pub fn socket_code(&self) -> Option<ErrorCode> {
        ErrorCode::from_code(self.code)
    }

    /// Serializes the Error object.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.detail.as_ref().is_some_and(|d| d.len() > MAX_DETAIL) {
            return Err(Error::rule(Object::ErrorObject, "detail longer than 256 bytes"));
        }
        let mut s = TlvStream::new();
        let m = Error::malformed(Object::ErrorObject);
        s.insert(0, tu64(VERSION)).map_err(&m)?;
        s.insert(2, tu64(self.code)).map_err(&m)?;
        if let Some(c) = &self.scheme_code {
            s.insert(4, c.as_bytes()).map_err(&m)?;
        }
        if let Some(d) = &self.detail {
            s.insert(6, d.as_bytes()).map_err(&m)?;
        }
        if let Some(r) = self.retry_after {
            s.insert(8, tu64(r)).map_err(&m)?;
        }
        for (t, v) in &self.unknown {
            if t % 2 == 0 {
                return Err(m(MalformedKind::UnknownEvenType(*t)));
            }
            s.insert(*t, v.clone()).map_err(&m)?;
        }
        Ok(s.to_bytes())
    }

    /// Parses an Error object.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let m = Error::malformed(Object::ErrorObject);
        let s = TlvStream::parse(bytes, StreamKind::TopLevel).map_err(&m)?;
        let mut f = Fields::new(&s);
        let version = f.required_tu64(0).map_err(&m)?;
        if version != VERSION {
            return Err(Error::Version { object: Object::ErrorObject, version });
        }
        let code = f.required_tu64(2).map_err(&m)?;
        let scheme_code = f.utf8(4).map_err(&m)?;
        let detail = f.utf8(6).map_err(&m)?;
        if detail.as_ref().is_some_and(|d| d.len() > MAX_DETAIL) {
            return Err(Error::rule(Object::ErrorObject, "detail longer than 256 bytes"));
        }
        let retry_after = f.tu64(8).map_err(&m)?;
        let unknown = f.finish().map_err(&m)?;
        Ok(Self { code, scheme_code, detail, retry_after, unknown })
    }
}

impl From<ErrorCode> for ErrorObject {
    fn from(c: ErrorCode) -> Self {
        Self::new(c)
    }
}

impl From<&Error> for ErrorObject {
    fn from(e: &Error) -> Self {
        let mut o = Self::new(e.code());
        o = o.with_detail(&e.to_string());
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_numbered_as_draft_00() {
        for (i, c) in ErrorCode::ALL.iter().enumerate() {
            assert_eq!(c.code(), u64::try_from(i).unwrap() + 1);
            assert_eq!(ErrorCode::from_code(c.code()), Some(*c));
            assert_eq!(c.name().parse::<ErrorCode>(), Ok(*c));
        }
        assert_eq!(ErrorCode::from_code(0), None);
        assert_eq!(ErrorCode::from_code(17), None);
        assert_eq!(ErrorCode::RateLimited.http_status(), 429);
        assert!(ErrorCode::Required.sends_fresh_offer());
        assert!(!ErrorCode::NotOffered.sends_fresh_offer());
    }

    #[test]
    fn required_error_matches_example() {
        // draft-00 10.3: `BNAP-Error: AAEBAgEQ` is 00 01 01 02 01 10.
        let b = ErrorObject::new(ErrorCode::Required).to_bytes().unwrap();
        assert_eq!(b, [0x00, 0x01, 0x01, 0x02, 0x01, 0x10]);
        assert_eq!(ErrorObject::parse(&b).unwrap().socket_code(), Some(ErrorCode::Required));
    }

    #[test]
    fn detail_is_capped() {
        let long = "é".repeat(200);
        let o = ErrorObject::new(ErrorCode::Malformed).with_detail(&long);
        assert!(o.detail.as_ref().unwrap().len() <= MAX_DETAIL);
        let b = o.to_bytes().unwrap();
        assert_eq!(ErrorObject::parse(&b).unwrap(), o);
    }
}
