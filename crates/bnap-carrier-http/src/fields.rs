//! The header fields of draft-00 10.2 and how they are read.

use bnap_core::error::{Error, MalformedKind, Object};
use bnap_core::offer::Offer;
use http::HeaderMap;
use http::header::HeaderName;

use crate::codec::{b64u, b64u_decode, b64u_len};

/// The HTTP authentication scheme of BNAP challenges.
pub const AUTH_SCHEME: &str = "BNAP";
/// `BNAP-Credential`: `b64u(Credential)`.
pub const BNAP_CREDENTIAL: HeaderName = HeaderName::from_static("bnap-credential");
/// `BNAP-Context`: `b64u(Context)`, optional.
pub const BNAP_CONTEXT: HeaderName = HeaderName::from_static("bnap-context");
/// `BNAP-Receipt`: `b64u(Response)`.
pub const BNAP_RECEIPT: HeaderName = HeaderName::from_static("bnap-receipt");
/// `BNAP-Error`: `b64u(Error)`.
pub const BNAP_ERROR: HeaderName = HeaderName::from_static("bnap-error");
/// `BNAP-Fund`: a client's request for a fund quote (`bnap:notes` 8.1).
pub const BNAP_FUND: HeaderName = HeaderName::from_static("bnap-fund");
/// `Payment-Receipt`: MPP's own receipt, sent next to `BNAP-Receipt`
/// (ERRATA row 33).
pub const PAYMENT_RECEIPT: HeaderName = HeaderName::from_static("payment-receipt");
/// The `Cache-Control` value of every BNAP answer (10.2, "Caching").
pub const NO_STORE: &str = "private, no-store";

/// Every field a client sends to the gate for BNAP. The gate removes them
/// before it forwards a request, so the application never sees them.
pub const REQUEST_FIELDS: [HeaderName; 3] = [BNAP_CREDENTIAL, BNAP_CONTEXT, BNAP_FUND];

/// `BNAP offer="<b64u(Offer)>"`, the `WWW-Authenticate` value of one offer.
#[must_use]
pub fn offer_challenge(offer: &Offer) -> String {
    format!("{AUTH_SCHEME} offer=\"{}\"", b64u(offer.bytes()))
}

/// The offer bytes of a `WWW-Authenticate` value written by
/// [`offer_challenge`], or `None` for another challenge.
#[must_use]
pub fn parse_offer_challenge(value: &str) -> Option<Vec<u8>> {
    let (scheme, rest) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case(AUTH_SCHEME) {
        return None;
    }
    let rest = rest.trim();
    let (name, quoted) = rest.split_once('=')?;
    if !name.trim().eq_ignore_ascii_case("offer") {
        return None;
    }
    let inner = quoted.trim().strip_prefix('"')?.strip_suffix('"')?;
    b64u_decode(inner)
}

/// The field value as received, with repeated field lines combined as in
/// RFC 9110 section 5.3 (joined by `", "`); empty when the field is absent.
#[must_use]
pub fn combined(headers: &HeaderMap, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, v) in headers.get_all(name).iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b", ");
        }
        out.extend_from_slice(v.as_bytes());
    }
    out
}

pub(crate) fn malformed(rule: &'static str) -> Error {
    Error::Malformed {
        object: Object::Credential,
        kind: MalformedKind::Rule(rule),
    }
}

/// The decoded `BNAP-Credential` of a request, if any.
///
/// The field is refused with `TOO_LARGE` when its value is longer than
/// `b64u` of `max` bytes, before anything is decoded, and with MALFORMED
/// when it appears twice or is not canonical `b64u`.
pub fn credential(headers: &HeaderMap, max: usize) -> Result<Option<Vec<u8>>, Error> {
    let mut values = headers.get_all(&BNAP_CREDENTIAL).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(malformed("more than one BNAP-Credential field"));
    }
    let raw = value.as_bytes();
    if raw.len() > b64u_len(max) {
        return Err(Error::TooLarge {
            object: Object::Credential,
            len: raw.len() / 4 * 3,
            max,
        });
    }
    let text = std::str::from_utf8(raw).map_err(|_| malformed("BNAP-Credential is not b64u"))?;
    let bytes = b64u_decode(text).ok_or_else(|| malformed("BNAP-Credential is not b64u"))?;
    if bytes.len() > max {
        return Err(Error::TooLarge {
            object: Object::Credential,
            len: bytes.len(),
            max,
        });
    }
    Ok(Some(bytes))
}

/// The decoded `BNAP-Context`, if sent. MALFORMED when it is sent twice or
/// is not 32 bytes of canonical `b64u`.
pub fn context(headers: &HeaderMap) -> Result<Option<[u8; 32]>, Error> {
    let mut values = headers.get_all(&BNAP_CONTEXT).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(malformed("more than one BNAP-Context field"));
    }
    value
        .to_str()
        .ok()
        .and_then(b64u_decode)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .map(Some)
        .ok_or_else(|| malformed("BNAP-Context is not a b64u Context"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn combines_repeated_fields() {
        let mut h = HeaderMap::new();
        assert_eq!(combined(&h, "accept"), b"");
        h.append("accept", HeaderValue::from_static("a/b"));
        h.append("accept", HeaderValue::from_static("c/d;q=0.5"));
        assert_eq!(combined(&h, "accept"), b"a/b, c/d;q=0.5");
    }

    #[test]
    fn credential_size_cap_comes_before_decoding() {
        let mut h = HeaderMap::new();
        let long = "A".repeat(12_289);
        h.insert(&BNAP_CREDENTIAL, HeaderValue::from_str(&long).unwrap());
        let e = credential(&h, 9216).unwrap_err();
        assert_eq!(e.code(), bnap_core::ErrorCode::TooLarge);
        // Exactly 12,288 characters of garbage is read, and refused as
        // MALFORMED, not TOO_LARGE.
        h.insert(
            &BNAP_CREDENTIAL,
            HeaderValue::from_str(&"!".repeat(12_288)).unwrap(),
        );
        assert_eq!(
            credential(&h, 9216).unwrap_err().code(),
            bnap_core::ErrorCode::Malformed
        );
    }

    #[test]
    fn a_credential_sent_twice_is_malformed() {
        let mut h = HeaderMap::new();
        h.append(&BNAP_CREDENTIAL, HeaderValue::from_static("AAEB"));
        h.append(&BNAP_CREDENTIAL, HeaderValue::from_static("AAEB"));
        assert_eq!(
            credential(&h, 9216).unwrap_err().code(),
            bnap_core::ErrorCode::Malformed
        );
    }

    #[test]
    fn offer_challenges_parse_back() {
        assert_eq!(
            parse_offer_challenge("BNAP offer=\"AAEB\"").unwrap(),
            vec![0, 1, 1]
        );
        assert!(parse_offer_challenge("L402 token=\"x\"").is_none());
        assert!(parse_offer_challenge("BNAP offer=AAEB").is_none());
    }

    #[test]
    fn context_must_be_32_bytes() {
        let mut h = HeaderMap::new();
        h.insert(
            &BNAP_CONTEXT,
            HeaderValue::from_str(&b64u(&[7; 32])).unwrap(),
        );
        assert_eq!(context(&h).unwrap(), Some([7; 32]));
        h.insert(
            &BNAP_CONTEXT,
            HeaderValue::from_str(&b64u(&[7; 31])).unwrap(),
        );
        assert!(context(&h).is_err());
    }
}
