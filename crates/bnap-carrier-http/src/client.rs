//! Client helpers: what a client reads from a gate's answer and writes
//! into its request.
//!
//! These only move bytes. A client still checks every offer (4.4, 9.3)
//! before it pays and every receipt before it trusts one.

use bnap_core::credential::Credential;
use bnap_core::error::ErrorObject;
use bnap_core::offer::Offer;
use bnap_core::response::Response;
use http::HeaderMap;
use http::header::{HeaderValue, InvalidHeaderValue, WWW_AUTHENTICATE};

use crate::codec::{b64u, b64u_decode};
use crate::fields::{BNAP_ERROR, BNAP_RECEIPT, parse_offer_challenge};

/// Every BNAP offer in a 402, parsed, in the order sent. Challenges that
/// do not parse are skipped (a client ignores what it cannot use).
#[must_use]
pub fn offers(headers: &HeaderMap) -> Vec<Offer> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(parse_offer_challenge)
        .filter_map(|b| Offer::parse(&b).ok())
        .collect()
}

/// Every `WWW-Authenticate` value that is not a BNAP challenge: the native
/// challenges (L402, `Payment`), as sent.
#[must_use]
pub fn native_challenges(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| parse_offer_challenge(v).is_none())
        .map(str::to_owned)
        .collect()
}

/// The `BNAP-Receipt`, parsed (not verified: check its ack under a pinned
/// receipt key).
#[must_use]
pub fn receipt(headers: &HeaderMap) -> Option<Response> {
    let v = headers.get(BNAP_RECEIPT)?.to_str().ok()?;
    Response::parse(&b64u_decode(v)?).ok()
}

/// The `BNAP-Error`, parsed. Errors are not signed: never treat one as
/// proof of anything.
#[must_use]
pub fn error(headers: &HeaderMap) -> Option<ErrorObject> {
    let v = headers.get(BNAP_ERROR)?.to_str().ok()?;
    ErrorObject::parse(&b64u_decode(v)?).ok()
}

/// The `BNAP-Credential` value of a credential.
pub fn credential_value(cred: &Credential) -> Result<HeaderValue, CredentialValueError> {
    let bytes = cred.to_bytes().map_err(CredentialValueError::Encode)?;
    HeaderValue::from_str(&b64u(&bytes)).map_err(CredentialValueError::Header)
}

/// Why [`credential_value`] failed.
#[derive(Debug, thiserror::Error)]
pub enum CredentialValueError {
    /// The credential breaks a record rule.
    #[error("the credential cannot be encoded: {0}")]
    Encode(bnap_core::Error),
    /// Not a header value (cannot happen for `b64u`).
    #[error("not a header value: {0}")]
    Header(InvalidHeaderValue),
}
