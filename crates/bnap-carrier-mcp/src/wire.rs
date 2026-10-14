//! Where BNAP messages travel in MCP (provisional), aligned with the MPP
//! MCP transport (draft-payment-transport-mcp-00).
//!
//! | Message | Place | Value |
//! | --- | --- | --- |
//! | Offer | an entry `{"org.bnap/offer": b64u(Offer)}` in `error.data.challenges` of a `tools/call` error | one entry per offer |
//! | Error | `error.data["org.bnap/error"]` | `b64u(Error)` (draft-00 8.2) |
//! | MPP challenges | `error.data.challenges`, next to the BNAP entries | the MPP MCP challenge objects (`request` as JSON) |
//! | HTTP status | `error.data.httpStatus` | the draft-00 8.2 status, 402 for payment required |
//! | Credential | `params._meta["org.bnap/credential"]` | `b64u(Credential)` |
//! | MPP credential | `params._meta["org.paymentauth/credential"]` | the MPP MCP credential object |
//! | Receipt | `result._meta["org.bnap/receipt"]` | `b64u(Response)` |
//! | MPP receipt | `result._meta["org.paymentauth/receipt"]` | the MPP MCP receipt object |
//!
//! JSON-RPC codes: [`PAYMENT_REQUIRED`] (-32042) when the call carried no
//! credential, [`VERIFICATION_FAILED`] (-32043) when a credential did not
//! admit the call and a new payment can (both with a fresh offer),
//! [`INVALID_PARAMS`] (-32602) for a credential or arguments that cannot be
//! read, and [`INTERNAL_ERROR`] (-32603) for everything a new payment does
//! not fix: PENDING, `RATE_LIMITED`, UNAVAILABLE.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::{ErrorCode, ErrorObject};
use serde_json::{Map, Value, json};

/// `_meta` key of a BNAP Credential in a `tools/call` request.
pub const CREDENTIAL: &str = "org.bnap/credential";
/// `_meta` key of a BNAP Response in a `tools/call` result.
pub const RECEIPT: &str = "org.bnap/receipt";
/// Member of a BNAP entry in `error.data.challenges`: `b64u(Offer)`.
///
/// An MPP client skips an entry that is not an MPP challenge (it has no
/// `id`, `realm`, `method`, `intent` or `request`), so BNAP offers and MPP
/// challenges share the one array the MPP MCP transport defines.
pub const OFFER: &str = "org.bnap/offer";
/// `error.data` key of the BNAP Error object.
pub const ERROR: &str = "org.bnap/error";
/// `_meta` key of an MPP credential (MPP MCP transport).
pub const MPP_CREDENTIAL: &str = "org.paymentauth/credential";
/// `_meta` key of an MPP receipt (MPP MCP transport).
pub const MPP_RECEIPT: &str = "org.paymentauth/receipt";
/// `error.data` key of the MPP challenges.
pub const CHALLENGES: &str = "challenges";
/// `error.data` key of the HTTP status the error maps to.
pub const HTTP_STATUS: &str = "httpStatus";

/// JSON-RPC code: payment required (MPP MCP transport).
pub const PAYMENT_REQUIRED: i32 = -32042;
/// JSON-RPC code: payment verification failed (MPP MCP transport).
pub const VERIFICATION_FAILED: i32 = -32043;
/// JSON-RPC code: invalid params.
pub const INVALID_PARAMS: i32 = -32602;
/// JSON-RPC code: internal error.
pub const INTERNAL_ERROR: i32 = -32603;

/// `b64u(bytes)`: base64url without padding.
#[must_use]
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Why a base64url value was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum B64Error {
    /// Longer than the decoded limit allows.
    #[error("the value is too large")]
    TooLarge,
    /// Not unpadded base64url in its one canonical form.
    #[error("the value is not base64url")]
    NotBase64url,
}

/// Reads `b64u(x)` in its one canonical form (no padding, no trailing
/// bits), refusing input that would decode to more than `max` bytes before
/// decoding it.
pub fn from_b64u(text: &str, max: usize) -> Result<Vec<u8>, B64Error> {
    // Four characters carry three bytes.
    if text.len() > max.div_ceil(3) * 4 {
        return Err(B64Error::TooLarge);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| B64Error::NotBase64url)?;
    if bytes.len() > max {
        return Err(B64Error::TooLarge);
    }
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(B64Error::NotBase64url);
    }
    Ok(bytes)
}

/// The JSON-RPC code a BNAP error travels under.
#[must_use]
pub fn jsonrpc_code(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::Required => PAYMENT_REQUIRED,
        ErrorCode::BadOffer
        | ErrorCode::Stale
        | ErrorCode::WrongScope
        | ErrorCode::NotOffered
        | ErrorCode::Policy
        | ErrorCode::Underpaid
        | ErrorCode::BadCredential
        | ErrorCode::Spent => VERIFICATION_FAILED,
        ErrorCode::Version | ErrorCode::Malformed | ErrorCode::TooLarge | ErrorCode::Binding => {
            INVALID_PARAMS
        }
        ErrorCode::Pending | ErrorCode::RateLimited | ErrorCode::Unavailable => INTERNAL_ERROR,
    }
}

/// True when the error comes with a fresh offer: the client can pay again.
#[must_use]
pub fn carries_offer(code: ErrorCode) -> bool {
    jsonrpc_code(code) == PAYMENT_REQUIRED || jsonrpc_code(code) == VERIFICATION_FAILED
}

/// A short message a user or a model can act on.
#[must_use]
pub fn message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Required => {
            "Payment required. Pay one of the offers in error.data and call the tool again with the credential in params._meta."
        }
        ErrorCode::BadOffer => {
            "The offer is unknown or not authentic. Pay the fresh offer in error.data."
        }
        ErrorCode::Stale => "The offer has expired. Pay the fresh offer in error.data.",
        ErrorCode::WrongScope => {
            "The credential was made for another call (tool or arguments differ). Pay the fresh offer in error.data for this call."
        }
        ErrorCode::NotOffered => {
            "The credential uses a scheme the offer does not list. Pay the fresh offer in error.data."
        }
        ErrorCode::Policy => {
            "The credential does not meet this tool's requirements. Pay the fresh offer in error.data."
        }
        ErrorCode::Underpaid => {
            "The payment is below the price. Pay the fresh offer in error.data in full."
        }
        ErrorCode::BadCredential => {
            "The payment did not verify. Pay the fresh offer in error.data."
        }
        ErrorCode::Spent => {
            "This payment was already used for another call. Pay the fresh offer in error.data."
        }
        ErrorCode::Version => "The BNAP version is not supported. Use version 1.",
        ErrorCode::Malformed => {
            "The request could not be read: check the credential encoding and the arguments."
        }
        ErrorCode::TooLarge => "The credential is too large. Name the offer by its ID.",
        ErrorCode::Binding => {
            "MCP credentials cannot be TLS-bound. Send the credential without a binding."
        }
        ErrorCode::Pending => {
            "This credential is still in use by a call in flight. Retry the same call later."
        }
        ErrorCode::RateLimited => "Too many calls for now. Retry later.",
        ErrorCode::Unavailable => "The payment service is unavailable. Retry the same call later.",
    }
}

/// What a payment error carries in `error.data`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ErrorData {
    /// The draft-00 8.2 HTTP status.
    pub http_status: u16,
    /// MPP MCP challenge objects, for clients that speak only MPP.
    pub challenges: Vec<Value>,
    /// `b64u(Offer)` of each fresh BNAP offer, sent as BNAP entries in
    /// `challenges`.
    pub offers: Vec<String>,
    /// The BNAP Error object.
    pub error: Option<ErrorObject>,
    /// `b64u(Response)` when the call reached commit and has a receipt.
    pub receipt: Option<String>,
}

impl ErrorData {
    /// The `error.data` object.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(HTTP_STATUS.into(), json!(self.http_status));
        if !self.challenges.is_empty() || !self.offers.is_empty() {
            let mut all: Vec<Value> = self.offers.iter().map(|o| json!({ OFFER: o })).collect();
            all.extend(self.challenges.iter().cloned());
            m.insert(CHALLENGES.into(), Value::Array(all));
        }
        if let Some(bytes) = self.error.as_ref().and_then(|e| e.to_bytes().ok()) {
            m.insert(ERROR.into(), Value::String(b64u(&bytes)));
        }
        if let Some(r) = &self.receipt {
            m.insert(RECEIPT.into(), Value::String(r.clone()));
        }
        Value::Object(m)
    }

    /// Reads `error.data`. Members it does not know are ignored; members of
    /// the wrong type are left out. A `challenges` entry with a string
    /// [`OFFER`] member is a BNAP offer; every other entry is kept as an
    /// MPP challenge.
    #[must_use]
    pub fn from_value(v: &Value) -> Self {
        let get_str = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let entries = v
            .get(CHALLENGES)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (bnap, mpp): (Vec<Value>, Vec<Value>) = entries
            .into_iter()
            .partition(|e| e.get(OFFER).is_some_and(Value::is_string));
        Self {
            http_status: v
                .get(HTTP_STATUS)
                .and_then(Value::as_u64)
                .and_then(|s| u16::try_from(s).ok())
                .unwrap_or(0),
            challenges: mpp,
            offers: bnap
                .iter()
                .filter_map(|e| e.get(OFFER).and_then(Value::as_str))
                .map(str::to_owned)
                .collect(),
            error: get_str(ERROR)
                .and_then(|s| from_b64u(&s, 1024).ok())
                .and_then(|b| ErrorObject::parse(&b).ok()),
            receipt: get_str(RECEIPT),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_read_in_one_form_only() {
        let s = b64u(&[0xfb, 0xff, 0x01]);
        assert_eq!(from_b64u(&s, 3).unwrap(), [0xfb, 0xff, 0x01]);
        assert_eq!(from_b64u(&s, 2), Err(B64Error::TooLarge));
        assert_eq!(from_b64u("+/8B", 3), Err(B64Error::NotBase64url));
        assert_eq!(from_b64u("-_8B=", 8), Err(B64Error::NotBase64url));
        // Trailing bits set: "AB" and "AA" both decode to one zero byte.
        assert_eq!(from_b64u("AB", 1), Err(B64Error::NotBase64url));
        assert_eq!(from_b64u("AA", 1).unwrap(), [0]);
        // The length check comes before decoding.
        assert_eq!(from_b64u(&"A".repeat(5000), 10), Err(B64Error::TooLarge));
    }

    #[test]
    fn every_socket_code_has_a_json_rpc_code_and_a_message() {
        for code in ErrorCode::ALL {
            let j = jsonrpc_code(code);
            assert!([-32042, -32043, -32602, -32603].contains(&j), "{code:?}");
            assert_ne!(message(code), "");
            assert!(!message(code).contains('\u{2014}'));
        }
        assert_eq!(jsonrpc_code(ErrorCode::Required), PAYMENT_REQUIRED);
        // A client that pays again on -32043 must never do so for PENDING.
        assert!(!carries_offer(ErrorCode::Pending));
        assert!(!carries_offer(ErrorCode::RateLimited));
        assert!(!carries_offer(ErrorCode::Unavailable));
        assert!(carries_offer(ErrorCode::WrongScope));
    }

    #[test]
    fn error_data_round_trips() {
        let d = ErrorData {
            http_status: 402,
            challenges: vec![json!({"id": "x", "method": "lightning"})],
            offers: vec![b64u(b"offer")],
            error: Some(ErrorObject::new(ErrorCode::Required)),
            receipt: None,
        };
        let v = d.to_value();
        assert_eq!(v["httpStatus"], 402);
        // The BNAP offer is an entry of the one challenges array.
        assert_eq!(v["challenges"][0]["org.bnap/offer"], b64u(b"offer"));
        assert_eq!(v["challenges"][1]["method"], "lightning");
        assert_eq!(ErrorData::from_value(&v), d);
    }
}
