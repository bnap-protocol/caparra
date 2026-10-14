//! The client side: reading a payment error, attaching a credential and
//! reading a receipt, on JSON values as any MCP client library holds them.

use bnap_core::{ErrorObject, Offer, Response};
use serde_json::{Map, Value};

use crate::wire::{self, ErrorData, b64u, from_b64u};

/// The largest object a client reads from a server: 64 KiB.
const MAX_READ: usize = 64 * 1024;

/// What a `tools/call` error tells a client.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentError {
    /// The JSON-RPC code.
    pub code: i32,
    /// The BNAP Error object, if the server sent one.
    pub error: Option<ErrorObject>,
    /// Every BNAP offer, parsed (each still needs the client checks of
    /// draft-00 4.4).
    pub offers: Vec<Offer>,
    /// The MPP challenges, as sent.
    pub challenges: Vec<Value>,
    /// The `httpStatus`.
    pub http_status: u16,
    /// The receipt, when the call reached commit and failed.
    pub receipt: Option<Response>,
}

impl PaymentError {
    /// Reads the error's `code` and `data`. Offers that do not parse are
    /// left out.
    #[must_use]
    pub fn read(code: i32, data: Option<&Value>) -> Self {
        let d = data.map(ErrorData::from_value).unwrap_or_default();
        Self {
            code,
            error: d.error,
            offers: d
                .offers
                .iter()
                .filter_map(|o| from_b64u(o, MAX_READ).ok())
                .filter_map(|b| Offer::parse(&b).ok())
                .collect(),
            challenges: d.challenges,
            http_status: d.http_status,
            receipt: d.receipt.as_deref().and_then(read_receipt),
        }
    }

    /// True when paying again can answer the error (`-32042`, `-32043`).
    #[must_use]
    pub fn payable(&self) -> bool {
        self.code == wire::PAYMENT_REQUIRED || self.code == wire::VERIFICATION_FAILED
    }
}

/// `_meta` with a BNAP Credential: `{"org.bnap/credential": b64u(cred)}`.
#[must_use]
pub fn bnap_meta(credential: &[u8]) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(wire::CREDENTIAL.into(), Value::String(b64u(credential)));
    m
}

/// `_meta` with an MPP credential, from its HTTP token, in the MCP form.
pub fn mpp_meta(token: &str) -> Result<Map<String, Value>, crate::mpp::CredentialShape> {
    let mut m = Map::new();
    m.insert(
        wire::MPP_CREDENTIAL.into(),
        crate::mpp::credential_value(token)?,
    );
    Ok(m)
}

/// The BNAP receipt in a result's `_meta`, parsed (its ack still needs
/// the client checks of draft-00 9.3).
#[must_use]
pub fn receipt(meta: Option<&Map<String, Value>>) -> Option<Response> {
    meta?
        .get(wire::RECEIPT)
        .and_then(Value::as_str)
        .and_then(read_receipt)
}

fn read_receipt(s: &str) -> Option<Response> {
    from_b64u(s, MAX_READ)
        .ok()
        .and_then(|b| Response::parse(&b).ok())
}
