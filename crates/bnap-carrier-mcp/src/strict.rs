//! The strict JSON layer: every MCP message is read as I-JSON before rmcp
//! parses it.
//!
//! rmcp parses a request into `serde_json` values, which keep the last of
//! two members with one name. The action scope hashes the parsed
//! arguments, so `{"to":"a","to":"b"}` could hash as one call while a tool
//! reading the raw bytes with another parser runs the other. JCS assumes
//! I-JSON (RFC 7493), so a message that names a member twice at any depth
//! is refused here, before rmcp sees it, with MALFORMED (draft-00 8.2) as a
//! JSON-RPC error.
//!
//! [`strict_json`] is an axum middleware for the streamable HTTP endpoint.
//! Every POST body it passes carries the [`StrictJson`] marker in its
//! request extensions, which rmcp hands to the handler inside
//! `http::request::Parts`; [`crate::PricedTools`] refuses a priced call
//! that does not carry it (fail closed, UNAVAILABLE), so a priced tool
//! served without this layer never runs.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bnap_core::ErrorCode;
use bnap_core::manifest::{ManifestError, parse_strict};
use serde_json::{Value, json};

use crate::wire::{self, ErrorData};

/// The largest MCP message body the layer reads: 4 MiB.
pub const DEFAULT_MAX_BODY: usize = 4 << 20;

/// Marker in the request extensions: the body was read as I-JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictJson;

/// The layer's settings, as the middleware state.
#[derive(Debug, Clone, Copy)]
pub struct StrictConfig {
    /// The largest body read, in bytes; a larger one is refused with 413.
    pub max_body: usize,
}

impl Default for StrictConfig {
    fn default() -> Self {
        Self {
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

/// The middleware: `axum::middleware::from_fn_with_state(StrictConfig::default(), strict_json)`.
///
/// POST bodies that are JSON and name no member twice pass with the
/// [`StrictJson`] marker. A body that names a member twice is answered
/// with a JSON-RPC error (MALFORMED, `-32602`, `httpStatus` 400) and never
/// reaches rmcp. A body that is not JSON passes without the marker, for
/// rmcp to answer with its parse error. Other methods pass unchanged.
pub async fn strict_json(State(config): State<StrictConfig>, req: Request, next: Next) -> Response {
    if req.method() != Method::POST {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    let Ok(bytes) = to_bytes(body, config.max_body).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    match parse_strict(&bytes) {
        Ok(_) => {
            parts.extensions.insert(StrictJson);
        }
        Err(ManifestError::DuplicateMember(name)) => return duplicate(&bytes, &name),
        Err(_) => {}
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// The JSON-RPC error for a message that names `name` twice. The `id` is
/// read leniently, so the client can match the answer; a notification (no
/// `id`) gets a bare 400.
fn duplicate(bytes: &[u8], name: &str) -> Response {
    let id = serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .filter(|id| id.is_string() || id.is_number());
    let Some(id) = id else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    tracing::debug!(member = name, "refused a message that names a member twice");
    let code = ErrorCode::Malformed;
    let data = ErrorData {
        http_status: code.http_status(),
        error: Some(bnap_core::ErrorObject::new(code).with_detail("a JSON member is named twice")),
        ..ErrorData::default()
    };
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": wire::jsonrpc_code(code),
            "message": wire::message(code),
            "data": data.to_value(),
        },
    });
    let mut res = (StatusCode::OK, body.to_string()).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}
