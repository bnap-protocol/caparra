//! [`HttpCarrier`]: the HTTP carrier of draft-00 section 10.

use bnap_core::error::{Error, ErrorCode, ErrorObject};
use bnap_core::hash::Scope;
use bnap_core::http as scopes;
use bnap_core::response::Response as Receipt;
use bnap_plug::carrier::{Carrier, Challenge, RawCredential};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, RETRY_AFTER, WWW_AUTHENTICATE};
use http::{HeaderMap, Method, StatusCode};

use crate::codec::b64u;
use crate::fields::{self, BNAP_ERROR, BNAP_RECEIPT, NO_STORE, malformed};

/// A request as the carrier reads it: everything the action scope covers,
/// as received.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The method exactly as sent (methods are case-sensitive).
    pub method: Method,
    /// The request-target in origin form, path and query bytes exactly as
    /// received.
    pub target: String,
    /// The request's fields.
    pub headers: HeaderMap,
    /// The content as sent, after any content coding.
    pub body: Bytes,
    /// The fields the matched route lists, lower case, in the route's
    /// order; hashed into the action scope (10.1).
    pub scope_headers: Vec<String>,
}

impl HttpRequest {
    /// The carrier's view of a request.
    #[must_use]
    pub fn new(parts: &http::request::Parts, body: Bytes, scope_headers: Vec<String>) -> Self {
        Self {
            method: parts.method.clone(),
            target: origin_form(&parts.uri),
            headers: parts.headers.clone(),
            body,
            scope_headers,
        }
    }
}

/// The request-target in origin form: the path and query as received
/// (`/` when the target names none, as in `OPTIONS *` or an authority).
#[must_use]
pub fn origin_form(uri: &http::Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned())
}

/// A native scheme whose credential travels in `Authorization` (5.4), and
/// the function that takes its native credential bytes out of a field
/// value, such as `bnap_scheme_l402::credential_from_authorization`.
#[derive(Clone)]
pub struct NativeAuth {
    /// The scheme ID, such as `httpauth:L402`.
    pub scheme: String,
    /// `Some(native credential bytes)` for a field value of this scheme.
    pub parse: fn(&str) -> Option<&str>,
}

impl std::fmt::Debug for NativeAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAuth")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

/// The HTTP carrier: scopes (10.1) and fields (10.2) for one manifest
/// origin.
#[derive(Debug, Clone)]
pub struct HttpCarrier {
    origin: String,
    max_credential: usize,
    natives: Vec<NativeAuth>,
}

impl HttpCarrier {
    /// The carrier for the manifest's `origin`. Credentials are capped at
    /// `min(max_credential, 9,216)` bytes (DECISIONS row 30), whatever the
    /// manifest's `limits` say.
    #[must_use]
    pub fn new(origin: impl Into<String>, max_credential: usize) -> Self {
        Self {
            origin: origin.into(),
            max_credential: max_credential.min(scopes::HTTP_MAX_CREDENTIAL),
            natives: Vec::new(),
        }
    }

    /// Recognizes the native credentials of these schemes in
    /// `Authorization`.
    #[must_use]
    pub fn with_natives(mut self, natives: Vec<NativeAuth>) -> Self {
        self.natives = natives;
        self
    }

    /// The manifest origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The credential size cap, in bytes.
    #[must_use]
    pub fn max_credential(&self) -> usize {
        self.max_credential
    }

    /// The native schemes this carrier recognizes.
    #[must_use]
    pub fn natives(&self) -> &[NativeAuth] {
        &self.natives
    }

    /// The native credential in `Authorization`, if any: its scheme and
    /// bytes. More than one is MALFORMED.
    pub fn native(&self, headers: &HeaderMap) -> Result<Option<(String, Vec<u8>)>, Error> {
        let mut found = None;
        for value in headers.get_all(AUTHORIZATION) {
            let Ok(text) = value.to_str() else { continue };
            for n in &self.natives {
                if let Some(bytes) = (n.parse)(text) {
                    if found.is_some() {
                        return Err(malformed("more than one value credential"));
                    }
                    found = Some((n.scheme.clone(), bytes.as_bytes().to_vec()));
                }
            }
        }
        Ok(found)
    }
}

impl Carrier for HttpCarrier {
    type Request = HttpRequest;
    type Response = http::response::Parts;

    fn name(&self) -> &str {
        "http"
    }

    fn action_scope(&self, req: &HttpRequest) -> Result<Scope, Error> {
        let values: Vec<Vec<u8>> = req
            .scope_headers
            .iter()
            .map(|n| fields::combined(&req.headers, n))
            .collect();
        let listed: Vec<(&str, &[u8])> = req
            .scope_headers
            .iter()
            .zip(&values)
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        Ok(scopes::action_scope(
            req.method.as_str(),
            &scopes::target(&self.origin, &req.target),
            &req.body,
            &listed,
        ))
    }

    fn route_scope(&self, route_id: &str) -> Scope {
        scopes::route_scope(&self.origin, route_id)
    }

    fn extract(&self, req: &HttpRequest) -> Result<Option<RawCredential>, Error> {
        let bnap = fields::credential(&req.headers, self.max_credential)?;
        let native = self.native(&req.headers)?;
        match (bnap, native) {
            (Some(_), Some(_)) => Err(malformed("more than one value credential")),
            (Some(b), None) => Ok(Some(RawCredential::Bnap(b))),
            (None, Some((scheme, bytes))) => Ok(Some(RawCredential::Native { scheme, bytes })),
            (None, None) => Ok(None),
        }
    }

    fn offer(&self, challenge: &Challenge<'_>, out: &mut http::response::Parts) {
        out.status = StatusCode::PAYMENT_REQUIRED;
        for offer in challenge.offers {
            if let Ok(v) = HeaderValue::from_str(&fields::offer_challenge(offer)) {
                out.headers.append(WWW_AUTHENTICATE, v);
            }
        }
        for native in challenge.natives {
            if let Ok(v) = HeaderValue::from_str(&native.value) {
                out.headers.append(WWW_AUTHENTICATE, v);
            }
        }
        if let Some(e) = challenge.error {
            set_error_fields(e, out);
        }
        out.headers.insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    }

    fn receipt(&self, receipt: &Receipt, out: &mut http::response::Parts) {
        if let Ok(v) = HeaderValue::from_str(&b64u(receipt.bytes())) {
            out.headers.insert(BNAP_RECEIPT, v);
        }
        out.headers.insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    }

    fn error(&self, error: &ErrorObject, out: &mut http::response::Parts) {
        out.status = status_of(error);
        set_error_fields(error, out);
        out.headers.insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    }
}

fn set_error_fields(error: &ErrorObject, out: &mut http::response::Parts) {
    if let Ok(bytes) = error.to_bytes()
        && let Ok(v) = HeaderValue::from_str(&b64u(&bytes))
    {
        out.headers.insert(BNAP_ERROR, v);
    }
    if let Some(secs) = error.retry_after {
        out.headers.insert(RETRY_AFTER, HeaderValue::from(secs));
    }
}

/// The HTTP status of an error code (8.2); 400 for a code this build does
/// not know.
#[must_use]
pub fn status_of(error: &ErrorObject) -> StatusCode {
    error
        .socket_code()
        .and_then(|c| StatusCode::from_u16(c.http_status()).ok())
        .unwrap_or(StatusCode::BAD_REQUEST)
}

/// A short message a person can act on, for each error code.
#[must_use]
pub fn message(code: Option<ErrorCode>) -> &'static str {
    match code {
        Some(ErrorCode::Version) => "This gate speaks BNAP version 1. Update the client.",
        Some(ErrorCode::Malformed) => {
            "The BNAP credential could not be read. Check how it was encoded."
        }
        Some(ErrorCode::TooLarge) => {
            "The BNAP credential is too large. Send offer_id instead of the whole offer."
        }
        Some(ErrorCode::BadOffer) => {
            "The offer is not one this gate issued or still holds. Use a fresh offer from WWW-Authenticate."
        }
        Some(ErrorCode::Stale) => "The offer has expired. Use a fresh offer from WWW-Authenticate.",
        Some(ErrorCode::WrongScope) => {
            "The offer is for another request. Use a fresh offer from WWW-Authenticate."
        }
        Some(ErrorCode::NotOffered) => {
            "The credential uses a scheme the offer does not list. Pay with a scheme from the offer."
        }
        Some(ErrorCode::Policy) => {
            "This route does not accept the credential. Use another scheme from the offer, or add the attestation it requires."
        }
        Some(ErrorCode::Underpaid) => {
            "The payment is below the price. Pay at least the amount in the offer."
        }
        Some(ErrorCode::BadCredential) => {
            "The payment scheme rejected the credential. See scheme_code for the reason."
        }
        Some(ErrorCode::Binding) => {
            "This gate cannot check a TLS binding. Send the credential without one."
        }
        Some(ErrorCode::Spent) => {
            "This payment was already used for another request. Pay again with a fresh offer."
        }
        Some(ErrorCode::Pending) => {
            "The same credential is still being processed. Retry after Retry-After seconds."
        }
        Some(ErrorCode::RateLimited) => "Too many requests. Retry after Retry-After seconds.",
        Some(ErrorCode::Unavailable) => {
            "The gate cannot reach its store, signer or payment rail. Retry later with the same credential."
        }
        Some(ErrorCode::Required) => {
            "Payment required. Pay with one of the offers in WWW-Authenticate."
        }
        None => "The request was refused.",
    }
}

/// An error body in the shape OpenAI-compatible clients read:
/// `{"error": {"type": "bnap", "code": "...", "message": "...", ...}}`.
#[must_use]
pub fn error_body(error: &ErrorObject) -> Bytes {
    let code = error.socket_code();
    let mut e = serde_json::json!({
        "type": "bnap",
        "code": code.map_or_else(|| error.code.to_string(), |c| c.name().to_owned()),
        "message": message(code),
    });
    if let Some(s) = &error.scheme_code {
        e["scheme_code"] = s.clone().into();
    }
    if let Some(r) = error.retry_after {
        e["retry_after"] = r.into();
    }
    Bytes::from(serde_json::json!({ "error": e }).to_string())
}

/// A whole error answer: status, `BNAP-Error`, `Cache-Control` and the
/// JSON body of [`error_body`].
#[must_use]
pub fn error_response(carrier: &HttpCarrier, error: &ErrorObject) -> http::Response<Bytes> {
    let (mut parts, ()) = http::Response::new(()).into_parts();
    carrier.error(error, &mut parts);
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    http::Response::from_parts(parts, error_body(error))
}

/// A whole 402 answer with every offer and native challenge.
#[must_use]
pub fn challenge_response(carrier: &HttpCarrier, challenge: &Challenge<'_>) -> http::Response<Bytes> {
    let (mut parts, ()) = http::Response::new(()).into_parts();
    carrier.offer(challenge, &mut parts);
    parts
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let body = challenge
        .error
        .map_or_else(|| error_body(&ErrorObject::new(ErrorCode::Required)), error_body);
    http::Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bnap_core::hash::sha256;

    fn request(method: &str, target: &str, body: &'static [u8]) -> HttpRequest {
        let req = http::Request::builder()
            .method(method)
            .uri(target)
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        HttpRequest::new(&parts, Bytes::from_static(body), Vec::new())
    }

    const BODY: &[u8] =
        br#"{"model":"m-1","messages":[{"role":"user","content":"hi"}],"max_tokens":256}"#;

    #[test]
    fn the_action_scope_is_the_draft_vector() {
        let c = HttpCarrier::new("https://api.example", 9216);
        let s = c
            .action_scope(&request("POST", "/v1/chat/completions", BODY))
            .unwrap();
        assert_eq!(
            hex(&s.0),
            "02be38b55551b02bee2daab2ca3d752e9538cc288f57a6dea67ccaf6971b3717"
        );
        assert_eq!(
            hex(&c.route_scope("chat").0),
            "862d641e67813f6e78b20a81aa929519e66a978e69e8a4d3e27280990697f3a0"
        );
    }

    #[test]
    fn the_target_is_hashed_as_received() {
        let c = HttpCarrier::new("https://api.example", 9216);
        let a = c.action_scope(&request("GET", "/a?b=1", b"")).unwrap();
        let b = c.action_scope(&request("GET", "/a?b=%31", b"")).unwrap();
        let d = c.action_scope(&request("GET", "/a?b=1", b"")).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, d);
        let m = c.action_scope(&request("get", "/a?b=1", b"")).unwrap();
        assert_ne!(a, m, "methods are case-sensitive");
    }

    #[test]
    fn listed_headers_are_combined_and_absent_ones_empty() {
        let c = HttpCarrier::new("https://api.example", 9216);
        let mut r = request("POST", "/x", b"{}");
        r.scope_headers = vec!["accept".into(), "anthropic-version".into()];
        r.headers.append("accept", HeaderValue::from_static("a"));
        r.headers.append("accept", HeaderValue::from_static("b"));
        let s = c.action_scope(&r).unwrap();
        let want = scopes::action_scope(
            "POST",
            "https://api.example/x",
            b"{}",
            &[("accept", b"a, b"), ("anthropic-version", b"")],
        );
        assert_eq!(s, want);
        assert_ne!(sha256(&s.0), sha256(&c.action_scope(&request("POST", "/x", b"{}")).unwrap().0));
    }

    fn l402(v: &str) -> Option<&str> {
        v.strip_prefix("L402 ")
    }

    #[test]
    fn one_value_credential_per_request() {
        let c = HttpCarrier::new("https://api.example", 9216).with_natives(vec![NativeAuth {
            scheme: "httpauth:L402".into(),
            parse: l402,
        }]);
        let mut r = request("GET", "/", b"");
        r.headers
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer sk-api-key"));
        assert_eq!(c.extract(&r).unwrap(), None, "an API key is not a value credential");
        r.headers
            .insert(AUTHORIZATION, HeaderValue::from_static("L402 mac:pre"));
        assert_eq!(
            c.extract(&r).unwrap(),
            Some(RawCredential::Native {
                scheme: "httpauth:L402".into(),
                bytes: b"mac:pre".to_vec()
            })
        );
        r.headers
            .insert(&fields::BNAP_CREDENTIAL, HeaderValue::from_static("AAEB"));
        assert_eq!(c.extract(&r).unwrap_err().code(), ErrorCode::Malformed);
        r.headers.remove(&fields::BNAP_CREDENTIAL);
        r.headers
            .append(AUTHORIZATION, HeaderValue::from_static("L402 other:pre"));
        assert_eq!(c.extract(&r).unwrap_err().code(), ErrorCode::Malformed);
    }

    #[test]
    fn every_answer_is_private_and_not_stored() {
        let c = HttpCarrier::new("https://api.example", 9216);
        let e = ErrorObject::new(ErrorCode::Spent);
        let r = error_response(&c, &e);
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(r.headers()[CACHE_CONTROL], NO_STORE);
        let body: serde_json::Value = serde_json::from_slice(r.body()).unwrap();
        assert_eq!(body["error"]["code"], "SPENT");
        let mut p = ErrorObject::new(ErrorCode::Pending);
        p.retry_after = Some(7);
        let r = error_response(&c, &p);
        assert_eq!(r.headers()[RETRY_AFTER], "7");
        let ch = challenge_response(
            &c,
            &Challenge {
                offers: &[],
                natives: &[],
                error: None,
            },
        );
        assert_eq!(ch.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(ch.headers()[CACHE_CONTROL], NO_STORE);
    }

    #[test]
    fn the_http_cap_is_never_raised() {
        assert_eq!(HttpCarrier::new("o", 16_384).max_credential(), 9216);
        assert_eq!(HttpCarrier::new("o", 4096).max_credential(), 4096);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
