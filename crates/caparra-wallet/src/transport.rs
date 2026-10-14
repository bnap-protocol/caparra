//! How the wallet talks HTTP.
//!
//! [`Transport`] is one request, one response. [`HttpsTransport`] is the
//! real one: HTTPS only, certificates checked against the origin (rustls
//! with the platform's web roots through reqwest), no redirects (a manifest
//! or a paid response is taken only from the URL asked), bounded bodies.
//! Tests plug an in-process server in instead.

use serde::{Deserialize, Serialize};

/// Largest response body read, bytes.
pub const MAX_BODY: usize = 16 << 20;

/// An HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// The method, as sent.
    pub method: String,
    /// The absolute URL.
    pub url: String,
    /// Header fields, in order.
    pub headers: Vec<(String, String)>,
    /// The content.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A request with no fields and no content.
    #[must_use]
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a field.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the content.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The combined value of a field (RFC 9110 5.3), or `None`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<String> {
        combine(&self.headers, name)
    }
}

/// An HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Header fields, in order.
    pub headers: Vec<(String, String)>,
    /// The content.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value of a field.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a field, in order.
    #[must_use]
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn combine(headers: &[(String, String)], name: &str) -> Option<String> {
    let v: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    (!v.is_empty()).then(|| v.join(", "))
}

/// One HTTP exchange.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Sends `req` and returns the response, or why none came.
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String>;
}

/// The HTTPS transport.
#[derive(Debug, Clone)]
pub struct HttpsTransport {
    client: reqwest::Client,
}

impl HttpsTransport {
    /// A transport with a 60 s timeout.
    pub fn new() -> Result<Self, String> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl Transport for HttpsTransport {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let url = url::Url::parse(&req.url).map_err(|e| e.to_string())?;
        if url.scheme() != "https" {
            return Err("only https URLs are fetched".into());
        }
        let method =
            reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut b = self.client.request(method, url);
        for (n, v) in &req.headers {
            b = b.header(n, v);
        }
        let mut resp = b.body(req.body).send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err("the response is too large".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
