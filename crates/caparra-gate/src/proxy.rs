//! The standalone reverse proxy front: forwards a request to the
//! application with the request-target byte for byte as received (draft-00
//! 10.1: the action that was paid for is the action that runs).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response, Uri};
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Hop-by-hop fields (RFC 9110 7.6.1), never forwarded either way.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// Why the upstream URL was refused.
#[derive(Debug, thiserror::Error)]
#[error("gate.upstream {0:?} must be http://host[:port] with no path")]
pub struct UpstreamError(pub String);

/// The proxy service.
#[derive(Clone, Debug)]
pub struct Upstream {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl Upstream {
    /// A proxy to `base`, `http://host[:port]`. HTTPS upstreams need a TLS
    /// client this build does not carry; put the gate next to the
    /// application.
    pub fn new(base: &str) -> Result<Self, UpstreamError> {
        let uri: Uri = base.parse().map_err(|_| UpstreamError(base.into()))?;
        let ok_path = uri.path_and_query().is_none_or(|p| p.as_str() == "/");
        match (uri.scheme(), uri.authority()) {
            (Some(s), Some(a)) if *s == http::uri::Scheme::HTTP && ok_path => Ok(Self {
                scheme: s.clone(),
                authority: a.clone(),
                client: Client::builder(TokioExecutor::new()).build_http(),
            }),
            _ => Err(UpstreamError(base.into())),
        }
    }

    async fn forward(self, req: Request<Bytes>) -> Result<Response<hyper::body::Incoming>, String> {
        let (mut parts, body) = req.into_parts();
        let pq = parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
            .to_owned();
        parts.uri = Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(pq.as_str())
            .build()
            .map_err(|e| e.to_string())?;
        if parts
            .uri
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            != Some(pq.as_str())
        {
            return Err("the request-target would change on the way upstream".into());
        }
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(http::header::TRANSFER_ENCODING);
        parts.headers.insert(
            HOST,
            HeaderValue::from_str(self.authority.as_str()).map_err(|e| e.to_string())?,
        );
        parts.version = http::Version::HTTP_11;
        let mut resp = self
            .client
            .request(Request::from_parts(parts, Full::new(body)))
            .await
            .map_err(|e| e.to_string())?;
        strip_hop_by_hop(resp.headers_mut());
        Ok(resp)
    }
}

/// Removes hop-by-hop fields, and every field `Connection` names.
pub fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(n);
    }
}

impl tower::Service<Request<Bytes>> for Upstream {
    type Response = Response<hyper::body::Incoming>;
    type Error = String;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, String>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), String>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        Box::pin(self.clone().forward(req))
    }
}

/// The inner service of the auth fronts: allows whatever the gate
/// forwards (requests off every route).
#[derive(Clone, Copy, Debug, Default)]
pub struct Allow;

impl tower::Service<Request<Bytes>> for Allow {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Bytes>) -> Self::Future {
        std::future::ready(Ok(Response::new(Full::new(Bytes::new()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_bases() {
        assert!(Upstream::new("http://127.0.0.1:9000").is_ok());
        assert!(Upstream::new("http://127.0.0.1:9000/").is_ok());
        assert!(Upstream::new("https://api.example").is_err());
        assert!(Upstream::new("http://h/v1").is_err());
        assert!(Upstream::new("not a url").is_err());
    }

    #[test]
    fn connection_named_fields_go() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("x-secret, keep-alive"),
        );
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert("te", HeaderValue::from_static("trailers"));
        h.insert("x-kept", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-kept"));
    }
}
