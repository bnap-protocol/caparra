//! [`BnapLayer`]: a tower `Layer` that runs a [`Gatekeeper`] in front of
//! any service.
//!
//! For every request the layer buffers the content (the action scope
//! hashes it), asks the gatekeeper what to do, and then:
//!
//! - [`Admit::Forward`]: the request is not a BNAP action; it goes to the
//!   inner service and its answer comes back untouched.
//! - [`Admit::Answer`]: the gatekeeper answers itself (a 402, an error, a
//!   replayed receipt, the manifest).
//! - [`Admit::Run`]: the credential committed. The layer runs the action
//!   on the inner service under the ticket's deadline, buffers the answer
//!   (the receipt goes in a header, so the charge must be known before the
//!   first byte), meters it when the offer is metered, settles through the
//!   ticket, and only then sends the answer with its `BNAP-Receipt`
//!   (6.4: no Response before the settlement is durable).
//!
//! The action counts as OK when the inner service answers 2xx in time and,
//! on a metered offer, its answer can be metered. Anything else is
//! FAILED, which charges nothing and refunds as the value scheme allows.
//! A metering failure withholds the answer (502), so a client is never
//! given an unmetered result for free.

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};

use crate::fields::NO_STORE;

/// A boxed error, as bodies and services return them.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body of every answer the layer sends.
pub type BoxBody = UnsyncBoxBody<Bytes, BoxError>;

/// The client's address, as a request extension. The server that accepts
/// the connection inserts it; the gatekeeper uses it for per-address
/// limits (draft-00 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddr(pub IpAddr);

/// A request as the gatekeeper receives it: the head and the whole
/// content.
#[derive(Debug)]
pub struct GateRequest {
    /// Method, target, fields and extensions as received.
    pub parts: http::request::Parts,
    /// The content as sent.
    pub body: Bytes,
}

/// What the gatekeeper decided.
pub enum Admit {
    /// Not a BNAP action: hand the request to the inner service as is.
    Forward(Request<Bytes>),
    /// Answer now; the inner service is not called.
    Answer(Response<Bytes>),
    /// Run the action, then settle it with the ticket.
    Run(Run),
}

impl std::fmt::Debug for Admit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward(r) => f.debug_tuple("Forward").field(r).finish(),
            Self::Answer(r) => f.debug_tuple("Answer").field(&r.status()).finish(),
            Self::Run(r) => f.debug_tuple("Run").field(&r.request).finish(),
        }
    }
}

/// A committed action: the request to run, and the ticket that settles it.
pub struct Run {
    /// The request for the inner service, with the BNAP fields removed.
    pub request: Request<Bytes>,
    /// Settles the outcome once the action is done.
    pub ticket: Box<dyn Ticket>,
}

/// How the action ended, as the layer saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// The inner service answered 2xx in time; `units` is the meter's count
    /// (0 when the offer is not metered).
    Ok {
        /// Meter units.
        units: u64,
    },
    /// The action failed, timed out or could not be metered.
    Failed {
        /// For logs only.
        reason: String,
    },
}

/// Settles one committed outcome. The gatekeeper makes one per
/// [`Admit::Run`], and the layer consumes it exactly once.
#[async_trait::async_trait]
pub trait Ticket: Send {
    /// How long the action may run: the outcome's `pending_timeout` less a
    /// margin. The layer stops waiting after it and settles FAILED.
    fn timeout(&self) -> Duration;

    /// True when the offer is metered, so the answer must be metered.
    fn metered(&self) -> bool;

    /// The meter's count for this answer. Called only when [`Self::metered`]
    /// and the inner service answered 2xx.
    fn meter(&self, head: &http::response::Parts, body: &[u8]) -> Result<u64, String>;

    /// Settles the outcome and returns the fields to add to the answer
    /// (`BNAP-Receipt`, and a scheme's own receipt such as
    /// `Payment-Receipt`), or the whole answer to send instead when the
    /// settlement or the receipt failed. `answer` is the application's
    /// answer as the client will get it (after [`strip_fields`]), when there
    /// is one, so the ticket can keep it for replays (6.4).
    async fn settle(
        self: Box<Self>,
        done: Done,
        answer: Option<Kept>,
    ) -> Result<HeaderMap, Response<Bytes>>;
}

/// The application's answer to a committed action, as the client gets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// The status.
    pub status: StatusCode,
    /// The `Content-Type`, if any.
    pub content_type: Option<HeaderValue>,
    /// The content.
    pub body: Bytes,
}

/// Removes every field the gate alone may write from an application's
/// answer: `BNAP-*` fields, `Payment-Receipt`, `Authentication-Info` and
/// `BNAP` challenges in `WWW-Authenticate`. The application can then never
/// pass off a receipt, an error or an offer as the gate's.
pub fn strip_fields(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .keys()
        .filter(|n| {
            let n = n.as_str();
            n.starts_with("bnap-") || n == "payment-receipt" || n == "authentication-info"
        })
        .cloned()
        .collect();
    for n in names {
        headers.remove(n);
    }
    let challenges: Vec<HeaderValue> = headers
        .get_all(http::header::WWW_AUTHENTICATE)
        .iter()
        .filter(|v| !is_bnap_challenge(v.as_bytes()))
        .cloned()
        .collect();
    if headers.contains_key(http::header::WWW_AUTHENTICATE) {
        headers.remove(http::header::WWW_AUTHENTICATE);
        for v in challenges {
            headers.append(http::header::WWW_AUTHENTICATE, v);
        }
    }
}

fn is_bnap_challenge(v: &[u8]) -> bool {
    let v = v.trim_ascii_start();
    v.len() >= 4
        && v[..4].eq_ignore_ascii_case(b"bnap")
        && v.get(4).is_none_or(|b| !b.is_ascii_alphanumeric())
}

/// Decides, for every request, whether it is a BNAP action and what to do.
#[async_trait::async_trait]
pub trait Gatekeeper: Send + Sync + 'static {
    /// The decision for one request.
    async fn admit(&self, req: GateRequest) -> Admit;
}

/// Size limits of the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimits {
    /// Largest request content buffered, in bytes; larger is 413.
    pub request: usize,
    /// Largest answer buffered for a BNAP action, in bytes; larger fails
    /// the action (502).
    pub response: usize,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            request: 1 << 20,
            response: 16 << 20,
        }
    }
}

/// The layer. `IB` is the inner service's request body type, built from
/// the buffered content (`Full<Bytes>` by default, `axum::body::Body` for
/// an axum router).
pub struct BnapLayer<G, IB = Full<Bytes>> {
    gate: Arc<G>,
    limits: BodyLimits,
    _body: PhantomData<fn() -> IB>,
}

impl<G, IB> Clone for BnapLayer<G, IB> {
    fn clone(&self) -> Self {
        Self {
            gate: self.gate.clone(),
            limits: self.limits,
            _body: PhantomData,
        }
    }
}

impl<G, IB> std::fmt::Debug for BnapLayer<G, IB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BnapLayer")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<G: Gatekeeper, IB> BnapLayer<G, IB> {
    /// A layer around `gate` with the default limits.
    #[must_use]
    pub fn new(gate: Arc<G>) -> Self {
        Self {
            gate,
            limits: BodyLimits::default(),
            _body: PhantomData,
        }
    }

    /// The same layer with these limits.
    #[must_use]
    pub fn with_limits(mut self, limits: BodyLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl<S, G, IB> tower::Layer<S> for BnapLayer<G, IB> {
    type Service = BnapService<S, G, IB>;

    fn layer(&self, inner: S) -> Self::Service {
        BnapService {
            inner,
            gate: self.gate.clone(),
            limits: self.limits,
            _body: PhantomData,
        }
    }
}

/// The service [`BnapLayer`] makes.
pub struct BnapService<S, G, IB = Full<Bytes>> {
    inner: S,
    gate: Arc<G>,
    limits: BodyLimits,
    _body: PhantomData<fn() -> IB>,
}

impl<S: Clone, G, IB> Clone for BnapService<S, G, IB> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: self.gate.clone(),
            limits: self.limits,
            _body: PhantomData,
        }
    }
}

impl<S, G, IB> std::fmt::Debug for BnapService<S, G, IB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BnapService")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S, G, IB, B, RB> tower::Service<Request<B>> for BnapService<S, G, IB>
where
    S: tower::Service<Request<IB>, Response = Response<RB>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display + Send,
    G: Gatekeeper,
    IB: From<Bytes> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    RB: Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    type Response = Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The inner service is cloned per call and made ready there.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let gate = self.gate.clone();
        let limits = self.limits;
        Box::pin(async move { Ok(handle(inner, gate, limits, req).await) })
    }
}

async fn handle<S, G, IB, B, RB>(
    inner: S,
    gate: Arc<G>,
    limits: BodyLimits,
    req: Request<B>,
) -> Response<BoxBody>
where
    S: tower::Service<Request<IB>, Response = Response<RB>> + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display + Send,
    G: Gatekeeper,
    IB: From<Bytes> + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
    RB: Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    let (parts, body) = req.into_parts();
    tracing::trace!(uri = %parts.uri, "layer: reading the request content");
    let body = match Limited::new(body, limits.request).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return plain(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The request content is too large for this gate.",
            );
        }
    };
    // 10.2: every answer to a request that carried a credential is
    // private and never stored, whoever wrote it.
    let carried = parts.headers.contains_key(crate::fields::BNAP_CREDENTIAL);
    match gate.admit(GateRequest { parts, body }).await {
        Admit::Answer(mut r) => {
            if carried {
                r.headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
            }
            full(r)
        }
        Admit::Forward(r) => match call(inner, r).await {
            Ok(mut resp) => {
                strip_fields(resp.headers_mut());
                if carried {
                    resp.headers_mut()
                        .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
                }
                resp.map(|b| b.map_err(Into::into).boxed_unsync())
            }
            Err(e) => {
                tracing::warn!("upstream failed: {e}");
                plain(
                    StatusCode::BAD_GATEWAY,
                    "The upstream service did not answer.",
                )
            }
        },
        // The action and its settlement run in their own task: a client
        // that disconnects cannot cancel the settlement (10.2: it is charged
        // for what was produced, and can fetch the receipt by replay, 6.4).
        Admit::Run(run) => match tokio::spawn(run_action(inner, limits, run)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("the action task failed: {e}");
                plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The gate failed while settling. Retry with the same credential.",
                )
            }
        },
    }
}

async fn call<S, IB, RB>(mut inner: S, req: Request<Bytes>) -> Result<Response<RB>, S::Error>
where
    S: tower::Service<Request<IB>, Response = Response<RB>>,
    IB: From<Bytes>,
{
    std::future::poll_fn(|cx| inner.poll_ready(cx)).await?;
    inner.call(req.map(IB::from)).await
}

async fn run_action<S, IB, RB>(inner: S, limits: BodyLimits, run: Run) -> Response<BoxBody>
where
    S: tower::Service<Request<IB>, Response = Response<RB>> + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Display + Send,
    IB: From<Bytes> + Send + 'static,
    RB: Body<Data = Bytes> + Send + 'static,
    RB::Error: Into<BoxError>,
{
    let Run { request, ticket } = run;
    let deadline = ticket.timeout();
    let action = async {
        let resp = call(inner, request).await.map_err(|e| e.to_string())?;
        let (mut head, body) = resp.into_parts();
        strip_fields(&mut head.headers);
        let body = Limited::new(body, limits.response)
            .collect()
            .await
            .map_err(|_| "the answer is too large to buffer".to_owned())?
            .to_bytes();
        Ok::<_, String>((head, body))
    };
    let (outcome, answer) = match tokio::time::timeout(deadline, action).await {
        Err(_) => (
            Done::Failed {
                reason: "the action outlived its pending timeout".into(),
            },
            Err((
                StatusCode::GATEWAY_TIMEOUT,
                "The upstream service took too long. Nothing was charged.",
            )),
        ),
        Ok(Err(e)) => (
            Done::Failed { reason: e },
            Err((
                StatusCode::BAD_GATEWAY,
                "The upstream service did not answer. Nothing was charged.",
            )),
        ),
        Ok(Ok((head, body))) if !head.status.is_success() => (
            Done::Failed {
                reason: format!("the upstream answered {}", head.status),
            },
            Ok((head, body)),
        ),
        Ok(Ok((head, body))) if ticket.metered() => match ticket.meter(&head, &body) {
            Ok(units) => (Done::Ok { units }, Ok((head, body))),
            Err(e) => (
                Done::Failed {
                    reason: format!("the answer could not be metered: {e}"),
                },
                Err((
                    StatusCode::BAD_GATEWAY,
                    "The upstream answer did not report its usage, so it could not be metered. Nothing was charged.",
                )),
            ),
        },
        Ok(Ok((head, body))) => (Done::Ok { units: 0 }, Ok((head, body))),
    };
    if let Done::Failed { reason } = &outcome {
        tracing::info!("action failed: {reason}");
    }
    let kept = answer.as_ref().ok().map(|(head, body)| Kept {
        status: head.status,
        content_type: head.headers.get(CONTENT_TYPE).cloned(),
        body: body.clone(),
    });
    let fields = match ticket.settle(outcome, kept).await {
        Ok(f) => f,
        Err(resp) => return full(resp),
    };
    let mut resp = match answer {
        Ok((head, body)) => Response::from_parts(head, body),
        Err((status, text)) => {
            let r = plain_bytes(status, text);
            let (head, body) = r.into_parts();
            Response::from_parts(head, body)
        }
    };
    let headers = resp.headers_mut();
    for (name, value) in &fields {
        headers.insert(name.clone(), value.clone());
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    headers.remove(CONTENT_LENGTH);
    full(resp)
}

fn full(r: Response<Bytes>) -> Response<BoxBody> {
    r.map(|b| {
        Full::new(b)
            .map_err(|e: Infallible| match e {})
            .boxed_unsync()
    })
}

fn plain_bytes(status: StatusCode, text: &str) -> Response<Bytes> {
    let code = match status {
        StatusCode::PAYLOAD_TOO_LARGE => "TOO_LARGE",
        StatusCode::GATEWAY_TIMEOUT => "UPSTREAM_TIMEOUT",
        _ => "UPSTREAM",
    };
    let body = serde_json::json!({ "error": { "type": "gateway", "code": code, "message": text } });
    let mut r = Response::new(Bytes::from(body.to_string()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    r
}

fn plain(status: StatusCode, text: &str) -> Response<BoxBody> {
    full(plain_bytes(status, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tower::{Layer as _, ServiceExt as _};

    struct TestTicket {
        metered: bool,
        log: Arc<Mutex<Vec<Done>>>,
    }

    #[async_trait::async_trait]
    impl Ticket for TestTicket {
        fn timeout(&self) -> Duration {
            Duration::from_millis(200)
        }
        fn metered(&self) -> bool {
            self.metered
        }
        fn meter(&self, _head: &http::response::Parts, body: &[u8]) -> Result<u64, String> {
            std::str::from_utf8(body)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| "no count".into())
        }
        async fn settle(
            self: Box<Self>,
            done: Done,
            _answer: Option<Kept>,
        ) -> Result<HeaderMap, Response<Bytes>> {
            self.log.lock().unwrap().push(done);
            let mut h = HeaderMap::new();
            h.insert("bnap-receipt", HeaderValue::from_static("AAEB"));
            Ok(h)
        }
    }

    struct TestGate {
        metered: bool,
        log: Arc<Mutex<Vec<Done>>>,
    }

    #[async_trait::async_trait]
    impl Gatekeeper for TestGate {
        async fn admit(&self, req: GateRequest) -> Admit {
            match req.parts.uri.path() {
                "/free" | "/free-inject" => {
                    Admit::Forward(Request::from_parts(req.parts, req.body))
                }
                "/answer" => Admit::Answer(Response::new(Bytes::from_static(b"402"))),
                _ => Admit::Run(Run {
                    request: Request::from_parts(req.parts, req.body),
                    ticket: Box::new(TestTicket {
                        metered: self.metered,
                        log: self.log.clone(),
                    }),
                }),
            }
        }
    }

    async fn upstream(req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_owned();
        if path == "/slow" {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let mut r = Response::new(Full::new(Bytes::from(match path.as_str() {
            "/count" => "850",
            _ => "hello",
        })));
        if path == "/fail" {
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        }
        if path.ends_with("inject") {
            r.headers_mut()
                .insert("bnap-receipt", HeaderValue::from_static("Zm9yZ2Vk"));
            r.headers_mut()
                .insert("bnap-error", HeaderValue::from_static("AAEB"));
        }
        Ok(r)
    }

    async fn send(metered: bool, path: &str) -> (Response<BoxBody>, Vec<Done>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(TestGate {
            metered,
            log: log.clone(),
        });
        let svc = BnapLayer::<_, Full<Bytes>>::new(gate).layer(tower::service_fn(upstream));
        let req = Request::builder()
            .uri(path)
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        let log = log.lock().unwrap().clone();
        (resp, log)
    }

    #[tokio::test]
    async fn a_run_is_settled_before_the_answer_with_its_receipt() {
        let (r, log) = send(false, "/x").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()["bnap-receipt"], "AAEB");
        assert_eq!(r.headers()[CACHE_CONTROL], NO_STORE);
        assert_eq!(log, vec![Done::Ok { units: 0 }]);
    }

    #[tokio::test]
    async fn metered_answers_are_counted() {
        let (r, log) = send(true, "/count").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(log, vec![Done::Ok { units: 850 }]);
        let (r, log) = send(true, "/x").await;
        assert_eq!(
            r.status(),
            StatusCode::BAD_GATEWAY,
            "unmetered answers are withheld"
        );
        assert!(matches!(log[0], Done::Failed { .. }));
    }

    #[tokio::test]
    async fn failures_and_timeouts_settle_failed() {
        let (r, log) = send(false, "/fail").await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(matches!(log[0], Done::Failed { .. }));
        let (r, log) = send(false, "/slow").await;
        assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(matches!(log[0], Done::Failed { .. }));
    }

    #[test]
    fn the_application_cannot_write_bnap_fields() {
        let mut h = HeaderMap::new();
        h.insert("bnap-receipt", HeaderValue::from_static("AAEB"));
        h.insert("BNAP-Error", HeaderValue::from_static("AAEB"));
        h.insert("payment-receipt", HeaderValue::from_static("x"));
        h.insert("authentication-info", HeaderValue::from_static("bnap=x"));
        h.append(
            "www-authenticate",
            HeaderValue::from_static("BNAP offer=\"AAEB\""),
        );
        h.append(
            "www-authenticate",
            HeaderValue::from_static("bnap offer=\"AAEB\""),
        );
        h.append(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"api\""),
        );
        h.append("www-authenticate", HeaderValue::from_static("BNAPX x=1"));
        h.insert("x-other", HeaderValue::from_static("kept"));
        strip_fields(&mut h);
        let mut left: Vec<_> = h
            .iter()
            .map(|(n, v)| format!("{n}: {}", v.to_str().unwrap()))
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "www-authenticate: BNAPX x=1",
                "www-authenticate: Bearer realm=\"api\"",
                "x-other: kept"
            ]
        );
    }

    #[tokio::test]
    async fn upstream_bnap_fields_never_reach_the_client() {
        let (r, _) = send(false, "/inject").await;
        assert_eq!(
            r.headers()["bnap-receipt"],
            "AAEB",
            "the gate's own receipt"
        );
        assert!(r.headers().get("bnap-error").is_none());
        let (r, _) = send(false, "/free-inject").await;
        assert!(r.headers().get("bnap-receipt").is_none());
    }

    #[tokio::test]
    async fn a_forwarded_request_with_a_credential_is_not_stored() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(TestGate {
            metered: false,
            log,
        });
        let svc = BnapLayer::<_, Full<Bytes>>::new(gate).layer(tower::service_fn(upstream));
        let req = Request::builder()
            .uri("/free")
            .header("bnap-credential", "AAEB")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let r = svc.clone().oneshot(req).await.unwrap();
        assert_eq!(r.headers()[CACHE_CONTROL], NO_STORE);
        let req = Request::builder()
            .uri("/free")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let r = svc.oneshot(req).await.unwrap();
        assert!(r.headers().get(CACHE_CONTROL).is_none());
    }

    #[tokio::test]
    async fn a_client_that_disconnects_does_not_cancel_the_settlement() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(TestGate {
            metered: false,
            log: log.clone(),
        });
        let svc = BnapLayer::<_, Full<Bytes>>::new(gate).layer(tower::service_fn(upstream));
        let req = Request::builder()
            .uri("/slow")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap();
        // The client goes away after 50 ms; the action's deadline is 200 ms.
        let gone = tokio::time::timeout(Duration::from_millis(50), svc.oneshot(req)).await;
        assert!(gone.is_err());
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            log.lock().unwrap().len(),
            1,
            "settled although the client left"
        );
    }

    #[tokio::test]
    async fn forwards_and_answers_settle_nothing() {
        let (r, log) = send(false, "/free").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().get("bnap-receipt").is_none());
        assert_eq!(log, Vec::<Done>::new());
        let (r, log) = send(false, "/answer").await;
        assert_eq!(r.into_body().collect().await.unwrap().to_bytes(), "402");
        assert_eq!(log, Vec::<Done>::new());
    }
}
