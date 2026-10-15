//! Start-up: load and check everything, refuse to start on any error, then
//! serve.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use bnap_carrier_http::{BnapLayer, BodyLimits, ClientAddr};
use bnap_core::offer::OfferFields;
use bnap_core::sign::UnsignedOffer;
use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower::Layer as _;

use crate::config::{Config, Front};
use crate::gate::{Gate, Settings};
use crate::plugs::{Clock, Plugs};
use crate::proxy::{Allow, Upstream};
use crate::registry::Registry;

/// How often the sweep runs (draft-00 6.4: timeouts and record deletion).
pub const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// A started gate.
pub struct Running {
    /// The gatekeeper.
    pub gate: Gate,
    /// The plugs (tests reach the fake rails through it).
    pub plugs: Arc<Plugs>,
    /// The bound address.
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Running {
    /// Stops serving and waits for the server task.
    pub async fn stop(mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        let _ = (&mut self.task).await;
    }

    /// Waits until the server stops (on its own error, or a signal the
    /// caller wired to [`Running::stop`]).
    pub async fn wait(mut self) {
        let _ = (&mut self.task).await;
    }
}

/// Everything the gate checks before it serves, without serving: the
/// registry digest, the configuration's rules, the manifest, every plug,
/// and that the signer holds the manifest's offer key.
pub async fn prepare(cfg: &Config, clock: &Clock) -> anyhow::Result<(Gate, Arc<Plugs>)> {
    let registry = Registry::embedded()?;
    let plans = cfg.plan(&registry)?;
    let now = clock();
    let bytes = std::fs::read(&cfg.manifest.file)
        .map_err(|e| anyhow::anyhow!("manifest {}: {e}", cfg.manifest.file.display()))?;
    let loaded = crate::manifest::check(&bytes, cfg, &plans, now)?;
    if cfg.gate.front == Front::Proxy {
        Upstream::new(cfg.gate.upstream.as_deref().unwrap_or_default())?;
    }
    let plugs = crate::plugs::build(cfg, &plans, loaded.limits.pending_timeout, clock).await?;
    // The signer must hold the offer key the manifest lists.
    let probe = OfferFields::new(
        bnap_core::hash::Scope([0; 32]),
        now + 60,
        loaded.offer_key.kid,
        [0; 16],
    );
    let mut probe = probe;
    probe.pay = vec![bnap_core::offer::PayEntry::new("bnap:probe", 0, "sat")];
    let unsigned = UnsignedOffer::new(&probe, Some(&plugs.mac_keys[0]))
        .map_err(|e| anyhow::anyhow!("probe offer: {e}"))?;
    let sig = plugs
        .signer
        .schnorr(unsigned.message())
        .await
        .map_err(|e| {
            anyhow::anyhow!("the signer does not sign with the manifest's offer key: {e}")
        })?;
    unsigned
        .finish(&sig)
        .map_err(|e| anyhow::anyhow!("the signer's offer signature does not verify: {e}"))?;
    probe_receipt(&plugs, &loaded, now).await?;
    let gate = Gate::new(
        Settings {
            front: cfg.gate.front,
            origin: cfg.gate.origin.clone(),
            plans,
            manifest: loaded,
            exact_lifetime: cfg.gate.offer_lifetime_s,
            route_lifetime: cfg.gate.route_offer_lifetime_s,
            keep_response: cfg.gate.keep_response_bytes,
            limits: cfg.limits.clone(),
            trust_forwarded_for: cfg.gate.trust_forwarded_for,
        },
        &plugs,
        registry,
        clock.clone(),
    );
    Ok((gate, Arc::new(plugs)))
}

/// The signer must acknowledge with the manifest's receipt key: a probe
/// outcome (a price-0 entry, no value, random Context) is committed, settled FAILED
/// and acknowledged through the same path a paid request takes, so a gate
/// that could not sign receipts never admits an action it cannot answer.
async fn probe_receipt(
    plugs: &Plugs,
    loaded: &crate::manifest::Loaded,
    now: u64,
) -> anyhow::Result<()> {
    use bnap_core::outcome::{self, Admitted, ReceiptInput, Request};
    use bnap_core::response::Status;
    use bnap_core::store::Settlement;
    let mut f = OfferFields::new(
        bnap_core::hash::Scope(rand::random()),
        now + 60,
        loaded.offer_key.kid,
        rand::random(),
    );
    f.pay = vec![bnap_core::offer::PayEntry::new("bnap:probe", 0, "sat")];
    let context = bnap_core::hash::Context(rand::random());
    let admitted = outcome::process(
        &*plugs.store,
        &Request {
            offer: &f,
            context: &context,
            pay_body: &[],
            attest_bodies: &[],
            schemes: &[],
            rail_ids: &[],
            pay: Some(bnap_core::pricing::PayValue {
                scheme: "bnap:probe",
                claimed: 0,
                backing: Vec::new(),
                refund: bnap_core::pricing::Refund::None,
            }),
            attest: &[],
            now,
        },
        &loaded.limits,
    )
    .await
    .map_err(|e| anyhow::anyhow!("receipt probe: the use store refused the probe outcome: {e}"))?;
    let Admitted::New(pending) = admitted else {
        anyhow::bail!("receipt probe: a fresh probe outcome was already known");
    };
    let charge = pending.charge(Status::Failed, 0);
    let recorded = outcome::settle(
        &*plugs.store,
        &pending,
        &Settlement::new(&charge, now),
        &loaded.limits,
    )
    .await
    .map_err(|e| anyhow::anyhow!("receipt probe: settle: {e:?}"))?;
    let unsigned = recorded
        .unsigned_receipt(&ReceiptInput {
            offer_id: f
                .offer_id()
                .map_err(|e| anyhow::anyhow!("receipt probe: {e}"))?,
            digest: bnap_core::hash::Digest(rand::random()),
            unit: Some("sat".into()),
            metered: false,
            receipt_key: loaded.receipt_key.kid,
        })
        .ok_or_else(|| anyhow::anyhow!("receipt probe: no receipt for a settled outcome"))?
        .map_err(|e| anyhow::anyhow!("receipt probe: {e}"))?;
    let sig = plugs
        .signer
        .schnorr(unsigned.message())
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "the signer does not sign receipts with the manifest's receipt key: {e}"
            )
        })?;
    unsigned
        .finish(&sig)
        .map_err(|e| anyhow::anyhow!("the signer's receipt signature does not verify: {e}"))?;
    Ok(())
}

/// Starts the gate on `listener` (or on `gate.listen`).
pub async fn start(
    cfg: &Config,
    clock: Clock,
    listener: Option<TcpListener>,
) -> anyhow::Result<Running> {
    let (gate, plugs) = prepare(cfg, &clock).await?;
    let listener = match listener {
        Some(l) => l,
        None => TcpListener::bind(&cfg.gate.listen).await?,
    };
    let addr = listener.local_addr()?;
    let limits = BodyLimits {
        request: cfg.gate.max_request_bytes,
        response: cfg.gate.max_response_bytes,
    };
    let layer = BnapLayer::<Gate, Bytes>::new(Arc::new(gate.clone())).with_limits(limits);
    let router = match cfg.gate.front {
        Front::Proxy => {
            let up = Upstream::new(cfg.gate.upstream.as_deref().unwrap_or_default())?;
            axum::Router::new().fallback_service(with_addr(layer.layer(up)))
        }
        _ => axum::Router::new().fallback_service(with_addr(layer.layer(Allow))),
    };
    let (tx, rx) = oneshot::channel::<()>();
    let sweep = tokio::spawn(sweep_loop(gate.clone(), plugs.clone(), clock.clone()));
    let task = tokio::spawn(async move {
        let serve = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        });
        if let Err(e) = serve.await {
            tracing::error!("server: {e}");
        }
        sweep.abort();
    });
    tracing::info!(%addr, front = ?cfg.gate.front, "caparra-gate serving");
    Ok(Running {
        gate,
        plugs,
        addr,
        shutdown: Some(tx),
        task,
    })
}

type AddAddr = fn(http::Request<axum::body::Body>) -> http::Request<axum::body::Body>;

/// Puts the connection's peer address in a [`ClientAddr`] extension.
fn with_addr<S>(inner: S) -> tower::util::MapRequest<S, AddAddr> {
    fn add(mut req: http::Request<axum::body::Body>) -> http::Request<axum::body::Body> {
        if let Some(ConnectInfo(a)) = req.extensions().get::<ConnectInfo<SocketAddr>>().copied() {
            req.extensions_mut().insert(ClientAddr(a.ip()));
        }
        req
    }
    tower::util::MapRequest::new(inner, add as fn(_) -> _)
}

async fn sweep_loop(gate: Gate, plugs: Arc<Plugs>, clock: Clock) {
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    loop {
        tick.tick().await;
        let now = clock();
        let inner = gate.inner();
        match bnap_core::outcome::sweep(&*plugs.store, now, inner.limits()).await {
            Ok(s) if !s.timed_out.is_empty() || s.purged > 0 => {
                tracing::info!(timed_out = s.timed_out.len(), purged = s.purged, "sweep");
            }
            Ok(_) => {}
            Err(e) => tracing::error!("sweep: {e}"),
        }
        if let Err(e) = plugs.sqlite.prune_counters(now).await {
            tracing::error!("prune counters: {e}");
        }
    }
}
