//! The gate's TOML configuration, and its validation at start.
//!
//! The shape follows the overview's "One config, any mix" example, with
//! draft-00's member names where they differ (ERRATA row 11: `value` in
//! basis points, not `percent`). [`Config::plan`] checks everything that
//! can be checked without starting a plug and refuses to start when:
//!
//! - a route can be satisfied by none of its enabled schemes under the
//!   registry's effective-vector rule (section 11, overview rules);
//! - a route lists an experimental scheme without `allow_experimental`;
//! - a route lists a scheme on a non-Bitcoin rail or unit without
//!   `allow_non_bitcoin`;
//! - a scheme is unknown to the registry, not implemented by this build,
//!   or registered with a use model the socket cannot enforce here;
//! - an attestation of class None would waive, discount or carry a quota
//!   (draft-00 7), or an effect's value or epoch is out of range (4.1);
//! - a metered route has no meter or rate, or runs behind a front that
//!   cannot see the answer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use bnap_core::class::BindingClass;
use bnap_core::manifest::{Route, RouteAttest, RouteScopeMode};
use bnap_core::offer::Effect;
use bnap_core::policy::{Candidate, Require, RoutePolicy};
use serde::{Deserialize, Serialize};

use crate::registry::Registry;

/// Value schemes this build can run.
pub const VALUE_SCHEMES: [&str; 3] = [
    bnap_scheme_notes::SCHEME_ID,
    bnap_scheme_l402::SCHEME_ID,
    bnap_scheme_mpp::SCHEME_ID,
];

/// Attestation schemes this build can run.
pub const ATTEST_SCHEMES: [&str; 3] = [
    bnap_scheme_dpop::DPOP,
    bnap_scheme_dpop::BEARER,
    bnap_scheme_webbotauth::ID,
];

/// The whole configuration file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[gate]`.
    pub gate: GateSection,
    /// `[manifest]`.
    pub manifest: ManifestSection,
    /// `[store]`.
    #[serde(default)]
    pub store: StoreSection,
    /// `[signer]`.
    pub signer: SignerSection,
    /// `[[rail]]`.
    #[serde(default, rename = "rail")]
    pub rails: Vec<RailSection>,
    /// `[[scheme]]`: value schemes.
    #[serde(default, rename = "scheme")]
    pub schemes: Vec<SchemeSection>,
    /// `[[attest]]`: attestation schemes.
    #[serde(default, rename = "attest")]
    pub attests: Vec<AttestSection>,
    /// `[pricing]`.
    #[serde(default)]
    pub pricing: PricingSection,
    /// `[[route]]`.
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteSection>,
    /// `[limits]`: per-address bounds on unauthenticated work.
    #[serde(default)]
    pub limits: LimitSection,
}

/// How the gate is put in front of the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Front {
    /// Standalone reverse proxy (default): the gate forwards to `upstream`.
    #[default]
    Proxy,
    /// Caddy `forward_auth`: the gate answers the subrequest only.
    ForwardAuth,
    /// nginx `auth_request`: as `forward_auth`, with nginx's status rules.
    AuthRequest,
    /// Envoy `ext_authz`: not implemented in this build (refused at start).
    EnvoyExtAuthz,
}

impl Front {
    /// True for the fronts that only ask the gate for a decision and never
    /// show it the request content or the application's answer.
    #[must_use]
    pub fn is_auth(self) -> bool {
        matches!(self, Self::ForwardAuth | Self::AuthRequest)
    }
}

/// `[gate]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateSection {
    /// The manifest origin (RFC 6454 serialization), such as
    /// `https://api.example`.
    pub origin: String,
    /// Listen address, such as `0.0.0.0:8080`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The front.
    #[serde(default)]
    pub front: Front,
    /// The application, for the proxy front: `http://host:port`.
    #[serde(default)]
    pub upstream: Option<String>,
    /// `limits.replay_window` of the manifest the sign command writes.
    #[serde(default = "default_replay_window")]
    pub replay_window_s: u64,
    /// `limits.pending_timeout` of the manifest the sign command writes.
    #[serde(default = "default_pending_timeout")]
    pub pending_timeout_s: u64,
    /// Lifetime of exact-scope offers.
    #[serde(default = "default_exact_lifetime")]
    pub offer_lifetime_s: u64,
    /// Lifetime of route-scope offers.
    #[serde(default = "default_route_lifetime")]
    pub route_offer_lifetime_s: u64,
    /// File holding the current `K_mac`, 64 hex characters.
    pub mac_key_file: PathBuf,
    /// Retired `K_mac` files, kept until every offer made under them has
    /// expired.
    #[serde(default)]
    pub retired_mac_key_files: Vec<PathBuf>,
    /// Largest request content the gate buffers, bytes.
    #[serde(default = "default_max_request")]
    pub max_request_bytes: usize,
    /// Largest answer the gate buffers for a paid action, bytes.
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
    /// Largest answer kept in the outcome record for replays, bytes; 0 keeps
    /// none (a replay then gets the receipt alone, draft-00 6.4).
    #[serde(default = "default_keep_response")]
    pub keep_response_bytes: usize,
    /// Read the client address from `X-Forwarded-For` (set this only when a
    /// trusted front sets that field). Auth fronts always do.
    #[serde(default)]
    pub trust_forwarded_for: bool,
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_replay_window() -> u64 {
    bnap_core::limits::DEFAULT_REPLAY_WINDOW
}
fn default_pending_timeout() -> u64 {
    bnap_core::limits::DEFAULT_PENDING_TIMEOUT
}
fn default_exact_lifetime() -> u64 {
    300
}
fn default_route_lifetime() -> u64 {
    3600
}
fn default_max_request() -> usize {
    1 << 20
}
fn default_max_response() -> usize {
    16 << 20
}
fn default_keep_response() -> usize {
    64 << 10
}

/// `[manifest]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSection {
    /// The pre-signed manifest the gate serves (made by `caparra-gate
    /// manifest sign`).
    pub file: PathBuf,
    /// The root key (64 hex) the manifest must be signed by; recommended,
    /// so a swapped file is refused.
    #[serde(default)]
    pub root: Option<String>,
    /// The `required` flag the sign command writes.
    #[serde(default)]
    pub required: bool,
    /// The `max_age` the sign command writes, seconds (at most 30 days).
    #[serde(default = "default_max_age")]
    pub max_age_s: u64,
}

fn default_max_age() -> u64 {
    7 * 86_400
}

/// `[store]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSection {
    /// `sqlite` (default) or `memory` (tests only; logged loudly).
    #[serde(default = "default_store_kind")]
    pub kind: String,
    /// The SQLite file of the use store.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// The SQLite file of the `bnap:notes` issuer tables (fund quotes,
    /// signed outputs); defaults to `path` with `.issuer` appended.
    #[serde(default)]
    pub issuer_path: Option<PathBuf>,
}

fn default_store_kind() -> String {
    "sqlite".into()
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            kind: default_store_kind(),
            path: None,
            issuer_path: None,
        }
    }
}

/// `[signer]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSection {
    /// `file` (keys in this process) or `process` (the `bnap-signer`
    /// socket, recommended).
    pub kind: String,
    /// The key file, for `file`.
    #[serde(default)]
    pub keys: Option<PathBuf>,
    /// The socket, for `process`.
    #[serde(default)]
    pub socket: Option<PathBuf>,
    /// The user the signer process runs as, for `process`.
    #[serde(default)]
    pub signer_uid: Option<u32>,
}

/// `[[rail]]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RailSection {
    /// The rail's name in this file.
    pub id: String,
    /// `lnd`, `phoenixd`, `nwc` or `fake` (tests).
    pub kind: String,
    /// The registry rail entry it stands for. Fixed for real rails
    /// (`ln:lnd`, `ln:phoenixd`, `ln:nwc`); required for `fake`.
    #[serde(default)]
    pub registry: Option<String>,
    /// Invoice expiry, seconds; at most the exact-offer lifetime.
    #[serde(default)]
    pub invoice_expiry_s: Option<u64>,
    /// LND: `https://host:port`.
    #[serde(default)]
    pub address: Option<String>,
    /// LND: TLS certificate file.
    #[serde(default)]
    pub cert: Option<PathBuf>,
    /// LND: invoice macaroon file.
    #[serde(default)]
    pub macaroon: Option<PathBuf>,
    /// phoenixd: `http://host:port`.
    #[serde(default)]
    pub url: Option<String>,
    /// phoenixd: file holding the HTTP password.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// NWC: name of the environment variable holding the receive-only URI.
    #[serde(default)]
    pub uri_env: Option<String>,
    /// fake: seed, 64 hex.
    #[serde(default)]
    pub seed: Option<String>,
}

impl RailSection {
    /// The registry rail entry this rail stands for.
    #[must_use]
    pub fn registry_id(&self) -> Option<String> {
        match self.kind.as_str() {
            "lnd" => Some("ln:lnd".into()),
            "phoenixd" => Some("ln:phoenixd".into()),
            "nwc" => Some("ln:nwc".into()),
            _ => self.registry.clone(),
        }
    }
}

/// `[[scheme]]`: one value scheme.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemeSection {
    /// The registered scheme ID.
    pub id: String,
    /// Rail IDs (from `[[rail]]`) that confirm its payments.
    #[serde(default)]
    pub rails: Vec<String>,
    /// Shorthand for one rail.
    #[serde(default)]
    pub rail: Option<String>,
    /// `false` keeps it configured but off.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// L402 / MPP: file holding the scheme's secret (64 hex).
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// MPP: realm; defaults to the origin's host.
    #[serde(default)]
    pub realm: Option<String>,
    /// MPP: `mainnet`, `signet` or `regtest`.
    #[serde(default)]
    pub network: Option<String>,
    /// `bnap:notes`: funding inside the 402 up to this many sat.
    #[serde(default)]
    pub max_fund_sat: Option<u64>,
    /// `bnap:notes`: the issuer's Cashu API base; defaults to
    /// `<origin>/cashu`.
    #[serde(default)]
    pub issuer_url: Option<String>,
}

fn yes() -> bool {
    true
}

impl SchemeSection {
    /// Every rail ID named.
    #[must_use]
    pub fn rail_ids(&self) -> Vec<String> {
        let mut v = self.rails.clone();
        if let Some(r) = &self.rail
            && !v.contains(r)
        {
            v.push(r.clone());
        }
        v
    }
}

/// `[[attest]]`: one attestation scheme.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestSection {
    /// The registered scheme ID.
    pub id: String,
    /// `false` keeps it configured but off.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `DPoP` and Bearer: JWK thumbprints (b64u) the operator registered as
    /// keys.
    #[serde(default)]
    pub keys: Vec<String>,
    /// `DPoP` and Bearer: access tokens the operator honours, each with the
    /// thumbprint it is bound to (empty for a Bearer token).
    #[serde(default)]
    pub tokens: Vec<TokenSection>,
    /// Web Bot Auth: agents the operator honours.
    #[serde(default)]
    pub agents: Vec<AgentSection>,
}

/// A token an attestation authority honours.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSection {
    /// The token.
    pub token: String,
    /// The thumbprint of the key it is bound to, if any.
    #[serde(default)]
    pub jkt: Option<String>,
}

/// A Web Bot Auth agent the operator honours.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    /// The agent's `Signature-Agent` URL.
    pub url: String,
    /// Its Ed25519 public key, 64 hex.
    pub key: String,
}

/// `[pricing]`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PricingSection {
    /// `table` (the only kind).
    #[serde(default)]
    pub kind: Option<String>,
    /// Route ID to price map; overrides the route's own `price`.
    #[serde(default)]
    pub table: BTreeMap<String, BTreeMap<String, u64>>,
}

/// An attestation a route accepts, as written in the file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteAttestSection {
    /// Scheme ID.
    pub scheme: String,
    /// `required`, `waive`, `discount` or `quota`.
    pub effect: Effect,
    /// Basis points for a discount, actions per epoch for a quota.
    #[serde(default)]
    pub value: Option<u64>,
    /// Quota epoch, seconds.
    #[serde(default)]
    pub epoch: Option<u64>,
}

/// What kind of application a route fronts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Upstream {
    /// Any HTTP application.
    #[default]
    Http,
    /// An OpenAI-compatible inference API: the meter `tokens` reads
    /// `usage.total_tokens`, and a request asking for a stream is refused on
    /// a metered route (streaming is not metered by this build).
    Openai,
}

/// `[[route]]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSection {
    /// Route ID, the input of the route scope.
    pub id: String,
    /// A method, one space, and a path (`/*` matches every path below).
    #[serde(rename = "match")]
    pub match_: String,
    /// `exact` or `route`.
    #[serde(default = "default_scope")]
    pub scope: RouteScopeMode,
    /// Price per call; the ceiling on a metered route.
    #[serde(default)]
    pub price: BTreeMap<String, u64>,
    /// The charge is set at settlement by the meter.
    #[serde(default)]
    pub metered: bool,
    /// The meter's name, such as `tokens`.
    #[serde(default)]
    pub meter: Option<String>,
    /// JSON pointer to the meter's count in the answer; for `tokens` the
    /// default is `/usage/total_tokens`.
    #[serde(default)]
    pub meter_path: Option<String>,
    /// Price per 1,000 meter units, in the price's unit (DECISIONS row 13:
    /// in the offer, not the manifest).
    #[serde(default)]
    pub rate: Option<u64>,
    /// Required properties.
    #[serde(default)]
    pub require: BTreeMap<String, String>,
    /// Value schemes, in preference order.
    #[serde(default)]
    pub accept: Vec<String>,
    /// Attestations.
    #[serde(default)]
    pub attest: Vec<RouteAttestSection>,
    /// Request fields hashed into the scope, lower case.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Experimental schemes may be listed.
    #[serde(default)]
    pub allow_experimental: bool,
    /// Schemes on non-Bitcoin rails or units may be listed.
    #[serde(default)]
    pub allow_non_bitcoin: bool,
    /// The kind of application.
    #[serde(default)]
    pub upstream: Upstream,
}

fn default_scope() -> RouteScopeMode {
    RouteScopeMode::Route
}

/// `[limits]`: per-address bounds (draft-00 12, DECISIONS row 24).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSection {
    /// Exact-scope offers with native challenges (each mints an invoice) and
    /// fund quotes, per client address per minute.
    #[serde(default = "default_mint")]
    pub mints_per_minute: u32,
    /// Requests carrying a credential that reach a scheme plug, per client
    /// address per minute.
    #[serde(default = "default_verify")]
    pub verifies_per_minute: u32,
    /// Requests carrying a credential that reach a scheme plug, per offer
    /// per minute (a route offer is shared by every client).
    #[serde(default = "default_verify_offer")]
    pub verifies_per_offer_per_minute: u32,
    /// Most change outputs one outcome may have signed.
    #[serde(default = "default_outputs")]
    pub max_change_outputs: usize,
}

fn default_mint() -> u32 {
    20
}
fn default_verify() -> u32 {
    600
}
fn default_verify_offer() -> u32 {
    6000
}
fn default_outputs() -> usize {
    64
}

impl Default for LimitSection {
    fn default() -> Self {
        Self {
            mints_per_minute: default_mint(),
            verifies_per_minute: default_verify(),
            verifies_per_offer_per_minute: default_verify_offer(),
            max_change_outputs: default_outputs(),
        }
    }
}

/// Why the configuration was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML syntax or an unknown member.
    #[error("the configuration does not parse: {0}")]
    Parse(String),
    /// A rule this module enforces.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

/// Where a pay entry goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The route-scope offer.
    Route,
    /// The metered exact-scope offer.
    ExactMetered,
    /// The non-metered exact-scope offer (priced at the ceiling on a
    /// metered route).
    ExactPlain,
}

/// One pay entry of a route's offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayPlan {
    /// Scheme ID.
    pub scheme: String,
    /// The amount (the ceiling on a metered entry).
    pub amount: u64,
    /// The unit.
    pub unit: String,
    /// Per 1,000 units, on a metered entry.
    pub rate: Option<u64>,
    /// The offer it goes in.
    pub slot: Slot,
    /// Binding class.
    pub class: BindingClass,
}

/// One attest entry of a route's offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestPlan {
    /// As written.
    pub attest: RouteAttestSection,
    /// Binding class.
    pub class: BindingClass,
}

/// A route, resolved against the registry and the enabled schemes.
#[derive(Debug, Clone)]
pub struct RoutePlan {
    /// As written.
    pub section: RouteSection,
    /// The price map in force (the pricing table's, or the route's).
    pub price: BTreeMap<String, u64>,
    /// Pay entries, in the route's preference order.
    pub pay: Vec<PayPlan>,
    /// Attest entries, in the route's order.
    pub attest: Vec<AttestPlan>,
    /// The manifest route this gate must serve.
    pub manifest: Route,
}

impl RoutePlan {
    /// The JSON pointer of the meter.
    #[must_use]
    pub fn meter_path(&self) -> Option<String> {
        if !self.section.metered {
            return None;
        }
        self.section.meter_path.clone().or_else(|| {
            (self.section.meter.as_deref() == Some("tokens"))
                .then(|| "/usage/total_tokens".to_owned())
        })
    }
}

impl Config {
    /// Parses a configuration file's text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Reads and parses a configuration file.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Parse(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// The rail registry entries a scheme is configured with.
    fn scheme_rail_entries(&self, s: &SchemeSection) -> Vec<String> {
        s.rail_ids()
            .iter()
            .filter_map(|id| self.rails.iter().find(|r| &r.id == id))
            .filter_map(RailSection::registry_id)
            .collect()
    }

    /// Checks the whole configuration and resolves every route. Nothing is
    /// started; an error means the gate must not start.
    #[allow(clippy::too_many_lines)]
    pub fn plan(&self, registry: &Registry) -> Result<Vec<RoutePlan>, ConfigError> {
        check_origin(&self.gate.origin)?;
        if self.gate.front == Front::EnvoyExtAuthz {
            return Err(invalid(
                "front = \"envoy_ext_authz\" is not implemented in this build (documented stub); use proxy, forward_auth or auth_request",
            ));
        }
        if self.gate.front == Front::Proxy && self.gate.upstream.is_none() {
            return Err(invalid("front = \"proxy\" needs gate.upstream"));
        }
        if self.gate.offer_lifetime_s < 60 || self.gate.route_offer_lifetime_s < 60 {
            return Err(invalid("offer lifetimes must be at least 60 s"));
        }
        if self.manifest.max_age_s > 2_592_000 {
            return Err(invalid("manifest.max_age_s is at most 30 days"));
        }
        if let Some(k) = &self.pricing.kind
            && k != "table"
        {
            return Err(invalid(format!(
                "pricing.kind {k:?}: only \"table\" exists"
            )));
        }
        for t in self.pricing.table.keys() {
            if !self.routes.iter().any(|r| &r.id == t) {
                return Err(invalid(format!("pricing.table names unknown route {t:?}")));
            }
        }
        let mut seen = BTreeSet::new();
        for r in &self.rails {
            if !seen.insert(&r.id) {
                return Err(invalid(format!("rail {:?} is listed twice", r.id)));
            }
            let Some(entry) = r.registry_id() else {
                return Err(invalid(format!(
                    "rail {:?} of kind {:?} needs `registry`, the registry rail entry it stands for",
                    r.id, r.kind
                )));
            };
            if !matches!(r.kind.as_str(), "lnd" | "phoenixd" | "nwc" | "fake") {
                return Err(invalid(format!(
                    "rail {:?}: kind {:?} is not implemented",
                    r.id, r.kind
                )));
            }
            if registry.rail(&entry).is_none() {
                return Err(invalid(format!(
                    "rail {:?}: {entry:?} is not in the registry",
                    r.id
                )));
            }
            if !entry.starts_with("ln:") {
                return Err(invalid(format!(
                    "rail {:?}: only Lightning rails are implemented",
                    r.id
                )));
            }
        }
        let mut seen = BTreeSet::new();
        for s in &self.schemes {
            if !seen.insert(&s.id) {
                return Err(invalid(format!("scheme {:?} is listed twice", s.id)));
            }
            for rid in s.rail_ids() {
                if !self.rails.iter().any(|r| r.id == rid) {
                    return Err(invalid(format!(
                        "scheme {:?} names unknown rail {rid:?}",
                        s.id
                    )));
                }
            }
        }
        let mut seen = BTreeSet::new();
        for a in &self.attests {
            if !seen.insert(&a.id) {
                return Err(invalid(format!("attestation {:?} is listed twice", a.id)));
            }
        }
        let mut ids = BTreeSet::new();
        let mut plans = Vec::new();
        for r in &self.routes {
            if !ids.insert(r.id.clone()) {
                return Err(invalid(format!("route {:?} is listed twice", r.id)));
            }
            plans.push(self.plan_route(registry, r)?);
        }
        Ok(plans)
    }

    #[allow(clippy::too_many_lines)]
    fn plan_route(&self, registry: &Registry, r: &RouteSection) -> Result<RoutePlan, ConfigError> {
        let id = &r.id;
        let route_err = |m: String| invalid(format!("route {id:?}: {m}"));
        if r.id.is_empty() {
            return Err(invalid("a route needs an id"));
        }
        let Some((method, path)) = r.match_.split_once(' ') else {
            return Err(route_err(
                "match must be a method, one space and a path".into(),
            ));
        };
        if method.is_empty() || !path.starts_with('/') || path.contains(' ') {
            return Err(route_err(
                "match must be a method, one space and a path".into(),
            ));
        }
        for h in &r.headers {
            if h.is_empty()
                || !h.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b"-!#$%&'*+.^_`|~".contains(&b)
                })
            {
                return Err(route_err(format!(
                    "header {h:?} must be a lower-case field name"
                )));
            }
        }
        let price = self
            .pricing
            .table
            .get(&r.id)
            .cloned()
            .unwrap_or_else(|| r.price.clone());
        if r.metered {
            if r.meter.is_none() {
                return Err(route_err("a metered route needs a meter".into()));
            }
            if r.rate.is_none() {
                return Err(route_err("a metered route needs a rate".into()));
            }
            if price.len() != 1 {
                return Err(route_err(
                    "a metered route has exactly one price unit".into(),
                ));
            }
            if self.gate.front.is_auth() {
                return Err(route_err(
                    "a metered route needs the proxy front: an auth front never shows the gate the answer".into(),
                ));
            }
            let path = r.meter_path.clone().or_else(|| {
                (r.meter.as_deref() == Some("tokens")).then(|| "/usage/total_tokens".into())
            });
            if path.is_none() {
                return Err(route_err(
                    "meter_path is required for a meter other than tokens".into(),
                ));
            }
        }
        let require_raw: BTreeMap<String, serde_json::Value> = r
            .require
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        let require = Require::parse(Some(&require_raw)).map_err(|e| route_err(e.to_string()))?;
        let policy = RoutePolicy {
            route: r.id.clone(),
            require,
            allow_experimental: r.allow_experimental,
        };

        // Value schemes: known, value, enabled, implemented, enforceable.
        let mut pay_candidates = Vec::new();
        for s in &r.accept {
            let entry = registry
                .scheme(s)
                .ok_or_else(|| route_err(format!("scheme {s:?} is not in the registry")))?;
            if !entry.is_value() || entry.status == "does-not-fit" {
                return Err(route_err(format!("{s:?} is not a value scheme")));
            }
            if entry.non_bitcoin() && !r.allow_non_bitcoin {
                return Err(route_err(format!(
                    "{s:?} uses a non-Bitcoin rail or unit; set allow_non_bitcoin on the route to turn it on"
                )));
            }
            if !VALUE_SCHEMES.contains(&s.as_str()) {
                return Err(route_err(format!("{s:?} is not implemented by this build")));
            }
            if entry.model().is_none() {
                return Err(route_err(format!(
                    "{s:?}: its use model cannot be enforced here"
                )));
            }
            let Some(section) = self.schemes.iter().find(|c| &c.id == s) else {
                return Err(route_err(format!("{s:?} has no [[scheme]] section")));
            };
            if !section.enabled {
                continue;
            }
            if section.rail_ids().is_empty() {
                return Err(route_err(format!("{s:?} needs a rail")));
            }
            let rails = self.scheme_rail_entries(section);
            pay_candidates.push(Candidate {
                scheme: s.clone(),
                effect: None,
                vector: registry.effective(s, &rails),
            });
        }
        let mut attest_candidates = Vec::new();
        for a in &r.attest {
            let s = &a.scheme;
            let entry = registry
                .scheme(s)
                .ok_or_else(|| route_err(format!("attestation {s:?} is not in the registry")))?;
            if !entry.is_attestation() {
                return Err(route_err(format!("{s:?} is not an attestation scheme")));
            }
            if !ATTEST_SCHEMES.contains(&s.as_str()) {
                return Err(route_err(format!("{s:?} is not implemented by this build")));
            }
            if entry.model() != Some(bnap_core::store::UseModel::Reusable) {
                return Err(route_err(format!(
                    "{s:?}: its use model cannot be enforced here"
                )));
            }
            check_effect(a).map_err(route_err)?;
            if a.effect != Effect::Required && !entry.class().may_affect_price() {
                return Err(route_err(format!(
                    "{s:?} is class {} and may not waive, discount or carry a quota (draft-00 7)",
                    entry.class().as_str()
                )));
            }
            if a.effect == Effect::Quota {
                return Err(route_err(format!(
                    "{s:?}: no implemented attestation registers a quota_id, so it cannot carry a quota"
                )));
            }
            let Some(section) = self.attests.iter().find(|c| &c.id == s) else {
                return Err(route_err(format!("{s:?} has no [[attest]] section")));
            };
            if !section.enabled {
                if a.effect == Effect::Required {
                    return Err(route_err(format!("required attestation {s:?} is disabled")));
                }
                continue;
            }
            attest_candidates.push(Candidate {
                scheme: s.clone(),
                effect: Some(a.effect),
                vector: registry.effective(s, &[]),
            });
        }
        let selection = policy
            .select(&pay_candidates, &attest_candidates)
            .map_err(|e| route_err(e.to_string()))?;
        for c in &pay_candidates {
            if !selection.pay.contains(&c.scheme) {
                tracing::warn!(route = %r.id, scheme = %c.scheme, "left out of offers: fails the route's require or is experimental without allow_experimental");
            }
        }

        // Pay entries and their offers.
        let mut pay = Vec::new();
        for s in &selection.pay {
            let entry = registry.scheme(s).expect("checked above");
            let class = entry.class();
            let unit = price
                .keys()
                .find(|u| entry.units.contains(u))
                .ok_or_else(|| route_err(format!("{s:?} pays in none of the price's units")))?
                .clone();
            let amount = price[&unit];
            let meterable = entry.meterable();
            let slot = if r.scope == RouteScopeMode::Route
                && class.route_scope_allowed()
                && (!r.metered || meterable)
            {
                Slot::Route
            } else if r.metered && meterable {
                Slot::ExactMetered
            } else {
                Slot::ExactPlain
            };
            if class == BindingClass::None && amount > 0 {
                return Err(route_err(format!(
                    "{s:?} is class None and admissible only at price 0 (DECISIONS row 25)"
                )));
            }
            let rate = (r.metered && slot != Slot::ExactPlain).then_some(r.rate.unwrap_or(0));
            pay.push(PayPlan {
                scheme: s.clone(),
                amount,
                unit,
                rate,
                slot,
                class,
            });
        }
        let attest: Vec<AttestPlan> = r
            .attest
            .iter()
            .filter(|a| selection.attest.contains(&a.scheme))
            .map(|a| AttestPlan {
                attest: a.clone(),
                class: registry.class(&a.scheme),
            })
            .collect();
        if price.is_empty() && !pay.is_empty() {
            return Err(route_err("a route with value schemes needs a price".into()));
        }
        let manifest = Route {
            id: r.id.clone(),
            match_: r.match_.clone(),
            scope: r.scope,
            metered: r.metered,
            meter: r.meter.clone(),
            price: price.clone(),
            pay: selection.pay.clone(),
            attest: attest
                .iter()
                .map(|a| RouteAttest {
                    scheme: a.attest.scheme.clone(),
                    effect: a.attest.effect,
                    value: a.attest.value,
                    epoch: a.attest.epoch,
                })
                .collect(),
            require: (!r.require.is_empty()).then_some(require_raw),
            headers: r.headers.clone(),
        };
        Ok(RoutePlan {
            section: r.clone(),
            price,
            pay,
            attest,
            manifest,
        })
    }
}

fn check_effect(a: &RouteAttestSection) -> Result<(), String> {
    match a.effect {
        Effect::Discount => match a.value {
            Some(v) if (1..=10_000).contains(&v) => Ok(()),
            _ => Err(format!(
                "{:?}: a discount needs value 1 to 10,000 basis points",
                a.scheme
            )),
        },
        Effect::Quota => match (a.value, a.epoch) {
            (Some(v), Some(e)) if v >= 1 && e >= 1 => Ok(()),
            _ => Err(format!(
                "{:?}: a quota needs value and epoch of at least 1",
                a.scheme
            )),
        },
        Effect::Required | Effect::Waive => Ok(()),
    }
}

/// Checks an RFC 6454 origin serialization: `http` or `https`, lower case,
/// no path, query, fragment or user info, default port omitted.
pub fn check_origin(origin: &str) -> Result<(), ConfigError> {
    let bad = || invalid(format!("gate.origin {origin:?} is not an RFC 6454 origin"));
    let (scheme, rest) = origin.split_once("://").ok_or_else(bad)?;
    if !matches!(scheme, "https" | "http") || rest.is_empty() {
        return Err(bad());
    }
    if rest
        .bytes()
        .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@') || b.is_ascii_uppercase())
    {
        return Err(bad());
    }
    if (scheme == "https" && rest.ends_with(":443")) || (scheme == "http" && rest.ends_with(":80"))
    {
        return Err(bad());
    }
    Ok(())
}
