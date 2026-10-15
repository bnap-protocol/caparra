//! Builds the operator's plugs from the configuration: signer, use store,
//! rails, value and attestation schemes, and the `bnap:notes` issuer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bnap_core::store::{StoreError, UseStore};
use bnap_plug::{
    BlindSignature, BlindedOutput, ChangeLimit, CoreMessage, CredentialScheme, FundingRail,
    KeysetId, Point, Signer, SignerError,
};
use bnap_rail_fake::FakeRail;
use bnap_scheme_notes::{IssuerStore as _, KeysetInfo, KeysetState, NotesConfig, NotesScheme};
use bnap_signer_file::FileSigner;
use bnap_store_sqlite::SqliteStore;

use crate::config::{Config, RoutePlan};
use crate::issuer::GateIssuerStore;

/// The gate's clock, Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// The system clock.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Why a plug could not be built.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlugError(pub String);

fn perr(m: impl Into<String>) -> PlugError {
    PlugError(m.into())
}

/// Reads a file holding hex (whitespace around it ignored).
pub fn read_hex(path: &Path) -> Result<Vec<u8>, PlugError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| perr(format!("{}: {e}", path.display())))?;
    hex::decode(text.trim()).map_err(|e| perr(format!("{}: not hex: {e}", path.display())))
}

/// Reads a file holding exactly 32 bytes of hex.
pub fn read_key32(path: &Path) -> Result<[u8; 32], PlugError> {
    read_hex(path)?
        .try_into()
        .map_err(|_| perr(format!("{}: not 32 bytes", path.display())))
}

/// A value scheme and the rails that confirm its payments.
#[derive(Clone)]
pub struct ValuePlug {
    /// The plug.
    pub scheme: Arc<dyn CredentialScheme>,
    /// Rails, in the configured order.
    pub rails: Vec<Arc<dyn FundingRail>>,
}

/// A temporary SQLite directory for `kind = "memory"`, removed on drop.
#[derive(Debug)]
pub struct TempDb(PathBuf);

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every plug the gate runs with.
pub struct Plugs {
    /// The signer.
    pub signer: Arc<dyn Signer>,
    /// The use store.
    pub store: Arc<dyn UseStore>,
    /// The same store, for counter pruning.
    pub sqlite: SqliteStore,
    /// Rails by configured ID.
    pub rails: BTreeMap<String, Arc<dyn FundingRail>>,
    /// Fake rails by configured ID (tests pay their invoices).
    pub fakes: BTreeMap<String, Arc<FakeRail>>,
    /// Value schemes by scheme ID.
    pub values: BTreeMap<String, ValuePlug>,
    /// Attestation schemes by scheme ID.
    pub attests: BTreeMap<String, Arc<dyn CredentialScheme>>,
    /// The notes scheme, when enabled.
    pub notes: Option<Arc<NotesScheme>>,
    /// The notes issuer tables, when notes are enabled.
    pub issuer: Option<Arc<GateIssuerStore>>,
    /// The notes issuer's URL, as offers name it.
    pub issuer_url: Option<String>,
    /// Current `K_mac` first, then the retired ones.
    pub mac_keys: Vec<[u8; 32]>,
    /// Held so a memory store's files live as long as the gate.
    pub temp: Option<TempDb>,
}

impl std::fmt::Debug for Plugs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugs")
            .field("rails", &self.rails.keys().collect::<Vec<_>>())
            .field("values", &self.values.keys().collect::<Vec<_>>())
            .field("attests", &self.attests.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Builds every plug. `pending_timeout` is the manifest's.
#[allow(clippy::too_many_lines)]
pub async fn build(
    cfg: &Config,
    plans: &[RoutePlan],
    pending_timeout: u64,
    clock: &Clock,
) -> Result<Plugs, PlugError> {
    let mut mac_keys = vec![read_key32(&cfg.gate.mac_key_file)?];
    for p in &cfg.gate.retired_mac_key_files {
        mac_keys.push(read_key32(p)?);
    }

    // Signer.
    let mut file_signer: Option<Arc<FileSigner>> = None;
    let mut process: Option<ProcessKeysets> = None;
    let signer: Arc<dyn Signer> = match cfg.signer.kind.as_str() {
        "file" => {
            let path = cfg
                .signer
                .keys
                .as_ref()
                .ok_or_else(|| perr("signer.kind = \"file\" needs signer.keys"))?;
            let c = clock.clone();
            let s = Arc::new(
                FileSigner::load(path)
                    .map_err(|e| perr(format!("signer key file: {e}")))?
                    .with_clock(move || c()),
            );
            file_signer = Some(s.clone());
            s
        }
        "process" => {
            let (signer, keysets) = process_signer(cfg)?;
            process = Some(keysets);
            signer
        }
        k => return Err(perr(format!("signer.kind {k:?}: use file or process"))),
    };

    // Use store.
    let (store_path, issuer_path, temp) = match cfg.store.kind.as_str() {
        "sqlite" => {
            let p = cfg
                .store
                .path
                .clone()
                .ok_or_else(|| perr("store.kind = \"sqlite\" needs store.path"))?;
            let i = cfg.store.issuer_path.clone().unwrap_or_else(|| {
                let mut s = p.clone().into_os_string();
                s.push(".issuer");
                PathBuf::from(s)
            });
            (p, i, None)
        }
        "memory" => {
            tracing::warn!(
                "STORE IS NOT DURABLE: store.kind = \"memory\" keeps the use store in a temporary file deleted at exit; a restart forgets every spent credential. Tests only."
            );
            let dir = std::env::temp_dir().join(format!(
                "caparra-gate-{}-{}",
                std::process::id(),
                hex::encode(rand::random::<[u8; 8]>())
            ));
            std::fs::create_dir_all(&dir).map_err(|e| perr(e.to_string()))?;
            (dir.join("use.db"), dir.join("issuer.db"), Some(TempDb(dir)))
        }
        k => return Err(perr(format!("store.kind {k:?}: use sqlite or memory"))),
    };
    let sqlite = SqliteStore::open(&store_path)
        .await
        .map_err(|e: StoreError| perr(format!("use store: {e}")))?;
    let store: Arc<dyn UseStore> = Arc::new(sqlite.clone());

    // Rails.
    let mut rails: BTreeMap<String, Arc<dyn FundingRail>> = BTreeMap::new();
    let mut fakes = BTreeMap::new();
    for r in &cfg.rails {
        let rail: Arc<dyn FundingRail> = match r.kind.as_str() {
            "fake" => {
                tracing::warn!(rail = %r.id, "FAKE RAIL: invoices are never paid by anyone but a test");
                let seed: [u8; 32] = match &r.seed {
                    Some(s) => hex::decode(s)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| {
                            perr(format!("rail {:?}: seed is not 32 bytes of hex", r.id))
                        })?,
                    None => rand::random(),
                };
                let mut f = FakeRail::new(seed);
                if let Some(t) = r.invoice_expiry_s {
                    f = f.with_ttl(t);
                }
                let f = Arc::new(f);
                f.set_now(clock());
                fakes.insert(r.id.clone(), f.clone());
                f
            }
            "lnd" => {
                bnap_rail_lnd::install_crypto_provider();
                let mut c = bnap_rail_lnd::LndConfig::new(
                    r.address
                        .clone()
                        .ok_or_else(|| perr("lnd rail needs address"))?,
                    r.cert.clone().ok_or_else(|| perr("lnd rail needs cert"))?,
                    r.macaroon
                        .clone()
                        .ok_or_else(|| perr("lnd rail needs macaroon"))?,
                );
                if let Some(t) = r.invoice_expiry_s {
                    c.expiry = t;
                }
                Arc::new(
                    bnap_rail_lnd::LndRail::connect(&c)
                        .await
                        .map_err(|e| perr(format!("rail {:?}: {e}", r.id)))?,
                )
            }
            "phoenixd" => {
                let pw = r
                    .password_file
                    .as_ref()
                    .ok_or_else(|| perr("phoenixd rail needs password_file"))?;
                let password = std::fs::read_to_string(pw)
                    .map_err(|e| perr(format!("{}: {e}", pw.display())))?;
                let mut c = bnap_rail_phoenixd::PhoenixdConfig::new(
                    r.url
                        .clone()
                        .ok_or_else(|| perr("phoenixd rail needs url"))?,
                    password.trim(),
                );
                if let Some(t) = r.invoice_expiry_s {
                    c.expiry = t;
                }
                Arc::new(
                    bnap_rail_phoenixd::PhoenixdRail::new(&c)
                        .map_err(|e| perr(format!("rail {:?}: {e}", r.id)))?,
                )
            }
            "nwc" => {
                bnap_rail_lnd::install_crypto_provider();
                let var = r.uri_env.as_deref().unwrap_or("NWC_URI");
                let uri =
                    std::env::var(var).map_err(|_| perr(format!("nwc rail: ${var} is not set")))?;
                let rail = match r.invoice_expiry_s {
                    Some(t) => {
                        bnap_rail_nwc::NwcRail::with(&uri, t, std::time::Duration::from_secs(30))
                    }
                    None => bnap_rail_nwc::NwcRail::new(&uri),
                }
                .map_err(|e| perr(format!("rail {:?}: {e}", r.id)))?;
                Arc::new(rail)
            }
            k => return Err(perr(format!("rail kind {k:?} is not implemented"))),
        };
        if let Some(t) = r.invoice_expiry_s
            && t > cfg.gate.offer_lifetime_s
        {
            return Err(perr(format!(
                "rail {:?}: invoice_expiry_s must not exceed gate.offer_lifetime_s (an invoice may not outlive its offer)",
                r.id
            )));
        }
        rails.insert(r.id.clone(), rail);
    }

    // One invoice per offer, shared by L402 and MPP on the same rail
    // (DECISIONS row 24).
    let mut shared: BTreeMap<String, Arc<dyn FundingRail>> = BTreeMap::new();
    let mut invoices_of = |id: &str| -> Arc<dyn FundingRail> {
        shared
            .entry(id.to_owned())
            .or_insert_with(|| Arc::new(bnap_scheme_l402::OfferInvoices::new(rails[id].clone())))
            .clone()
    };

    // Which schemes some route uses.
    let used: std::collections::BTreeSet<&str> = plans
        .iter()
        .flat_map(|p| p.pay.iter().map(|e| e.scheme.as_str()))
        .collect();
    let used_attest: std::collections::BTreeSet<&str> = plans
        .iter()
        .flat_map(|p| p.attest.iter().map(|a| a.attest.scheme.as_str()))
        .collect();

    let mut values = BTreeMap::new();
    let mut notes = None;
    let mut issuer = None;
    let mut issuer_url = None;
    for s in cfg
        .schemes
        .iter()
        .filter(|s| s.enabled && used.contains(s.id.as_str()))
    {
        let rail_ids = s.rail_ids();
        let srails: Vec<Arc<dyn FundingRail>> = rail_ids.iter().map(|r| rails[r].clone()).collect();
        let first = rail_ids
            .first()
            .ok_or_else(|| perr(format!("{} needs a rail", s.id)))?;
        let scheme: Arc<dyn CredentialScheme> = match s.id.as_str() {
            bnap_scheme_l402::SCHEME_ID => {
                let secret = read_key32(
                    s.secret_file
                        .as_ref()
                        .ok_or_else(|| perr("httpauth:L402 needs secret_file"))?,
                )?;
                Arc::new(bnap_scheme_l402::L402::new(
                    bnap_scheme_l402::MacaroonKeys::new(secret),
                    invoices_of(first),
                ))
            }
            bnap_scheme_mpp::SCHEME_ID => {
                let secret = read_hex(
                    s.secret_file
                        .as_ref()
                        .ok_or_else(|| perr("payment:lightning/charge needs secret_file"))?,
                )?;
                let keys = bnap_scheme_mpp::ChallengeKeys::new(secret)
                    .map_err(|e| perr(format!("payment:lightning/charge secret: {e}")))?;
                let network = match s.network.as_deref().unwrap_or("mainnet") {
                    "mainnet" => bnap_scheme_mpp::Network::Mainnet,
                    "signet" => bnap_scheme_mpp::Network::Signet,
                    "regtest" => bnap_scheme_mpp::Network::Regtest,
                    n => return Err(perr(format!("network {n:?}: mainnet, signet or regtest"))),
                };
                let realm = s.realm.clone().unwrap_or_else(|| host_of(&cfg.gate.origin));
                Arc::new(
                    bnap_scheme_mpp::LightningCharge::new(keys, realm, network, invoices_of(first))
                        .map_err(|e| perr(format!("payment:lightning/charge: {e}")))?,
                )
            }
            bnap_scheme_notes::SCHEME_ID => {
                let store = Arc::new(
                    GateIssuerStore::open(&issuer_path)
                        .await
                        .map_err(|e| perr(e.0))?,
                );
                let now = clock();
                let keysets = match (&file_signer, &process) {
                    (Some(fs), _) => fs
                        .keysets()
                        .iter()
                        .map(|k| PublicKeyset {
                            keys: k.public_keys(),
                            input_fee_ppk: k.input_fee_ppk(),
                            final_expiry: k.final_expiry(),
                            active: k.active(),
                        })
                        .collect(),
                    (None, Some(p)) => p.keysets().await?,
                    (None, None) => {
                        return Err(perr("bnap:notes needs a signer that holds notes keysets"));
                    }
                };
                if keysets.is_empty() {
                    return Err(perr("bnap:notes: the signer holds no notes keyset"));
                }
                for k in keysets {
                    let mut info = KeysetInfo::new(k.keys, k.input_fee_ppk, k.final_expiry, now)
                        .map_err(|e| perr(format!("keyset: {e}")))?;
                    info.state = if k.active {
                        info.activated_at = Some(now);
                        KeysetState::Active
                    } else {
                        KeysetState::InputsOnly
                    };
                    store.put_keyset(&info).await.map_err(|e| perr(e.0))?;
                }
                let url = s
                    .issuer_url
                    .clone()
                    .unwrap_or_else(|| format!("{}/cashu", cfg.gate.origin));
                issuer_url = Some(url.clone());
                let mut nc = NotesConfig::new(url);
                nc.max_fund = s.max_fund_sat;
                nc.pending_timeout = pending_timeout;
                for p in plans {
                    if p.section.require.get("link-payment").map(String::as_str)
                        == Some("unlinkable")
                    {
                        nc.unlinkable_routes.insert(p.section.id.clone());
                    }
                }
                let n = Arc::new(NotesScheme::new(
                    nc,
                    store.clone(),
                    Some(rails[first].clone()),
                ));
                notes = Some(n.clone());
                issuer = Some(store);
                n
            }
            id => return Err(perr(format!("{id} is not implemented"))),
        };
        values.insert(
            s.id.clone(),
            ValuePlug {
                scheme,
                rails: srails,
            },
        );
    }

    let mut attests: BTreeMap<String, Arc<dyn CredentialScheme>> = BTreeMap::new();
    for a in cfg
        .attests
        .iter()
        .filter(|a| a.enabled && used_attest.contains(a.id.as_str()))
    {
        let scheme: Arc<dyn CredentialScheme> = match a.id.as_str() {
            bnap_scheme_dpop::DPOP | bnap_scheme_dpop::BEARER => {
                let mut auth = bnap_scheme_dpop::StaticAuthority::new();
                for k in &a.keys {
                    auth =
                        auth.with_key(bnap_scheme_dpop::Thumbprint::from_b64u(k).ok_or_else(
                            || perr(format!("{}: key {k:?} is not a thumbprint", a.id)),
                        )?);
                }
                for t in &a.tokens {
                    let info = match &t.jkt {
                        Some(j) => bnap_scheme_dpop::TokenInfo::bound_to(
                            bnap_scheme_dpop::Thumbprint::from_b64u(j).ok_or_else(|| {
                                perr(format!("{}: jkt {j:?} is not a thumbprint", a.id))
                            })?,
                        ),
                        None => bnap_scheme_dpop::TokenInfo::bearer(),
                    };
                    auth = auth.with_token(t.token.clone(), info);
                }
                let auth = Arc::new(auth);
                if a.id == bnap_scheme_dpop::DPOP {
                    Arc::new(bnap_scheme_dpop::DpopScheme::new(auth))
                } else {
                    Arc::new(bnap_scheme_dpop::BearerScheme::new(auth))
                }
            }
            bnap_scheme_webbotauth::ID => {
                let mut dir = bnap_scheme_webbotauth::StaticDirectory::new();
                for ag in &a.agents {
                    let key: [u8; 32] = hex::decode(&ag.key)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| {
                        perr(format!("agent {:?}: key is not 32 bytes of hex", ag.url))
                    })?;
                    dir = dir.with_agent_key(ag.url.clone(), key);
                }
                Arc::new(bnap_scheme_webbotauth::WebBotAuthScheme::new(
                    &authority_of(&cfg.gate.origin),
                    Arc::new(dir),
                ))
            }
            id => return Err(perr(format!("{id} is not implemented"))),
        };
        attests.insert(a.id.clone(), scheme);
    }

    Ok(Plugs {
        signer,
        store,
        sqlite,
        rails,
        fakes,
        values,
        attests,
        notes,
        issuer,
        issuer_url,
        mac_keys,
        temp,
    })
}

/// The public half of a notes keyset, from whichever signer holds it.
struct PublicKeyset {
    keys: std::collections::BTreeMap<u64, [u8; 33]>,
    input_fee_ppk: u64,
    final_expiry: u64,
    active: bool,
}

/// Asks the signer process for its keysets (only when `bnap:notes` is
/// configured, so a gate without notes works with an older signer).
#[cfg(unix)]
struct ProcessKeysets(Arc<bnap_signer_process::ProcessSigner>);

#[cfg(unix)]
impl ProcessKeysets {
    async fn keysets(&self) -> Result<Vec<PublicKeyset>, PlugError> {
        let sets = self
            .0
            .keysets()
            .await
            .map_err(|e| perr(format!("the signer process's keysets: {e}")))?;
        Ok(sets
            .into_iter()
            .map(|k| PublicKeyset {
                keys: k.keys.into_iter().map(|k| (k.amount, k.public)).collect(),
                input_fee_ppk: k.input_fee_ppk,
                final_expiry: k.final_expiry,
                active: k.active,
            })
            .collect())
    }
}

#[cfg(not(unix))]
struct ProcessKeysets;

#[cfg(not(unix))]
impl ProcessKeysets {
    #[allow(clippy::unused_async)]
    async fn keysets(&self) -> Result<Vec<PublicKeyset>, PlugError> {
        Err(perr("signer.kind = \"process\" needs a Unix system"))
    }
}

#[cfg(unix)]
fn process_signer(cfg: &Config) -> Result<(Arc<dyn Signer>, ProcessKeysets), PlugError> {
    let socket = cfg
        .signer
        .socket
        .clone()
        .ok_or_else(|| perr("signer.kind = \"process\" needs signer.socket"))?;
    let mut s = bnap_signer_process::ProcessSigner::new(socket);
    if let Some(uid) = cfg.signer.signer_uid {
        s = s.with_signer_uid(uid);
    }
    let s = Arc::new(s);
    Ok((s.clone(), ProcessKeysets(s)))
}

#[cfg(not(unix))]
fn process_signer(_cfg: &Config) -> Result<(Arc<dyn Signer>, ProcessKeysets), PlugError> {
    Err(perr("signer.kind = \"process\" needs a Unix system"))
}

/// The authority of an origin: host, and port when it is not the default.
#[must_use]
pub fn authority_of(origin: &str) -> String {
    origin
        .split_once("://")
        .map_or(origin, |(_, a)| a)
        .to_owned()
}

/// The host of an origin, without port.
#[must_use]
pub fn host_of(origin: &str) -> String {
    let a = authority_of(origin);
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_owned();
    }
    a.split(':').next().unwrap_or(&a).to_owned()
}

/// A signer whose `blind_sign` refuses once an outcome's change ledger
/// holds more than `max` outputs: the store bounds their value at the
/// admitted value, this bounds their count (plug work, draft-00 12).
pub struct OutputBound {
    /// The real signer.
    pub inner: Arc<dyn Signer>,
    /// The use store whose ledger counts.
    pub store: Arc<dyn UseStore>,
    /// Most outputs per outcome.
    pub max: usize,
}

#[async_trait::async_trait]
impl Signer for OutputBound {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<bnap_core::Signature, SignerError> {
        self.inner.schnorr(msg).await
    }

    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        unit: &str,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        self.inner
            .verify_unblinded(keyset, unit, amount, secret, c)
            .await
    }

    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let reserved = self
            .store
            .outcome(&limit.replay_key)
            .await
            .map_err(|e| SignerError::Unavailable(e.to_string()))?
            .map_or(0, |r| r.change_outputs.len());
        if reserved > self.max || outputs.len() > self.max {
            return Err(SignerError::Refused(format!(
                "more than {} change outputs for one outcome",
                self.max
            )));
        }
        self.inner.blind_sign(keyset, outputs, limit).await
    }
}
