//! Settlement rail for a phoenixd Lightning node.
//!
//! [`PhoenixdRail`] is an operator-trusted `ln` [`FundingRail`] on
//! ACINQ's phoenixd, through its HTTP API with basic auth (the
//! `http-password` of `phoenix.conf`; any user name):
//!
//! - `request` is `POST /createinvoice` with `amountSat`, `descriptionHash`
//!   (the 32-byte memo, the `OfferID`) and `expirySeconds`. Its [`PayId`]
//!   is the payment hash.
//! - `confirm` and `status` are `GET /payments/incoming/{paymentHash}`.
//!   Only `isPaid` is [`PayState::Paid`]; an answer for another payment
//!   hash is refused; no such payment (204) is [`RailError::NotConfirmed`].
//!   The amount is reported in `msat`: for a paid invoice with an amount,
//!   the invoice amount, since a receiver settles a BOLT 11 invoice only
//!   when at least that much arrived (`receivedSat` is net of the liquidity
//!   fees the operator pays, and truncated to sat); otherwise
//!   `receivedSat` plus `fees`.
//! - [`PhoenixdRail::verify_webhook`] checks a webhook's
//!   `X-Phoenix-Signature` (hex HMAC-SHA256 of the body under the
//!   `webhook-secret`, compared in constant time) and reads the event. A
//!   webhook is a hint that a payment arrived; admission still confirms
//!   through the API, never from the webhook.
//!
//! An unreachable node, an HTTP error or an answer that does not parse is
//! [`RailError::Unavailable`]: the gate fails closed. The rail never pays.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bnap_core::hash::hmac_sha256_verify;
use bnap_core::ids::rail;
use bnap_plug::{Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailRef};
use serde::Deserialize;

/// phoenixd's default listen address.
pub const DEFAULT_URL: &str = "http://127.0.0.1:9740";
/// How long invoices live unless the configuration says otherwise: five
/// minutes, the lifetime of an exact-scope offer (draft-00 section 10 asks
/// for minutes). An invoice must not outlive the offer that carries it: a
/// payment made after the offer is STALE is refused, and a class O scheme
/// refunds nothing, so the Lightning schemes refuse to offer such an
/// invoice. Set the expiry to the gate's exact-scope offer lifetime or less.
pub const DEFAULT_EXPIRY: u64 = 300;
/// How long an API call may take before the rail gives up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// The webhook signature header.
pub const SIGNATURE_HEADER: &str = "X-Phoenix-Signature";

/// Where phoenixd is and how to authenticate to it.
#[derive(Clone, PartialEq, Eq)]
pub struct PhoenixdConfig {
    /// The API's base URL, such as `http://127.0.0.1:9740`.
    pub url: String,
    /// The `http-password` (full or limited access; invoices need only the
    /// limited one).
    pub password: String,
    /// The `webhook-secret`, to check webhooks with.
    pub webhook_secret: Option<String>,
    /// Invoice lifetime in seconds: at most the exact-scope offer lifetime.
    pub expiry: u64,
    /// The longest an API call may take.
    pub timeout: Duration,
}

impl std::fmt::Debug for PhoenixdConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoenixdConfig")
            .field("url", &self.url)
            .field("expiry", &self.expiry)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn config_error(msg: impl Into<String>) -> RailError {
    RailError::Unavailable(msg.into())
}

/// Reads a password file: either `phoenix.conf` (the value of
/// `key=`, such as `http-password=`) or a file holding only the secret.
pub fn read_secret_file(path: &Path, key: &str) -> Result<String, RailError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| config_error(format!("cannot read {}: {e}", path.display())))?;
    let prefix = format!("{key}=");
    let value = text
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix))
        .map_or_else(|| text.trim(), str::trim);
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Err(config_error(format!("no {key} in {}", path.display())));
    }
    Ok(value.to_owned())
}

impl PhoenixdConfig {
    /// A configuration with the default expiry and timeout.
    #[must_use]
    pub fn new(url: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            password: password.into(),
            webhook_secret: None,
            expiry: DEFAULT_EXPIRY,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Reads `PHOENIXD_URL` (default [`DEFAULT_URL`]), the password from
    /// `PHOENIXD_PASSWORD` or the file `PHOENIXD_PASSWORD_FILE` (such as
    /// `~/.phoenix/phoenix.conf`), and the webhook secret from
    /// `PHOENIXD_WEBHOOK_SECRET` or `PHOENIXD_WEBHOOK_SECRET_FILE` if set.
    pub fn from_env() -> Result<Self, RailError> {
        let env = |k: &str| std::env::var(k).ok();
        let secret = |direct: &str, file: &str, key: &str| -> Result<Option<String>, RailError> {
            match (env(direct), env(file)) {
                (Some(v), _) => Ok(Some(v)),
                (None, Some(f)) => read_secret_file(Path::new(&f), key).map(Some),
                (None, None) => Ok(None),
            }
        };
        let password = secret(
            "PHOENIXD_PASSWORD",
            "PHOENIXD_PASSWORD_FILE",
            "http-password",
        )?
        .ok_or_else(|| config_error("PHOENIXD_PASSWORD or PHOENIXD_PASSWORD_FILE is not set"))?;
        let mut c = Self::new(
            env("PHOENIXD_URL").unwrap_or_else(|| DEFAULT_URL.into()),
            password,
        );
        c.webhook_secret = secret(
            "PHOENIXD_WEBHOOK_SECRET",
            "PHOENIXD_WEBHOOK_SECRET_FILE",
            "webhook-secret",
        )?;
        Ok(c)
    }
}

/// An `ln` funding rail on phoenixd.
#[derive(Clone)]
pub struct PhoenixdRail {
    http: reqwest::Client,
    base: String,
    password: String,
    webhook_secret: Option<String>,
    expiry: u64,
}

impl std::fmt::Debug for PhoenixdRail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoenixdRail")
            .field("base", &self.base)
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}

/// `POST /createinvoice`'s answer.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedInvoice {
    payment_hash: String,
    serialized: String,
}

/// `GET /payments/incoming/{hash}`'s answer, the fields the rail reads.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IncomingPayment {
    /// Hex payment hash.
    pub payment_hash: String,
    /// The invoice was paid.
    pub is_paid: bool,
    /// The invoice expired unpaid.
    #[serde(default)]
    pub is_expired: bool,
    /// The invoice amount, if it had one.
    #[serde(default)]
    pub requested_sat: Option<u64>,
    /// What arrived, net of fees, truncated to sat.
    #[serde(default)]
    pub received_sat: u64,
    /// The fees taken from it, in msat.
    #[serde(default)]
    pub fees: u64,
}

/// What phoenixd's answer says about the payment `hash`.
pub fn confirmed(hash: &[u8; 32], p: &IncomingPayment) -> Result<Confirmed, RailError> {
    if !p.payment_hash.eq_ignore_ascii_case(&hex::encode(hash)) {
        return Err(RailError::Unavailable(
            "phoenixd answered for another payment hash".into(),
        ));
    }
    let state = if p.is_paid {
        PayState::Paid
    } else if p.is_expired {
        PayState::Expired
    } else {
        PayState::Pending
    };
    let amount = if p.is_paid {
        let gross = p.received_sat.saturating_mul(1_000).saturating_add(p.fees);
        p.requested_sat
            .map_or(gross, |r| r.saturating_mul(1_000).max(gross))
    } else {
        0
    };
    Ok(Confirmed {
        canonical: rail::ln(hash),
        state,
        amount,
        unit: "msat".into(),
    })
}

/// Checks `X-Phoenix-Signature`: lower- or upper-case hex of
/// HMAC-SHA256(`secret`, `body`), compared in constant time.
#[must_use]
pub fn verify_webhook_signature(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let mut tag = [0; 32];
    hex::decode_to_slice(signature.trim(), &mut tag).is_ok()
        && hmac_sha256_verify(secret, body, &tag)
}

/// A webhook event.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebhookEvent {
    /// `payment_received`: an invoice was paid.
    PaymentReceived {
        /// The payment hash.
        payment_hash: [u8; 32],
        /// What arrived, in sat.
        amount_sat: u64,
        /// The invoice's external ID, if it had one.
        external_id: Option<String>,
    },
    /// Any other event, by its `type`.
    Other(String),
}

/// Why a webhook was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebhookError {
    /// No webhook secret is configured.
    NoSecret,
    /// The signature does not verify.
    BadSignature,
    /// The body is not an event.
    Malformed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEvent {
    #[serde(rename = "type")]
    kind: String,
    payment_hash: Option<String>,
    amount_sat: Option<u64>,
    external_id: Option<String>,
}

impl PhoenixdRail {
    /// A rail for the configured node. Nothing is contacted yet.
    pub fn new(config: &PhoenixdConfig) -> Result<Self, RailError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| config_error(e.to_string()))?;
        Ok(Self {
            http,
            base: config.url.trim_end_matches('/').to_owned(),
            password: config.password.clone(),
            webhook_secret: config.webhook_secret.clone(),
            expiry: config.expiry,
        })
    }

    /// Checks a webhook's signature header and reads its event.
    pub fn verify_webhook(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<WebhookEvent, WebhookError> {
        let secret = self.webhook_secret.as_ref().ok_or(WebhookError::NoSecret)?;
        if !verify_webhook_signature(secret.as_bytes(), body, signature) {
            return Err(WebhookError::BadSignature);
        }
        let raw: RawEvent = serde_json::from_slice(body).map_err(|_| WebhookError::Malformed)?;
        if raw.kind != "payment_received" {
            return Ok(WebhookEvent::Other(raw.kind));
        }
        let mut payment_hash = [0; 32];
        hex::decode_to_slice(
            raw.payment_hash.ok_or(WebhookError::Malformed)?,
            &mut payment_hash,
        )
        .map_err(|_| WebhookError::Malformed)?;
        Ok(WebhookEvent::PaymentReceived {
            payment_hash,
            amount_sat: raw.amount_sat.ok_or(WebhookError::Malformed)?,
            external_id: raw.external_id,
        })
    }

    async fn incoming(&self, hash: &[u8; 32]) -> Result<Confirmed, RailError> {
        let url = format!("{}/payments/incoming/{}", self.base, hex::encode(hash));
        let resp = self
            .http
            .get(url)
            .basic_auth("", Some(&self.password))
            .send()
            .await
            .map_err(|e| RailError::Unavailable(format!("phoenixd: {e}")))?;
        match resp.status().as_u16() {
            204 | 404 => {
                return Err(RailError::NotConfirmed(
                    "phoenixd has no incoming payment with this hash".into(),
                ));
            }
            200 => {}
            s => return Err(RailError::Unavailable(format!("phoenixd answered {s}"))),
        }
        let p: IncomingPayment = resp
            .json()
            .await
            .map_err(|e| RailError::Unavailable(format!("phoenixd: {e}")))?;
        confirmed(hash, &p)
    }
}

fn payment_hash(bytes: &[u8]) -> Result<[u8; 32], RailError> {
    bytes
        .try_into()
        .map_err(|_| RailError::NotConfirmed("not a 32-byte payment hash".into()))
}

/// phoenixd takes whole sat.
fn amount_sat(amount: u64, unit: &str) -> Result<u64, RailError> {
    match unit {
        "sat" => Ok(amount),
        "msat" if amount.is_multiple_of(1_000) => Ok(amount / 1_000),
        _ => Err(RailError::Unavailable(format!(
            "phoenixd invoices are in whole sat, not {amount} {unit}"
        ))),
    }
}

#[async_trait::async_trait]
impl FundingRail for PhoenixdRail {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        let sat = amount_sat(amount, unit)?;
        // Every value is digits or hex: no form escaping is needed.
        let form = format!(
            "amountSat={sat}&descriptionHash={}&expirySeconds={}",
            hex::encode(memo),
            self.expiry
        );
        let resp = self
            .http
            .post(format!("{}/createinvoice", self.base))
            .basic_auth("", Some(&self.password))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form)
            .send()
            .await
            .map_err(|e| RailError::Unavailable(format!("phoenixd: {e}")))?;
        if !resp.status().is_success() {
            return Err(RailError::Unavailable(format!(
                "phoenixd answered {}",
                resp.status().as_u16()
            )));
        }
        let inv: GeneratedInvoice = resp
            .json()
            .await
            .map_err(|e| RailError::Unavailable(format!("phoenixd: {e}")))?;
        let mut hash = [0; 32];
        hex::decode_to_slice(&inv.payment_hash, &mut hash)
            .map_err(|_| RailError::Unavailable("phoenixd returned no payment hash".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| config_error(e.to_string()))?
            .as_secs();
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.to_owned(),
            request: inv.serialized,
            amount,
            unit: unit.to_owned(),
            expires: now.saturating_add(self.expiry),
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        Ok(self.incoming(&payment_hash(&id.0)?).await?.state)
    }

    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError> {
        if reference.kind != rail::LN {
            return Err(RailError::WrongKind {
                want: rail::LN.to_owned(),
                got: reference.kind.clone(),
            });
        }
        self.incoming(&payment_hash(&reference.reference)?).await
    }
}

#[cfg(test)]
mod tests;
