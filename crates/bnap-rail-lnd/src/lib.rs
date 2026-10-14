//! Settlement rail for an LND Lightning node over gRPC.
//!
//! [`LndRail`] is an operator-trusted `ln` [`FundingRail`] on the
//! operator's own LND node, through `fedimint-tonic-lnd`. It needs the
//! node's gRPC address, its TLS certificate and a macaroon, all read from
//! files ([`LndConfig`]); an `invoice.macaroon` is enough, since the rail
//! only adds and looks up invoices.
//!
//! - `request` adds an invoice whose description hash is the 32-byte memo
//!   (the `OfferID`, draft-00 4.2 step 3). Its [`PayId`] is the payment
//!   hash.
//! - `confirm` looks the invoice up by payment hash and reports, as the
//!   node knows them, the canonical bytes (the payment hash, draft-00 6.1),
//!   the state and `amt_paid_msat` in `msat`. Only `SETTLED` is
//!   [`PayState::Paid`]: an `ACCEPTED` (held) invoice is not final. A
//!   keysend or AMP invoice never confirms: its preimage is the payer's, not
//!   the node's, so it proves nothing a scheme could rely on. An answer for
//!   another payment hash is refused.
//! - A node that cannot be reached, or does not answer within
//!   [`LndConfig::timeout`], is [`RailError::Unavailable`]: the gate fails
//!   closed.
//!
//! The rail never pays: it only receives.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bnap_core::ids::rail;
use bnap_plug::{Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailRef};
use fedimint_tonic_lnd::LightningClient;
use fedimint_tonic_lnd::lnrpc::invoice::InvoiceState;
use fedimint_tonic_lnd::lnrpc::{Invoice, PaymentHash};

/// How long invoices live unless the configuration says otherwise.
pub const DEFAULT_EXPIRY: u64 = 3_600;
/// How long a node call may take before the rail gives up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the node is and the files that authenticate to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndConfig {
    /// The gRPC address, `https://host:port`.
    pub address: String,
    /// The node's `tls.cert`.
    pub cert: PathBuf,
    /// A macaroon allowed to add and look up invoices (`invoice.macaroon`).
    pub macaroon: PathBuf,
    /// Invoice lifetime in seconds.
    pub expiry: u64,
    /// The longest a node call may take.
    pub timeout: Duration,
}

impl LndConfig {
    /// A configuration with the default expiry and timeout.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        cert: impl Into<PathBuf>,
        macaroon: impl Into<PathBuf>,
    ) -> Self {
        Self {
            address: address.into(),
            cert: cert.into(),
            macaroon: macaroon.into(),
            expiry: DEFAULT_EXPIRY,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Reads `BNAP_LND_ADDRESS`, `BNAP_LND_CERT` and `BNAP_LND_MACAROON`,
    /// and `BNAP_LND_INVOICE_EXPIRY` if set.
    pub fn from_env() -> Result<Self, RailError> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| RailError::Unavailable(format!("{name} is not set")))
        };
        let mut c = Self::new(
            var("BNAP_LND_ADDRESS")?,
            var("BNAP_LND_CERT")?,
            var("BNAP_LND_MACAROON")?,
        );
        if let Ok(e) = std::env::var("BNAP_LND_INVOICE_EXPIRY") {
            c.expiry = e.parse().map_err(|_| {
                RailError::Unavailable("BNAP_LND_INVOICE_EXPIRY is not a number".into())
            })?;
        }
        Ok(c)
    }
}

/// An `ln` funding rail on an LND node.
#[derive(Clone)]
pub struct LndRail {
    client: LightningClient,
    expiry: u64,
    timeout: Duration,
}

impl std::fmt::Debug for LndRail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndRail")
            .field("expiry", &self.expiry)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Installs aws-lc-rs as the process's rustls crypto provider unless one
/// is installed already. The LND client's certificate check needs one.
pub fn install_crypto_provider() {
    // An error means a provider is installed already, which is fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn down(e: impl std::fmt::Display) -> RailError {
    RailError::Unavailable(e.to_string())
}

impl LndRail {
    /// Connects to the node. The certificate and macaroon files are read
    /// now; a missing or unreadable file is [`RailError::Unavailable`].
    pub async fn connect(config: &LndConfig) -> Result<Self, RailError> {
        install_crypto_provider();
        let mut client = fedimint_tonic_lnd::connect(
            config.address.clone(),
            config.cert.clone(),
            config.macaroon.clone(),
        )
        .await
        .map_err(down)?;
        Ok(Self {
            client: client.lightning().clone(),
            expiry: config.expiry,
            timeout: config.timeout,
        })
    }

    async fn lookup(&self, hash: &[u8; 32]) -> Result<Invoice, RailError> {
        let mut c = self.client.clone();
        let call = c.lookup_invoice(PaymentHash {
            r_hash: hash.to_vec(),
            ..PaymentHash::default()
        });
        match tokio::time::timeout(self.timeout, call).await {
            Err(_) => Err(RailError::Unavailable("LND did not answer in time".into())),
            Ok(Err(status)) => Err(status_error(&status)),
            Ok(Ok(resp)) => Ok(resp.into_inner()),
        }
    }
}

/// A gRPC failure: an unknown invoice is [`RailError::NotConfirmed`],
/// anything else [`RailError::Unavailable`].
#[must_use]
pub fn status_error(status: &fedimint_tonic_lnd::tonic::Status) -> RailError {
    use fedimint_tonic_lnd::tonic::Code;
    let unknown_invoice = status.code() == Code::NotFound
        || status.message().contains("unable to locate invoice")
        || status.message().contains("there are no existing invoices");
    if unknown_invoice {
        RailError::NotConfirmed("the node has no invoice with this payment hash".into())
    } else {
        RailError::Unavailable(format!("LND: {}", status.message()))
    }
}

/// The amount an LND invoice asks for, in msat, from a rail amount.
pub fn value_msat(amount: u64, unit: &str) -> Result<i64, RailError> {
    let msat = match unit {
        "sat" => amount.checked_mul(1_000),
        "msat" => Some(amount),
        other => {
            return Err(RailError::Unavailable(format!(
                "a Lightning rail takes sat or msat, not {other}"
            )));
        }
    };
    msat.and_then(|m| i64::try_from(m).ok())
        .ok_or_else(|| RailError::Unavailable("amount too large for an invoice".into()))
}

/// What an invoice LND returned says about the payment `hash`: refused if
/// it names another hash, never [`PayState::Paid`] unless `SETTLED` and
/// neither keysend nor AMP.
pub fn confirmed(hash: &[u8; 32], inv: &Invoice) -> Result<Confirmed, RailError> {
    if inv.r_hash.as_slice() != hash {
        return Err(RailError::Unavailable(
            "LND answered for another payment hash".into(),
        ));
    }
    if inv.is_keysend || inv.is_amp {
        return Err(RailError::NotConfirmed(
            "a keysend or AMP invoice proves no invoice payment".into(),
        ));
    }
    let state = match inv.state() {
        InvoiceState::Settled => PayState::Paid,
        InvoiceState::Open | InvoiceState::Accepted => PayState::Pending,
        InvoiceState::Canceled => PayState::Expired,
    };
    let paid = if state == PayState::Paid {
        u64::try_from(inv.amt_paid_msat).unwrap_or(0)
    } else {
        0
    };
    Ok(Confirmed {
        canonical: rail::ln(hash),
        state,
        amount: paid,
        unit: "msat".into(),
    })
}

fn payment_hash(bytes: &[u8]) -> Result<[u8; 32], RailError> {
    bytes
        .try_into()
        .map_err(|_| RailError::NotConfirmed("not a 32-byte payment hash".into()))
}

#[async_trait::async_trait]
impl FundingRail for LndRail {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        let value_msat = value_msat(amount, unit)?;
        let expiry = i64::try_from(self.expiry).map_err(down)?;
        let mut c = self.client.clone();
        let call = c.add_invoice(Invoice {
            value_msat,
            description_hash: memo.to_vec(),
            expiry,
            ..Invoice::default()
        });
        let added = match tokio::time::timeout(self.timeout, call).await {
            Err(_) => return Err(RailError::Unavailable("LND did not answer in time".into())),
            Ok(Err(status)) => {
                return Err(RailError::Unavailable(format!("LND: {}", status.message())));
            }
            Ok(Ok(resp)) => resp.into_inner(),
        };
        let hash: [u8; 32] = added
            .r_hash
            .as_slice()
            .try_into()
            .map_err(|_| RailError::Unavailable("LND returned no payment hash".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(down)?
            .as_secs();
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.to_owned(),
            request: added.payment_request,
            amount,
            unit: unit.to_owned(),
            expires: now.saturating_add(self.expiry),
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        let hash = payment_hash(&id.0)?;
        Ok(confirmed(&hash, &self.lookup(&hash).await?)?.state)
    }

    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError> {
        if reference.kind != rail::LN {
            return Err(RailError::WrongKind {
                want: rail::LN.to_owned(),
                got: reference.kind.clone(),
            });
        }
        let hash = payment_hash(&reference.reference)?;
        confirmed(&hash, &self.lookup(&hash).await?)
    }
}

#[cfg(test)]
mod tests {
    use fedimint_tonic_lnd::tonic::{Code, Status};

    use super::*;

    fn invoice(hash: [u8; 32], state: InvoiceState, paid: i64) -> Invoice {
        let mut inv = Invoice {
            r_hash: hash.to_vec(),
            amt_paid_msat: paid,
            value_msat: 21_000,
            ..Invoice::default()
        };
        inv.set_state(state);
        inv
    }

    #[test]
    fn only_a_settled_invoice_is_paid() {
        let h = [7; 32];
        let c = confirmed(&h, &invoice(h, InvoiceState::Settled, 21_000)).unwrap();
        assert_eq!(c.canonical, h.to_vec());
        assert_eq!(
            (c.state, c.amount, c.unit.as_str()),
            (PayState::Paid, 21_000, "msat")
        );
        for (s, want) in [
            (InvoiceState::Open, PayState::Pending),
            (InvoiceState::Accepted, PayState::Pending),
            (InvoiceState::Canceled, PayState::Expired),
        ] {
            let c = confirmed(&h, &invoice(h, s, 21_000)).unwrap();
            assert_eq!((c.state, c.amount), (want, 0), "{s:?}");
        }
    }

    #[test]
    fn keysend_amp_and_foreign_answers_never_confirm() {
        let h = [7; 32];
        let mut ks = invoice(h, InvoiceState::Settled, 21_000);
        ks.is_keysend = true;
        assert!(matches!(
            confirmed(&h, &ks),
            Err(RailError::NotConfirmed(_))
        ));
        let mut amp = invoice(h, InvoiceState::Settled, 21_000);
        amp.is_amp = true;
        assert!(matches!(
            confirmed(&h, &amp),
            Err(RailError::NotConfirmed(_))
        ));
        let other = invoice([8; 32], InvoiceState::Settled, 21_000);
        assert!(matches!(
            confirmed(&h, &other),
            Err(RailError::Unavailable(_))
        ));
        // A negative amount never backs anything.
        let neg = invoice(h, InvoiceState::Settled, -5);
        assert_eq!(confirmed(&h, &neg).unwrap().amount, 0);
    }

    #[test]
    fn units_convert_to_msat_exactly() {
        assert_eq!(value_msat(21, "sat").unwrap(), 21_000);
        assert_eq!(value_msat(21_001, "msat").unwrap(), 21_001);
        assert!(value_msat(21, "USD").is_err());
        assert!(value_msat(u64::MAX, "sat").is_err());
        assert!(value_msat(u64::MAX, "msat").is_err());
    }

    #[test]
    fn grpc_errors_map_to_rail_errors() {
        let nf = Status::new(Code::NotFound, "invoice not found");
        assert!(matches!(status_error(&nf), RailError::NotConfirmed(_)));
        let old = Status::new(Code::Unknown, "unable to locate invoice");
        assert!(matches!(status_error(&old), RailError::NotConfirmed(_)));
        let down = Status::new(Code::Unavailable, "connection refused");
        assert!(matches!(status_error(&down), RailError::Unavailable(_)));
        let auth = Status::new(Code::Unknown, "permission denied");
        assert!(matches!(status_error(&auth), RailError::Unavailable(_)));
    }

    #[test]
    fn configuration_has_defaults() {
        let c = LndConfig::new("https://127.0.0.1:10009", "tls.cert", "invoice.macaroon");
        assert_eq!(c.expiry, DEFAULT_EXPIRY);
        assert_eq!(c.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn missing_files_fail_closed() {
        install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let c = LndConfig::new(
            "https://127.0.0.1:1",
            "/nonexistent/tls.cert",
            "/nonexistent/invoice.macaroon",
        );
        let e = rt.block_on(LndRail::connect(&c)).unwrap_err();
        assert!(matches!(e, RailError::Unavailable(_)));
    }
}
