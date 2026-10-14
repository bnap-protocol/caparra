//! Settlement rail over Nostr Wallet Connect (NIP-47).
//!
//! [`NwcRail`] is an `ln` [`FundingRail`] on a wallet reached through a
//! `nostr+walletconnect://` URI, with the `nwc` crate. It is receive-only:
//! it calls `make_invoice` and `lookup_invoice` and nothing else, and the
//! connection SHOULD be granted only those two methods. A NWC wallet is
//! custodial or remote, so the registry records it as
//! `custody = "third-party-custodial"`.
//!
//! - `request` is `make_invoice` with the amount in msat, the 32-byte memo
//!   (the `OfferID`) as `description_hash`, and an expiry. The wallet must
//!   return the invoice's payment hash, which is the [`PayId`].
//! - `confirm` and `status` are `lookup_invoice` by payment hash. The
//!   answer must name that payment hash and be an `incoming` transaction:
//!   an outgoing payment the wallet made settles a hash too, and must never
//!   back an action. Only `settled` is [`PayState::Paid`] (for a wallet that
//!   sends no `state`, a `settled_at` with a preimage that opens the hash);
//!   a preimage that does not hash to the payment hash is refused. The
//!   amount is reported in `msat`, as the wallet reports it.
//! - A relay or wallet that does not answer within the timeout, or answers
//!   with an error other than `NOT_FOUND`, is [`RailError::Unavailable`]:
//!   the gate fails closed.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bnap_core::hash::sha256;
use bnap_core::ids::rail;
use bnap_plug::{Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailRef};
use nwc::prelude::{
    ErrorCode, LookupInvoiceRequest, LookupInvoiceResponse, MakeInvoiceRequest,
    NostrWalletConnectOptions, NostrWalletConnectURI, TransactionState, TransactionType, nip47,
};

/// How long invoices live unless the configuration says otherwise.
pub const DEFAULT_EXPIRY: u64 = 3_600;
/// How long a wallet request may take before the rail gives up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// An `ln` funding rail on a NIP-47 wallet.
pub struct NwcRail {
    client: nwc::NWC,
    expiry: u64,
}

impl std::fmt::Debug for NwcRail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URI holds the connection's secret key: never shown.
        f.debug_struct("NwcRail")
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}

fn down(e: impl std::fmt::Display) -> RailError {
    RailError::Unavailable(format!("NWC: {e}"))
}

impl NwcRail {
    /// A rail for the wallet `uri` names, with the default expiry and
    /// timeout. Relays are contacted on the first request.
    pub fn new(uri: &str) -> Result<Self, RailError> {
        Self::with(uri, DEFAULT_EXPIRY, DEFAULT_TIMEOUT)
    }

    /// A rail with an invoice expiry and a request timeout.
    pub fn with(uri: &str, expiry: u64, timeout: Duration) -> Result<Self, RailError> {
        // The relay connections use rustls; give it a provider first.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let uri = NostrWalletConnectURI::parse(uri)
            .map_err(|_| RailError::Unavailable("not a nostr+walletconnect URI".into()))?;
        let opts = NostrWalletConnectOptions::new().timeout(timeout);
        Ok(Self {
            client: nwc::NWC::with_opts(uri, opts),
            expiry,
        })
    }

    /// Reads the URI from `BNAP_NWC_URI`, or from the file
    /// `BNAP_NWC_URI_FILE`.
    pub fn from_env() -> Result<Self, RailError> {
        let uri = match (
            std::env::var("BNAP_NWC_URI"),
            std::env::var("BNAP_NWC_URI_FILE"),
        ) {
            (Ok(u), _) => u,
            (Err(_), Ok(path)) => std::fs::read_to_string(&path)
                .map_err(|e| RailError::Unavailable(format!("cannot read {path}: {e}")))?
                .trim()
                .to_owned(),
            _ => {
                return Err(RailError::Unavailable(
                    "BNAP_NWC_URI or BNAP_NWC_URI_FILE is not set".into(),
                ));
            }
        };
        Self::new(&uri)
    }

    async fn lookup(&self, hash: &[u8; 32]) -> Result<Confirmed, RailError> {
        let answer = self
            .client
            .lookup_invoice(LookupInvoiceRequest {
                payment_hash: Some(hex::encode(hash)),
                invoice: None,
            })
            .await;
        match answer {
            Ok(r) => confirmed(hash, &r),
            Err(nwc::Error::NIP47(nip47::Error::ErrorCode(e))) if e.code == ErrorCode::NotFound => {
                Err(RailError::NotConfirmed(
                    "the wallet has no invoice with this payment hash".into(),
                ))
            }
            Err(e) => Err(down(e)),
        }
    }
}

/// The amount a NIP-47 `make_invoice` asks for, in msat.
pub fn amount_msat(amount: u64, unit: &str) -> Result<u64, RailError> {
    match unit {
        "sat" => amount
            .checked_mul(1_000)
            .ok_or_else(|| RailError::Unavailable("amount too large".into())),
        "msat" => Ok(amount),
        other => Err(RailError::Unavailable(format!(
            "a Lightning rail takes sat or msat, not {other}"
        ))),
    }
}

/// What a `lookup_invoice` answer says about the payment `hash`.
pub fn confirmed(hash: &[u8; 32], r: &LookupInvoiceResponse) -> Result<Confirmed, RailError> {
    if !r.payment_hash.eq_ignore_ascii_case(&hex::encode(hash)) {
        return Err(RailError::Unavailable(
            "the wallet answered for another payment hash".into(),
        ));
    }
    if r.transaction_type != Some(TransactionType::Incoming) {
        return Err(RailError::NotConfirmed(
            "not an incoming payment of this wallet".into(),
        ));
    }
    let opens = match &r.preimage {
        Some(p) => {
            let mut pre = [0; 32];
            if hex::decode_to_slice(p, &mut pre).is_err() || sha256(&pre) != *hash {
                return Err(RailError::NotConfirmed(
                    "the wallet's preimage does not open the payment hash".into(),
                ));
            }
            true
        }
        None => false,
    };
    let state = match r.state {
        Some(TransactionState::Settled) => PayState::Paid,
        Some(TransactionState::Expired) => PayState::Expired,
        Some(TransactionState::Failed) => PayState::Failed,
        // A wallet of an older NIP-47 revision: settled when it reports a
        // settlement time and a preimage that opens the hash.
        None if r.settled_at.is_some() && opens => PayState::Paid,
        Some(TransactionState::Pending) | None => PayState::Pending,
    };
    Ok(Confirmed {
        canonical: rail::ln(hash),
        state,
        amount: if state == PayState::Paid { r.amount } else { 0 },
        unit: "msat".into(),
    })
}

fn payment_hash(bytes: &[u8]) -> Result<[u8; 32], RailError> {
    bytes
        .try_into()
        .map_err(|_| RailError::NotConfirmed("not a 32-byte payment hash".into()))
}

#[async_trait::async_trait]
impl FundingRail for NwcRail {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        let made = self
            .client
            .make_invoice(MakeInvoiceRequest {
                amount: amount_msat(amount, unit)?,
                description: None,
                description_hash: Some(hex::encode(memo)),
                expiry: Some(self.expiry),
            })
            .await
            .map_err(down)?;
        let hash_hex = made
            .payment_hash
            .ok_or_else(|| RailError::Unavailable("the wallet returned no payment hash".into()))?;
        let mut hash = [0; 32];
        hex::decode_to_slice(&hash_hex, &mut hash)
            .map_err(|_| RailError::Unavailable("the wallet's payment hash is not hex".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(down)?
            .as_secs();
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.to_owned(),
            request: made.invoice,
            amount,
            unit: unit.to_owned(),
            expires: now.saturating_add(self.expiry),
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        Ok(self.lookup(&payment_hash(&id.0)?).await?.state)
    }

    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError> {
        if reference.kind != rail::LN {
            return Err(RailError::WrongKind {
                want: rail::LN.to_owned(),
                got: reference.kind.clone(),
            });
        }
        self.lookup(&payment_hash(&reference.reference)?).await
    }
}

#[cfg(test)]
mod tests {
    use nwc::prelude::Timestamp;

    use super::*;

    const PREIMAGE: [u8; 32] = [5; 32];

    fn hash() -> [u8; 32] {
        sha256(&PREIMAGE)
    }

    fn lookup(state: Option<TransactionState>, settled: bool) -> LookupInvoiceResponse {
        LookupInvoiceResponse {
            transaction_type: Some(TransactionType::Incoming),
            state,
            invoice: Some("lnbcrt1x".into()),
            description: None,
            description_hash: Some(hex::encode([7; 32])),
            preimage: settled.then(|| hex::encode(PREIMAGE)),
            payment_hash: hex::encode(hash()),
            amount: 21_000,
            fees_paid: 0,
            created_at: Timestamp::from(1_u64),
            expires_at: None,
            settled_at: settled.then(|| Timestamp::from(2_u64)),
            metadata: None,
        }
    }

    #[test]
    fn a_settled_incoming_invoice_is_paid_in_msat() {
        let c = confirmed(&hash(), &lookup(Some(TransactionState::Settled), true)).unwrap();
        assert_eq!(c.canonical, hash().to_vec());
        assert_eq!(
            (c.state, c.amount, c.unit.as_str()),
            (PayState::Paid, 21_000, "msat")
        );
        for (s, want) in [
            (TransactionState::Pending, PayState::Pending),
            (TransactionState::Expired, PayState::Expired),
            (TransactionState::Failed, PayState::Failed),
        ] {
            let c = confirmed(&hash(), &lookup(Some(s), false)).unwrap();
            assert_eq!((c.state, c.amount), (want, 0), "{s:?}");
        }
        // An older wallet without `state`.
        assert_eq!(
            confirmed(&hash(), &lookup(None, true)).unwrap().state,
            PayState::Paid
        );
        assert_eq!(
            confirmed(&hash(), &lookup(None, false)).unwrap().state,
            PayState::Pending
        );
    }

    #[test]
    fn outgoing_foreign_and_bad_preimage_answers_never_confirm() {
        let mut out = lookup(Some(TransactionState::Settled), true);
        out.transaction_type = Some(TransactionType::Outgoing);
        assert!(matches!(
            confirmed(&hash(), &out),
            Err(RailError::NotConfirmed(_))
        ));
        let mut untyped = lookup(Some(TransactionState::Settled), true);
        untyped.transaction_type = None;
        assert!(confirmed(&hash(), &untyped).is_err());
        let other = lookup(Some(TransactionState::Settled), true);
        assert!(matches!(
            confirmed(&[1; 32], &other),
            Err(RailError::Unavailable(_))
        ));
        let mut wrong = lookup(Some(TransactionState::Settled), true);
        wrong.preimage = Some(hex::encode([6; 32]));
        assert!(matches!(
            confirmed(&hash(), &wrong),
            Err(RailError::NotConfirmed(_))
        ));
        // Upper-case hex from the wallet is the same hash.
        let mut upper = lookup(Some(TransactionState::Settled), true);
        upper.payment_hash = upper.payment_hash.to_uppercase();
        assert!(confirmed(&hash(), &upper).is_ok());
    }

    #[test]
    fn units_convert_to_msat_exactly() {
        assert_eq!(amount_msat(21, "sat").unwrap(), 21_000);
        assert_eq!(amount_msat(21_001, "msat").unwrap(), 21_001);
        assert!(amount_msat(21, "USD").is_err());
        assert!(amount_msat(u64::MAX, "sat").is_err());
    }

    #[test]
    fn uris_are_checked_and_never_shown() {
        assert!(NwcRail::new("https://example.com").is_err());
        assert!(NwcRail::new("nostr+walletconnect://nothex?relay=wss://r.example").is_err());
        let pk = "b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4";
        let sk = "71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";
        let uri = format!("nostr+walletconnect://{pk}?relay=wss%3A%2F%2Frelay.example&secret={sk}");
        let r = NwcRail::new(&uri).unwrap();
        assert!(!format!("{r:?}").contains(sk));
        assert_eq!(r.kind(), "ln");
    }
}
