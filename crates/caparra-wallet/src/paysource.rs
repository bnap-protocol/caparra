//! Where Lightning payments come from: a Nostr Wallet Connect wallet
//! (`pay_invoice`), or a command such as `lncli payinvoice` for regtest.
//!
//! A pay source is told the amount it may pay and the most it may take in
//! fees; the wallet has already reserved both against its caps. The wallet
//! checks every preimage it gets back against the invoice's payment hash.

use std::fmt;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

use crate::error::{Code, Refusal, Result};

/// A payment that went through.
#[derive(Clone, PartialEq, Eq)]
pub struct Paid {
    /// The preimage.
    pub preimage: [u8; 32],
    /// What the payment took in routing fees, sat, rounded up.
    pub fee_sat: u64,
}

impl fmt::Debug for Paid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Paid")
            .field("fee_sat", &self.fee_sat)
            .finish_non_exhaustive()
    }
}

/// Pays BOLT 11 invoices.
#[async_trait::async_trait]
pub trait PaySource: Send + Sync {
    /// Pays `invoice`, an invoice for `amount_sat`, with at most
    /// `max_fee_sat` in routing fees.
    async fn pay_invoice(&self, invoice: &str, amount_sat: u64, max_fee_sat: u64) -> Result<Paid>;
}

/// A pay source as configured. The NWC URI holds a secret, so it lives
/// only in the encrypted store and is never printed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PaySourceConfig {
    /// No pay source: only notes already held can pay.
    #[default]
    None,
    /// Nostr Wallet Connect.
    Nwc {
        /// The `nostr+walletconnect://` URI.
        uri: String,
    },
    /// A command that pays the invoice given as its last argument, or in
    /// place of `{invoice}`; `{max_fee}` becomes the fee limit in sat. It
    /// prints JSON with `payment_preimage` and `fee_sat` or `fee_msat`, as
    /// `lncli payinvoice --json` does.
    Command {
        /// The program and its arguments.
        argv: Vec<String>,
    },
}

impl fmt::Debug for PaySourceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

impl PaySourceConfig {
    /// A description with no secret in it.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::Nwc { .. } => "nwc (connection secret hidden)".into(),
            Self::Command { argv } => format!("command: {}", argv.join(" ")),
        }
    }

    /// The pay source, or `None` when none is configured.
    #[must_use]
    pub fn build(&self) -> Option<Box<dyn PaySource>> {
        match self {
            Self::None => None,
            Self::Nwc { uri } => Some(Box::new(NwcSource { uri: uri.clone() })),
            Self::Command { argv } => Some(Box::new(CommandSource { argv: argv.clone() })),
        }
    }
}

fn failed(m: impl fmt::Display) -> Refusal {
    Refusal::new(
        Code::PaymentFailed,
        format!("The Lightning payment failed: {m}. Nothing was paid."),
    )
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// Pays over Nostr Wallet Connect (NIP-47 `pay_invoice`).
pub struct NwcSource {
    uri: String,
}

#[async_trait::async_trait]
impl PaySource for NwcSource {
    async fn pay_invoice(
        &self,
        invoice: &str,
        _amount_sat: u64,
        _max_fee_sat: u64,
    ) -> Result<Paid> {
        use nwc::prelude::{NWC, NostrWalletConnectOptions, NostrWalletConnectURI, nip47};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let uri = NostrWalletConnectURI::parse(&self.uri).map_err(|_| {
            Refusal::new(Code::NoPaySource, "The NWC connection URI does not parse.")
        })?;
        let nwc = NWC::with_opts(
            uri,
            NostrWalletConnectOptions::new().timeout(Duration::from_secs(90)),
        );
        let r = nwc
            .pay_invoice(nip47::PayInvoiceRequest::new(invoice))
            .await;
        nwc.shutdown().await;
        let r = r.map_err(failed)?;
        let preimage =
            hex32(&r.preimage).ok_or_else(|| failed("the wallet returned no preimage"))?;
        Ok(Paid {
            preimage,
            fee_sat: r.fees_paid.unwrap_or(0).div_ceil(1000),
        })
    }
}

/// Pays by running a command (`lncli payinvoice` on regtest).
pub struct CommandSource {
    argv: Vec<String>,
}

#[async_trait::async_trait]
impl PaySource for CommandSource {
    async fn pay_invoice(&self, invoice: &str, _amount_sat: u64, max_fee_sat: u64) -> Result<Paid> {
        let mut argv: Vec<String> = self
            .argv
            .iter()
            .map(|a| {
                a.replace("{invoice}", invoice)
                    .replace("{max_fee}", &max_fee_sat.to_string())
            })
            .collect();
        if !self.argv.iter().any(|a| a.contains("{invoice}")) {
            argv.push(invoice.to_owned());
        }
        let (prog, args) = argv
            .split_first()
            .ok_or_else(|| Refusal::new(Code::NoPaySource, "The pay command is empty."))?;
        let mut child = tokio::process::Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| failed(format!("cannot run {prog}: {e}")))?;
        let mut out = Vec::new();
        if let Some(mut s) = child.stdout.take() {
            s.read_to_end(&mut out).await.map_err(failed)?;
        }
        let status = tokio::time::timeout(Duration::from_secs(120), child.wait())
            .await
            .map_err(|_| failed("the pay command timed out"))?
            .map_err(failed)?;
        if !status.success() {
            return Err(failed(format!("{prog} exited with {status}")));
        }
        parse_command_output(&out)
    }
}

/// Reads the JSON a pay command printed: `payment_preimage` (hex), and the
/// fee as `fee_sat`, `fee_msat`, or `payment_route.total_fees` /
/// `total_fees_msat`. A failed status is refused.
pub fn parse_command_output(out: &[u8]) -> Result<Paid> {
    let text = String::from_utf8_lossy(out);
    // lncli may print progress lines before the JSON object.
    let start = text
        .find('{')
        .ok_or_else(|| failed("the pay command printed no JSON"))?;
    let v: serde_json::Value = serde_json::Deserializer::from_str(&text[start..])
        .into_iter()
        .next()
        .ok_or_else(|| failed("the pay command printed no JSON"))?
        .map_err(failed)?;
    if let Some(s) = v.get("status").and_then(|s| s.as_str())
        && s != "SUCCEEDED"
    {
        return Err(failed(format!("status {s}")));
    }
    if let Some(e) = v.get("payment_error").and_then(|s| s.as_str())
        && !e.is_empty()
    {
        return Err(failed(e));
    }
    let preimage = v
        .get("payment_preimage")
        .and_then(|p| p.as_str())
        .and_then(hex32)
        .ok_or_else(|| failed("no payment_preimage in the output"))?;
    let num =
        |p: &serde_json::Value| -> Option<u64> { p.as_u64().or_else(|| p.as_str()?.parse().ok()) };
    let route = v.get("payment_route");
    let fee_sat = v
        .get("fee_msat")
        .and_then(num)
        .or_else(|| route?.get("total_fees_msat").and_then(num))
        .map(|m| m.div_ceil(1000))
        .or_else(|| v.get("fee_sat").and_then(num))
        .or_else(|| route?.get("total_fees").and_then(num))
        .unwrap_or(0);
    Ok(Paid { preimage, fee_sat })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lncli_output() {
        let p = parse_command_output(
            br#"Payment hash: aa
{"payment_hash":"aa","payment_preimage":"0101010101010101010101010101010101010101010101010101010101010101","status":"SUCCEEDED","fee_sat":"0","fee_msat":"1500"}"#,
        )
        .unwrap();
        assert_eq!(p.preimage, [1; 32]);
        assert_eq!(p.fee_sat, 2);
        assert!(parse_command_output(br#"{"status":"FAILED"}"#).is_err());
        assert!(parse_command_output(b"nope").is_err());
    }

    #[test]
    fn the_nwc_secret_is_never_printed() {
        let c = PaySourceConfig::Nwc {
            uri: "nostr+walletconnect://abc?secret=deadbeef".into(),
        };
        assert!(!format!("{c:?}").contains("deadbeef"));
        assert!(!c.describe().contains("deadbeef"));
    }
}
