//! BOLT 11 invoices, as the wallet checks them before paying.

use std::str::FromStr;
use std::time::Duration;

use cashu::Bolt11Invoice;
use cashu::lightning_invoice::Bolt11InvoiceDescriptionRef;

/// What the wallet reads from an invoice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// The amount, msat; `None` for an invoice without one.
    pub amount_msat: Option<u64>,
    /// The payment hash.
    pub payment_hash: [u8; 32],
    /// The description hash, when the invoice commits to one.
    pub description_hash: Option<[u8; 32]>,
    /// When it stops being payable, Unix seconds.
    pub expires_at: u64,
}

impl Invoice {
    /// Decodes and checks the signature of an invoice.
    pub fn decode(s: &str) -> Result<Self, String> {
        let inv = Bolt11Invoice::from_str(s).map_err(|e| format!("not a BOLT11 invoice: {e}"))?;
        let h: &[u8] = inv.payment_hash().as_ref();
        let payment_hash: [u8; 32] = h.try_into().map_err(|_| "bad payment hash")?;
        let description_hash = match inv.description() {
            Bolt11InvoiceDescriptionRef::Hash(d) => {
                let b: &[u8] = d.0.as_ref();
                Some(b.try_into().map_err(|_| "bad description hash")?)
            }
            Bolt11InvoiceDescriptionRef::Direct(_) => None,
        };
        let expires_at = inv.expires_at().unwrap_or(Duration::MAX).as_secs();
        Ok(Self {
            amount_msat: inv.amount_milli_satoshis(),
            payment_hash,
            description_hash,
            expires_at,
        })
    }

    /// The amount in whole sat; `None` for an invoice without an amount
    /// or one that is not a whole number of sat.
    #[must_use]
    pub fn amount_sat(&self) -> Option<u64> {
        self.amount_msat.filter(|m| m % 1000 == 0).map(|m| m / 1000)
    }
}
