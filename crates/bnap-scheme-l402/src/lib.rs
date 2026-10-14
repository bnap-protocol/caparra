//! Payment scheme for L402 (macaroon plus Lightning invoice).
//!
//! `httpauth:L402` is a class O value scheme (registry entry
//! `httpauth:L402`): the server mints a macaroon that commits to an
//! invoice's payment hash and embeds the offer, the client pays the invoice
//! and presents `macaroon:preimage`. It follows bLIP-26 as the open pull
//! request revision states it (ERRATA row 34) and Lightning Labs' macaroon
//! layout:
//!
//! - **Challenge** ([`Challenge`]): `L402 version="0", token="…",
//!   macaroon="…", invoice="…"`. Parsers accept the scheme names `L402` and
//!   `LSAT` and either parameter name.
//! - **Macaroon** ([`MacaroonKeys`]): identifier `version ‖ payment_hash ‖
//!   user_id`, first-party caveats `bnap_offer=<OfferID hex>` and
//!   `bnap_expires=<offer expires>`, root key derived from a secret only
//!   this scheme holds, so it is authenticated without state (draft-00 5.4).
//! - **Credential** ([`Token`]): `macaroon:preimage`, the native credential
//!   bytes and the BNAP credential body alike, in one canonical form.
//! - **Verification**: the macaroon is authentic, names this offer, and
//!   `SHA-256(preimage)` is its payment hash. The scheme's local ID is the
//!   payment hash, and it returns the `ln` rail reference
//!   `ln:<payment hash>`, so the gate's Lightning rail confirms the payment,
//!   its amount and its finality, and bnap-core computes the `RailId`. The
//!   value it claims is the pay entry's amount; admission counts at most
//!   what the rail confirmed (draft-00 7, ERRATA N3b-15).
//! - **Settlement**: nothing. L402 registers `refund = "none"`, so the
//!   socket gives it no change budget, and it signs nothing.
//!
//! Native credentials (a client that sends `Authorization: L402 …` and no
//! BNAP credential) come back through [`CredentialScheme::recover_native`]:
//! it authenticates the macaroon and returns the `OfferID` its caveat names,
//! and the gate runs the offer checks and builds the synthetic envelope of
//! draft-00 5.4 with `bnap_core::credential::native_context` and
//! `native_digest` over the same token bytes.
//!
//! The native artifact this scheme adds to an offer is the whole challenge
//! (kind `l402-macaroon`), so a client compares the `WWW-Authenticate`
//! value it got with the signed offer byte for byte (draft-00 9.3). The
//! invoice inside it comes from the gate's Lightning rail with the
//! `OfferID` as its description hash; give the scheme an
//! [`OfferInvoices`] so L402 and `payment:lightning/charge` share one
//! invoice per offer.

pub mod header;
pub mod invoices;
pub mod token;

use std::sync::Arc;

use bnap_core::credential::SchemePart;
use bnap_core::hash::sha256;
use bnap_core::ids::rail;
use bnap_core::limits::CLOCK_SKEW;
use bnap_plug::{
    CredentialScheme, Entry, FundingRail, NativeArtifact, NativeCredential, NativeCtx, OfferCtx,
    OfferRole, RailRef, SchemeError, SchemeOffer, Verified, VerifyCtx,
};

pub use header::{Challenge, HeaderError, authorization, credential_from_authorization};
pub use invoices::OfferInvoices;
pub use token::{Identifier, MacaroonKeys, Minted, Token, TokenError};

/// The registered scheme ID.
pub const SCHEME_ID: &str = "httpauth:L402";
/// The registry's label for this scheme's native artifact.
pub const NATIVE_KIND: &str = "l402-macaroon";
/// The only unit the scheme takes (registry `units`).
pub const UNIT: &str = "sat";

/// The L402 scheme plug.
pub struct L402 {
    keys: MacaroonKeys,
    rail: Arc<dyn FundingRail>,
}

impl std::fmt::Debug for L402 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L402")
            .field("keys", &self.keys)
            .field("rail", &self.rail.kind())
            .finish()
    }
}

impl L402 {
    /// The scheme with its macaroon keys and the Lightning rail it mints
    /// invoices on (an [`OfferInvoices`] shared with the gate's other
    /// Lightning schemes).
    #[must_use]
    pub fn new(keys: MacaroonKeys, rail: Arc<dyn FundingRail>) -> Self {
        Self { keys, rail }
    }

    /// The macaroon keys.
    #[must_use]
    pub fn keys(&self) -> &MacaroonKeys {
        &self.keys
    }

    /// Reads a body and checks its macaroon.
    fn open(&self, body: &[u8]) -> Result<(Token, Minted), SchemeError> {
        let token = Token::parse(body).map_err(|e| reject("MALFORMED", &e))?;
        let minted = self
            .keys
            .open(&token)
            .map_err(|e| reject("BAD_MACAROON", &e))?;
        Ok((token, minted))
    }
}

fn reject(code: &str, detail: &impl ToString) -> SchemeError {
    SchemeError::rejected(SCHEME_ID, code, detail.to_string())
}

fn unavailable(e: &impl ToString) -> SchemeError {
    SchemeError::Unavailable(e.to_string())
}

#[async_trait::async_trait]
impl CredentialScheme for L402 {
    fn id(&self) -> &str {
        SCHEME_ID
    }

    /// No params. Refuses a route-scope or metered offer, and any role but
    /// a pay entry in sat: class O needs an exact-scope offer (4.3), and
    /// L402 has neither atomic refund nor `upto` (7).
    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        match cx.role {
            OfferRole::Pay { unit, .. } if unit == UNIT && !cx.route_scope && !cx.metered => {
                Ok(SchemeOffer::default())
            }
            _ => Err(SchemeError::Unsupported),
        }
    }

    /// Mints the invoice (description hash = `OfferID`) and the macaroon,
    /// and returns the challenge as the `l402-macaroon` artifact. Refuses
    /// ([`SchemeError::Unavailable`]) an invoice that stays payable after
    /// the offer or the entry's quote expires (plus the 60 s skew): a
    /// client only sees the invoice's expiry, and a payment the gate then
    /// refuses STALE is not refunded.
    async fn native(&self, cx: &NativeCtx<'_>) -> Result<Option<NativeArtifact>, SchemeError> {
        if cx.entry.unit != UNIT {
            return Err(SchemeError::Unsupported);
        }
        let req = self
            .rail
            .request(cx.entry.amount, UNIT, cx.offer_id.0)
            .await
            .map_err(|e| unavailable(&e))?;
        if req.rail_kind != rail::LN || req.amount != cx.entry.amount || req.unit != UNIT {
            return Err(SchemeError::Unavailable(
                "the rail made another kind of payment request".into(),
            ));
        }
        // The gate takes a credential until the offer, or the entry's
        // quote, expires, with the skew (4.4 step 4). An invoice still
        // payable after that takes a payment the gate refuses STALE, and
        // L402 refunds nothing: fail closed rather than offer it.
        let deadline = cx.entry.effective_quote_expires(cx.expires).min(cx.expires);
        if req.expires > deadline.saturating_add(CLOCK_SKEW) {
            return Err(SchemeError::Unavailable(
                "the invoice outlives the offer: set the rail's invoice expiry \
                 to the offer lifetime or less"
                    .into(),
            ));
        }
        let hash: [u8; 32] = req.id.0.as_slice().try_into().map_err(|_| {
            SchemeError::Unavailable("an ln rail's PayId must be the payment hash".into())
        })?;
        let token = self
            .keys
            .mint(cx.offer_id, &hash, cx.expires)
            .map_err(|e| unavailable(&e))?;
        let challenge = Challenge {
            token,
            invoice: req.request,
        };
        Ok(Some(NativeArtifact {
            kind: NATIVE_KIND.to_owned(),
            data: challenge.to_header().into_bytes(),
        }))
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let Entry::Pay(entry) = cx.entry else {
            return Err(reject("NOT_PAY", &"L402 is a value scheme"));
        };
        if entry.unit != UNIT {
            return Err(reject("UNIT", &"L402 pays in sat"));
        }
        if !part.witness.is_empty() {
            return Err(reject("WITNESS", &"class O has no witness"));
        }
        let (token, minted) = self.open(&part.body)?;
        let offer = cx.offer;
        if minted.offer_id != offer.offer_id() || minted.expires != offer.fields().expires {
            return Err(reject(
                "OFFER_MISMATCH",
                &"the macaroon was minted for another offer",
            ));
        }
        let hash = minted.identifier.payment_hash;
        if sha256(token.preimage()) != hash {
            return Err(reject(
                "BAD_PREIMAGE",
                &"the preimage does not hash to the payment hash",
            ));
        }
        Ok(Verified {
            use_ids: vec![hash.to_vec()],
            rail_ids: vec![RailRef {
                kind: rail::LN.to_owned(),
                reference: rail::ln(&hash),
            }],
            value: entry.amount,
            quota_id: None,
        })
    }

    /// Authenticates the token's macaroon and returns the `OfferID` its
    /// caveat names; the gate looks the offer up in its cache of offers
    /// issued with natives. The clock is not checked here: the gate's offer
    /// checks (4.4) decide expiry, so a replay of a recorded outcome can
    /// still be answered (ERRATA N3b-22).
    async fn recover_native(
        &self,
        native: &[u8],
        _now: u64,
    ) -> Result<NativeCredential, SchemeError> {
        let (_, minted) = self.open(native)?;
        Ok(NativeCredential {
            offer_id: minted.offer_id,
            offer: None,
            part: SchemePart::new(SCHEME_ID, native.to_vec()),
        })
    }
}

#[cfg(test)]
mod tests;
