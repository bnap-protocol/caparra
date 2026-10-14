//! Payment scheme for the Machine Payments Protocol (MPP).
//!
//! This crate registers MPP's Lightning charge as the class O value scheme
//! `payment:lightning/charge` (registry entry of that name): the `Payment`
//! HTTP authentication scheme of draft-httpauth-payment-01 with the
//! `lightning` method and `charge` intent of draft-lightning-charge-00.
//!
//! - **Challenge** ([`Challenge`]): `Payment id="…", realm="…",
//!   method="lightning", intent="charge", request="…", expires="…",
//!   opaque="…"`. `request` is `b64u(JCS({amount, currency: "sat",
//!   methodDetails: {invoice, network, paymentHash}}))`; `opaque` is
//!   `b64u(JCS({"bnap_offer": hex(OfferID)}))`; `id` is the HMAC-SHA256 of
//!   the pipe-joined fields (5.1.2.1.1), so it binds the invoice, the
//!   amount and the offer, and the gate checks a credential without state
//!   (draft-00 5.4).
//! - **Credential** ([`Credential`]): `b64u(JCS({challenge, payload:
//!   {preimage}}))`, the value of `Authorization: Payment …`. It is the
//!   native credential bytes and the BNAP credential body alike, read in
//!   one canonical form.
//! - **Verification**: the echoed challenge is one this gate issued (its
//!   id verifies under a held secret, realm, method and intent match), its
//!   `opaque` names this offer, its amount is the pay entry's, and
//!   `SHA-256(preimage)` is its payment hash. The local ID is the payment
//!   hash and the rail reference `ln:<payment hash>`, the same `RailId` as
//!   L402's for the same payment, so one payment admits one action whichever
//!   scheme presents it (draft-00 6.1).
//! - **Settlement**: on OK, the `scheme_result` is the `Payment-Receipt`
//!   value ([`Receipt`], reference = payment hash), which the carrier sends
//!   next to `BNAP-Receipt` (ERRATA row 33). The registry gives this scheme
//!   `refund = "none"`, so it has no change budget and signs nothing.
//!
//! The `mpp` crate is not used: its core pulls `serde_json` with
//! `preserve_order`, which feature unification would turn on for every
//! crate in the workspace, and it has no `lightning` method. What this
//! scheme needs of the core (the HMAC binding, the auth-params and the
//! JCS objects) is small and lives here.

pub mod challenge;
pub mod json;
pub mod lightning;
pub mod time;

use std::sync::Arc;

use bnap_core::credential::SchemePart;
use bnap_core::hash::{OfferId, sha256};
use bnap_core::ids::rail;
use bnap_core::response::Status;
use bnap_plug::{
    CappedSigner, CredentialScheme, Entry, FundingRail, NativeArtifact, NativeCredential,
    NativeCtx, OfferCtx, OfferRole, RailRef, SchemeError, SchemeOffer, SettleCtx, Verified,
    VerifyCtx,
};
use serde_json::json;

pub use challenge::{Challenge, authorization, credential_from_authorization};
pub use lightning::{ChargeRequest, Credential, INTENT, METHOD, Network, Receipt};

/// The registered scheme ID.
pub const SCHEME_ID: &str = "payment:lightning/charge";
/// The registry's label for this scheme's native artifact.
pub const NATIVE_KIND: &str = "mpp-challenge";
/// The only unit the scheme takes (registry `units`).
pub const UNIT: &str = "sat";
/// The `opaque` member that carries the `OfferID`.
pub const OFFER_MEMBER: &str = "bnap_offer";

/// Why a Payment object could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MppError {
    /// Not a `Payment` field value.
    #[error("not a Payment field value")]
    NotPayment,
    /// An object or parameter is not in its canonical form.
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// The secrets challenge IDs are bound under: the current one, and retired
/// ones still accepted until every offer issued under them has expired.
#[derive(Clone)]
pub struct ChallengeKeys {
    current: Vec<u8>,
    retired: Vec<Vec<u8>>,
}

impl std::fmt::Debug for ChallengeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeKeys")
            .field("retired", &self.retired.len())
            .finish_non_exhaustive()
    }
}

impl ChallengeKeys {
    /// Keys with one current secret of at least 32 bytes (5.1.2.1.1 asks
    /// for a server secret; this scheme refuses a shorter one). The secret
    /// MUST be used for nothing else.
    pub fn new(current: impl Into<Vec<u8>>) -> Result<Self, MppError> {
        let current = current.into();
        if current.len() < 32 {
            return Err(MppError::Malformed("secret shorter than 32 bytes"));
        }
        Ok(Self {
            current,
            retired: Vec::new(),
        })
    }

    /// Adds retired secrets, still accepted when checking.
    #[must_use]
    pub fn with_retired(mut self, retired: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.retired.extend(retired);
        self
    }

    /// Binds `c` under the current secret.
    #[must_use]
    pub fn bind(&self, c: Challenge) -> Challenge {
        c.bound(&self.current)
    }

    /// Whether `c`'s id verifies under a held secret.
    #[must_use]
    pub fn verify(&self, c: &Challenge) -> bool {
        std::iter::once(&self.current)
            .chain(&self.retired)
            .any(|k| c.verify_id(k))
    }
}

/// The `payment:lightning/charge` scheme plug.
pub struct LightningCharge {
    keys: ChallengeKeys,
    realm: String,
    network: Network,
    rail: Arc<dyn FundingRail>,
}

impl std::fmt::Debug for LightningCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightningCharge")
            .field("keys", &self.keys)
            .field("realm", &self.realm)
            .field("network", &self.network)
            .field("rail", &self.rail.kind())
            .finish()
    }
}

fn reject(code: &str, detail: &impl ToString) -> SchemeError {
    SchemeError::rejected(SCHEME_ID, code, detail.to_string())
}

fn unavailable(detail: impl Into<String>) -> SchemeError {
    SchemeError::Unavailable(detail.into())
}

impl LightningCharge {
    /// The scheme with its challenge keys, the realm it issues challenges
    /// for (the origin's host), the network of its Lightning rail, and that
    /// rail (an `OfferInvoices` shared with the gate's other Lightning
    /// schemes, so one offer has one invoice). A realm holding `"`, `\` or
    /// a control character is refused.
    pub fn new(
        keys: ChallengeKeys,
        realm: impl Into<String>,
        network: Network,
        rail: Arc<dyn FundingRail>,
    ) -> Result<Self, MppError> {
        let realm = realm.into();
        if realm.is_empty()
            || realm
                .chars()
                .any(|c| c == '"' || c == '\\' || c.is_control())
        {
            return Err(MppError::Malformed("realm"));
        }
        Ok(Self {
            keys,
            realm,
            network,
            rail,
        })
    }

    /// The challenge keys.
    #[must_use]
    pub fn keys(&self) -> &ChallengeKeys {
        &self.keys
    }

    /// The bound challenge for an invoice under an offer: what the native
    /// artifact carries.
    #[must_use]
    pub fn challenge(
        &self,
        offer_id: &OfferId,
        expires: u64,
        request: &ChargeRequest,
    ) -> Challenge {
        self.keys.bind(Challenge {
            id: String::new(),
            realm: self.realm.clone(),
            method: METHOD.to_owned(),
            intent: INTENT.to_owned(),
            request: request.encode(),
            expires: Some(time::rfc3339(expires)),
            opaque: Some(json::encode(
                &json!({ OFFER_MEMBER: hex::encode(offer_id.0) }),
            )),
            ..Challenge::default()
        })
    }

    /// Reads a credential and checks that its challenge is one this gate
    /// issued: id, realm, method, intent, and no field this gate never sets.
    /// Returns the credential and the `OfferID` its `opaque` names.
    fn open(&self, body: &[u8]) -> Result<(Credential, OfferId), SchemeError> {
        let cred = Credential::decode(body).map_err(|e| reject("MALFORMED", &e))?;
        let c = &cred.challenge;
        let issued_here = c.realm == self.realm
            && c.method == METHOD
            && c.intent == INTENT
            && c.digest.is_none()
            && c.header.is_none()
            && c.description.is_none()
            && self.keys.verify(c);
        if !issued_here {
            return Err(reject(
                "UNKNOWN_CHALLENGE",
                &"the challenge was not issued by this gate",
            ));
        }
        let opaque = c
            .opaque
            .as_deref()
            .ok_or_else(|| reject("UNKNOWN_CHALLENGE", &"no opaque"))?;
        let v = json::decode(opaque.as_bytes()).map_err(|e| reject("MALFORMED", &e))?;
        let m = json::object(&v, &[OFFER_MEMBER], "opaque").map_err(|e| reject("MALFORMED", &e))?;
        let hex = json::required(m, OFFER_MEMBER, "opaque.bnap_offer")
            .and_then(|s| json::hex32(s, "opaque.bnap_offer"))
            .map_err(|e| reject("MALFORMED", &e))?;
        Ok((cred, OfferId(hex)))
    }
}

#[async_trait::async_trait]
impl CredentialScheme for LightningCharge {
    fn id(&self) -> &str {
        SCHEME_ID
    }

    /// No params. Refuses a route-scope or metered offer, and any role but
    /// a pay entry in sat: class O needs an exact-scope offer (4.3), and
    /// the scheme has neither atomic refund nor `upto` (7).
    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        match cx.role {
            OfferRole::Pay { unit, .. } if unit == UNIT && !cx.route_scope && !cx.metered => {
                Ok(SchemeOffer::default())
            }
            _ => Err(SchemeError::Unsupported),
        }
    }

    /// Mints the invoice (description hash = `OfferID`) and returns the
    /// bound challenge as the `mpp-challenge` artifact.
    async fn native(&self, cx: &NativeCtx<'_>) -> Result<Option<NativeArtifact>, SchemeError> {
        if cx.entry.unit != UNIT {
            return Err(SchemeError::Unsupported);
        }
        let req = self
            .rail
            .request(cx.entry.amount, UNIT, cx.offer_id.0)
            .await
            .map_err(|e| unavailable(e.to_string()))?;
        if req.rail_kind != rail::LN || req.amount != cx.entry.amount || req.unit != UNIT {
            return Err(unavailable("the rail made another kind of payment request"));
        }
        let payment_hash: [u8; 32] = req
            .id
            .0
            .as_slice()
            .try_into()
            .map_err(|_| unavailable("an ln rail's PayId must be the payment hash"))?;
        let request = ChargeRequest {
            amount: cx.entry.amount,
            invoice: req.request,
            payment_hash,
            network: self.network,
            description: None,
        };
        let challenge = self.challenge(cx.offer_id, cx.expires, &request);
        Ok(Some(NativeArtifact {
            kind: NATIVE_KIND.to_owned(),
            data: challenge.to_header().into_bytes(),
        }))
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let Entry::Pay(entry) = cx.entry else {
            return Err(reject("NOT_PAY", &"a value scheme"));
        };
        if entry.unit != UNIT {
            return Err(reject("UNIT", &"the lightning method pays in sat"));
        }
        if !part.witness.is_empty() {
            return Err(reject("WITNESS", &"class O has no witness"));
        }
        let (cred, offer_id) = self.open(&part.body)?;
        if cred.source.is_some() {
            // draft-00 5.1: a body may hold no byte the scheme does not
            // verify, and nothing verifies a payer identifier.
            return Err(reject("SOURCE", &"an unverified source is not accepted"));
        }
        let offer = cx.offer;
        if offer_id != offer.offer_id()
            || cred.challenge.expires.as_deref() != Some(&*time::rfc3339(offer.fields().expires))
        {
            return Err(reject(
                "OFFER_MISMATCH",
                &"the challenge was issued for another offer",
            ));
        }
        let request =
            ChargeRequest::decode(&cred.challenge.request).map_err(|e| reject("MALFORMED", &e))?;
        if request.amount != entry.amount || request.network != self.network {
            return Err(reject(
                "AMOUNT",
                &"the challenge is for another amount or network",
            ));
        }
        let hash = request.payment_hash;
        if sha256(&cred.preimage) != hash {
            return Err(reject(
                "INVALID_PREIMAGE",
                &"the preimage does not hash to the payment hash",
            ));
        }
        Ok(Verified {
            use_ids: vec![hash.to_vec()],
            rail_ids: vec![RailRef {
                kind: rail::LN.to_owned(),
                reference: rail::ln(&hash),
            }],
            value: request.amount,
            quota_id: None,
        })
    }

    /// On OK, the `Payment-Receipt` value, timestamped with the settle's
    /// clock; on FAILED, nothing. Signs nothing.
    async fn settle(
        &self,
        part: &SchemePart,
        verified: &Verified,
        cx: &SettleCtx<'_>,
        _signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        if cx.status != Status::Ok {
            return Ok(None);
        }
        let cred = Credential::decode(&part.body).map_err(|e| reject("MALFORMED", &e))?;
        let payment_hash: [u8; 32] = verified
            .use_ids
            .first()
            .and_then(|h| h.as_slice().try_into().ok())
            .ok_or_else(|| reject("MALFORMED", &"no payment hash"))?;
        let receipt = Receipt {
            challenge_id: cred.challenge.id,
            payment_hash,
            timestamp: cx.now,
        };
        Ok(Some(receipt.encode().into_bytes()))
    }

    /// Checks the challenge's id and returns the `OfferID` its `opaque`
    /// names; the gate looks the offer up in its cache of offers issued
    /// with natives. The clock is not checked here: the gate's offer checks
    /// (4.4) decide expiry (ERRATA N3b-22).
    async fn recover_native(
        &self,
        native: &[u8],
        _now: u64,
    ) -> Result<NativeCredential, SchemeError> {
        let (_, offer_id) = self.open(native)?;
        Ok(NativeCredential {
            offer_id,
            offer: None,
            part: SchemePart::new(SCHEME_ID, native.to_vec()),
        })
    }
}

#[cfg(test)]
mod tests;
