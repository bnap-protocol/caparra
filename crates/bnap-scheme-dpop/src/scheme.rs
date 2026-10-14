//! The two plugs: [`DpopScheme`] (`httpauth:DPoP`, class A) and
//! [`BearerScheme`] (`httpauth:Bearer`, class none).

use std::sync::Arc;

use bnap_core::credential::SchemePart;
use bnap_core::hash::sha256;
use bnap_plug::{
    CredentialScheme, Entry, OfferCtx, OfferRole, SchemeError, SchemeOffer, Verified, VerifyCtx,
};

use crate::authority::{Authority, TokenStatus};
use crate::body::{BearerBody, DpopBody};
use crate::codes;
use crate::proof::{self, ProofCheck};

/// The scheme ID of OAuth access tokens and API keys with `DPoP`.
pub const DPOP: &str = "httpauth:DPoP";

/// The scheme ID of the same tokens without `DPoP`.
pub const BEARER: &str = "httpauth:Bearer";

fn reject(scheme: &str, code: &str, detail: impl Into<String>) -> SchemeError {
    SchemeError::rejected(scheme, code, detail)
}

/// Both schemes are attestations: a pay entry, a part of another scheme or
/// a witness (class A and none have none) is refused.
fn attest_part(scheme: &str, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<(), SchemeError> {
    match cx.entry {
        Entry::Attest(e) if e.scheme == scheme => {}
        _ => {
            return Err(reject(
                scheme,
                codes::NOT_AN_ATTESTATION,
                "the scheme is an attestation and has no pay entry",
            ));
        }
    }
    if part.scheme != scheme {
        return Err(reject(scheme, codes::BAD_BODY, "a part of another scheme"));
    }
    if !part.witness.is_empty() {
        return Err(reject(
            scheme,
            codes::BAD_BODY,
            "a witness, which only class S schemes have",
        ));
    }
    Ok(())
}

fn attest_offer(cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
    match cx.role {
        OfferRole::Attest { .. } => Ok(SchemeOffer::default()),
        OfferRole::Pay { .. } => Err(SchemeError::Unsupported),
    }
}

fn unavailable(e: &crate::authority::AuthorityError) -> SchemeError {
    SchemeError::Unavailable(e.to_string())
}

/// `httpauth:DPoP`: an OAuth access token, or a registered key, with a `DPoP`
/// proof (RFC 9449) that carries the Context in its `bnap_ctx` claim.
///
/// `verify` checks the proof ([`proof::check`]), then asks the
/// [`Authority`]:
///
/// - with an access token, the proof's `ath` must be the token's hash, the
///   token must be active and bound (`cnf.jkt`) to the proof's key: a token
///   bound to no key is a bearer token, class none, and is refused here
///   (`UNBOUND_TOKEN`); present it as `httpauth:Bearer` instead;
/// - without one, the proof carries no `ath` and its key must be one the
///   operator registered.
///
/// It returns one local ID, the key's JWK SHA-256 thumbprint (RFC 7638),
/// which is also the quota identity (`quota_id`), as the registry entry
/// says. The registry sets the use model (`reusable`) and the class (A);
/// effects come from the offer.
pub struct DpopScheme {
    authority: Arc<dyn Authority>,
    max_age: Option<u64>,
}

impl DpopScheme {
    /// A scheme that checks tokens and keys with `authority`.
    #[must_use]
    pub fn new(authority: Arc<dyn Authority>) -> Self {
        Self {
            authority,
            max_age: None,
        }
    }

    /// Also refuses proofs whose `iat` is more than `seconds` (plus a
    /// clock skew) in the past. See [`proof`] for why the default has no
    /// such limit.
    #[must_use]
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }
}

impl std::fmt::Debug for DpopScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopScheme")
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl CredentialScheme for DpopScheme {
    fn id(&self) -> &str {
        DPOP
    }

    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        attest_offer(cx)
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        attest_part(DPOP, part, cx)?;
        let body = DpopBody::parse(&part.body)
            .map_err(|e| reject(DPOP, codes::BAD_BODY, e.to_string()))?;
        let token = body.access_token.as_deref();
        let checked = proof::check(
            body.proof.as_bytes(),
            &ProofCheck {
                context: cx.context,
                now: cx.now,
                max_age: self.max_age,
                access_token: token,
            },
        )
        .map_err(|e| reject(DPOP, e.code(), e.to_string()))?;
        let jkt = checked.jkt;
        match token {
            Some(t) => match self
                .authority
                .check_token(t, cx.now)
                .await
                .map_err(|e| unavailable(&e))?
            {
                TokenStatus::Inactive => {
                    return Err(reject(
                        DPOP,
                        codes::INVALID_TOKEN,
                        "the token is not active",
                    ));
                }
                TokenStatus::Active(info) => match info.jkt {
                    None => {
                        return Err(reject(
                            DPOP,
                            codes::UNBOUND_TOKEN,
                            "a bearer token is class none: present it as httpauth:Bearer",
                        ));
                    }
                    Some(bound) if bound != jkt => {
                        return Err(reject(
                            DPOP,
                            codes::KEY_MISMATCH,
                            "the token is bound to another key",
                        ));
                    }
                    Some(_) => {}
                },
            },
            None => {
                if !self
                    .authority
                    .check_key(&jkt, cx.now)
                    .await
                    .map_err(|e| unavailable(&e))?
                {
                    return Err(reject(
                        DPOP,
                        codes::UNKNOWN_KEY,
                        "no token, and the key is not registered",
                    ));
                }
            }
        }
        Ok(Verified {
            use_ids: vec![jkt.0.to_vec()],
            rail_ids: Vec::new(),
            value: 0,
            quota_id: Some(jkt.0.to_vec()),
        })
    }
}

/// `httpauth:Bearer`: the same OAuth access tokens and API keys without
/// `DPoP`. Class none in the registry, so the socket never lets it waive,
/// discount or carry a quota (draft-00 section 7, enforced in bnap-core);
/// it can only satisfy a `required` attestation.
///
/// `verify` asks the [`Authority`] whether the token is active and refuses
/// a token bound to a `DPoP` key (`DPOP_BOUND_TOKEN`): sent without its
/// proof, such a token is a downgrade (RFC 9449 section 7.1). It returns
/// one local ID, SHA-256 of the token, and no quota identity, as the
/// registry entry says.
pub struct BearerScheme {
    authority: Arc<dyn Authority>,
}

impl BearerScheme {
    /// A scheme that checks tokens with `authority`.
    #[must_use]
    pub fn new(authority: Arc<dyn Authority>) -> Self {
        Self { authority }
    }
}

impl std::fmt::Debug for BearerScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerScheme").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl CredentialScheme for BearerScheme {
    fn id(&self) -> &str {
        BEARER
    }

    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        attest_offer(cx)
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        attest_part(BEARER, part, cx)?;
        let body = BearerBody::parse(&part.body)
            .map_err(|e| reject(BEARER, codes::BAD_BODY, e.to_string()))?;
        match self
            .authority
            .check_token(&body.token, cx.now)
            .await
            .map_err(|e| unavailable(&e))?
        {
            TokenStatus::Inactive => Err(reject(
                BEARER,
                codes::INVALID_TOKEN,
                "the token is not active",
            )),
            TokenStatus::Active(info) if info.jkt.is_some() => Err(reject(
                BEARER,
                codes::DPOP_BOUND_TOKEN,
                "a DPoP-bound token needs its proof: present it as httpauth:DPoP",
            )),
            TokenStatus::Active(_) => Ok(Verified {
                use_ids: vec![sha256(body.token.as_bytes()).to_vec()],
                rail_ids: Vec::new(),
                value: 0,
                quota_id: None,
            }),
        }
    }
}
