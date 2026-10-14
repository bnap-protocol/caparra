//! Attestation bodies the wallet signs over a credential's Context:
//! Web Bot Auth (`Ed25519`) and `DPoP` (ES256, a key registered with the
//! operator, no access token).
//!
//! The Context covers the scheme IDs but no body, so the bodies are signed
//! after the Context and before the Digest, which covers them (N8 notes).

use bnap_core::hash::Context;

use crate::error::{Code, Refusal, Result};
use crate::records::AttestKeys;
use crate::wallet::random_id;

fn failed(e: impl std::fmt::Display) -> Refusal {
    Refusal::new(Code::BadInput, format!("cannot sign the attestation: {e}"))
}

/// The attest body of `scheme` for this request.
///
/// A Web Bot Auth signature lasts until the offer's expiry plus
/// `pending_timeout` and a clock skew, so a replay that fetches a missed
/// receipt still verifies (N8-3), and never more than 24 hours.
#[allow(clippy::too_many_arguments)]
pub fn body(
    scheme: &str,
    keys: &AttestKeys,
    ctx: &Context,
    url: &url::Url,
    method: &str,
    now: u64,
    offer_expires: u64,
    pending_timeout: u64,
) -> Result<Vec<u8>> {
    match scheme {
        bnap_scheme_webbotauth::ID => {
            let key = ed25519_dalek::SigningKey::from_bytes(&keys.wba);
            let authority = match url.port() {
                Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
                None => url.host_str().unwrap_or("").to_owned(),
            };
            let expires = offer_expires
                .saturating_add(pending_timeout)
                .saturating_add(120)
                .min(now + bnap_scheme_webbotauth::DEFAULT_MAX_LIFETIME);
            let b = bnap_scheme_webbotauth::client::sign(
                &key,
                &bnap_scheme_webbotauth::client::SignParams {
                    authority: &authority,
                    context: ctx,
                    agent: keys.agent.as_deref(),
                    created: now,
                    expires,
                    nonce: None,
                },
            )
            .map_err(failed)?;
            Ok(b.to_bytes())
        }
        bnap_scheme_dpop::DPOP => {
            let key = bnap_scheme_dpop::client::ProofKey::es256(&keys.dpop)
                .ok_or_else(|| failed("the DPoP key is not valid"))?;
            let mut htu = url.clone();
            htu.set_query(None);
            htu.set_fragment(None);
            let jti = random_id();
            let proof = bnap_scheme_dpop::client::sign_proof(
                &key,
                &bnap_scheme_dpop::client::ProofClaims {
                    context: ctx,
                    htm: method,
                    htu: htu.as_str(),
                    iat: now,
                    jti: &jti,
                    access_token: None,
                },
            );
            Ok(bnap_scheme_dpop::client::body(&proof, None))
        }
        other => Err(failed(format!("the wallet cannot sign {other}"))),
    }
}
