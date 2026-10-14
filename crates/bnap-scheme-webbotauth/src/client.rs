//! The agent side: signing a request's Context as a Web Bot Auth signature
//! and putting the three fields in the `httpsig:web-bot-auth` attest body.
//!
//! The signature covers `@authority`, `bnap-context` (the credential's
//! Context, base64url, as the `BNAP-Context` field carries it, draft-00
//! 10.2) and, with an agent URL, the `Signature-Agent` member keyed to the
//! label (draft-ietf-webbotauth-httpsig-protocol-00 5.2.1), with the
//! parameters `created`, `expires`, `keyid` (the key's JWK thumbprint) and
//! `tag="web-bot-auth"`. Every field is written in its strict
//! structured-field serialization, the only form the scheme accepts.
//!
//! Choose `expires` with replays in mind: a client fetches a receipt it
//! missed by sending the same credential again (draft-00 6.4), the gate
//! verifies it again, and a signature that has expired by then no longer
//! verifies, so the replay does not find its outcome.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::hash::Context;
use ed25519_dalek::Signer as _;
use sfv::SerializeValue as _;

use crate::body::WbaBody;
use crate::directory::keyid;
use crate::scheme::{CONTEXT_FIELD, TAG};

/// Why a signature could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot sign: {0}")]
pub struct SignError(pub String);

/// What one signature covers.
#[derive(Debug, Clone, Copy)]
pub struct SignParams<'a> {
    /// The gate's authority (`@authority`): host, and port when not the
    /// default.
    pub authority: &'a str,
    /// The Context of the credential the signature goes in.
    pub context: &'a Context,
    /// The agent's `https` URL for `Signature-Agent`, if it publishes one.
    pub agent: Option<&'a str>,
    /// The signature label, such as `sig1`.
    pub label: &'a str,
    /// `created`, Unix seconds.
    pub created: u64,
    /// `expires`, Unix seconds.
    pub expires: u64,
    /// `nonce`, if any.
    pub nonce: Option<&'a str>,
}

fn sfv_string(s: &str) -> Result<sfv::BareItem, SignError> {
    sfv::String::from_string(s.to_owned())
        .map(sfv::BareItem::String)
        .map_err(|(e, _)| SignError(e.to_string()))
}

fn sfv_key(s: &str) -> Result<sfv::Key, SignError> {
    sfv::Key::from_string(s.to_owned()).map_err(|(e, _)| SignError(e.to_string()))
}

fn sfv_int(v: u64) -> Result<sfv::BareItem, SignError> {
    sfv::BareItem::try_from(v).map_err(|e| SignError(e.to_string()))
}

fn component(name: &str, key: Option<&str>) -> Result<sfv::Item, SignError> {
    let mut params = sfv::Parameters::new();
    if let Some(k) = key {
        params.insert(sfv_key("key")?, sfv_string(k)?);
    }
    Ok(sfv::Item::with_params(sfv_string(name)?, params))
}

/// Signs `p` with `key` and returns the attest body.
pub fn sign(key: &ed25519_dalek::SigningKey, p: &SignParams<'_>) -> Result<WbaBody, SignError> {
    let context = URL_SAFE_NO_PAD.encode(p.context.0);
    let mut items = vec![component("@authority", None)?, component(CONTEXT_FIELD, None)?];
    let mut values = vec![p.authority.to_ascii_lowercase(), context];
    let mut agent_field = None;
    if let Some(url) = p.agent {
        let member = sfv::Item::new(sfv_string(url)?);
        let mut d = sfv::Dictionary::new();
        d.insert(sfv_key(p.label)?, sfv::ListEntry::Item(member.clone()));
        agent_field = d.serialize_value();
        items.push(component("signature-agent", Some(p.label))?);
        values.push(member.serialize_value());
    }
    let mut params = sfv::Parameters::new();
    params.insert(sfv_key("created")?, sfv_int(p.created)?);
    params.insert(sfv_key("expires")?, sfv_int(p.expires)?);
    params.insert(
        sfv_key("keyid")?,
        sfv_string(&keyid(&key.verifying_key().to_bytes()))?,
    );
    if let Some(n) = p.nonce {
        params.insert(sfv_key("nonce")?, sfv_string(n)?);
    }
    params.insert(sfv_key("tag")?, sfv_string(TAG)?);
    let inner = sfv::InnerList::with_params(items.clone(), params);
    let signature_params = vec![sfv::ListEntry::InnerList(inner.clone())]
        .serialize_value()
        .ok_or_else(|| SignError("empty signature parameters".into()))?;

    // The signature base of RFC 9421 section 2.5.
    let mut base = String::new();
    for (item, value) in items.iter().zip(&values) {
        let _ = writeln!(base, "{}: {value}", item.serialize_value());
    }
    let _ = write!(base, "\"@signature-params\": {signature_params}");
    let sig = key.sign(base.as_bytes()).to_bytes().to_vec();

    let label = sfv_key(p.label)?;
    let mut input = sfv::Dictionary::new();
    input.insert(label.clone(), sfv::ListEntry::InnerList(inner));
    let mut signature = sfv::Dictionary::new();
    signature.insert(
        label,
        sfv::ListEntry::Item(sfv::Item::new(sfv::BareItem::ByteSequence(sig))),
    );
    Ok(WbaBody {
        signature: signature
            .serialize_value()
            .ok_or_else(|| SignError("empty Signature".into()))?,
        signature_input: input
            .serialize_value()
            .ok_or_else(|| SignError("empty Signature-Input".into()))?,
        signature_agent: agent_field,
    })
}
