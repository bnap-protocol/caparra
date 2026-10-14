//! [`WebBotAuthScheme`]: the `httpsig:web-bot-auth` plug.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::credential::SchemePart;
use bnap_core::limits::CLOCK_SKEW;
use bnap_plug::{
    CredentialScheme, Entry, OfferCtx, OfferRole, SchemeError, SchemeOffer, Verified, VerifyCtx,
};
use sfv::SerializeValue as _;
use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::SignedMessage;

use crate::body::WbaBody;
use crate::codes;
use crate::directory::{AgentType, KeyDirectory, KeyQuery, SignatureAgent, thumbprint};

/// The scheme ID.
pub const ID: &str = "httpsig:web-bot-auth";

/// The HTTP field the Context travels in (draft-00 10.2), as a covered
/// component name.
pub const CONTEXT_FIELD: &str = "bnap-context";

/// The `tag` every Web Bot Auth signature carries.
pub const TAG: &str = "web-bot-auth";

/// The longest signature lifetime (`expires - created`) accepted by
/// default: 24 hours, the bound the draft recommends to agents (section
/// 5.2).
pub const DEFAULT_MAX_LIFETIME: u64 = 86_400;

fn reject(code: &str, detail: impl Into<String>) -> SchemeError {
    SchemeError::rejected(ID, code, detail)
}

/// A component this scheme lets a signature cover.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    /// `"@authority"`: the gate's own authority, from its configuration.
    Authority,
    /// `"bnap-context"`: the Context the gate computed, in base64url.
    Context,
    /// `"signature-agent"`, the whole field (the legacy String form).
    AgentField,
    /// `"signature-agent";key="<label>"`, the member keyed to the label.
    AgentMember,
}

/// What [`parse`] read from a canonical body.
#[derive(Debug)]
struct Parsed {
    label: String,
    components: Vec<Component>,
    created: u64,
    expires: u64,
    keyid: String,
    /// The member value the signature base names for the agent, serialized
    /// strictly (RFC 9421 2.1.2), when the member is covered.
    agent_member: Option<String>,
    /// The agent to resolve the key at, if the request names a usable one.
    agent: Option<SignatureAgent>,
}

/// One dictionary member, as a canonical field holds it.
fn single_member(field: &str, what: &str) -> Result<(String, sfv::ListEntry), SchemeError> {
    let d = sfv::Parser::new(field)
        .parse_dictionary()
        .map_err(|e| reject(codes::BAD_BODY, format!("{what}: {e}")))?;
    if d.serialize_value().as_deref() != Some(field) {
        return Err(reject(
            codes::BAD_BODY,
            format!("{what} is not in its strict serialization"),
        ));
    }
    if d.len() != 1 {
        return Err(reject(
            codes::BAD_BODY,
            format!("{what} must hold exactly one signature"),
        ));
    }
    let (k, v) = d.into_iter().next().unwrap_or_else(|| unreachable!());
    Ok((k.as_str().to_owned(), v))
}

fn string_param<'a>(p: &'a sfv::Parameters, name: &str) -> Result<Option<&'a str>, SchemeError> {
    match p.get(name) {
        None => Ok(None),
        Some(v) => v.as_string().map(|s| Some(s.as_str())).ok_or_else(|| {
            reject(
                codes::BAD_SIGNATURE_INPUT,
                format!("{name} is not a String"),
            )
        }),
    }
}

fn time_param(p: &sfv::Parameters, name: &str) -> Result<u64, SchemeError> {
    let v = p
        .get(name)
        .ok_or_else(|| reject(codes::BAD_SIGNATURE_INPUT, format!("{name} is missing")))?;
    v.as_integer()
        .and_then(|i| u64::try_from(i64::from(i)).ok())
        .ok_or_else(|| {
            reject(
                codes::BAD_SIGNATURE_INPUT,
                format!("{name} is not a non-negative Integer"),
            )
        })
}

/// Reads the covered components: only `@authority`, `bnap-context` and the
/// agent, each once, the first two always.
fn components(items: &[sfv::Item], label: &str) -> Result<Vec<Component>, SchemeError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let name = item.bare_item.as_string().ok_or_else(|| {
            reject(codes::BAD_SIGNATURE_INPUT, "a component that is not a String")
        })?;
        let c = match (name.as_str(), item.params.len()) {
            ("@authority", 0) => Component::Authority,
            (CONTEXT_FIELD, 0) => Component::Context,
            ("signature-agent", 0) => Component::AgentField,
            ("signature-agent", 1)
                if item
                    .params
                    .get("key")
                    .and_then(|k| k.as_string())
                    .is_some_and(|k| k.as_str() == label) =>
            {
                Component::AgentMember
            }
            (other, _) => {
                return Err(reject(
                    codes::UNSUPPORTED_COMPONENT,
                    format!(
                        "{other:?} with these parameters cannot be built from the Context and the gate's authority"
                    ),
                ));
            }
        };
        let agent = |c: &Component| matches!(c, Component::AgentField | Component::AgentMember);
        if out.contains(&c) || (agent(&c) && out.iter().any(agent)) {
            return Err(reject(codes::BAD_SIGNATURE_INPUT, "a component named twice"));
        }
        out.push(c);
    }
    for (needed, name) in [
        (Component::Authority, "@authority"),
        (Component::Context, CONTEXT_FIELD),
    ] {
        if !out.contains(&needed) {
            return Err(reject(
                codes::MISSING_COMPONENT,
                format!("the signature does not cover {name}"),
            ));
        }
    }
    Ok(out)
}

/// Reads the agent the signature covers: the member keyed to the label, or
/// the legacy String form of the whole field.
fn agent(
    field: &str,
    covered: &Component,
    label: &str,
) -> Result<(Option<String>, Option<SignatureAgent>), SchemeError> {
    let bad = |d: &str| reject(codes::BAD_AGENT, d.to_owned());
    let (item, member) = match covered {
        Component::AgentMember => {
            let (key, entry) = single_member(field, "Signature-Agent")?;
            if key != label {
                return Err(bad("the Signature-Agent member is not keyed to the label"));
            }
            let sfv::ListEntry::Item(item) = entry else {
                return Err(bad("the Signature-Agent member is not an Item"));
            };
            let member = item.serialize_value();
            (item, Some(member))
        }
        _ => {
            let item = sfv::Parser::new(field)
                .parse_item()
                .map_err(|e| bad(&format!("Signature-Agent: {e}")))?;
            if item.serialize_value() != field {
                return Err(bad("Signature-Agent is not in its strict serialization"));
            }
            (item, None)
        }
    };
    let url = item
        .bare_item
        .as_string()
        .ok_or_else(|| bad("the agent is not a String"))?
        .as_str();
    if !url.starts_with("https://") || url.len() == "https://".len() {
        return Err(bad("the agent URL is not https"));
    }
    let kind = match item.params.get("type") {
        None => Some(AgentType::Directory),
        Some(t) => t
            .as_token()
            .ok_or_else(|| bad("type is not a Token"))
            .map(|t| AgentType::from_token(t.as_str()))?,
    };
    // A member of a type this verifier does not know, or a directory member
    // that is not an origin, MUST be ignored (sections 5.2.1, 5.5): the
    // signature then stands on a key the verifier holds.
    let usable = kind.filter(|k| *k != AgentType::Directory || is_origin(url));
    Ok((
        member,
        usable.map(|kind| SignatureAgent {
            url: url.to_owned(),
            kind,
        }),
    ))
}

/// `https://host[:port]`, optionally with an empty path `/`.
fn is_origin(url: &str) -> bool {
    let rest = &url["https://".len()..];
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    !rest.is_empty() && !rest.contains(['/', '?', '#', '@'])
}

/// Every check that needs no key: canonical fields, one signature, the
/// allowed components, the parameters.
fn parse(body: &WbaBody) -> Result<Parsed, SchemeError> {
    let (label, input) = single_member(&body.signature_input, "Signature-Input")?;
    let (sig_label, sig) = single_member(&body.signature, "Signature")?;
    if sig_label != label {
        return Err(reject(
            codes::BAD_BODY,
            "Signature and Signature-Input name different labels",
        ));
    }
    let sfv::ListEntry::Item(sig) = sig else {
        return Err(reject(codes::BAD_BODY, "the signature is not an Item"));
    };
    if sig.bare_item.as_byte_sequence().is_none() || !sig.params.is_empty() {
        return Err(reject(
            codes::BAD_BODY,
            "the signature is not a bare Byte Sequence",
        ));
    }
    let sfv::ListEntry::InnerList(input) = input else {
        return Err(reject(
            codes::BAD_SIGNATURE_INPUT,
            "Signature-Input is not an Inner List",
        ));
    };
    let components = components(&input.items, &label)?;
    let p = &input.params;
    if string_param(p, "tag")? != Some(TAG) {
        return Err(reject(codes::BAD_SIGNATURE_INPUT, "tag is not web-bot-auth"));
    }
    if let Some(alg) = string_param(p, "alg")?
        && alg != "ed25519"
    {
        return Err(reject(codes::UNSUPPORTED_ALG, format!("alg {alg}")));
    }
    string_param(p, "nonce")?;
    let keyid = string_param(p, "keyid")?
        .ok_or_else(|| reject(codes::BAD_SIGNATURE_INPUT, "keyid is missing"))?
        .to_owned();
    let created = time_param(p, "created")?;
    let expires = time_param(p, "expires")?;

    let covered_agent = components
        .iter()
        .find(|c| matches!(c, Component::AgentField | Component::AgentMember));
    let (agent_member, agent) = match (&body.signature_agent, covered_agent) {
        (None, None) => (None, None),
        (Some(field), Some(c)) => agent(field, c, &label)?,
        (Some(_), None) => {
            return Err(reject(
                codes::BAD_AGENT,
                "Signature-Agent is sent but not covered",
            ));
        }
        (None, Some(_)) => {
            return Err(reject(
                codes::BAD_AGENT,
                "the signature covers a Signature-Agent that is not sent",
            ));
        }
    };
    Ok(Parsed {
        label,
        components,
        created,
        expires,
        keyid,
        agent_member,
        agent,
    })
}

/// The request as the signature base sees it: the gate's own authority,
/// the Context it computed, and the body's three fields. Nothing comes from
/// the HTTP request (draft-00 5.1).
struct Message<'a> {
    authority: &'a str,
    context: String,
    body: &'a WbaBody,
    label: &'a str,
    agent_member: Option<&'a str>,
}

impl SignedMessage for Message<'_> {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        let one = |s: &str| vec![s.to_owned()];
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                one(self.authority)
            }
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                match (name.as_str(), parameters.0.as_slice()) {
                    ("signature", []) => one(&self.body.signature),
                    ("signature-input", []) => one(&self.body.signature_input),
                    (CONTEXT_FIELD, []) => one(&self.context),
                    ("signature-agent", []) => {
                        self.body.signature_agent.iter().cloned().collect()
                    }
                    ("signature-agent", [HTTPFieldParameters::Key(k)]) if k == self.label => {
                        self.agent_member.map(str::to_owned).into_iter().collect()
                    }
                    _ => Vec::new(),
                }
            }
            CoveredComponent::Derived(_) => Vec::new(),
        }
    }
}

/// `httpsig:web-bot-auth`: a Web Bot Auth signature (RFC 9421, profiled by
/// draft-ietf-webbotauth-httpsig-protocol-00) whose covered components
/// include `bnap-context`, the Context, which makes it class A.
///
/// The client sends the `Signature`, `Signature-Input` and
/// `Signature-Agent` field values in its attest body ([`crate::body`]).
/// `verify` builds the signature base from the gate's own values only
/// (draft-00 5.1): `@authority` is the authority this scheme was configured
/// with (the manifest origin's), `bnap-context` is the base64url Context
/// the gate computed, and the agent comes from the body. A signature may
/// therefore cover exactly `@authority`, `bnap-context` and, when sent,
/// the agent (the member keyed to its label, or the legacy String form):
/// any other component, such as `@path`, is refused, since the Context
/// already binds the method, target, content and listed headers through
/// the action scope. It then asks the [`KeyDirectory`] for the key the
/// pair (agent URL, `keyid`) names, checks that the key's JWK thumbprint
/// is the `keyid`, and verifies the signature with Cloudflare's
/// `web-bot-auth` crate.
///
/// It returns one local ID, the key's JWK SHA-256 thumbprint (RFC 7638),
/// which is also its quota identity, as the registry entry says. The
/// registry sets the use model (`reusable`) and the class (A); effects come
/// from the offer.
pub struct WebBotAuthScheme {
    authority: String,
    directory: Arc<dyn KeyDirectory>,
    max_lifetime: Option<u64>,
}

impl WebBotAuthScheme {
    /// A scheme for the gate that serves `authority` (the host, and the
    /// port when it is not the default, of the manifest's origin), resolving
    /// keys with `directory`.
    #[must_use]
    pub fn new(authority: &str, directory: Arc<dyn KeyDirectory>) -> Self {
        Self {
            authority: authority.to_ascii_lowercase(),
            directory,
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
        }
    }

    /// Sets the longest accepted `expires - created`; `None` accepts any.
    #[must_use]
    pub fn with_max_lifetime(mut self, seconds: Option<u64>) -> Self {
        self.max_lifetime = seconds;
        self
    }
}

impl std::fmt::Debug for WebBotAuthScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebBotAuthScheme")
            .field("authority", &self.authority)
            .field("max_lifetime", &self.max_lifetime)
            .finish_non_exhaustive()
    }
}

impl WebBotAuthScheme {
    fn check_time(&self, p: &Parsed, now: u64) -> Result<(), SchemeError> {
        if p.expires < p.created {
            return Err(reject(
                codes::BAD_SIGNATURE_INPUT,
                "expires is before created",
            ));
        }
        if p.created > now.saturating_add(CLOCK_SKEW) {
            return Err(reject(codes::STALE_SIGNATURE, "created is in the future"));
        }
        if now > p.expires.saturating_add(CLOCK_SKEW) {
            return Err(reject(codes::STALE_SIGNATURE, "the signature has expired"));
        }
        if let Some(max) = self.max_lifetime
            && p.expires - p.created > max
        {
            return Err(reject(
                codes::LIFETIME_TOO_LONG,
                "expires is too far after created",
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl CredentialScheme for WebBotAuthScheme {
    fn id(&self) -> &str {
        ID
    }

    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        match cx.role {
            OfferRole::Attest { .. } => Ok(SchemeOffer::default()),
            OfferRole::Pay { .. } => Err(SchemeError::Unsupported),
        }
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        match cx.entry {
            Entry::Attest(e) if e.scheme == ID => {}
            _ => {
                return Err(reject(
                    codes::NOT_AN_ATTESTATION,
                    "the scheme is an attestation and has no pay entry",
                ));
            }
        }
        if part.scheme != ID || !part.witness.is_empty() {
            return Err(reject(
                codes::BAD_BODY,
                "another scheme's part, or a witness, which class A has not",
            ));
        }
        let body = WbaBody::parse(&part.body).map_err(|e| reject(codes::BAD_BODY, e.to_string()))?;
        let p = parse(&body)?;
        self.check_time(&p, cx.now)?;
        let keyid: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&p.keyid)
            .ok()
            .filter(|k| URL_SAFE_NO_PAD.encode(k) == p.keyid)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| reject(codes::BAD_KEYID, "keyid is not a base64url SHA-256 thumbprint"))?;

        let key = self
            .directory
            .resolve(&KeyQuery {
                agent: p.agent.as_ref(),
                keyid: &p.keyid,
                now: cx.now,
            })
            .await
            .map_err(|e| SchemeError::Unavailable(e.to_string()))?
            .ok_or_else(|| reject(codes::UNKNOWN_KEY, "the directory does not list this key for this agent"))?;
        let local = thumbprint(&key);
        if local != keyid {
            return Err(reject(codes::KEYID_MISMATCH, "the key's thumbprint is not the keyid"));
        }
        if ed25519_dalek::VerifyingKey::from_bytes(&key).is_err() {
            return Err(reject(codes::UNKNOWN_KEY, "the directory key is not an Ed25519 key"));
        }

        let message = Message {
            authority: &self.authority,
            context: URL_SAFE_NO_PAD.encode(cx.context.0),
            body: &body,
            label: &p.label,
            agent_member: p.agent_member.as_deref(),
        };
        let verifier = web_bot_auth::WebBotAuthVerifier::parse(&message)
            .map_err(|e| reject(codes::BAD_SIGNATURE_INPUT, e.to_string()))?;
        let mut ring = KeyRing::default();
        ring.import_raw(p.keyid.clone(), Algorithm::Ed25519, key.to_vec());
        verifier
            .verify(&ring, Some(p.keyid.clone()))
            .map_err(|e| reject(codes::BAD_SIGNATURE, e.to_string()))?;
        debug_assert!(p.components.contains(&Component::Context));
        Ok(Verified {
            use_ids: vec![local.to_vec()],
            rail_ids: Vec::new(),
            value: 0,
            quota_id: Some(local.to_vec()),
        })
    }
}
