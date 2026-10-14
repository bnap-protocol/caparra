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
use web_bot_auth::components::{
    CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters,
};
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

/// The one signature label an attest body may use, in `Signature` and
/// `Signature-Input` alike.
///
/// RFC 9421 does not sign the label (the dictionary key): the signature
/// base covers the components and the parameters only. A body free to
/// choose its label would let anyone who sees a credential rename it and
/// get another body that verifies over the same Context, so another Digest
/// and another `ReplayKey` (draft-00 5.1, "Canonical bodies"). The label is
/// therefore fixed by the adapter's wire format. `sig1` is the label the
/// `web-bot-auth` crate's own signer writes.
pub const LABEL: &str = "sig1";

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
    /// `"signature-agent";key="<key>"`, one member of the dictionary.
    AgentMember(String),
}

/// What [`parse`] read from a canonical body.
#[derive(Debug)]
struct Parsed {
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
fn components(items: &[sfv::Item]) -> Result<Vec<Component>, SchemeError> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let name = item.bare_item.as_string().ok_or_else(|| {
            reject(
                codes::BAD_SIGNATURE_INPUT,
                "a component that is not a String",
            )
        })?;
        let c = match (name.as_str(), item.params.len()) {
            ("@authority", 0) => Component::Authority,
            (CONTEXT_FIELD, 0) => Component::Context,
            ("signature-agent", 0) => Component::AgentField,
            ("signature-agent", 1) if item.params.contains_key("key") => {
                let key = string_param(&item.params, "key")?.unwrap_or_default();
                Component::AgentMember(key.to_owned())
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
        let agent = |c: &Component| matches!(c, Component::AgentField | Component::AgentMember(_));
        if out.contains(&c) || (agent(&c) && out.iter().any(agent)) {
            return Err(reject(
                codes::BAD_SIGNATURE_INPUT,
                "a component named twice",
            ));
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

/// Reads the agent the signature covers: the one member of the dictionary
/// form, which must be the member the component names, or the legacy String
/// form of the whole field.
fn agent(
    field: &str,
    covered: &Component,
) -> Result<(Option<String>, Option<SignatureAgent>), SchemeError> {
    let bad = |d: &str| reject(codes::BAD_AGENT, d.to_owned());
    let (item, member) = if let Component::AgentMember(covered_key) = covered {
        let (key, entry) = single_member(field, "Signature-Agent")?;
        if key != *covered_key {
            return Err(bad(
                "the covered Signature-Agent member is not the one sent",
            ));
        }
        let sfv::ListEntry::Item(item) = entry else {
            return Err(bad("the Signature-Agent member is not an Item"));
        };
        let member = item.serialize_value();
        (item, Some(member))
    } else {
        let item = sfv::Parser::new(field)
            .parse_item()
            .map_err(|e| bad(&format!("Signature-Agent: {e}")))?;
        if item.serialize_value() != field {
            return Err(bad("Signature-Agent is not in its strict serialization"));
        }
        (item, None)
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

/// Every check that needs no key: canonical fields, one signature under
/// [`LABEL`], the allowed components, the parameters.
fn parse(body: &WbaBody) -> Result<Parsed, SchemeError> {
    let (label, input) = single_member(&body.signature_input, "Signature-Input")?;
    let (sig_label, sig) = single_member(&body.signature, "Signature")?;
    // The label is outside the signature base: only one spelling verifies.
    if label != LABEL || sig_label != LABEL {
        return Err(reject(
            codes::BAD_BODY,
            format!("the signature label is not {LABEL}"),
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
    let components = components(&input.items)?;
    let p = &input.params;
    if string_param(p, "tag")? != Some(TAG) {
        return Err(reject(
            codes::BAD_SIGNATURE_INPUT,
            "tag is not web-bot-auth",
        ));
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
        .find(|c| matches!(c, Component::AgentField | Component::AgentMember(_)));
    let (agent_member, agent) = match (&body.signature_agent, covered_agent) {
        (None, None) => (None, None),
        (Some(field), Some(c)) => agent(field, c)?,
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
    /// The `bnap-context` value; `None` signs nothing over a Context (only
    /// for checking the draft's own vectors).
    context: Option<String>,
    body: &'a WbaBody,
    /// The covered member's key and its strictly serialized value.
    agent_member: Option<(&'a str, &'a str)>,
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
                    (CONTEXT_FIELD, []) => self.context.iter().cloned().collect(),
                    ("signature-agent", []) => self.body.signature_agent.iter().cloned().collect(),
                    ("signature-agent", [HTTPFieldParameters::Key(k)]) => self
                        .agent_member
                        .filter(|(key, _)| key == k)
                        .map(|(_, v)| v.to_owned())
                        .into_iter()
                        .collect(),
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
/// `Signature-Agent` field values in its attest body ([`crate::body`]),
/// with the one signature under the label [`LABEL`], since RFC 9421 does
/// not sign the label.
/// `verify` builds the signature base from the gate's own values only
/// (draft-00 5.1): `@authority` is the authority this scheme was configured
/// with (the manifest origin's), `bnap-context` is the base64url Context
/// the gate computed, and the agent comes from the body. A signature may
/// therefore cover exactly `@authority`, `bnap-context` and, when sent,
/// the agent (its one dictionary member, or the legacy String form):
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
        let body =
            WbaBody::parse(&part.body).map_err(|e| reject(codes::BAD_BODY, e.to_string()))?;
        let p = parse(&body)?;
        self.check_time(&p, cx.now)?;
        let keyid: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&p.keyid)
            .ok()
            .filter(|k| URL_SAFE_NO_PAD.encode(k) == p.keyid)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                reject(
                    codes::BAD_KEYID,
                    "keyid is not a base64url SHA-256 thumbprint",
                )
            })?;

        let key = self
            .directory
            .resolve(&KeyQuery {
                agent: p.agent.as_ref(),
                keyid: &p.keyid,
                now: cx.now,
            })
            .await
            .map_err(|e| SchemeError::Unavailable(e.to_string()))?
            .ok_or_else(|| {
                reject(
                    codes::UNKNOWN_KEY,
                    "the directory does not list this key for this agent",
                )
            })?;
        let local = thumbprint(&key);
        if local != keyid {
            return Err(reject(
                codes::KEYID_MISMATCH,
                "the key's thumbprint is not the keyid",
            ));
        }
        if ed25519_dalek::VerifyingKey::from_bytes(&key).is_err() {
            return Err(reject(
                codes::UNKNOWN_KEY,
                "the directory key is not an Ed25519 key",
            ));
        }

        let member_key = p.components.iter().find_map(|c| match c {
            Component::AgentMember(k) => Some(k.as_str()),
            _ => None,
        });
        let message = Message {
            authority: &self.authority,
            context: Some(URL_SAFE_NO_PAD.encode(cx.context.0)),
            body: &body,
            agent_member: member_key.zip(p.agent_member.as_deref()),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The Ed25519 key of RFC 9421 appendix B.1.4, which the Web Bot Auth
    /// draft's vectors use.
    fn test_key() -> [u8; 32] {
        URL_SAFE_NO_PAD
            .decode("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
            .unwrap()
            .try_into()
            .unwrap()
    }

    const KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

    /// Verifies a body with the crate over this module's signature base,
    /// with no Context (the draft's vectors cover none).
    fn verify_vector(body: &WbaBody, member: Option<(&str, &str)>) -> bool {
        let m = Message {
            authority: "example.com",
            context: None,
            body,
            agent_member: member,
        };
        let mut ring = KeyRing::default();
        ring.import_raw(KEYID.into(), Algorithm::Ed25519, test_key().to_vec());
        web_bot_auth::WebBotAuthVerifier::parse(&m)
            .and_then(|v| v.verify(&ring, Some(KEYID.into())))
            .is_ok()
    }

    /// draft-ietf-webbotauth-httpsig-protocol-00 appendix E.2.1.
    fn e21() -> WbaBody {
        WbaBody {
            signature: "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:".into(),
            signature_input: concat!(
                r#"sig2=("@authority" "signature-agent";key="agent2")"#,
                r#";created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U""#,
                r#";alg="ed25519";expires=4889289600"#,
                r#";nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==""#,
                r#";tag="web-bot-auth""#
            )
            .into(),
            signature_agent: Some(r#"agent2="https://signature-agent.test""#.into()),
        }
    }

    /// Appendix E.2.2, the legacy String form of `Signature-Agent`.
    fn e22() -> WbaBody {
        WbaBody {
            signature: "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:".into(),
            signature_input: concat!(
                r#"sig2=("@authority" "signature-agent")"#,
                r#";created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U""#,
                r#";alg="ed25519";expires=1735693200"#,
                r#";nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==""#,
                r#";tag="web-bot-auth""#
            )
            .into(),
            signature_agent: Some(r#""https://signature-agent.test""#.into()),
        }
    }

    #[test]
    fn the_signature_base_matches_the_draft_vectors() {
        // Both vectors verify over the base this module's lookups build,
        // and only with the member value the component names.
        let member = r#""https://signature-agent.test""#;
        assert!(verify_vector(&e21(), Some(("agent2", member))));
        assert!(!verify_vector(
            &e21(),
            Some(("agent2", r#""https://other.test""#))
        ));
        assert!(!verify_vector(&e21(), Some(("agent1", member))));
        assert!(verify_vector(&e22(), None));

        // The canonical-form checks accept both fields as they are.
        for b in [e21(), e22()] {
            let (label, _) = single_member(&b.signature_input, "Signature-Input").unwrap();
            assert_eq!(label, "sig2");
            single_member(&b.signature, "Signature").unwrap();
        }
        // The label is not in the signature base: renamed in both fields,
        // the vectors still verify. That is why a body has one label only.
        for (b, m) in [(e21(), Some(("agent2", member))), (e22(), None)] {
            let renamed = with_label(&b, LABEL);
            assert!(verify_vector(&renamed, m));
            assert_eq!(code(&parse(&b).unwrap_err()), "BAD_BODY");
            // Read as BNAP attestations under the fixed label they are still
            // refused: they do not cover bnap-context, so they embed no
            // Context and are not class A.
            assert_eq!(code(&parse(&renamed).unwrap_err()), "MISSING_COMPONENT");
        }
    }

    /// `b` with its signature label renamed to `to` in both fields.
    fn with_label(b: &WbaBody, to: &str) -> WbaBody {
        let rename = |f: &str| format!("{to}={}", f.split_once('=').unwrap().1);
        WbaBody {
            signature: rename(&b.signature),
            signature_input: rename(&b.signature_input),
            signature_agent: b.signature_agent.clone(),
        }
    }

    /// The part of a refusal's scheme code after `httpsig:web-bot-auth/`.
    fn code(e: &SchemeError) -> String {
        let full = e.to_error_object().scheme_code.unwrap();
        full.strip_prefix("httpsig:web-bot-auth/")
            .unwrap()
            .to_owned()
    }

    /// A body that would pass every key-free check under [`LABEL`].
    fn labelled(label: &str) -> WbaBody {
        let input = format!(
            r#"{label}=("@authority" "bnap-context");created=1;expires=2;keyid="k";tag="web-bot-auth""#
        );
        WbaBody {
            signature: format!("{label}=:AAAA:"),
            signature_input: input,
            signature_agent: None,
        }
    }

    #[test]
    fn only_the_fixed_label_is_accepted() {
        assert!(parse(&labelled(LABEL)).is_ok());
        for other in ["sig2", "zz", "bnap", "sig10", "a"] {
            assert_eq!(code(&parse(&labelled(other)).unwrap_err()), "BAD_BODY");
        }
        // One field renamed, the other kept.
        let mut half = labelled(LABEL);
        half.signature = "sig2=:AAAA:".into();
        assert_eq!(code(&parse(&half).unwrap_err()), "BAD_BODY");
    }

    #[test]
    fn the_agent_is_the_covered_member() {
        let p = Component::AgentMember("agent2".into());
        let (member, found) = agent(r#"agent2="https://signature-agent.test""#, &p).unwrap();
        assert_eq!(member.as_deref(), Some(r#""https://signature-agent.test""#));
        assert_eq!(
            found,
            Some(SignatureAgent {
                url: "https://signature-agent.test".into(),
                kind: AgentType::Directory,
            })
        );
        // Another member than the covered one, two members, http, a type
        // this verifier ignores, a directory that is not an origin.
        assert!(agent(r#"agent3="https://signature-agent.test""#, &p).is_err());
        assert!(agent(r#"agent2="https://a.test", agent3="https://b.test""#, &p).is_err());
        assert!(agent(r#"agent2="http://signature-agent.test""#, &p).is_err());
        let ignored = agent(r#"agent2="https://a.test";type=carrier-pigeon"#, &p).unwrap();
        assert_eq!(ignored.1, None);
        let not_origin = agent(r#"agent2="https://a.test/keys""#, &p).unwrap();
        assert_eq!(not_origin.1, None);
        let jwks = agent(r#"agent2="https://a.test/keys";type=jwks_uri"#, &p).unwrap();
        assert_eq!(jwks.1.map(|a| a.kind), Some(AgentType::JwksUri));
        // Whitespace the strict serialization does not have.
        assert!(agent(r#"agent2 = "https://a.test""#, &p).is_err());
    }
}
