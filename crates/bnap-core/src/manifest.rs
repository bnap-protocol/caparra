//! The manifest and pinning (draft-00 section 9).
//!
//! The manifest is JSON, served at `https://<origin>/.well-known/bnap`. Its
//! `sig` is a signature by `root` over
//! `H_"bnap/manifest"(JCS(manifest without sig))`, JCS being RFC 8785.
//!
//! The signature is checked over the document as received, as a JSON value,
//! so members this crate does not know are still covered. The typed
//! [`Manifest`] is read from that same value.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hash::{sha256, tagged_hash, tags};
use crate::limits::CLOCK_SKEW;
use crate::offer::Effect;
use crate::schnorr::{Key, Signature, SigningKey};

/// Highest `max_age`: 2,592,000 seconds, 30 days.
pub const MAX_MAX_AGE: u64 = 2_592_000;
/// Longest a pin lasts: 30 days.
pub const MAX_PIN: u64 = 2_592_000;
/// Largest integer a manifest may hold: 2⁵³.
pub const MAX_JSON_INT: u64 = 1 << 53;

/// What an online key is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// Signs offers.
    Offer,
    /// Signs Response acks.
    Receipt,
    /// A use this crate does not know; such a key is never accepted.
    Other(String),
}

impl KeyUse {
    /// The JSON spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Offer => "offer",
            Self::Receipt => "receipt",
            Self::Other(s) => s,
        }
    }
}

impl Serialize for KeyUse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyUse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(match s.as_str() {
            "offer" => Self::Offer,
            "receipt" => Self::Receipt,
            _ => Self::Other(s),
        })
    }
}

/// An online key: `{"kid": hex key, "use": "offer" or "receipt", "not_after": time}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestKey {
    /// The x-only public key.
    pub kid: Key,
    /// What it signs.
    #[serde(rename = "use")]
    pub key_use: KeyUse,
    /// Expiry, Unix seconds.
    pub not_after: u64,
}

/// The `limits` member. Absent members take the defaults of
/// [`crate::limits::Limits`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestLimits {
    /// How long outcome records are kept, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_window: Option<u64>,
    /// How long an outcome may stay PENDING, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_timeout: Option<u64>,
    /// Offer size limit, bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_offer: Option<u64>,
    /// Credential size limit, bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credential: Option<u64>,
    /// Response size limit, bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_response: Option<u64>,
}

/// Which offers a route gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteScopeMode {
    /// Exact-scope offers only.
    Exact,
    /// Route-scope offers for class S and A schemes, exact-scope for the rest.
    Route,
}

/// An attestation a route accepts. `effect` is written by name:
/// `required`, `waive`, `discount` or `quota` (ERRATA row 12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAttest {
    /// Scheme ID.
    pub scheme: String,
    /// What it does to the price.
    pub effect: Effect,
    /// Basis points for a discount; actions per epoch for a quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// Quota epoch, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
}

/// A route (9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Route ID, the input of the route scope.
    pub id: String,
    /// A method, one space, and a path; a path ending in `/*` matches every
    /// path below it.
    #[serde(rename = "match")]
    pub match_: String,
    /// `exact` or `route`.
    pub scope: RouteScopeMode,
    /// The charge is set at settlement.
    #[serde(default)]
    pub metered: bool,
    /// The meter's name, such as `tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    /// Price per unit; on a metered route, the ceiling (ERRATA row 13).
    #[serde(default)]
    pub price: BTreeMap<String, u64>,
    /// Value scheme IDs.
    #[serde(default)]
    pub pay: Vec<String>,
    /// Attestations.
    #[serde(default)]
    pub attest: Vec<RouteAttest>,
    /// Required properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<BTreeMap<String, Value>>,
    /// Request fields the HTTP carrier hashes into the scope, lower case.
    #[serde(default)]
    pub headers: Vec<String>,
}

impl Route {
    /// True when a request with `method` and `path` (its query, if any, is
    /// ignored) matches this route.
    #[must_use]
    pub fn matches(&self, method: &str, path: &str) -> bool {
        let Some((m, p)) = self.match_.split_once(' ') else {
            return false;
        };
        if m != method {
            return false;
        }
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        match p.strip_suffix('*') {
            Some(prefix) if prefix.ends_with('/') => path.starts_with(prefix),
            _ => p == path,
        }
    }
}

/// The manifest document, without `sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always 1.
    pub bnap: u64,
    /// The origin it covers, as in RFC 6454.
    pub origin: String,
    /// Increases with every change.
    pub seq: u64,
    /// Issue time, Unix seconds.
    pub issued: u64,
    /// Lifetime in seconds, at most 30 days.
    pub max_age: u64,
    /// The key that signs this manifest.
    pub root: Key,
    /// The offline key that may sign the next root's manifest.
    pub backup: Key,
    /// Online keys.
    pub keys: Vec<ManifestKey>,
    /// The `bnap-required` flag.
    #[serde(default)]
    pub required: bool,
    /// Limits.
    #[serde(default)]
    pub limits: ManifestLimits,
    /// Carrier names, such as `["http", "mcp"]`.
    #[serde(default)]
    pub carriers: Vec<String>,
    /// Routes.
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// Not JSON, or not a JSON object.
    #[error("not a JSON object: {0}")]
    Json(String),
    /// A value other than strings, booleans, objects, arrays and integers
    /// no larger than 2⁵³.
    #[error("disallowed JSON value: {0}")]
    Value(&'static str),
    /// A member is missing or has the wrong type.
    #[error("bad member: {0}")]
    Member(String),
    /// `bnap` is not 1.
    #[error("bnap is not 1")]
    Version,
    /// `max_age` above 30 days.
    #[error("max_age above 30 days")]
    MaxAge,
    /// `origin` is not a lower-case RFC 6454 serialization, or not the
    /// origin it was fetched from.
    #[error("origin mismatch or not serialized as in RFC 6454")]
    Origin,
    /// `sig` does not verify under `root`.
    #[error("sig does not verify under root")]
    Signature,
    /// `issued` and `max_age` do not bracket the client's clock.
    #[error("manifest not valid at this time")]
    Time,
    /// Neither the pinned root and backup, nor a rotation to the pinned backup.
    #[error("root and backup do not match the pin")]
    PinMismatch,
    /// `seq` not above the pin's, and not the pinned bytes.
    #[error("seq does not increase: rollback")]
    Rollback,
}

/// RFC 8785 JCS of a serializable value.
pub fn jcs<T: Serialize>(v: &T) -> Result<Vec<u8>, ManifestError> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| ManifestError::Json(e.to_string()))
}

impl Manifest {
    /// JCS of the manifest without `sig`.
    pub fn jcs(&self) -> Result<Vec<u8>, ManifestError> {
        jcs(self)
    }

    /// The message the root signs: `H_"bnap/manifest"(JCS(manifest without sig))`.
    pub fn sig_message(&self) -> Result<[u8; 32], ManifestError> {
        Ok(tagged_hash(tags::MANIFEST, &self.jcs()?))
    }

    /// Signs the manifest with `root`, which must be the key in `root`, and
    /// returns the served document: JCS of the manifest with `sig` added.
    pub fn sign(&self, root: &SigningKey, aux: &[u8; 32]) -> Result<Vec<u8>, ManifestError> {
        if root.public_key() != self.root {
            return Err(ManifestError::Member("root is not the signing key".into()));
        }
        let sig = root.sign(&self.sig_message()?, aux);
        let mut v = serde_json::to_value(self).map_err(|e| ManifestError::Json(e.to_string()))?;
        if let Value::Object(o) = &mut v {
            o.insert("sig".into(), Value::String(sig.to_hex()));
        }
        jcs(&v)
    }
}

/// A parsed manifest document with its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    manifest: Manifest,
    unsigned: Value,
    sig: Signature,
    hash: [u8; 32],
}

impl SignedManifest {
    /// Parses a manifest document: JSON, the value rules of 9.1, the typed
    /// members, `bnap == 1`, `max_age` at most 30 days and the origin form.
    /// The signature is not checked; see [`SignedManifest::verify`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut v: Value =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
        check_values(&v)?;
        let Value::Object(o) = &mut v else {
            return Err(ManifestError::Json("top level is not an object".into()));
        };
        let sig = match o.remove("sig") {
            Some(Value::String(s)) => Signature::from_hex(&s)
                .map_err(|_| ManifestError::Member("sig is not 64 hex bytes".into()))?,
            _ => return Err(ManifestError::Member("sig missing or not a string".into())),
        };
        let manifest: Manifest =
            serde_json::from_value(v.clone()).map_err(|e| ManifestError::Member(e.to_string()))?;
        if manifest.bnap != 1 {
            return Err(ManifestError::Version);
        }
        if manifest.max_age > MAX_MAX_AGE {
            return Err(ManifestError::MaxAge);
        }
        if !valid_origin(&manifest.origin) {
            return Err(ManifestError::Origin);
        }
        Ok(Self {
            manifest,
            unsigned: v,
            sig,
            hash: sha256(bytes),
        })
    }

    /// The typed manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// `sig`.
    #[must_use]
    pub fn sig(&self) -> Signature {
        self.sig
    }

    /// `H(m bytes)`: SHA-256 of the document as received.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// JCS of the document as received, without `sig`.
    pub fn jcs(&self) -> Result<Vec<u8>, ManifestError> {
        jcs(&self.unsigned)
    }

    /// Verifies `sig` under the manifest's own `root`.
    pub fn verify(&self) -> Result<(), ManifestError> {
        let msg = tagged_hash(tags::MANIFEST, &self.jcs()?);
        self.manifest
            .root
            .verify(&msg, &self.sig)
            .map_err(|_| ManifestError::Signature)
    }
}

/// Values 9.1 allows: strings, booleans, objects, arrays and integers no
/// larger than 2⁵³ (in magnitude). No null, no fractions.
fn check_values(v: &Value) -> Result<(), ManifestError> {
    match v {
        Value::Null => Err(ManifestError::Value("null")),
        Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            let ok = n.as_u64().is_some_and(|u| u <= MAX_JSON_INT)
                || n.as_i64().is_some_and(|i| i.unsigned_abs() <= MAX_JSON_INT);
            if ok {
                Ok(())
            } else {
                Err(ManifestError::Value(
                    "number that is not an integer within 2^53",
                ))
            }
        }
        Value::Array(a) => a.iter().try_for_each(check_values),
        Value::Object(o) => o.values().try_for_each(check_values),
    }
}

/// An RFC 6454 origin serialization as draft-00 9.1 asks: lower case,
/// `scheme://host[:port]`, no path, default port omitted.
fn valid_origin(o: &str) -> bool {
    let Some((scheme, authority)) = o.split_once("://") else {
        return false;
    };
    if scheme.is_empty() || authority.is_empty() || o.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if authority.contains(['/', '?', '#', '@']) {
        return false;
    }
    let default_port = match scheme {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    !default_port.is_some_and(|p| authority.ends_with(p))
}

/// A client's pin for one origin (9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Pinned root.
    pub root: Key,
    /// Pinned backup.
    pub backup: Key,
    /// Highest `seq` seen.
    pub seq: u64,
    /// `H(m bytes)` of the pinned document.
    pub hash: [u8; 32],
    /// The `bnap-required` flag.
    pub required: bool,
    /// The online keys.
    pub keys: Vec<ManifestKey>,
    /// The pin lapses after this time.
    pub until: u64,
}

impl Pin {
    /// True while the pin has not lapsed.
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        now <= self.until
    }
}

/// The client's `fetch(origin)` rule of 9.3 after the GET: checks the
/// fetched document `bytes` against the current pin and returns the new pin.
///
/// Requires `bnap == 1`, `origin` equal to the fetched origin, `sig` valid
/// under `root`, and `issued - 60 <= now <= issued + max_age + 60`. With a
/// live pin, requires the same root and backup or a rotation to the pinned
/// backup, and a higher `seq` or the identical bytes.
pub fn accept(
    pin: Option<&Pin>,
    origin: &str,
    bytes: &[u8],
    now: u64,
) -> Result<(Pin, SignedManifest), ManifestError> {
    let sm = SignedManifest::parse(bytes)?;
    let m = sm.manifest();
    if m.origin != origin {
        return Err(ManifestError::Origin);
    }
    sm.verify()?;
    if now < m.issued.saturating_sub(CLOCK_SKEW)
        || now
            > m.issued
                .saturating_add(m.max_age)
                .saturating_add(CLOCK_SKEW)
    {
        return Err(ManifestError::Time);
    }
    if let Some(p) = pin.filter(|p| p.is_live(now)) {
        let same = m.root == p.root && m.backup == p.backup;
        let rotation = m.root == p.backup;
        if !same && !rotation {
            return Err(ManifestError::PinMismatch);
        }
        if m.seq <= p.seq && sm.hash() != p.hash {
            return Err(ManifestError::Rollback);
        }
    }
    let new = Pin {
        root: m.root,
        backup: m.backup,
        seq: m.seq,
        hash: sm.hash(),
        required: m.required,
        keys: m.keys.clone(),
        until: m
            .issued
            .saturating_add(m.max_age)
            .min(now.saturating_add(MAX_PIN)),
    };
    Ok((new, sm))
}

impl fmt::Display for KeyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert!(valid_origin("https://api.example"));
        assert!(valid_origin("https://api.example:8443"));
        assert!(!valid_origin("https://api.example:443"));
        assert!(!valid_origin("https://API.example"));
        assert!(!valid_origin("https://api.example/"));
        assert!(!valid_origin("api.example"));
    }

    #[test]
    fn route_match() {
        let mut r = Route {
            id: "chat".into(),
            match_: "POST /v1/chat/completions".into(),
            scope: RouteScopeMode::Route,
            metered: false,
            meter: None,
            price: BTreeMap::new(),
            pay: vec![],
            attest: vec![],
            require: None,
            headers: vec![],
        };
        assert!(r.matches("POST", "/v1/chat/completions"));
        assert!(r.matches("POST", "/v1/chat/completions?x=1"));
        assert!(!r.matches("post", "/v1/chat/completions"));
        assert!(!r.matches("POST", "/v1/chat"));
        r.match_ = "GET /files/*".into();
        assert!(r.matches("GET", "/files/a/b"));
        assert!(!r.matches("GET", "/filesx"));
        assert!(!r.matches("GET", "/files"));
    }

    #[test]
    fn value_rules() {
        assert!(
            check_values(&serde_json::json!({"a": [1, true, "x", {"b": 9007199254740992u64}]}))
                .is_ok()
        );
        assert!(check_values(&serde_json::json!({"a": 9007199254740993u64})).is_err());
        assert!(check_values(&serde_json::json!({"a": 1.5})).is_err());
        assert!(check_values(&serde_json::json!({"a": null})).is_err());
    }
}
