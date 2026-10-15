//! The registry export (`registry/generated/registry.json` of the BNAP
//! repository), embedded and checked against its digest at start.
//!
//! The gate takes every scheme, rail and verifier fact from here (draft-00
//! section 11): binding class, use model, refund, `upto`, units, rail kinds
//! and the property vectors. A plug's own description of itself is never
//! read.

use std::collections::BTreeMap;
use std::str::FromStr;

use bnap_core::class::BindingClass;
use bnap_core::hash::sha256;
use bnap_core::policy::{EffectiveVector, Part, PartKind, PropertyVector};
use bnap_core::pricing::Refund;
use bnap_core::store::UseModel;
use serde::Deserialize;

/// The export, byte for byte as copied from the BNAP repository.
pub const REGISTRY_JSON: &str = include_str!("../registry/registry.json");

/// The digest the export must carry and hash to. Pinned here so that
/// swapping the file needs a code change too.
pub const REGISTRY_DIGEST: &str =
    "06cd086aab52775673424886462f8b4940cb62d28404e4475c15b2b9a755994f";

/// Rail kinds that move bitcoin. Every other kind (`evm`, `card`) is a
/// non-Bitcoin rail and stays off unless a route turns it on.
pub const BITCOIN_RAIL_KINDS: [&str; 2] = ["ln", "onchain"];

/// Why the registry could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The export is not the JSON this build expects.
    #[error("the registry export does not parse: {0}")]
    Parse(String),
    /// The digest member, or the hash of the export, is not the pinned one.
    #[error("the registry export digest is {found}, expected {expected}")]
    Digest {
        /// What the export carries or hashes to.
        found: String,
        /// [`REGISTRY_DIGEST`].
        expected: String,
    },
}

/// A scheme entry (value or attestation).
#[derive(Debug, Clone, Deserialize)]
pub struct SchemeEntry {
    /// `credential` (value) or `attestation`.
    pub kind: String,
    /// `value`, `attestation` or `both`.
    #[serde(default)]
    pub role: Option<String>,
    /// `S`, `A`, `O` or `none`.
    #[serde(default)]
    pub binding: Option<String>,
    /// `single`, `rate` or `reusable`.
    #[serde(rename = "use", default)]
    pub use_model: Option<String>,
    /// `none`, `out-of-band` or `atomic`.
    #[serde(default)]
    pub refund: Option<String>,
    /// May settle a lower amount than authorized.
    #[serde(default)]
    pub upto: Option<bool>,
    /// Units the scheme pays in.
    #[serde(default)]
    pub units: Vec<String>,
    /// Rail kinds the scheme relies on.
    #[serde(default)]
    pub rail_kinds: Vec<String>,
    /// Verifier entries.
    #[serde(default)]
    pub verifiers: Vec<String>,
    /// `provisional`, `does-not-fit`, ...
    #[serde(default)]
    pub status: String,
    /// The property vector.
    #[serde(default)]
    pub vector: PropertyVector,
}

impl SchemeEntry {
    /// The binding class; an entry without one counts as class None.
    #[must_use]
    pub fn class(&self) -> BindingClass {
        self.binding
            .as_deref()
            .and_then(|b| BindingClass::from_str(b).ok())
            .unwrap_or(BindingClass::None)
    }

    /// The use model the socket enforces, or `None` for `rate`, whose `k`
    /// and epoch the registry does not give (the gate refuses such schemes).
    #[must_use]
    pub fn model(&self) -> Option<UseModel> {
        match self.use_model.as_deref() {
            Some("single") => Some(UseModel::Single),
            Some("reusable") => Some(UseModel::Reusable),
            _ => None,
        }
    }

    /// The registered refund property; missing means `none`.
    #[must_use]
    pub fn refund(&self) -> Refund {
        Refund::from_token(self.refund.as_deref().unwrap_or("none"))
    }

    /// True for a value scheme.
    #[must_use]
    pub fn is_value(&self) -> bool {
        matches!(self.role.as_deref(), Some("value" | "both"))
    }

    /// True for an attestation scheme.
    #[must_use]
    pub fn is_attestation(&self) -> bool {
        matches!(self.role.as_deref(), Some("attestation" | "both"))
    }

    /// May appear in a metered offer (draft-00 7: `refund = "atomic"` or
    /// `upto = true`).
    #[must_use]
    pub fn meterable(&self) -> bool {
        bnap_core::pricing::metered_entry_allowed(
            self.refund.as_deref().unwrap_or("none"),
            self.upto.unwrap_or(false),
        )
    }

    /// True when the scheme relies on a rail kind that does not move
    /// bitcoin.
    #[must_use]
    pub fn non_bitcoin(&self) -> bool {
        self.rail_kinds
            .iter()
            .any(|k| !BITCOIN_RAIL_KINDS.contains(&k.as_str()))
            || self.units.iter().any(|u| u != "sat" && u != "msat")
    }
}

/// A rail or verifier entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PlugEntry {
    /// The property vector.
    #[serde(default)]
    pub vector: PropertyVector,
}

#[derive(Debug, Deserialize)]
struct Export {
    digest: String,
    schemes: BTreeMap<String, SchemeEntry>,
    rails: BTreeMap<String, PlugEntry>,
    verifiers: BTreeMap<String, PlugEntry>,
}

/// The loaded, digest-checked registry.
#[derive(Debug, Clone)]
pub struct Registry {
    digest: String,
    schemes: BTreeMap<String, SchemeEntry>,
    rails: BTreeMap<String, PlugEntry>,
    verifiers: BTreeMap<String, PlugEntry>,
}

impl Registry {
    /// The embedded export, checked.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_json(REGISTRY_JSON, REGISTRY_DIGEST)
    }

    /// An export, checked: its `digest` member must equal `expected`, and
    /// so must SHA-256 of the RFC 8785 serialization of the export without
    /// that member (how `registry/validate.py --export` computes it).
    pub fn from_json(text: &str, expected: &str) -> Result<Self, RegistryError> {
        let mut value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| RegistryError::Parse(e.to_string()))?;
        let obj = value
            .as_object_mut()
            .ok_or_else(|| RegistryError::Parse("not an object".into()))?;
        let member = obj
            .remove("digest")
            .and_then(|d| d.as_str().map(str::to_owned))
            .unwrap_or_default();
        let jcs =
            bnap_core::manifest::jcs(&value).map_err(|e| RegistryError::Parse(e.to_string()))?;
        let computed = hex::encode(sha256(&jcs));
        for found in [&member, &computed] {
            if found != expected {
                return Err(RegistryError::Digest {
                    found: found.clone(),
                    expected: expected.to_owned(),
                });
            }
        }
        let export: Export =
            serde_json::from_str(text).map_err(|e| RegistryError::Parse(e.to_string()))?;
        Ok(Self {
            digest: export.digest,
            schemes: export.schemes,
            rails: export.rails,
            verifiers: export.verifiers,
        })
    }

    /// The export's digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// A scheme entry.
    #[must_use]
    pub fn scheme(&self, id: &str) -> Option<&SchemeEntry> {
        self.schemes.get(id)
    }

    /// A rail entry, such as `ln:lnd`.
    #[must_use]
    pub fn rail(&self, id: &str) -> Option<&PlugEntry> {
        self.rails.get(id)
    }

    /// The binding class of a scheme; unknown schemes count as class None.
    #[must_use]
    pub fn class(&self, id: &str) -> BindingClass {
        self.scheme(id)
            .map_or(BindingClass::None, SchemeEntry::class)
    }

    /// The effective vector of a scheme with these rail entries (section
    /// 11): the per-property minimum over the scheme, every rail it is
    /// configured with and its verifiers. A missing entry counts as every
    /// property at its weakest.
    #[must_use]
    pub fn effective(&self, scheme: &str, rails: &[String]) -> EffectiveVector {
        let entry = self.scheme(scheme);
        let kind = if entry.is_some_and(|e| e.kind == "attestation") {
            PartKind::Attestation
        } else {
            PartKind::Credential
        };
        let mut parts = vec![entry.map_or(Part::unknown(kind), |e| Part::known(kind, &e.vector))];
        for r in rails {
            parts.push(
                self.rails
                    .get(r)
                    .map_or(Part::unknown(PartKind::Rail), |e| {
                        Part::known(PartKind::Rail, &e.vector)
                    }),
            );
        }
        for v in entry.map(|e| e.verifiers.as_slice()).unwrap_or_default() {
            parts.push(
                self.verifiers
                    .get(v)
                    .map_or(Part::unknown(PartKind::Verifier), |e| {
                        Part::known(PartKind::Verifier, &e.vector)
                    }),
            );
        }
        EffectiveVector::compute(&parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_export_matches_its_digest() {
        let r = Registry::embedded().unwrap();
        assert_eq!(r.digest(), REGISTRY_DIGEST);
        let notes = r.scheme("bnap:notes").unwrap();
        assert_eq!(notes.class(), BindingClass::S);
        assert_eq!(notes.model(), Some(UseModel::Single));
        assert!(notes.meterable());
        let l402 = r.scheme("httpauth:L402").unwrap();
        assert_eq!(l402.class(), BindingClass::O);
        assert!(!l402.meterable());
        assert!(r.scheme("x402:exact@eip155:8453").unwrap().non_bitcoin());
        assert!(!l402.non_bitcoin());
    }

    #[test]
    fn a_changed_export_is_refused() {
        // One property changed: the member still says the old digest, the
        // content no longer hashes to it.
        let tampered = REGISTRY_JSON.replacen("\"key-witnessed\"", "\"bearer\"", 1);
        assert!(matches!(
            Registry::from_json(&tampered, REGISTRY_DIGEST),
            Err(RegistryError::Digest { .. })
        ));
        // The right content under another pinned digest is refused too.
        assert!(Registry::from_json(REGISTRY_JSON, &"0".repeat(64)).is_err());
    }

    #[test]
    fn rails_lower_the_effective_vector() {
        let r = Registry::embedded().unwrap();
        let alone = r.effective("bnap:notes", &[]);
        let with_nwc = r.effective("bnap:notes", &["ln:nwc".into()]);
        assert_eq!(alone.value("custody"), Some("operator-iou"));
        assert_eq!(with_nwc.value("custody"), Some("third-party-custodial"));
        let unknown = r.effective("bnap:notes", &["ln:nowhere".into()]);
        assert_eq!(unknown.rank("finality"), Some(0));
    }
}
