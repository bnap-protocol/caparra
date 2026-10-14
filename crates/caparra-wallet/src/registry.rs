//! The scheme registry as the wallet reads it.
//!
//! Binding classes, use models, refund properties and property vectors come
//! from the registry export embedded at build time (`data/registry.json`),
//! never from a server, an offer or a plug (overview, "Scheme properties and
//! route policy": plugins MUST NOT declare properties at runtime).
//!
//! The effective vector the wallet judges a pay entry by is the per-property
//! minimum over the scheme's entry and every verifier the entry lists: the
//! client cannot see which verifier or rail the operator runs, so it assumes
//! the weakest it may be. An unknown scheme is all weakest values
//! (`bnap_core::policy`).

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::OnceLock;

use bnap_core::BindingClass;
use bnap_core::hash::sha256;
use bnap_core::policy::{EffectiveVector, Part, PartKind, PropertyVector};
use serde::Deserialize;

/// The embedded export, byte for byte.
pub const EXPORT: &str = include_str!("../data/registry.json");

/// One scheme entry, as the wallet needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeEntry {
    /// The scheme ID.
    pub id: String,
    /// A credential (value) scheme or an attestation.
    pub kind: PartKind,
    /// Its binding class.
    pub binding: BindingClass,
    /// `single`, `rate` or `reusable`, as the socket enforces it.
    pub use_model: String,
    /// `none`, `out-of-band` or `atomic`; `None` for attestations.
    pub refund: Option<String>,
    /// Its property vector.
    pub vector: PropertyVector,
    /// The verifiers it may be checked by.
    pub verifiers: Vec<String>,
}

/// The parsed registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    schemes: BTreeMap<String, SchemeEntry>,
    verifiers: BTreeMap<String, PropertyVector>,
    digest: String,
}

#[derive(Deserialize)]
struct RawExport {
    digest: String,
    schemes: BTreeMap<String, RawScheme>,
    verifiers: BTreeMap<String, RawVerifier>,
}

#[derive(Deserialize)]
struct RawScheme {
    kind: String,
    binding: String,
    #[serde(rename = "use")]
    use_model: String,
    #[serde(default)]
    refund: Option<String>,
    #[serde(default)]
    vector: PropertyVector,
    #[serde(default)]
    verifiers: Vec<String>,
}

#[derive(Deserialize)]
struct RawVerifier {
    #[serde(default)]
    vector: PropertyVector,
}

impl Registry {
    /// Parses a registry export.
    pub fn parse(json: &str) -> Result<Self, String> {
        let raw: RawExport = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let mut schemes = BTreeMap::new();
        for (id, s) in raw.schemes {
            let kind = match s.kind.as_str() {
                "credential" => PartKind::Credential,
                "attestation" => PartKind::Attestation,
                other => return Err(format!("{id}: unknown kind {other}")),
            };
            let binding = BindingClass::from_str(&s.binding)
                .map_err(|_| format!("{id}: unknown binding {}", s.binding))?;
            schemes.insert(
                id.clone(),
                SchemeEntry {
                    id,
                    kind,
                    binding,
                    use_model: s.use_model,
                    refund: s.refund,
                    vector: s.vector,
                    verifiers: s.verifiers,
                },
            );
        }
        let verifiers = raw
            .verifiers
            .into_iter()
            .map(|(id, v)| (id, v.vector))
            .collect();
        Ok(Self {
            schemes,
            verifiers,
            digest: raw.digest,
        })
    }

    /// The embedded registry.
    ///
    /// # Panics
    ///
    /// Never at run time: the embedded file is checked by a unit test.
    #[must_use]
    pub fn embedded() -> &'static Self {
        static R: OnceLock<Registry> = OnceLock::new();
        R.get_or_init(|| Self::parse(EXPORT).expect("the embedded registry export parses"))
    }

    /// The export's own digest field.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// A scheme's entry.
    #[must_use]
    pub fn scheme(&self, id: &str) -> Option<&SchemeEntry> {
        self.schemes.get(id)
    }

    /// A scheme's binding class; `None` for a scheme the registry does not
    /// list (bnap-core then counts it as class None).
    #[must_use]
    pub fn class_of(&self, id: &str) -> Option<BindingClass> {
        self.scheme(id).map(|s| s.binding)
    }

    /// The effective vector the wallet judges `id` by: the minimum over the
    /// scheme's entry and each verifier it lists. An unknown scheme, or an
    /// unknown verifier, counts as every property at its weakest.
    #[must_use]
    pub fn effective(&self, id: &str, kind: PartKind) -> EffectiveVector {
        let Some(s) = self.scheme(id) else {
            return EffectiveVector::compute(&[Part::unknown(kind)]);
        };
        let mut parts = vec![Part::known(s.kind, &s.vector)];
        for v in &s.verifiers {
            parts.push(match self.verifiers.get(v) {
                Some(vector) => Part::known(PartKind::Verifier, vector),
                None => Part::unknown(PartKind::Verifier),
            });
        }
        EffectiveVector::compute(&parts)
    }
}

/// SHA-256 of the embedded export, hex.
#[must_use]
pub fn export_sha256() -> String {
    hex::encode(sha256(EXPORT.as_bytes()))
}

/// True when a scheme with this vector links payments or actions.
#[must_use]
pub fn linkable(v: &EffectiveVector) -> bool {
    v.value("link-payment") == Some("linkable") || v.value("link-actions") == Some("linkable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_export_is_the_one_named_here() {
        let r = Registry::embedded();
        assert_eq!(
            r.digest(),
            "e133cf496b0463d36ccca71dd78bf3a6c6a21cf67ef31c0497996c0eb1de261c"
        );
    }

    #[test]
    fn classes_and_vectors_come_from_the_registry() {
        let r = Registry::embedded();
        assert_eq!(r.class_of("bnap:notes"), Some(BindingClass::S));
        assert_eq!(r.class_of("httpauth:L402"), Some(BindingClass::O));
        assert_eq!(r.class_of("payment:lightning/charge"), Some(BindingClass::O));
        assert_eq!(r.class_of("httpsig:web-bot-auth"), Some(BindingClass::A));
        assert_eq!(r.class_of("vnd.example.unknown"), None);
        let notes = r.effective("bnap:notes", PartKind::Credential);
        assert_eq!(notes.value("link-payment"), Some("unlinkable"));
        assert_eq!(notes.value("refund"), Some("atomic"));
        assert!(!linkable(&notes));
        let l402 = r.effective("httpauth:L402", PartKind::Credential);
        assert_eq!(l402.value("link-payment"), Some("linkable"));
        assert!(linkable(&l402));
    }

    #[test]
    fn an_unknown_scheme_is_weakest_everywhere() {
        let v = Registry::embedded().effective("vnd.example.unknown", PartKind::Credential);
        assert_eq!(v.value("binding"), Some("none"));
        assert_eq!(v.value("use"), Some("reusable"));
        assert_eq!(v.value("maturity"), Some("experimental"));
    }
}
