//! Scheme properties and route policy (draft-00 section 11; overview,
//! "Scheme properties and route policy").
//!
//! Every registry entry carries a property vector. The gate computes each
//! pay entry's effective vector as the per-property minimum over its
//! scheme, its rails and its verifier, with an unknown value counted as the
//! weakest, and admits a scheme on a route only if every property meets the
//! route's `require`. There is no overall score.
//!
//! **The property order is an embedded table for now.** [`PROPERTIES`] is
//! defined here, copied from `registry/properties.toml` of the spec
//! repository (the twelve properties, their value tokens weakest first, and
//! the entry kinds each applies to). It is to be replaced by the registry
//! export (`registry/generated/registry.json`) once that is embedded; the
//! API stays the same.
//!
//! **Which entries take part.** A property only applies to the entry kinds
//! the table lists (`applies_to`): a rail has no binding class, so a rail
//! does not lower an effective binding to `none`, and an attestation has no
//! refund, so a route's `refund` requirement does not constrain
//! attestations. Within the entries a property applies to, a missing value,
//! an unknown token and an entry missing from the registry all count as the
//! weakest value (ERRATA N3b-5).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::offer::Effect;

/// The kind of a registry entry, for `applies_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartKind {
    /// A credential (value) scheme.
    Credential,
    /// An attestation scheme.
    Attestation,
    /// A funding rail.
    Rail,
    /// A verifier.
    Verifier,
}

/// One property: its token, its values weakest first, and the entry kinds
/// that carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDef {
    /// The key used in entries and in a route's `require`.
    pub id: &'static str,
    /// Value tokens, weakest first. A value's strength is its index.
    pub values: &'static [&'static str],
    /// The entry kinds that carry this property.
    pub applies_to: &'static [PartKind],
}

impl PropertyDef {
    /// The strength of `token`, or `None` for an unknown token.
    #[must_use]
    pub fn rank(&self, token: &str) -> Option<usize> {
        self.values.iter().position(|v| *v == token)
    }

    /// The token of strength `rank`.
    #[must_use]
    pub fn value(&self, rank: usize) -> Option<&'static str> {
        self.values.get(rank).copied()
    }

    /// True when entries of `kind` carry this property.
    #[must_use]
    pub fn applies(&self, kind: PartKind) -> bool {
        self.applies_to.contains(&kind)
    }
}

use PartKind::{Attestation as At, Credential as Cr, Rail as Ra, Verifier as Ve};

/// The twelve properties in vector order, from `registry/properties.toml`
/// (format 1). Embedded until the registry export replaces it.
pub const PROPERTIES: &[PropertyDef] = &[
    PropertyDef {
        id: "use",
        values: &["reusable", "rate", "single"],
        applies_to: &[Cr, At],
    },
    PropertyDef {
        id: "binding",
        values: &["none", "O", "A", "S"],
        applies_to: &[Cr, At],
    },
    PropertyDef {
        id: "theft",
        values: &["bearer", "key-witnessed"],
        applies_to: &[Cr, At],
    },
    PropertyDef {
        id: "link-payment",
        values: &["linkable", "unlinkable"],
        applies_to: &[Cr, Ra],
    },
    PropertyDef {
        id: "link-actions",
        values: &["linkable", "unlinkable"],
        applies_to: &[Cr, At],
    },
    PropertyDef {
        id: "issuer",
        values: &["third-party", "facilitator", "self-issued"],
        applies_to: &[Cr, At, Ve],
    },
    PropertyDef {
        id: "verify",
        values: &["online", "offline"],
        applies_to: &[Cr, At, Ve],
    },
    PropertyDef {
        id: "finality",
        values: &[
            "reversible",
            "freezable",
            "final-at-settlement",
            "final-on-verification",
        ],
        applies_to: &[Cr, Ra, Ve],
    },
    PropertyDef {
        id: "custody",
        values: &["third-party-custodial", "operator-iou", "self-custody"],
        applies_to: &[Cr, Ra, Ve],
    },
    PropertyDef {
        id: "refund",
        values: &["none", "out-of-band", "atomic"],
        applies_to: &[Cr],
    },
    PropertyDef {
        id: "pq",
        values: &["no", "yes"],
        applies_to: &[Cr, At, Ra],
    },
    PropertyDef {
        id: "maturity",
        values: &["experimental", "standard"],
        applies_to: &[Cr, At, Ra, Ve],
    },
];

/// The definition of property `id`.
#[must_use]
pub fn property(id: &str) -> Option<&'static PropertyDef> {
    PROPERTIES.iter().find(|p| p.id == id)
}

/// A registry entry's property map (its `vector` in the export): property
/// ID to value token.
pub type PropertyVector = BTreeMap<String, String>;

/// One entry taking part in an effective vector.
#[derive(Debug, Clone, Copy)]
pub struct Part<'a> {
    /// The entry's kind.
    pub kind: PartKind,
    /// The entry's vector; `None` when the registry has no entry for it,
    /// which counts as every applicable property at its weakest.
    pub vector: Option<&'a PropertyVector>,
}

impl<'a> Part<'a> {
    /// A part with a registry entry.
    #[must_use]
    pub fn known(kind: PartKind, vector: &'a PropertyVector) -> Self {
        Self {
            kind,
            vector: Some(vector),
        }
    }

    /// A part the registry does not list.
    #[must_use]
    pub fn unknown(kind: PartKind) -> Self {
        Self { kind, vector: None }
    }

    fn rank(&self, p: &PropertyDef) -> usize {
        self.vector
            .and_then(|v| v.get(p.id))
            .and_then(|t| p.rank(t))
            .unwrap_or(0)
    }
}

/// An effective property vector: property ID to strength, for the
/// properties that apply to at least one of its parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveVector(BTreeMap<&'static str, usize>);

impl EffectiveVector {
    /// The per-property minimum over `parts`: for each property, over the
    /// parts whose kind it applies to.
    ///
    /// For a pay entry the parts are its scheme, every rail it is
    /// configured with (a credential cannot show which one funded it) and
    /// its verifier.
    #[must_use]
    pub fn compute(parts: &[Part<'_>]) -> Self {
        let mut out = BTreeMap::new();
        for p in PROPERTIES {
            let min = parts
                .iter()
                .filter(|part| p.applies(part.kind))
                .map(|part| part.rank(p))
                .min();
            if let Some(r) = min {
                out.insert(p.id, r);
            }
        }
        Self(out)
    }

    /// The strength of property `id`; `None` when it applies to no part.
    #[must_use]
    pub fn rank(&self, id: &str) -> Option<usize> {
        self.0.get(id).copied()
    }

    /// The value token of property `id`.
    #[must_use]
    pub fn value(&self, id: &str) -> Option<&'static str> {
        let r = self.rank(id)?;
        property(id)?.value(r)
    }

    /// The vector as tokens, for a judge or a log.
    #[must_use]
    pub fn to_tokens(&self) -> BTreeMap<&'static str, &'static str> {
        self.0
            .iter()
            .filter_map(|(id, r)| Some((*id, property(id)?.value(*r)?)))
            .collect()
    }
}

/// Why a route's policy cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// `require` names a property the table does not define.
    #[error("require names an unknown property {0}")]
    UnknownProperty(String),
    /// `require` gives a property a value the table does not define.
    #[error("require gives {property} the unknown value {value}")]
    UnknownValue {
        /// The property.
        property: String,
        /// The value as written.
        value: String,
    },
    /// No enabled scheme satisfies the route: the gate refuses to start.
    #[error("route {0} can be satisfied by none of its enabled schemes")]
    Unsatisfiable(String),
    /// A required attestation fails the route's policy; dropping it would
    /// lift the requirement, so the gate refuses to start.
    #[error("route {route} requires attestation {scheme}, which fails its policy")]
    RequiredAttestation {
        /// The route.
        route: String,
        /// The attestation scheme.
        scheme: String,
    },
}

/// A route's `require`, parsed: property to minimum strength.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Require(BTreeMap<&'static str, usize>);

impl Require {
    /// Parses a manifest route's `require` (9.1). Each value must be a
    /// string token of its property. An unknown property or value is an
    /// error: a gate must not run a requirement it cannot enforce.
    pub fn parse(raw: Option<&BTreeMap<String, Value>>) -> Result<Self, PolicyError> {
        let mut out = BTreeMap::new();
        for (k, v) in raw.into_iter().flatten() {
            let p = property(k).ok_or_else(|| PolicyError::UnknownProperty(k.clone()))?;
            let unknown = || PolicyError::UnknownValue {
                property: k.clone(),
                value: v.to_string(),
            };
            let token = v.as_str().ok_or_else(unknown)?;
            out.insert(p.id, p.rank(token).ok_or_else(unknown)?);
        }
        Ok(Self(out))
    }

    /// Parses `property=value` pairs, for configuration and tests.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PolicyError> {
        let raw: BTreeMap<String, Value> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_owned(), Value::String(v.to_owned())))
            .collect();
        Self::parse(Some(&raw))
    }

    /// True when every required property of `v` is at least as strong as
    /// required. A property that applies to none of `v`'s parts does not
    /// constrain it.
    #[must_use]
    pub fn satisfied_by(&self, v: &EffectiveVector) -> bool {
        self.0
            .iter()
            .all(|(id, min)| v.rank(id).is_none_or(|r| r >= *min))
    }
}

/// A scheme a route enables, with its effective vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Scheme ID.
    pub scheme: String,
    /// `None` for a value scheme, the effect for an attestation.
    pub effect: Option<Effect>,
    /// The effective vector.
    pub vector: EffectiveVector,
}

/// The schemes a route may list in its offers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// Value schemes, in the route's order.
    pub pay: Vec<String>,
    /// Attestations, in the route's order.
    pub attest: Vec<String>,
}

/// A route's policy: its `require` and whether experimental entries are
/// allowed on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePolicy {
    /// The route ID, for errors.
    pub route: String,
    /// The parsed `require`.
    pub require: Require,
    /// Experimental entries (by `maturity`) need this on each route that
    /// uses them (overview rule; registry start-up refusal).
    pub allow_experimental: bool,
}

impl RoutePolicy {
    /// True when the route admits a scheme with effective vector `v`.
    #[must_use]
    pub fn admits(&self, v: &EffectiveVector) -> bool {
        let experimental = v.value("maturity") == Some("experimental");
        self.require.satisfied_by(v) && (self.allow_experimental || !experimental)
    }

    /// The gate's start-up check: which enabled schemes the route may list.
    ///
    /// The gate never lists a scheme that fails the policy, and refuses to
    /// start when no value scheme passes and no passing attestation waives,
    /// or when a required attestation fails.
    pub fn select(&self, pay: &[Candidate], attest: &[Candidate]) -> Result<Selection, PolicyError> {
        let mut sel = Selection::default();
        for c in pay.iter().filter(|c| self.admits(&c.vector)) {
            sel.pay.push(c.scheme.clone());
        }
        let mut waives = false;
        for c in attest {
            if self.admits(&c.vector) {
                waives |= c.effect == Some(Effect::Waive);
                sel.attest.push(c.scheme.clone());
            } else if c.effect == Some(Effect::Required) {
                return Err(PolicyError::RequiredAttestation {
                    route: self.route.clone(),
                    scheme: c.scheme.clone(),
                });
            }
        }
        if sel.pay.is_empty() && !waives {
            return Err(PolicyError::Unsatisfiable(self.route.clone()));
        }
        Ok(sel)
    }
}
