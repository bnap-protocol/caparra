//! The spend policy, enforced in code (overview, "Agents and clients"):
//! spending caps, the schemes a wallet may pay with, the properties it
//! requires of them, how it treats linkable schemes, and whether it may use
//! experimental ones.
//!
//! A person sets the policy (`bnap budget set`). A model, through the MCP
//! server, can only narrow it for its own session: [`SessionCaps`] holds
//! caps at or below the person's, and nothing a model sends can name a
//! scheme, lift a property or raise a cap above the hard cap.
//!
//! Every payment is first reserved in the ledger at its most expensive
//! (the value sent plus the most the pay source may take in fees), checked
//! against every cap, and later trued up to what it cost in the end: value
//! that left the wallet, routing fees included, minus change that came back.

use std::collections::BTreeMap;

use bnap_core::policy::{EffectiveVector, PartKind, property};
use serde::{Deserialize, Serialize};

use crate::error::{CapKind, Refusal, Result};
use crate::registry::{Registry, linkable};

/// The length of the rolling window of the per-origin and daily caps.
pub const DAY: u64 = 86_400;

/// The caps a person sets, in sat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    /// The most one request may cost.
    pub per_request: u64,
    /// The most one origin may get in any 24 hours.
    pub per_origin_day: u64,
    /// The most one task (a CLI `--task`, an MCP session) may spend.
    pub per_task: u64,
    /// The most every origin together may get in any 24 hours.
    pub daily: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            per_request: 100,
            per_origin_day: 1_000,
            per_task: 1_000,
            daily: 5_000,
        }
    }
}

impl Caps {
    /// The cap of one kind.
    #[must_use]
    pub fn get(&self, kind: CapKind) -> u64 {
        match kind {
            CapKind::PerRequest => self.per_request,
            CapKind::PerOrigin => self.per_origin_day,
            CapKind::PerTask => self.per_task,
            CapKind::Daily => self.daily,
        }
    }

    /// Sets the cap of one kind.
    pub fn set(&mut self, kind: CapKind, sat: u64) {
        match kind {
            CapKind::PerRequest => self.per_request = sat,
            CapKind::PerOrigin => self.per_origin_day = sat,
            CapKind::PerTask => self.per_task = sat,
            CapKind::Daily => self.daily = sat,
        }
    }
}

/// Every cap kind, in the order they are checked.
pub const CAP_KINDS: [CapKind; 4] = [
    CapKind::PerRequest,
    CapKind::PerTask,
    CapKind::PerOrigin,
    CapKind::Daily,
];

/// How the wallet treats schemes that link a payment or actions to the
/// payer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Linkability {
    /// Never pay with a linkable scheme.
    Never,
    /// Use a linkable scheme only when no unlinkable one can pay
    /// (overview, "Negotiation" step 3: the default).
    #[default]
    Fallback,
    /// Rank linkable schemes with the others, adding the penalty to their
    /// cost.
    Allow,
}

impl Linkability {
    /// The spelling in JSON and on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Fallback => "fallback",
            Self::Allow => "allow",
        }
    }

    /// Reads a spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "never" => Some(Self::Never),
            "fallback" => Some(Self::Fallback),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }
}

/// The most a pay source may take in Lightning routing fees for one
/// payment: `base_sat + ceil(amount × ppm / 10⁶)`. The whole ceiling is
/// reserved against the caps before paying, so fees count against them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    /// Fixed part, sat.
    pub base_sat: u64,
    /// Proportional part, parts per million.
    pub ppm: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            base_sat: 2,
            ppm: 5_000,
        }
    }
}

impl FeePolicy {
    /// The fee ceiling for a payment of `amount` sat.
    #[must_use]
    pub fn max_fee(&self, amount: u64) -> u64 {
        let prop = u128::from(amount) * u128::from(self.ppm);
        let prop = u64::try_from(prop.div_ceil(1_000_000)).unwrap_or(u64::MAX);
        self.base_sat.saturating_add(prop)
    }
}

/// The value schemes this wallet can pay with.
pub const VALUE_SCHEMES: [&str; 3] = [
    bnap_scheme_notes::SCHEME_ID,
    bnap_scheme_l402::SCHEME_ID,
    bnap_scheme_mpp::SCHEME_ID,
];

/// The attestation schemes this wallet can send.
pub const ATTEST_SCHEMES: [&str; 2] = [bnap_scheme_webbotauth::ID, bnap_scheme_dpop::DPOP];

/// The spend policy a person configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Hard caps.
    pub caps: Caps,
    /// Value schemes the wallet may pay with.
    pub allowed_schemes: Vec<String>,
    /// Properties every value scheme must have at least, as
    /// `property = value` tokens of the registry's property table.
    pub require: BTreeMap<String, String>,
    /// How linkable schemes are treated.
    pub linkable: Linkability,
    /// What a linkable scheme's cost is raised by when ranking, sat.
    pub linkable_penalty_sat: u64,
    /// May pay with schemes whose registry maturity is `experimental`.
    pub allow_experimental: bool,
    /// Attestation schemes the wallet may send (each identifies the
    /// wallet's key to the server, so none by default).
    pub attest: Vec<String>,
    /// The most the wallet holds in notes at one origin (the operator's
    /// IOU; bnap:notes 15 recommends 5,000 sat).
    pub max_balance_per_origin: u64,
    /// Lightning routing fee ceiling.
    pub fee: FeePolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            caps: Caps::default(),
            allowed_schemes: VALUE_SCHEMES.iter().map(|s| (*s).to_owned()).collect(),
            require: BTreeMap::new(),
            linkable: Linkability::default(),
            linkable_penalty_sat: 10,
            allow_experimental: false,
            attest: Vec::new(),
            max_balance_per_origin: 5_000,
            fee: FeePolicy::default(),
        }
    }
}

impl Policy {
    /// Checks a `property = value` requirement before it is stored: the
    /// property and the value must be in the registry's table.
    pub fn check_requirement(prop: &str, value: &str) -> Result<()> {
        let def = property(prop).ok_or_else(|| {
            Refusal::bad_input(format!(
                "Unknown property {prop}; see the registry's table."
            ))
        })?;
        def.rank(value).ok_or_else(|| {
            Refusal::bad_input(format!("Unknown value {value} for property {prop}."))
        })?;
        Ok(())
    }

    /// Whether the policy lets the wallet pay with `scheme` at all, by the
    /// registry's view of it. Returns the effective vector it judged.
    pub fn admit_scheme(&self, registry: &Registry, scheme: &str) -> Result<EffectiveVector> {
        if !self.allowed_schemes.iter().any(|s| s == scheme) || !VALUE_SCHEMES.contains(&scheme) {
            return Err(Refusal::scheme_not_allowed(scheme));
        }
        let v = registry.effective(scheme, PartKind::Credential);
        if !self.allow_experimental && v.value("maturity") != Some("standard") {
            return Err(Refusal::experimental(scheme));
        }
        for (prop, need) in &self.require {
            let def =
                property(prop).ok_or_else(|| Refusal::property(scheme, prop, "unknown", need))?;
            let min = def
                .rank(need)
                .ok_or_else(|| Refusal::property(scheme, prop, "unknown", need))?;
            match v.rank(def.id) {
                // The property does not apply to this kind of part.
                None => {}
                Some(r) if r >= min => {}
                Some(_) => {
                    let have = v.value(def.id).unwrap_or("unknown");
                    return Err(Refusal::property(scheme, prop, have, need));
                }
            }
        }
        if self.linkable == Linkability::Never && linkable(&v) {
            return Err(Refusal::linkable(scheme));
        }
        Ok(v)
    }

    /// Whether the policy lets the wallet send this attestation.
    #[must_use]
    pub fn may_attest(&self, scheme: &str) -> bool {
        ATTEST_SCHEMES.contains(&scheme) && self.attest.iter().any(|s| s == scheme)
    }
}

/// Caps a model narrowed for its own session, never above the hard caps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCaps {
    /// Per-request cap, if narrowed.
    pub per_request: Option<u64>,
    /// Per-task cap, if narrowed.
    pub per_task: Option<u64>,
    /// Per-origin cap, if narrowed.
    pub per_origin_day: Option<u64>,
    /// Daily cap, if narrowed.
    pub daily: Option<u64>,
}

impl SessionCaps {
    fn slot(&mut self, kind: CapKind) -> &mut Option<u64> {
        match kind {
            CapKind::PerRequest => &mut self.per_request,
            CapKind::PerTask => &mut self.per_task,
            CapKind::PerOrigin => &mut self.per_origin_day,
            CapKind::Daily => &mut self.daily,
        }
    }

    /// Sets a session cap. Refuses a value above the person's hard cap.
    pub fn set(&mut self, hard: &Caps, kind: CapKind, sat: u64) -> Result<()> {
        let h = hard.get(kind);
        if sat > h {
            return Err(Refusal::above_hard_cap(kind, sat, h));
        }
        *self.slot(kind) = Some(sat);
        Ok(())
    }

    /// The caps in force: each the lower of the hard cap and the session's.
    #[must_use]
    pub fn effective(&self, hard: &Caps) -> Caps {
        let pick = |h: u64, s: Option<u64>| s.map_or(h, |s| s.min(h));
        Caps {
            per_request: pick(hard.per_request, self.per_request),
            per_origin_day: pick(hard.per_origin_day, self.per_origin_day),
            per_task: pick(hard.per_task, self.per_task),
            daily: pick(hard.daily, self.daily),
        }
    }
}

/// One payment in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Its ID.
    pub id: String,
    /// The origin paid.
    pub origin: String,
    /// The task it was paid for.
    pub task: String,
    /// When it was reserved.
    pub at: u64,
    /// What was reserved: the most it can cost.
    pub reserved: u64,
    /// What it cost in the end, once known.
    pub actual: Option<u64>,
    /// What it paid for, for `bnap budget`.
    pub what: String,
}

impl LedgerEntry {
    /// What it counts against the caps: its final cost once known, its
    /// reservation until then.
    #[must_use]
    pub fn counted(&self) -> u64 {
        self.actual.unwrap_or(self.reserved)
    }
}

/// What the ledger says each cap still allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Remaining {
    /// Left for this request.
    pub per_request: u64,
    /// Left for this task.
    pub per_task: u64,
    /// Left for this origin in the last 24 hours.
    pub per_origin_day: u64,
    /// Left for every origin in the last 24 hours.
    pub daily: u64,
}

impl Remaining {
    /// What one cap kind leaves.
    #[must_use]
    pub fn get(&self, kind: CapKind) -> u64 {
        match kind {
            CapKind::PerRequest => self.per_request,
            CapKind::PerTask => self.per_task,
            CapKind::PerOrigin => self.per_origin_day,
            CapKind::Daily => self.daily,
        }
    }

    /// The least any cap leaves.
    #[must_use]
    pub fn min(&self) -> u64 {
        self.per_request
            .min(self.per_task)
            .min(self.per_origin_day)
            .min(self.daily)
    }
}

/// What the caps leave for a new payment to `origin` in `task` at `now`,
/// given the ledger.
#[must_use]
pub fn remaining(
    caps: &Caps,
    ledger: &[LedgerEntry],
    origin: &str,
    task: &str,
    now: u64,
) -> Remaining {
    let since = now.saturating_sub(DAY);
    let sum = |f: &dyn Fn(&LedgerEntry) -> bool| -> u64 {
        ledger
            .iter()
            .filter(|e| f(e))
            .fold(0u64, |a, e| a.saturating_add(e.counted()))
    };
    let task_spent = sum(&|e| e.task == task);
    let origin_spent = sum(&|e| e.origin == origin && e.at > since);
    let day_spent = sum(&|e| e.at > since);
    Remaining {
        per_request: caps.per_request,
        per_task: caps.per_task.saturating_sub(task_spent),
        per_origin_day: caps.per_origin_day.saturating_sub(origin_spent),
        daily: caps.daily.saturating_sub(day_spent),
    }
}

/// Checks that a payment of at most `cost` sat fits every cap.
pub fn check(
    caps: &Caps,
    ledger: &[LedgerEntry],
    origin: &str,
    task: &str,
    cost: u64,
    now: u64,
) -> Result<()> {
    let left = remaining(caps, ledger, origin, task, now);
    for kind in CAP_KINDS {
        let r = left.get(kind);
        if cost > r {
            return Err(Refusal::budget(kind, cost, r));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;

    fn entry(origin: &str, task: &str, at: u64, sat: u64) -> LedgerEntry {
        LedgerEntry {
            id: format!("{origin}{at}"),
            origin: origin.into(),
            task: task.into(),
            at,
            reserved: sat,
            actual: None,
            what: String::new(),
        }
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn every_cap_is_checked_and_names_what_it_leaves() {
        let caps = Caps {
            per_request: 100,
            per_origin_day: 300,
            per_task: 250,
            daily: 1_000,
        };
        let ledger = vec![
            entry("https://a.example", "t1", NOW - 10, 90),
            entry("https://a.example", "t2", NOW - 20, 90),
            entry("https://a.example", "t1", NOW - DAY - 5, 500),
        ];
        let e = check(&caps, &ledger, "https://a.example", "t9", 101, NOW).unwrap_err();
        assert_eq!(
            (e.code, e.cap, e.remaining),
            (Code::BudgetExceeded, Some(CapKind::PerRequest), Some(100))
        );
        // t1 spent 590 in all (the per-task cap has no window).
        let e = check(&caps, &ledger, "https://b.example", "t1", 10, NOW).unwrap_err();
        assert_eq!((e.cap, e.remaining), (Some(CapKind::PerTask), Some(0)));
        // a.example got 180 in the last 24 hours; the old 500 is outside.
        let e = check(&caps, &ledger, "https://a.example", "t9", 100, NOW)
            .map(|()| 0)
            .unwrap_or(1);
        assert_eq!(e, 0);
        let ledger2 = [
            ledger.clone(),
            vec![entry("https://a.example", "t3", NOW - 1, 100)],
        ]
        .concat();
        let e = check(&caps, &ledger2, "https://a.example", "t9", 30, NOW).unwrap_err();
        assert_eq!((e.cap, e.remaining), (Some(CapKind::PerOrigin), Some(20)));
        assert!(e.message.contains("leaves 20 sat"), "{}", e.message);
    }

    #[test]
    fn a_final_cost_replaces_the_reservation() {
        let caps = Caps {
            per_request: 1_000,
            per_origin_day: 1_000,
            per_task: 1_000,
            daily: 100,
        };
        let mut e = entry("o", "t", NOW, 100);
        assert!(check(&caps, std::slice::from_ref(&e), "o", "t", 1, NOW).is_err());
        e.actual = Some(40);
        assert!(check(&caps, std::slice::from_ref(&e), "o", "t", 60, NOW).is_ok());
        assert!(check(&caps, std::slice::from_ref(&e), "o", "t", 61, NOW).is_err());
    }

    #[test]
    fn a_session_never_raises_a_cap() {
        let hard = Caps::default();
        let mut s = SessionCaps::default();
        let e = s
            .set(&hard, CapKind::PerRequest, hard.per_request + 1)
            .unwrap_err();
        assert_eq!(e.code, Code::AboveHardCap);
        assert_eq!(s.effective(&hard), hard);
        s.set(&hard, CapKind::PerRequest, 7).unwrap();
        assert_eq!(s.effective(&hard).per_request, 7);
        // A lower hard cap set later wins over an older session cap.
        let mut lower = hard;
        lower.per_request = 3;
        assert_eq!(s.effective(&lower).per_request, 3);
    }

    #[test]
    fn fees_round_up() {
        let f = FeePolicy {
            base_sat: 1,
            ppm: 1_000,
        };
        assert_eq!(f.max_fee(0), 1);
        assert_eq!(f.max_fee(1), 2);
        assert_eq!(f.max_fee(1_000), 2);
        assert_eq!(f.max_fee(1_001), 3);
        assert_eq!(
            FeePolicy {
                base_sat: u64::MAX,
                ppm: 1
            }
            .max_fee(5),
            u64::MAX
        );
    }

    #[test]
    fn schemes_are_judged_by_the_registry() {
        let r = Registry::embedded();
        let mut p = Policy::default();
        // Every listed value scheme is experimental: refused without the opt-in.
        let e = p.admit_scheme(r, "bnap:notes").unwrap_err();
        assert_eq!(
            (e.code, e.property.as_deref()),
            (Code::Policy, Some("maturity"))
        );
        p.allow_experimental = true;
        p.admit_scheme(r, "bnap:notes").unwrap();
        p.admit_scheme(r, "httpauth:L402").unwrap();
        // Not in the allowed list.
        let e = p.admit_scheme(r, "cashu:nut22").unwrap_err();
        assert_eq!(e.scheme.as_deref(), Some("cashu:nut22"));
        p.allowed_schemes.push("cashu:nut22".into());
        assert!(
            p.admit_scheme(r, "cashu:nut22").is_err(),
            "not a scheme this wallet can pay with"
        );
        // A required property.
        p.require.insert("link-payment".into(), "unlinkable".into());
        let e = p.admit_scheme(r, "httpauth:L402").unwrap_err();
        assert_eq!(e.property.as_deref(), Some("link-payment"));
        assert!(e.message.contains("link-payment=linkable"), "{}", e.message);
        p.admit_scheme(r, "bnap:notes").unwrap();
        p.require.clear();
        p.linkable = Linkability::Never;
        assert_eq!(
            p.admit_scheme(r, "payment:lightning/charge")
                .unwrap_err()
                .code,
            Code::Policy
        );
        assert!(Policy::check_requirement("binding", "S").is_ok());
        assert!(Policy::check_requirement("binding", "X").is_err());
        assert!(Policy::check_requirement("colour", "S").is_err());
    }
}
