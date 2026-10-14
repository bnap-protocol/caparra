//! Ranking the pay entries a wallet could use (overview, "Negotiation",
//! client choice steps 3 and 4).
//!
//! Each candidate's cost is its amount in the budget's unit (sat) plus what
//! paying it takes on top: Lightning routing fees for schemes the pay
//! source settles, notes input fees, and the routing fee of a top-up. A
//! linkable candidate is dropped while an unlinkable one can pay (the
//! default), or ranked with the policy's penalty added. The server's order,
//! offer by offer and entry by entry, breaks ties.

use crate::policy::{Linkability, Policy};

/// One pay entry the wallet could pay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The offer's position in the 402, server order.
    pub offer: usize,
    /// The pay entry's position in its offer.
    pub entry: usize,
    /// The scheme ID.
    pub scheme: String,
    /// What the wallet sends as value, in sat.
    pub value_sat: u64,
    /// What it pays on top: routing fee ceiling, input fees.
    pub fee_sat: u64,
    /// Whether paying it links the payment or the action to the payer.
    pub linkable: bool,
}

impl Candidate {
    /// The most it can cost: value plus fees.
    #[must_use]
    pub fn cost(&self) -> u64 {
        self.value_sat.saturating_add(self.fee_sat)
    }

    fn rank_cost(&self, policy: &Policy) -> u64 {
        if self.linkable {
            self.cost().saturating_add(policy.linkable_penalty_sat)
        } else {
            self.cost()
        }
    }
}

/// An amount in a pay entry's unit, in sat; `None` for a unit the wallet
/// cannot convert (fiat and on-chain assets need a rate it does not have).
/// msat round up: the wallet never assumes it pays less than asked.
#[must_use]
pub fn to_sat(amount: u64, unit: &str) -> Option<u64> {
    match unit {
        "sat" => Some(amount),
        "msat" => Some(amount.div_ceil(1000)),
        _ => None,
    }
}

/// Orders the candidates, cheapest first, after the linkability rule.
#[must_use]
pub fn rank(mut cands: Vec<Candidate>, policy: &Policy) -> Vec<Candidate> {
    match policy.linkable {
        Linkability::Never => cands.retain(|c| !c.linkable),
        Linkability::Fallback if cands.iter().any(|c| !c.linkable) => {
            cands.retain(|c| !c.linkable);
        }
        Linkability::Fallback | Linkability::Allow => {}
    }
    cands.sort_by_key(|c| (c.rank_cost(policy), c.offer, c.entry));
    cands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(
        offer: usize,
        entry: usize,
        scheme: &str,
        value: u64,
        fee: u64,
        linkable: bool,
    ) -> Candidate {
        Candidate {
            offer,
            entry,
            scheme: scheme.into(),
            value_sat: value,
            fee_sat: fee,
            linkable,
        }
    }

    fn order(v: &[Candidate]) -> Vec<&str> {
        v.iter().map(|c| c.scheme.as_str()).collect()
    }

    #[test]
    fn cheapest_total_wins_and_fees_count() {
        let mut p = Policy::default();
        p.linkable = Linkability::Allow;
        p.linkable_penalty_sat = 0;
        let r = rank(
            vec![
                c(0, 0, "a", 20, 5, false),
                c(0, 1, "b", 21, 0, false),
                c(1, 0, "c", 19, 7, false),
            ],
            &p,
        );
        assert_eq!(order(&r), ["b", "a", "c"]);
    }

    #[test]
    fn server_order_breaks_ties() {
        let p = Policy::default();
        let r = rank(
            vec![
                c(1, 0, "late", 10, 0, false),
                c(0, 1, "second", 10, 0, false),
                c(0, 0, "first", 10, 0, false),
            ],
            &p,
        );
        assert_eq!(order(&r), ["first", "second", "late"]);
    }

    #[test]
    fn linkable_only_as_a_fallback_by_default() {
        let p = Policy::default();
        let r = rank(
            vec![c(0, 0, "l402", 1, 0, true), c(0, 1, "notes", 50, 0, false)],
            &p,
        );
        assert_eq!(order(&r), ["notes"]);
        let r = rank(
            vec![c(0, 0, "l402", 1, 0, true), c(0, 1, "mpp", 2, 0, true)],
            &p,
        );
        assert_eq!(order(&r), ["l402", "mpp"]);
    }

    #[test]
    fn the_penalty_ranks_linkable_schemes_lower() {
        let mut p = Policy::default();
        p.linkable = Linkability::Allow;
        p.linkable_penalty_sat = 10;
        let r = rank(
            vec![c(0, 0, "l402", 15, 0, true), c(0, 1, "notes", 20, 0, false)],
            &p,
        );
        assert_eq!(order(&r), ["notes", "l402"]);
        p.linkable_penalty_sat = 4;
        let r = rank(
            vec![c(0, 0, "l402", 15, 0, true), c(0, 1, "notes", 20, 0, false)],
            &p,
        );
        assert_eq!(order(&r), ["l402", "notes"]);
        p.linkable = Linkability::Never;
        let r = rank(vec![c(0, 0, "l402", 1, 0, true)], &p);
        assert!(r.is_empty());
    }

    #[test]
    fn units() {
        assert_eq!(to_sat(21, "sat"), Some(21));
        assert_eq!(to_sat(21_001, "msat"), Some(22));
        assert_eq!(to_sat(21_000, "msat"), Some(21));
        assert_eq!(to_sat(5, "USD"), None);
    }
}
