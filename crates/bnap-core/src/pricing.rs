//! Pricing, attestations and metering (draft-00 section 7).
//!
//! The offer is the quote. At verification time the gate uses only what the
//! offer says:
//!
//! ```text
//! price(base):
//!   p = base
//!   for each verified attestation, in offer order, effect waive:     p = 0
//!   for each verified attestation, in offer order, effect discount:  p = p - ⌊p × value / 10000⌋
//!   if p > 0: for the first verified quota attestation, in offer order, whose counter has room:
//!                                                                     p = 0, and add its counter to the commit
//!   return p
//!
//! admit:
//!   for each required attestation in the offer: if not verified -> POLICY
//!   p = price(entry.amount, or 0 if the credential has no pay)
//!   if p > 0 and no pay                                               -> UNDERPAID
//!   if the scheme's verified value < p                                -> UNDERPAID
//! ```
//!
//! **Without pay** the build does not use the literal base of 0. Read
//! literally, `price(0)` is always 0, so `if p > 0 and no pay` can never
//! fire and a credential with no `pay` and no verified waive (for example
//! one carrying only a discount attestation, verified or not) would be
//! admitted for free. [`admit`] instead prices a credential without pay at
//! [`NO_PAY_BASE`] (2⁶⁴ − 1): it is admitted only when its verified
//! attestations alone bring the price to 0, through a waive, a full
//! discount or a quota with room (ERRATA N3b-1, owner decision needed).
//!
//! [`admit`] makes the attestation and quota decision once, at admission,
//! and returns it inside the [`Admission`]. [`Admission::settle`] reuses
//! that decision for the charge, so settlement never consumes a quota
//! again. Only attestations of binding class S, A or O change the price; a
//! waive, discount or quota by a class None scheme has no effect.
//!
//! All arithmetic is exact. Metered charges are computed in 128 bits, which
//! holds every `units × rate` product, so a product beyond 2⁶⁴ simply
//! yields the ceiling.

use crate::class::BindingClass;
use crate::error::ErrorCode;
use crate::hash::{CounterKey, UseId};
use crate::ids::quota_key;
use crate::offer::{AttestEntry, Effect, MAX_DISCOUNT_BP, OfferFields};
use crate::response::Status;
use crate::store::CounterUse;

/// An attestation the credential carries that its scheme verified.
///
/// Attestations that failed verification are left out: one that is not
/// required has no effect and causes no error (section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttest {
    /// Scheme ID, as in the offer's attest entry.
    pub scheme: String,
    /// The scheme's binding class, from the registry.
    pub class: BindingClass,
    /// The socket `UseId` of the stable identity a quota counts against,
    /// built from the local ID the registry declares as `quota_id`
    /// ([`crate::ids::use_id`]). `None` for schemes that cannot carry a
    /// quota.
    pub quota_id: Option<UseId>,
}

impl VerifiedAttest {
    /// A verified attestation without a quota identity.
    #[must_use]
    pub fn new(scheme: impl Into<String>, class: BindingClass) -> Self {
        Self {
            scheme: scheme.into(),
            class,
            quota_id: None,
        }
    }

    /// The same, with the `UseId` a quota counts against.
    #[must_use]
    pub fn with_quota_id(mut self, id: UseId) -> Self {
        self.quota_id = Some(id);
        self
    }
}

/// A quota attestation chosen at admission: its counter joins the commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaUse {
    /// Scheme ID of the quota attestation.
    pub scheme: String,
    /// The counter, its limit (the entry's `value`) and when its epoch ends.
    pub counter: CounterUse,
}

/// The attestation results and the quota decision fixed at admission.
///
/// [`PriceDecision::price`] is `price(base)` of section 7 under this
/// decision, for any base: the entry amount at admission, the metered
/// amount at settlement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PriceDecision {
    /// The first verified waive in offer order, if any.
    pub waive: Option<String>,
    /// Verified discounts in offer order: scheme ID and basis points.
    pub discounts: Vec<(String, u64)>,
    /// The quota chosen at admission, if the price was above 0 and a
    /// verified quota had room.
    pub quota: Option<QuotaUse>,
    /// Verified attestations whose waive, discount or quota was ignored
    /// because their binding class is None (section 7).
    pub ignored: Vec<String>,
}

impl PriceDecision {
    /// `price(base)` under this decision.
    #[must_use]
    pub fn price(&self, base: u64) -> u64 {
        // price_wide never exceeds its input.
        narrow(self.price_wide(u128::from(base)))
    }

    /// `price(base)` in 128 bits, for metered amounts beyond 2⁶⁴.
    #[must_use]
    pub fn price_wide(&self, base: u128) -> u128 {
        let p = self.price_before_quota(base);
        if p > 0 && self.quota.is_some() { 0 } else { p }
    }

    fn price_before_quota(&self, base: u128) -> u128 {
        if self.waive.is_some() {
            return 0;
        }
        self.discounts
            .iter()
            .fold(base, |p, (_, bp)| discount(p, *bp))
    }

    /// The counter to add to the commit, if a quota was chosen.
    #[must_use]
    pub fn quota_counter(&self) -> Option<&CounterUse> {
        self.quota.as_ref().map(|q| &q.counter)
    }
}

/// `p - ⌊p × bp / 10000⌋`, exact for every `p`: the product is split so it
/// never overflows.
fn discount(p: u128, bp: u64) -> u128 {
    let bp = u128::from(bp.min(MAX_DISCOUNT_BP));
    let off = (p / 10_000) * bp + (p % 10_000) * bp / 10_000;
    p - off
}

/// A value at most `u64::MAX` back in 64 bits.
fn narrow(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// The quota attestations that could apply, in offer order, with their
/// counter keys at `now`.
///
/// A gate reads these counters from the use store before it calls
/// [`admit`], which picks the first one with room. Only verified quota
/// attestations of class S, A or O that name a quota identity are listed.
#[must_use]
pub fn quota_candidates(
    offer: &OfferFields,
    verified: &[VerifiedAttest],
    now: u64,
) -> Vec<QuotaUse> {
    offer
        .attest
        .iter()
        .filter(|e| e.effect == Effect::Quota)
        .filter_map(|e| {
            let v = find(verified, &e.scheme)?;
            if !v.class.may_affect_price() {
                return None;
            }
            quota_use(e, v.quota_id.as_ref()?, now)
        })
        .collect()
}

fn quota_use(e: &AttestEntry, id: &UseId, now: u64) -> Option<QuotaUse> {
    let (limit, epoch) = (e.value?, e.epoch?);
    let key = quota_key(id, limit, epoch, now)?;
    Some(QuotaUse {
        scheme: e.scheme.clone(),
        counter: CounterUse {
            key,
            limit,
            resets_at: epoch_end(now, epoch),
        },
    })
}

/// The end of the epoch window that holds `now`: `(⌊now / epoch⌋ + 1) × epoch`.
pub(crate) fn epoch_end(now: u64, epoch: u64) -> u64 {
    let window = now.checked_div(epoch).unwrap_or(0);
    window.saturating_add(1).saturating_mul(epoch)
}

fn find<'a>(verified: &'a [VerifiedAttest], scheme: &str) -> Option<&'a VerifiedAttest> {
    verified.iter().find(|v| v.scheme == scheme)
}

/// Makes the attestation and quota decision of `price(base)` for `offer`.
///
/// `counter` returns a counter's current value, as read from the use store;
/// a quota has room when its counter is below its limit.
#[must_use]
pub fn decide(
    offer: &OfferFields,
    verified: &[VerifiedAttest],
    base: u64,
    now: u64,
    counter: impl Fn(&CounterKey) -> u64,
) -> PriceDecision {
    let mut d = PriceDecision::default();
    for e in &offer.attest {
        let Some(v) = find(verified, &e.scheme) else {
            continue;
        };
        let affects = matches!(e.effect, Effect::Waive | Effect::Discount | Effect::Quota);
        if affects && !v.class.may_affect_price() {
            d.ignored.push(e.scheme.clone());
            continue;
        }
        match e.effect {
            Effect::Waive if d.waive.is_none() => d.waive = Some(e.scheme.clone()),
            Effect::Discount => {
                if let Some(bp) = e.value {
                    d.discounts.push((e.scheme.clone(), bp));
                }
            }
            _ => {}
        }
    }
    if d.price_before_quota(u128::from(base)) > 0 {
        d.quota = quota_candidates(offer, verified, now)
            .into_iter()
            .find(|q| counter(&q.counter.key) < q.counter.limit);
    }
    d
}

/// The base [`admit`] prices a credential without `pay` at: the largest
/// amount, so only a waive, a full discount or a quota makes it 0
/// (ERRATA N3b-1).
pub const NO_PAY_BASE: u64 = u64::MAX;

/// The value scheme the credential pays with and the value its `verify`
/// returned, in the chosen pay entry's unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayValue<'a> {
    /// Scheme ID of the credential's `pay` part.
    pub scheme: &'a str,
    /// Verified value, in the pay entry's unit.
    pub value: u64,
}

/// What [`admit`] needs.
#[derive(Debug, Clone, Copy)]
pub struct AdmitInput<'a> {
    /// The offer the credential uses, already checked (4.4).
    pub offer: &'a OfferFields,
    /// The credential's value scheme, if it has `pay`.
    pub pay: Option<PayValue<'a>>,
    /// Every attestation that verified.
    pub attest: &'a [VerifiedAttest],
    /// The gate's clock, for quota epochs.
    pub now: u64,
}

/// The chosen pay entry, as admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedPay {
    /// Index of the entry in the offer's `pay`.
    pub index: usize,
    /// Scheme ID.
    pub scheme: String,
    /// The entry's unit; the Response's `unit`.
    pub unit: String,
    /// The entry's amount; the ceiling in a metered offer.
    pub amount: u64,
    /// Price per 1,000 meter units, in a metered offer.
    pub rate: Option<u64>,
    /// The value the scheme verified.
    pub value: u64,
}

/// The result of admission: the decision, the price and the pay entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// Attestation results and quota decision, reused at settlement.
    pub decision: PriceDecision,
    /// `price(entry.amount)`, or `price(NO_PAY_BASE)` without pay (then
    /// always 0): the effective price; the most a metered action can be
    /// charged.
    pub price: u64,
    /// The chosen pay entry, when the credential has `pay`.
    pub pay: Option<AdmittedPay>,
    /// The offer is metered.
    pub metered: bool,
}

/// Why admission failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PriceError {
    /// POLICY: a required attestation did not verify.
    #[error("required attestation {0} did not verify")]
    Policy(String),
    /// UNDERPAID: the verified value is below the effective price, or the
    /// price is above 0 and the credential has no pay.
    #[error("value {value} below the effective price {price}")]
    Underpaid {
        /// The effective price.
        price: u64,
        /// The verified value (0 without pay).
        value: u64,
    },
    /// `NOT_OFFERED`: the pay scheme has no entry in the offer.
    #[error("scheme {0} is not offered")]
    NotOffered(String),
}

impl PriceError {
    /// The draft-00 error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Policy(_) => ErrorCode::Policy,
            Self::Underpaid { .. } => ErrorCode::Underpaid,
            Self::NotOffered(_) => ErrorCode::NotOffered,
        }
    }
}

/// Admission (section 7): required attestations, `price`, and the value
/// check; without pay, see [`NO_PAY_BASE`]. `counter` returns a counter's current value from the use store,
/// for the quota candidates of [`quota_candidates`].
pub fn admit(
    input: &AdmitInput<'_>,
    counter: impl Fn(&CounterKey) -> u64,
) -> Result<Admission, PriceError> {
    let offer = input.offer;
    for e in offer.attest.iter().filter(|e| e.effect == Effect::Required) {
        if find(input.attest, &e.scheme).is_none() {
            return Err(PriceError::Policy(e.scheme.clone()));
        }
    }
    let pay = match input.pay {
        None => None,
        Some(pv) => {
            let (index, e) = offer
                .pay_entry(pv.scheme)
                .ok_or_else(|| PriceError::NotOffered(pv.scheme.to_owned()))?;
            Some(AdmittedPay {
                index,
                scheme: e.scheme.clone(),
                unit: e.unit.clone(),
                amount: e.amount,
                rate: e.rate,
                value: pv.value,
            })
        }
    };
    let base = pay.as_ref().map_or(NO_PAY_BASE, |p| p.amount);
    let decision = decide(offer, input.attest, base, input.now, counter);
    let price = decision.price(base);
    let value = pay.as_ref().map_or(0, |p| p.value);
    if value < price {
        return Err(PriceError::Underpaid { price, value });
    }
    Ok(Admission {
        decision,
        price,
        pay,
        metered: offer.metered,
    })
}

/// The most change a scheme may sign at settlement: `value - charged`.
///
/// Only [`Admission::settle`] makes one, so the cap a signer enforces is
/// always the one this module computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeCap(u64);

impl ChangeCap {
    /// The cap in the pay entry's unit.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The charge settlement writes and the Response reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    /// OK or FAILED.
    pub status: Status,
    /// The Response's `charged`; 0 on FAILED.
    pub charged: u64,
    /// The Response's `metered_units`, in metered offers.
    pub metered_units: Option<u64>,
    /// The change the scheme may return: `value - charged`.
    pub cap: ChangeCap,
}

impl Admission {
    /// The charge for an outcome (sections 6.4 and 7).
    ///
    /// - OK, not metered: the effective price. Overpayment is left to the
    ///   scheme, which returns change up to [`Charge::cap`] if it can.
    /// - OK, metered: `min(price(⌈units × rate / 1000⌉), price(amount))`,
    ///   under the decision made at admission; `units` is reported as
    ///   `metered_units`.
    /// - FAILED: 0, and the cap is the whole value, which the scheme refunds
    ///   as its registered refund property allows.
    ///
    /// `units` is the meter's count and is ignored in non-metered offers.
    #[must_use]
    pub fn settle(&self, status: Status, units: u64) -> Charge {
        let value = self.pay.as_ref().map_or(0, |p| p.value);
        let metered_units = self.metered.then_some(units);
        let charged = match status {
            Status::Failed => 0,
            Status::Ok if !self.metered => self.price,
            Status::Ok => self.metered_charge(units),
        };
        Charge {
            status,
            charged,
            metered_units,
            cap: ChangeCap(value.saturating_sub(charged)),
        }
    }

    fn metered_charge(&self, units: u64) -> u64 {
        let Some(p) = &self.pay else {
            return 0;
        };
        let rate = u128::from(p.rate.unwrap_or(0));
        let used = (u128::from(units) * rate).div_ceil(1000);
        let used = self.decision.price_wide(used);
        let ceiling = self.decision.price_wide(u128::from(p.amount));
        narrow(used.min(ceiling))
    }
}

/// Draft-00 section 7: a pay entry may appear in a metered offer only if
/// its scheme's registry entry has `refund = "atomic"` or `upto = true`.
#[must_use]
pub fn metered_entry_allowed(refund: &str, upto: bool) -> bool {
    refund == "atomic" || upto
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discount_is_exact_for_wide_values() {
        assert_eq!(discount(10_000, 2000), 8000);
        assert_eq!(discount(9_999, 2000), 8000);
        assert_eq!(discount(1, 9999), 1);
        assert_eq!(discount(1, 10_000), 0);
        let big = u128::MAX;
        assert_eq!(discount(big, 10_000), 0);
        assert_eq!(discount(big, 5000), big - big / 2);
    }

    #[test]
    fn epoch_end_is_the_next_window_start() {
        assert_eq!(epoch_end(0, 60), 60);
        assert_eq!(epoch_end(59, 60), 60);
        assert_eq!(epoch_end(60, 60), 120);
    }
}
