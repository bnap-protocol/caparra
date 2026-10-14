//! Value, input fees and the output ladder (6.3), and the selection of the
//! outputs a settlement signs (7.2).
//!
//! ```text
//! I     = sum of the input amounts
//! F     = the fund quote's amount, or 0 without fund
//! fee   = (sum over the inputs of their keyset's input_fee_ppk + 999) div 1000
//! value = I + F - fee
//! ```
//!
//! All arithmetic is checked unsigned 64-bit; an overflow, or a fee above
//! `I + F`, is `BAD_AMOUNT`.

/// Why a value is not defined (6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    /// A sum overflows 64 bits.
    #[error("the amounts overflow 64 bits")]
    Overflow,
    /// The input fee is more than the inputs and the fund together.
    #[error("the fee {fee} exceeds the {total} sat of inputs and fund")]
    FeeAboveTotal {
        /// The fee.
        fee: u64,
        /// `I + F`.
        total: u64,
    },
}

/// The NUT-02 input fee of inputs on keysets with these `input_fee_ppk`
/// values: their sum rounded up to whole sats. `None` on overflow.
#[must_use]
pub fn input_fee(ppks: impl IntoIterator<Item = u64>) -> Option<u64> {
    let sum = ppks.into_iter().try_fold(0u64, u64::checked_add)?;
    Some(sum.checked_add(999)? / 1000)
}

/// The value of 6.3: inputs given as `(amount, input_fee_ppk)` of their
/// keyset, plus the fund quote's amount, which pays no fee.
pub fn value(inputs: impl IntoIterator<Item = (u64, u64)>, fund: u64) -> Result<u64, ValueError> {
    let mut total = fund;
    let mut ppk = 0u64;
    for (amount, p) in inputs {
        total = total.checked_add(amount).ok_or(ValueError::Overflow)?;
        ppk = ppk.checked_add(p).ok_or(ValueError::Overflow)?;
    }
    let fee = input_fee([ppk]).ok_or(ValueError::Overflow)?;
    total
        .checked_sub(fee)
        .ok_or(ValueError::FeeAboveTotal { fee, total })
}

/// The total of the outputs when they form a complete ladder (6.3): sorted
/// ascending, every amount is at most 1 more than the sum of the smaller
/// ones, so every amount from 0 to the total is a sum of some of them.
/// `None` when they do not, or the total overflows. No outputs make the
/// empty ladder, of total 0.
#[must_use]
pub fn ladder_total(amounts: &[u64]) -> Option<u64> {
    let mut sorted = amounts.to_vec();
    sorted.sort_unstable();
    let mut total = 0u64;
    for a in sorted {
        if a > total.checked_add(1)? {
            return None;
        }
        total = total.checked_add(a)?;
    }
    Some(total)
}

/// True when the outputs form a complete ladder whose total is at least
/// `value` (6.3).
#[must_use]
pub fn covers(amounts: &[u64], value: u64) -> bool {
    ladder_total(amounts).is_some_and(|t| t >= value)
}

/// The canonical ladder of `value` (6.3, P13): one output of each amount 1,
/// 2, 4, …, 2^(b-1), where b is the bit length of `value`. Empty for 0.
#[must_use]
pub fn canonical_ladder(value: u64) -> Vec<u64> {
    let bits = u64::BITS - value.leading_zeros();
    (0..bits).map(|i| 1u64 << i).collect()
}

/// The outputs a settlement signs for `change` (7.2):
///
/// ```text
/// r = change; S = {}
/// for i in the output indices, by amount descending, then by index ascending:
///     if amount(i) ≤ r:  S = S ∪ {i};  r = r - amount(i)
/// ```
///
/// Returns the indices in ascending order, or `None` when `r` is not 0 at
/// the end, which a complete power-of-two ladder covering the value rules
/// out (6.3).
#[must_use]
pub fn select(amounts: &[u64], change: u64) -> Option<Vec<usize>> {
    let (s, r) = select_among(amounts, |_| true, change);
    (r == 0).then_some(s)
}

/// The greedy of 7.2 over the outputs `eligible` admits only, toward
/// `target`: the indices taken, ascending, and what is left of `target`.
#[must_use]
pub fn select_among(
    amounts: &[u64],
    eligible: impl Fn(usize) -> bool,
    target: u64,
) -> (Vec<usize>, u64) {
    let mut order: Vec<usize> = (0..amounts.len()).filter(|&i| eligible(i)).collect();
    order.sort_by(|&a, &b| amounts[b].cmp(&amounts[a]).then(a.cmp(&b)));
    let mut r = target;
    let mut s = Vec::new();
    for i in order {
        if amounts[i] <= r {
            s.push(i);
            r -= amounts[i];
        }
    }
    s.sort_unstable();
    (s, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fees_round_up_per_credential() {
        assert_eq!(input_fee([]), Some(0));
        assert_eq!(input_fee([100]), Some(1));
        assert_eq!(input_fee([100, 0]), Some(1));
        assert_eq!(input_fee([100; 10]), Some(1));
        assert_eq!(input_fee([100; 11]), Some(2));
        assert_eq!(input_fee([2000]), Some(2));
        assert_eq!(input_fee([u64::MAX]), None);
    }

    #[test]
    fn value_of_the_vector_credentials() {
        // 3a: 1,024 on A (100 ppk) and 1,024 on B (0 ppk).
        assert_eq!(value([(1024, 100), (1024, 0)], 0), Ok(2047));
        // 3b: four notes on B.
        assert_eq!(value([(1024, 0), (512, 0), (128, 0), (16, 0)], 0), Ok(1680));
        // 3.6: the same four on A are one short.
        assert_eq!(
            value([(1024, 100), (512, 100), (128, 100), (16, 100)], 0),
            Ok(1679)
        );
        // The fee vector: one 1-sat input on C (2,000 ppk).
        assert_eq!(
            value([(1, 2000)], 0),
            Err(ValueError::FeeAboveTotal { fee: 2, total: 1 })
        );
        assert_eq!(value([(u64::MAX, 0)], 1), Err(ValueError::Overflow));
    }

    #[test]
    fn ladders() {
        assert_eq!(canonical_ladder(0), Vec::<u64>::new());
        assert_eq!(canonical_ladder(1), vec![1]);
        assert_eq!(canonical_ladder(1680).len(), 11);
        assert_eq!(ladder_total(&canonical_ladder(1680)), Some(2047));
        assert!(covers(&canonical_ladder(65_535), 65_535));
        assert!(covers(&[], 0));
        assert!(!covers(&[], 1));
        assert!(!covers(&[1, 4], 5), "2 and 3 cannot be formed");
        assert!(covers(&[1, 1, 2], 4));
        assert!(!covers(&[1, 2], 4), "complete, but below the value");
    }

    #[test]
    fn selection_matches_the_spec_examples() {
        let ladder = canonical_ladder(1680);
        // 10.3: 1,340 sat of change signs 1,024, 256, 32, 16, 8 and 4.
        let s = select(&ladder, 1340).unwrap();
        let amounts: Vec<u64> = s.iter().map(|&i| ladder[i]).collect();
        assert_eq!(amounts, vec![4, 8, 16, 32, 256, 1024]);
        // 18.2 item 6: 1,707 signs indices 0, 1, 3, 5, 7, 9 and 10.
        assert_eq!(select(&ladder, 1707).unwrap(), vec![0, 1, 3, 5, 7, 9, 10]);
        assert_eq!(select(&ladder, 2047).unwrap(), (0..11).collect::<Vec<_>>());
        assert_eq!(select(&ladder, 0).unwrap(), Vec::<usize>::new());
        assert_eq!(select(&ladder, 2048), None);
        // Equal amounts: the lower index first.
        assert_eq!(select(&[2, 1, 2], 2).unwrap(), vec![0]);
    }

    #[test]
    fn every_change_on_a_complete_ladder_is_exact() {
        let ladders = [vec![1, 1, 2, 4], vec![1, 2, 2, 8, 4], canonical_ladder(300)];
        for l in ladders {
            let total = ladder_total(&l).unwrap();
            for c in 0..=total {
                let s = select(&l, c).unwrap();
                assert_eq!(s.iter().map(|&i| l[i]).sum::<u64>(), c);
            }
        }
    }
}
