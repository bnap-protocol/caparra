//! One transaction's slice of the use store, as the
//! [`UseTable`](bnap_core::store::UseTable) that the rules of
//! [`bnap_core::store::logic`] run on.
//!
//! Every write method of the store works the same way: inside one
//! transaction it loads the rows the `logic` function of the same name
//! reads, runs that function over them, and writes back what it changed,
//! still inside the transaction. The store therefore behaves exactly as
//! `logic` run atomically, which is what the `UseStore` contract asks.
//!
//! A read of a row the method did not load is a bug in the store, never an
//! absent row: the table remembers it and [`TxTable::check`] fails the
//! method closed, before anything is written.
//!
//! Records are written back as a diff: an insert for a new record, a
//! delete, or an update of the record's own columns plus an insert of every
//! change output it gained. `logic` never changes a record's counters and
//! never removes an output, so a method may load a record without its
//! counters or outputs when it neither returns the record nor reads them
//! ([`Load`]).
//!
//! This file is identical in `bnap-store-sqlite` and `bnap-store-postgres`;
//! a test in `bnap-store-tests` keeps the two copies equal.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use bnap_core::store::{ChangeOutput, OutcomeRecord, UseTable};
use bnap_core::{CounterKey, ReplayKey};

/// How much of an outcome record a method loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Load {
    /// The record with its counters and every change output: for a record
    /// the method returns, as `outcome[rk]` reads it.
    Full,
    /// The record's columns and its counters, no outputs: the timeout,
    /// which gives the counters back.
    Counters,
    /// The record's columns only: a change reservation (with the outputs it
    /// names, see [`TxTable::load_outputs`]) or a purge.
    Columns,
}

/// One outcome record as the transaction found it and as it is now.
#[derive(Debug)]
struct Slot {
    before: Option<OutcomeRecord>,
    after: Option<OutcomeRecord>,
}

/// One counter as the transaction found it and as it is now.
#[derive(Debug, Clone, Copy)]
struct Count {
    before: u64,
    after: u64,
    resets_at: Option<u64>,
}

/// The rows one store method loaded, and what `logic` made of them.
#[derive(Debug, Default)]
pub(crate) struct TxTable {
    outcomes: BTreeMap<ReplayKey, Slot>,
    used: BTreeMap<[u8; 32], bool>,
    marked: Vec<([u8; 32], ReplayKey)>,
    counters: BTreeMap<CounterKey, Count>,
    missed: AtomicBool,
}

/// A write that would lose data the table did not load, or that `logic`
/// never makes: the method fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unsupported(pub(crate) &'static str);

/// An update of one outcome record.
#[derive(Debug)]
pub(crate) struct Update<'a> {
    /// The record.
    pub(crate) replay_key: &'a ReplayKey,
    /// Its new columns.
    pub(crate) record: &'a OutcomeRecord,
    /// Change outputs it gained.
    pub(crate) new_outputs: Vec<&'a ChangeOutput>,
}

/// A write to `counter[key]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CounterWrite {
    /// Set the value; `resets_at` when the commit knows the epoch's end.
    Set {
        /// The counter.
        key: CounterKey,
        /// Its new value, above 0.
        value: u64,
        /// When the counter's epoch ends.
        resets_at: Option<u64>,
    },
    /// The value went back to 0: delete the row.
    Delete(CounterKey),
}

/// Everything one method writes back, in the order to write it: deletes,
/// inserts, updates, then `used` and counters.
#[derive(Debug, Default)]
pub(crate) struct Writes<'a> {
    /// Records to delete, with their counters and outputs.
    pub(crate) deleted: Vec<&'a ReplayKey>,
    /// New records, with their counters and outputs.
    pub(crate) inserted: Vec<(&'a ReplayKey, &'a OutcomeRecord)>,
    /// Changed records.
    pub(crate) updated: Vec<Update<'a>>,
    /// New `used[id] = rk` rows.
    pub(crate) used: &'a [([u8; 32], ReplayKey)],
    /// Counter writes, by key.
    pub(crate) counters: Vec<CounterWrite>,
}

impl Writes<'_> {
    /// True when nothing changed.
    pub(crate) fn is_empty(&self) -> bool {
        self.deleted.is_empty()
            && self.inserted.is_empty()
            && self.updated.is_empty()
            && self.used.is_empty()
            && self.counters.is_empty()
    }
}

impl TxTable {
    /// Records what the transaction found under `rk`: `None` for no row.
    pub(crate) fn load_outcome(&mut self, rk: ReplayKey, record: Option<OutcomeRecord>) {
        self.outcomes.insert(
            rk,
            Slot {
                before: record.clone(),
                after: record,
            },
        );
    }

    /// Adds outputs the transaction found in `rk`'s change ledger to the
    /// loaded record, as if they had been loaded with it.
    pub(crate) fn load_outputs(&mut self, rk: &ReplayKey, outputs: &[ChangeOutput]) {
        if let Some(slot) = self.outcomes.get_mut(rk) {
            for r in [&mut slot.before, &mut slot.after].into_iter().flatten() {
                r.change_outputs.extend(outputs.iter().cloned());
            }
        }
    }

    /// Records whether `used[id]` exists.
    pub(crate) fn load_used(&mut self, id: [u8; 32], used: bool) {
        self.used.insert(id, used);
    }

    /// Records `counter[key]` (0 for no row), and when its epoch ends if
    /// the caller knows.
    pub(crate) fn load_counter(&mut self, key: CounterKey, value: u64, resets_at: Option<u64>) {
        self.counters.insert(
            key,
            Count {
                before: value,
                after: value,
                resets_at,
            },
        );
    }

    /// The counters the loaded records name that are not loaded yet.
    pub(crate) fn unloaded_counters(&self) -> Vec<CounterKey> {
        let mut keys: Vec<CounterKey> = self
            .outcomes
            .values()
            .filter_map(|s| s.before.as_ref())
            .flat_map(|r| r.counters.iter().copied())
            .filter(|k| !self.counters.contains_key(k))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    fn miss(&self) {
        self.missed.store(true, Ordering::Relaxed);
    }

    /// Fails when `logic` read or wrote a row this method did not load.
    pub(crate) fn check(&self) -> Result<(), Unsupported> {
        if self.missed.load(Ordering::Relaxed) {
            return Err(Unsupported("the store's rules read a row it did not load"));
        }
        Ok(())
    }

    /// What changed, in write order. Refuses an update that changes a
    /// record's counters or drops an output: `logic` makes neither, and
    /// the write-back could not express it.
    pub(crate) fn writes(&self) -> Result<Writes<'_>, Unsupported> {
        self.check()?;
        let mut w = Writes {
            used: &self.marked,
            ..Writes::default()
        };
        for (rk, slot) in &self.outcomes {
            match (&slot.before, &slot.after) {
                (None, None) => {}
                (Some(_), None) => w.deleted.push(rk),
                (None, Some(after)) => w.inserted.push((rk, after)),
                (Some(before), Some(after)) if before == after => {}
                (Some(before), Some(after)) => {
                    if before.counters != after.counters {
                        return Err(Unsupported("an update changed a record's counters"));
                    }
                    if !before.change_outputs.is_subset(&after.change_outputs) {
                        return Err(Unsupported("an update dropped a change output"));
                    }
                    w.updated.push(Update {
                        replay_key: rk,
                        record: after,
                        new_outputs: after
                            .change_outputs
                            .difference(&before.change_outputs)
                            .collect(),
                    });
                }
            }
        }
        for (key, c) in &self.counters {
            if c.before == c.after {
                continue;
            }
            w.counters.push(if c.after == 0 {
                CounterWrite::Delete(*key)
            } else {
                CounterWrite::Set {
                    key: *key,
                    value: c.after,
                    resets_at: c.resets_at,
                }
            });
        }
        Ok(w)
    }
}

impl UseTable for TxTable {
    fn outcome(&self, rk: &ReplayKey) -> Option<&OutcomeRecord> {
        if let Some(slot) = self.outcomes.get(rk) {
            slot.after.as_ref()
        } else {
            self.miss();
            None
        }
    }

    fn outcome_mut(&mut self, rk: &ReplayKey) -> Option<&mut OutcomeRecord> {
        if !self.outcomes.contains_key(rk) {
            self.miss();
            return None;
        }
        self.outcomes.get_mut(rk).and_then(|s| s.after.as_mut())
    }

    fn put_outcome(&mut self, rk: ReplayKey, rec: OutcomeRecord) {
        if let Some(slot) = self.outcomes.get_mut(&rk) {
            slot.after = Some(rec);
        } else {
            self.miss();
        }
    }

    fn delete_outcome(&mut self, rk: &ReplayKey) {
        if let Some(slot) = self.outcomes.get_mut(rk) {
            slot.after = None;
        } else {
            self.miss();
        }
    }

    /// Only the keys this method loaded: a method that iterates records
    /// (the timeout, the purge) loads every record its rule can select.
    fn outcome_keys(&self) -> Vec<ReplayKey> {
        self.outcomes
            .iter()
            .filter(|(_, s)| s.after.is_some())
            .map(|(rk, _)| *rk)
            .collect()
    }

    fn is_used(&self, id: &[u8; 32]) -> bool {
        if let Some(used) = self.used.get(id) {
            *used
        } else {
            self.miss();
            false
        }
    }

    fn mark_used(&mut self, id: [u8; 32], rk: ReplayKey) {
        match self.used.get_mut(&id) {
            Some(used) if !*used => {
                *used = true;
                self.marked.push((id, rk));
            }
            // Marking a loaded, used ID, or one never loaded: logic checks
            // every single before it marks one, so neither happens.
            _ => self.miss(),
        }
    }

    fn counter(&self, key: &CounterKey) -> u64 {
        if let Some(c) = self.counters.get(key) {
            c.after
        } else {
            self.miss();
            0
        }
    }

    fn set_counter(&mut self, key: CounterKey, value: u64) {
        if let Some(c) = self.counters.get_mut(&key) {
            c.after = value;
        } else {
            self.miss();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bnap_core::store::{OutcomeStatus, UseTable};
    use std::collections::BTreeSet;

    fn record() -> OutcomeRecord {
        OutcomeRecord {
            status: OutcomeStatus::Pending,
            created: 1,
            counters: vec![CounterKey([3; 32])],
            charged: None,
            metered_units: None,
            scheme_result: None,
            response: None,
            settled_at: None,
            timed_out: false,
            refund_recorded: false,
            keep_until: 2,
            refund_cap: 10,
            unit: "sat".into(),
            change_total: 0,
            change_cap_ok: None,
            change_outputs: BTreeSet::new(),
        }
    }

    fn output(amount: u64) -> ChangeOutput {
        ChangeOutput {
            keyset: b"k".to_vec(),
            amount,
            blinded: [2; 33],
        }
    }

    #[test]
    fn a_read_of_an_unloaded_row_fails_the_method() {
        let t = TxTable::default();
        assert!(!t.is_used(&[1; 32]));
        assert!(t.check().is_err());
        assert!(t.writes().is_err());
        let t = TxTable::default();
        assert_eq!(UseTable::counter(&t, &CounterKey([1; 32])), 0);
        assert!(t.check().is_err());
        let mut t = TxTable::default();
        t.put_outcome(ReplayKey([1; 32]), record());
        assert!(t.check().is_err());
    }

    #[test]
    fn a_loaded_absence_is_an_answer() {
        let mut t = TxTable::default();
        t.load_outcome(ReplayKey([1; 32]), None);
        t.load_used([5; 32], false);
        assert!(UseTable::outcome(&t, &ReplayKey([1; 32])).is_none());
        assert!(!t.is_used(&[5; 32]));
        t.mark_used([5; 32], ReplayKey([1; 32]));
        t.put_outcome(ReplayKey([1; 32]), record());
        let w = t.writes().unwrap();
        assert_eq!(w.inserted.len(), 1);
        assert_eq!(w.used, &[([5; 32], ReplayKey([1; 32]))]);
        assert!(w.updated.is_empty() && w.deleted.is_empty());
    }

    #[test]
    fn marking_a_used_id_is_refused() {
        let mut t = TxTable::default();
        t.load_used([5; 32], true);
        t.mark_used([5; 32], ReplayKey([1; 32]));
        assert!(t.check().is_err());
    }

    #[test]
    fn an_update_writes_only_the_outputs_it_gained() {
        let mut t = TxTable::default();
        let rk = ReplayKey([1; 32]);
        let mut rec = record();
        rec.change_outputs.insert(output(1));
        t.load_outcome(rk, Some(rec));
        let r = t.outcome_mut(&rk).unwrap();
        r.change_outputs.insert(output(2));
        r.change_total = 3;
        let w = t.writes().unwrap();
        assert_eq!(w.updated.len(), 1);
        assert_eq!(w.updated[0].new_outputs, vec![&output(2)]);
    }

    #[test]
    fn an_update_that_drops_an_output_or_changes_counters_is_refused() {
        let rk = ReplayKey([1; 32]);
        let mut rec = record();
        rec.change_outputs.insert(output(1));
        let mut t = TxTable::default();
        t.load_outcome(rk, Some(rec.clone()));
        t.outcome_mut(&rk).unwrap().change_outputs.clear();
        assert!(t.writes().is_err());
        let mut t = TxTable::default();
        t.load_outcome(rk, Some(rec));
        t.outcome_mut(&rk).unwrap().counters.clear();
        assert!(t.writes().is_err());
    }

    #[test]
    fn counters_back_at_zero_are_deleted() {
        let mut table = TxTable::default();
        let (back, up, same) = (
            CounterKey([1; 32]),
            CounterKey([2; 32]),
            CounterKey([3; 32]),
        );
        table.load_counter(back, 1, None);
        table.load_counter(up, 0, Some(60));
        table.load_counter(same, 4, None);
        table.set_counter(back, 0);
        table.set_counter(up, 1);
        assert_eq!(
            table.writes().unwrap().counters,
            vec![
                CounterWrite::Delete(back),
                CounterWrite::Set {
                    key: up,
                    value: 1,
                    resets_at: Some(60)
                }
            ]
        );
    }

    #[test]
    fn unloaded_counters_are_those_records_name() {
        let mut t = TxTable::default();
        t.load_outcome(ReplayKey([1; 32]), Some(record()));
        assert_eq!(t.unloaded_counters(), vec![CounterKey([3; 32])]);
        t.load_counter(CounterKey([3; 32]), 1, None);
        assert_eq!(t.unloaded_counters(), Vec::<CounterKey>::new());
    }
}
