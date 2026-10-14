//! The statements: loading rows into a [`TxTable`] and writing its diff
//! back, all on the one connection of a transaction.

use std::collections::BTreeSet;

use bnap_core::store::{ChangeOutput, OutcomeRecord, OutcomeStatus};
use bnap_core::{CounterKey, ReplayKey};
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Postgres, Row};

use crate::Error;
use crate::table::{CounterWrite, Load, Writes};

type Query = sqlx::query::Query<'static, Postgres, <Postgres as sqlx::Database>::Arguments>;

/// The BIGINT with the same 64 bits as `v`.
pub(crate) fn to_db(v: u64) -> i64 {
    i64::from_le_bytes(v.to_le_bytes())
}

/// The u64 with the same 64 bits as `v`.
pub(crate) fn from_db(v: i64) -> u64 {
    u64::from_le_bytes(v.to_le_bytes())
}

/// The largest BIGINT `x` such that every u64 `v < bound` has
/// `to_db(v) <= x` or `to_db(v) < 0`: a filter `col <= x` then selects every
/// row with `col < bound` and, at most, rows whose u64 is above `i64::MAX`
/// (stored negative), which the rules in Rust filter out again. `None` when
/// no u64 is below `bound`.
pub(crate) fn below(bound: u64) -> Option<i64> {
    let last = bound.checked_sub(1)?;
    Some(i64::try_from(last).unwrap_or(i64::MAX))
}

fn status_to_db(s: OutcomeStatus) -> i16 {
    match s {
        OutcomeStatus::Pending => 0,
        OutcomeStatus::Ok => 1,
        OutcomeStatus::Failed => 2,
    }
}

fn status_from_db(s: i16) -> Result<OutcomeStatus, Error> {
    match s {
        0 => Ok(OutcomeStatus::Pending),
        1 => Ok(OutcomeStatus::Ok),
        2 => Ok(OutcomeStatus::Failed),
        other => Err(Error::Corrupt(format!("outcome status {other}"))),
    }
}

fn fixed<const N: usize>(what: &str, v: &[u8]) -> Result<[u8; N], Error> {
    v.try_into()
        .map_err(|_| Error::Corrupt(format!("{what} of {} bytes", v.len())))
}

macro_rules! record_columns {
    () => {
        "status, created, charged, metered_units, scheme_result, response, settled_at, \
         timed_out, refund_recorded, keep_until, refund_cap, unit, change_total, change_cap_ok"
    };
}

/// An outcome row's own columns; no counters, no outputs.
fn record(row: &PgRow) -> Result<OutcomeRecord, Error> {
    let opt = |name: &str| -> Result<Option<u64>, Error> {
        Ok(row.try_get::<Option<i64>, _>(name)?.map(from_db))
    };
    Ok(OutcomeRecord {
        status: status_from_db(row.try_get("status")?)?,
        created: from_db(row.try_get("created")?),
        counters: Vec::new(),
        charged: opt("charged")?,
        metered_units: opt("metered_units")?,
        scheme_result: row.try_get("scheme_result")?,
        response: row.try_get("response")?,
        settled_at: opt("settled_at")?,
        timed_out: row.try_get("timed_out")?,
        refund_recorded: row.try_get("refund_recorded")?,
        keep_until: from_db(row.try_get("keep_until")?),
        refund_cap: from_db(row.try_get("refund_cap")?),
        unit: row.try_get("unit")?,
        change_total: from_db(row.try_get("change_total")?),
        change_cap_ok: opt("change_cap_ok")?,
        change_outputs: BTreeSet::new(),
    })
}

/// Binds the record's own columns in [`record_columns`] order.
fn bind_record(q: Query, r: &OutcomeRecord) -> Query {
    q.bind(status_to_db(r.status))
        .bind(to_db(r.created))
        .bind(r.charged.map(to_db))
        .bind(r.metered_units.map(to_db))
        .bind(r.scheme_result.clone())
        .bind(r.response.clone())
        .bind(r.settled_at.map(to_db))
        .bind(r.timed_out)
        .bind(r.refund_recorded)
        .bind(to_db(r.keep_until))
        .bind(to_db(r.refund_cap))
        .bind(r.unit.clone())
        .bind(to_db(r.change_total))
        .bind(r.change_cap_ok.map(to_db))
}

async fn counters_of(c: &mut PgConnection, rk: &ReplayKey) -> Result<Vec<CounterKey>, Error> {
    let rows = sqlx::query(
        "SELECT counter_key FROM outcome_counter WHERE replay_key = $1 ORDER BY position",
    )
    .bind(&rk.0[..])
    .fetch_all(&mut *c)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(CounterKey(fixed(
                "counter key",
                &r.try_get::<Vec<u8>, _>(0)?,
            )?))
        })
        .collect()
}

fn output(row: &PgRow) -> Result<ChangeOutput, Error> {
    Ok(ChangeOutput {
        keyset: row.try_get("keyset")?,
        amount: from_db(row.try_get("amount")?),
        blinded: fixed("blinded output", &row.try_get::<Vec<u8>, _>("blinded")?)?,
    })
}

async fn outputs_of(c: &mut PgConnection, rk: &ReplayKey) -> Result<BTreeSet<ChangeOutput>, Error> {
    let rows =
        sqlx::query("SELECT keyset, amount, blinded FROM change_output WHERE replay_key = $1")
            .bind(&rk.0[..])
            .fetch_all(&mut *c)
            .await?;
    rows.iter().map(output).collect()
}

/// `outcome[rk]`, loaded as `load` says.
pub(crate) async fn outcome(
    c: &mut PgConnection,
    rk: &ReplayKey,
    load: Load,
) -> Result<Option<OutcomeRecord>, Error> {
    let row = sqlx::query(concat!(
        "SELECT ",
        record_columns!(),
        " FROM outcome WHERE replay_key = $1"
    ))
    .bind(&rk.0[..])
    .fetch_optional(&mut *c)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let mut rec = record(&row)?;
    if load != Load::Columns {
        rec.counters = counters_of(c, rk).await?;
    }
    if load == Load::Full {
        rec.change_outputs = outputs_of(c, rk).await?;
    }
    Ok(Some(rec))
}

/// The outputs among `wanted` that `rk`'s change ledger already holds.
pub(crate) async fn outputs_among(
    c: &mut PgConnection,
    rk: &ReplayKey,
    wanted: &[ChangeOutput],
) -> Result<Vec<ChangeOutput>, Error> {
    let mut found = Vec::new();
    for o in wanted {
        let hit = sqlx::query(
            "SELECT 1 FROM change_output \
             WHERE replay_key = $1 AND keyset = $2 AND amount = $3 AND blinded = $4",
        )
        .bind(&rk.0[..])
        .bind(&o.keyset[..])
        .bind(to_db(o.amount))
        .bind(&o.blinded[..])
        .fetch_optional(&mut *c)
        .await?;
        if hit.is_some() {
            found.push(o.clone());
        }
    }
    Ok(found)
}

/// Every PENDING record created before `created_before`, with its
/// counters: what the timeout can select, and a few rows it then skips
/// (see [`below`]).
pub(crate) async fn pending_before(
    c: &mut PgConnection,
    created_before: u64,
) -> Result<Vec<(ReplayKey, OutcomeRecord)>, Error> {
    let Some(created_max) = below(created_before) else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(concat!(
        "SELECT replay_key, ",
        record_columns!(),
        " FROM outcome WHERE status = 0 AND created <= $1"
    ))
    .bind(created_max)
    .fetch_all(&mut *c)
    .await?;
    with_keys(c, &rows, Load::Counters).await
}

/// Every settled record created before `created_before` whose
/// `keep_until + 60` is before `now`, its columns only: what the purge can
/// select, and a few rows it then skips (see [`below`]).
pub(crate) async fn purgeable(
    c: &mut PgConnection,
    created_before: u64,
    now: u64,
) -> Result<Vec<(ReplayKey, OutcomeRecord)>, Error> {
    let skew = bnap_core::limits::CLOCK_SKEW;
    let (Some(created_max), Some(keep_max)) =
        (below(created_before), below(now.saturating_sub(skew)))
    else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(concat!(
        "SELECT replay_key, ",
        record_columns!(),
        " FROM outcome WHERE status <> 0 AND created <= $1 AND keep_until <= $2"
    ))
    .bind(created_max)
    .bind(keep_max)
    .fetch_all(&mut *c)
    .await?;
    with_keys(c, &rows, Load::Columns).await
}

async fn with_keys(
    c: &mut PgConnection,
    rows: &[PgRow],
    load: Load,
) -> Result<Vec<(ReplayKey, OutcomeRecord)>, Error> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let rk = ReplayKey(fixed(
            "replay key",
            &row.try_get::<Vec<u8>, _>("replay_key")?,
        )?);
        let mut rec = record(row)?;
        if load != Load::Columns {
            rec.counters = counters_of(c, &rk).await?;
        }
        if load == Load::Full {
            rec.change_outputs = outputs_of(c, &rk).await?;
        }
        out.push((rk, rec));
    }
    Ok(out)
}

/// True when `used[id]` exists.
pub(crate) async fn is_used(c: &mut PgConnection, id: &[u8; 32]) -> Result<bool, Error> {
    let row = sqlx::query("SELECT 1 FROM used WHERE use_id = $1")
        .bind(&id[..])
        .fetch_optional(&mut *c)
        .await?;
    Ok(row.is_some())
}

/// `counter[key]`, 0 when absent.
pub(crate) async fn counter(c: &mut PgConnection, key: &CounterKey) -> Result<u64, Error> {
    let v: Option<i64> = sqlx::query_scalar("SELECT value FROM counter WHERE counter_key = $1")
        .bind(&key.0[..])
        .fetch_optional(&mut *c)
        .await?;
    Ok(v.map_or(0, from_db))
}

async fn insert_output(
    c: &mut PgConnection,
    rk: &ReplayKey,
    o: &ChangeOutput,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO change_output (replay_key, keyset, amount, blinded) VALUES ($1, $2, $3, $4)",
    )
    .bind(&rk.0[..])
    .bind(&o.keyset[..])
    .bind(to_db(o.amount))
    .bind(&o.blinded[..])
    .execute(&mut *c)
    .await?;
    Ok(())
}

/// Writes `w` back, in its order.
pub(crate) async fn apply(c: &mut PgConnection, w: &Writes<'_>) -> Result<(), Error> {
    for rk in &w.deleted {
        for stmt in [
            "DELETE FROM change_output WHERE replay_key = $1",
            "DELETE FROM outcome_counter WHERE replay_key = $1",
            "DELETE FROM outcome WHERE replay_key = $1",
        ] {
            sqlx::query(stmt).bind(&rk.0[..]).execute(&mut *c).await?;
        }
    }
    for (rk, rec) in &w.inserted {
        let q = sqlx::query(concat!(
            "INSERT INTO outcome (replay_key, ",
            record_columns!(),
            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
        ))
        .bind(rk.0.to_vec());
        bind_record(q, rec).execute(&mut *c).await?;
        for (position, key) in rec.counters.iter().enumerate() {
            let position =
                i64::try_from(position).map_err(|_| Error::Corrupt("too many counters".into()))?;
            sqlx::query(
                "INSERT INTO outcome_counter (replay_key, position, counter_key) VALUES ($1, $2, $3)",
            )
            .bind(&rk.0[..])
            .bind(position)
            .bind(&key.0[..])
            .execute(&mut *c)
            .await?;
        }
        for o in &rec.change_outputs {
            insert_output(c, rk, o).await?;
        }
    }
    for u in &w.updated {
        let q = sqlx::query(
            "UPDATE outcome SET status = $1, created = $2, charged = $3, metered_units = $4, \
             scheme_result = $5, response = $6, settled_at = $7, timed_out = $8, \
             refund_recorded = $9, keep_until = $10, refund_cap = $11, unit = $12, \
             change_total = $13, change_cap_ok = $14 WHERE replay_key = $15",
        );
        let done = bind_record(q, u.record)
            .bind(u.replay_key.0.to_vec())
            .execute(&mut *c)
            .await?;
        if done.rows_affected() != 1 {
            return Err(Error::Corrupt(
                "an outcome row vanished inside its transaction".into(),
            ));
        }
        for o in &u.new_outputs {
            insert_output(c, u.replay_key, o).await?;
        }
    }
    for (id, rk) in w.used {
        sqlx::query("INSERT INTO used (use_id, replay_key) VALUES ($1, $2)")
            .bind(&id[..])
            .bind(&rk.0[..])
            .execute(&mut *c)
            .await?;
    }
    for cw in &w.counters {
        match cw {
            CounterWrite::Set {
                key,
                value,
                resets_at,
            } => {
                sqlx::query(
                    "INSERT INTO counter (counter_key, value, resets_at) VALUES ($1, $2, $3) \
                     ON CONFLICT (counter_key) DO UPDATE SET value = excluded.value, \
                     resets_at = coalesce(excluded.resets_at, counter.resets_at)",
                )
                .bind(&key.0[..])
                .bind(to_db(*value))
                .bind(resets_at.map(to_db))
                .execute(&mut *c)
                .await?;
            }
            CounterWrite::Delete(key) => {
                sqlx::query("DELETE FROM counter WHERE counter_key = $1")
                    .bind(&key.0[..])
                    .execute(&mut *c)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Deletes counters whose epoch ended at or before `ended_by`.
pub(crate) async fn prune_counters(c: &mut PgConnection, ended_by: i64) -> Result<u64, Error> {
    let done = sqlx::query(
        "DELETE FROM counter WHERE resets_at IS NOT NULL AND resets_at >= 0 AND resets_at <= $1",
    )
    .bind(ended_by)
    .execute(&mut *c)
    .await?;
    Ok(done.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_u64_round_trips() {
        for v in [0, 1, u64::MAX, 1 << 63, (1 << 63) - 1, 1_791_700_000] {
            assert_eq!(from_db(to_db(v)), v);
        }
    }

    #[test]
    fn below_selects_a_superset_of_the_rows_under_the_bound() {
        assert_eq!(below(0), None);
        assert_eq!(below(1), Some(0));
        assert_eq!(below(1_000), Some(999));
        assert_eq!(below(u64::MAX), Some(i64::MAX));
        // Every u64 below the bound passes `to_db(v) <= x` or is negative.
        for bound in [1, 1_000, 1 << 63, (1 << 63) + 5, u64::MAX] {
            let x = below(bound).unwrap();
            for v in [0, bound - 1, bound / 2, (1 << 63) - 1, 1 << 63] {
                if v < bound {
                    assert!(to_db(v) <= x || to_db(v) < 0, "{v} under {bound}");
                }
            }
        }
    }
}
