# Integration notes: N5, durable use stores

Branch `node/n5`, crates `crates/bnap-store-sqlite`,
`crates/bnap-store-postgres` and `crates/bnap-store-tests` (publish =
false). Built on `bnap-core` and `bnap-plug` as merged on `develop` at
`6410887`; **no change to either**. Normative source:
`bnap/spec/socket-draft-00.md` sections 6.2 to 6.4 and 12, through the
`UseStore` contract of `notes/n3-core.md`.

## Public API

| Crate | Item | What it is |
| --- | --- | --- |
| `bnap-store-sqlite` | `SqliteStore` | `UseStore` on one SQLite file. `open(path)`, `open_with(path, &SqliteConfig)`, `pool()`, `close()`, `prune_counters(now)`. `Clone` shares the pool |
| | `SqliteConfig` | `max_connections` (8), `busy_timeout` (10 s), `acquire_timeout` (10 s). Durability settings are not configurable |
| `bnap-store-postgres` | `PostgresStore` | `UseStore` on Postgres. `connect(url)`, `connect_with(PgConnectOptions, &PostgresConfig)`, `pool()`, `close()`, `prune_counters(now)`. `Clone` shares the pool |
| | `PostgresConfig` | `max_connections` (16), `acquire_timeout` (10 s), `max_retries` (64) |
| `bnap-store-tests` | `Tokio` | Multi-thread tokio runtime as `conformance::Executor` (`block_on` from several threads at once) |
| | `Held<S>` | A store plus a guard (temp dir, schema) dropped after it; implements `UseStore` by delegation |
| | `race`, `Dump`, `Tried`, `check_consistent` | Barrier start; raw table dump; "nothing half written" checker |
| | `scenarios::*` | Process-level concurrency scenarios for any `UseStore` (below), `gate` loop, `Log`, `audit`, `run` |

Both stores implement every `UseStore` method: `commit`, `counter`,
`outcome`, `settle`, `expire_pending`, `record_refund`, `reserve_change`,
`purge`. `prune_counters` is extra (not in the trait, see "Decisions").
`pool()` is for health checks and inspection; writing through it bypasses
the store's rules.

## How the stores work

**`store::logic` run inside one transaction.** Each write method opens one
transaction, loads into a `TxTable` (the crate-private `table.rs`) exactly
the rows the `bnap_core::store::logic` function of the same name reads,
runs that function on the `TxTable` (it implements `UseTable`), writes back
the diff, and commits. So the SQL stores behave exactly as the reference
`MemoryStore` does, rule for rule, including `change_cap_ok` pinning,
saturating arithmetic, the timeout inside `settle` and `ChangeOverCap`.
Writing the rules again in SQL was rejected: it duplicates `logic` and is
where drift would hide.

- Loads per method: `commit` loads `outcome[rk]` (full), `used[id]` for every
  single, every counter (with its `resets_at` from the plan); `settle` and
  `record_refund` load the record in full plus the counters it names;
  `expire_pending` loads every PENDING record created before
  `timeout_before` with its counters; `reserve_change` loads the record's
  columns plus only those of the request's outputs already in its ledger;
  `purge` loads the columns of every candidate. `outcome` reads the full
  record in one snapshot; `counter` is one `SELECT`.
- `Load::{Full, Counters, Columns}`: a record that is returned to the caller
  is always loaded in full (counters and every change output). Partial
  loads are safe for writing because an update writes only the record's own
  columns plus the outputs it gained; `logic` never changes a record's
  counters or drops an output, and `TxTable::writes` refuses an update that
  would (fails closed).
- **Miss guard.** A `logic` read of a row the method did not load (an
  `outcome`, `is_used`, `counter`, `put_outcome` or `mark_used` on an
  unloaded key) marks the table, and the method fails with a `StoreError`
  before writing. A store bug can therefore never read "absent" for a row
  it forgot to load.
- `table.rs` is byte-identical in both crates;
  `bnap-store-tests/tests/table_copies.rs` fails if they drift. Edit the
  SQLite copy and copy it over. `sql.rs` differs only in placeholders
  (`?` vs `$n`) and the status column type.

### SQLite

- WAL, `synchronous = FULL`, `fullfsync` and `checkpoint_fullfsync` (macOS
  `fsync` does not flush the disk cache; no-ops elsewhere),
  `foreign_keys = ON`, `busy_timeout` from the config.
- Every write method: `BEGIN IMMEDIATE` (takes the write lock before the
  first read, so no write interleaves), load, `logic`, write back, `COMMIT`.
- `outcome`: a deferred `BEGIN` (one WAL snapshot for the three reads).
  Reads never wait for the writer.
- One writer at a time per database file: write throughput is bounded by
  `fsync` latency. Several processes (gate instances) may share one file on
  one host (WAL needs shared memory: no network file systems).

### Postgres

- Every write method: `BEGIN ISOLATION LEVEL SERIALIZABLE`, load, `logic`,
  write back, `COMMIT`. On SQLSTATE `40001` (serialization failure),
  `40P01` (deadlock) or `23505` (unique violation from a concurrent insert
  of the same key), the whole method runs again from a fresh transaction,
  up to `max_retries` times, sleeping a random 0 to 2^n ms (capped at
  128 ms) between attempts. Nothing is written by an aborted attempt, so a
  retry is always safe.
- `outcome`: `REPEATABLE READ, READ ONLY` (one snapshot, never aborted,
  never blocks a writer). `counter`: one `SELECT`.
- `connect_with` appends `-c synchronous_commit=on` to the connection
  options, whatever the server default.
- The schema lives in the connection's `search_path` (`public` by
  default): one database can hold several stores in separate schemas (the
  tests do this). `sqlx`'s Postgres migrator takes an advisory lock, so
  instances starting together migrate once.

### Schema (`migrations/0001_use_store.sql` in each crate)

| Table | Primary key | Columns |
| --- | --- | --- |
| `used` | `use_id` (32 bytes) | `replay_key` |
| `counter` | `counter_key` (32 bytes) | `value`, `resets_at` (nullable; the epoch's end, from the commit plan) |
| `outcome` | `replay_key` (32 bytes) | every `OutcomeRecord` column (`status` 0/1/2, `created`, `charged`, `metered_units`, `scheme_result`, `response`, `settled_at`, `timed_out`, `refund_recorded`, `keep_until`, `refund_cap`, `unit`, `change_total`, `change_cap_ok`) |
| `outcome_counter` | (`replay_key`, `position`) | `counter_key`; FK to `outcome` on delete cascade; keeps `OutcomeRecord::counters` order |
| `change_output` | (`replay_key`, `keyset`, `amount`, `blinded`) | the change ledger's outputs; FK to `outcome` on delete cascade |

Indexes: `outcome (status, created)` for the timeout and purge scans,
`counter (resets_at)` for `prune_counters`. Length `CHECK`s on every key.
Every `u64` is stored as the signed 64-bit integer with the same bits, so
the whole range round-trips; comparisons happen in Rust (`logic`). The SQL
filters of the timeout and purge scans (`sql::below`) select a superset
(values above `i64::MAX` are stored negative and always selected), which
`logic` then filters exactly. **Never edit an applied migration** (sqlx
checks checksums); add `0002_...`.

## Tests

`bnap-store-tests` runs, for **each** backend (`tests/sqlite.rs`,
`tests/postgres.rs`):

1. `passes_the_conformance_suite`: `bnap_core::test_support::conformance::run`
   with a fresh store per scenario (SQLite: a new file in a temp dir;
   Postgres: a new schema, dropped afterwards) and the `Tokio` executor.
   This closes N3's deferred item S5c.
2. Process-level scenarios (`scenarios.rs`), 16 tasks behind a barrier,
   6 rounds, each task on its own pool connection, all through
   `outcome::process`, `settle`, `sweep`, `record_refund`,
   `reserve_change`:
   - `one_note_admits_one_action`: 16 credentials, one note: one New, 15
     SPENT, no loser record; the note is then SPENT under `cashu:nut24` too.
   - `one_payment_under_two_schemes_admits_one_action`: L402 and MPP on one
     Lightning payment hash: one New, 15 SPENT.
   - `settle_and_sweep_race_to_one_transition`: settles at the deadline vs
     sweeps past it: one transition, losers see the winner's record, the
     rate counter given back exactly when FAILED.
   - `concurrent_replays_get_one_answer`: 16 copies: one New, 15 PENDING
     with `retry_after = 300`; settled: 16 replays of the one record,
     nothing written; crashed: 16 late copies time it out once and 16
     concurrent `record_refund`s keep one result, returned to all.
   - `counters_never_pass_their_limit`: quota of 3 (attestation-only) gives
     exactly 3 New (losers UNDERPAID or `RATE_LIMITED`), counter 3; rate of
     5 gives exactly 5, counter 5.
   - `change_reservations_keep_one_total`: 96 sat outcome, 8 sat outputs
     under OK cap 46 and FAILED cap 96 at once: the ledger holds exactly the
     outputs let through, total at most 96, at most 5 under OK; re-reserving
     adds nothing.
   - `change_outputs_are_matched_whole` (sequential, repair round 1): one
     blinded message `B_` throughout, 96 sat outcome under the FAILED cap:
     `(k,1,B_)` gives total 1, `(k,95,B_)` total 96 (another amount is a
     fresh output), `(k2,1,B_)` is `OverCap {97, 96}` (another keyset is
     fresh), `(k,1000000,B_)` is over the cap, a known batch adds nothing, a
     batch with one fresh output is over the cap, re-reserving `(k,1,B_)`
     gives 96 and leaves the record unchanged. It pins the SQL stores'
     partial ledger load (`sql::outputs_among`), which `MemoryStore` does
     not have and the conformance suite does not reach.
   - `mixed_load_moves_each_outcome_once`: 8 gate loops x 60 rounds
     (admit, settle OK, reserve then settle, settle FAILED, leave PENDING,
     sweep): every outcome is exactly what the one call that moved it
     wrote, the shared counter equals the outcomes not FAILED, every change
     total equals its outputs.
3. `a_pool_dropped_mid_transaction_leaves_a_consistent_store`: 8 gate loops
   (shared rate counter, settles, reservations, sweeps); the test waits for
   24 admissions and for a transaction to be open (SQLite: a probe's
   `BEGIN IMMEDIATE` is busy; Postgres: `pg_stat_activity` shows the
   store's application name in a transaction), aborts every task, (Postgres:
   `pg_terminate_backend` on the store's sessions), drops the store, waits
   for the old pool to finish closing, reopens, and checks: every `used`
   row names an outcome, each tried credential committed whole or not at
   all, counters equal their live outcomes, change totals equal their
   outputs, no orphan rows, every acknowledged commit survived, and the
   reopened store still admits and settles. Three rounds on one database.
4. SQLite only, `a_killed_writer_loses_nothing_it_acknowledged`: the test
   binary starts itself as a writer process (the ignored test
   `killed_writer_child`, inert unless `BNAP_N5_CHILD_DB` is set), reads
   what it tried and what was acknowledged, SIGKILLs it after 60
   admissions, reopens and runs the same checks. Three rounds. (A process
   kill tests atomicity and recovery; power-loss durability rests on
   `synchronous = FULL` and `fullfsync`, which
   `the_schema_is_applied_once_and_a_store_reopens_its_file` asserts.)
5. `the_schema_is_applied_once_...`: reopen or reconnect, replay a settled
   outcome, assert WAL + `synchronous = FULL` (SQLite) and
   `synchronous_commit = on` (Postgres).
6. `pruning_spares_live_counters` (repair round 1; the generic body is
   `scenarios::pruning_spares_live_counters`, which takes the store's
   `prune_counters` and a raw row writer as closures, since pruning is not
   on the trait): commits at `T0` under `rate(10, 60)` (`resets_at` =
   `ceil(T0/60)*60`) and under a one-hour quota, plants raw rows with
   `resets_at` NULL, 2^63 and `u64::MAX`. `prune_counters` deletes nothing
   at 0, `T0`, `resets_at` and `resets_at + 60` (both counters still 1);
   at `resets_at + 61` exactly one (the rate counter reads 0, the live
   quota counter 1); the quota counter goes at its own epoch end + 61; at
   `u64::MAX` nothing more, and every planted row still reads 1.

Unit tests in each store crate: `TxTable` (miss guard, diff, counter
deletes at 0, refused updates) and `sql` (u64 round trip, `below`
superset), plus `backoff` bounds for Postgres.

### Mutation probes (run in this worktree, reverted)

| Probe | Caught by |
| --- | --- |
| SQLite `settle` loads in one transaction, writes in a second | `mixed_load_moves_each_outcome_once` (3 of 3), both crash tests. **Not** by the conformance suite or `settle_and_sweep_race_to_one_transition`: SQLite's busy handler favours the connection that just committed, so the two halves almost never interleave in a barrier race. The mixed-load scenario was added for this |
| SQLite `reserve_change` split | conformance, `change_reservations_keep_one_total`, mixed load |
| SQLite `expire_pending` split | conformance, `settle_and_sweep_race...`, mixed load |
| SQLite `commit` split | conformance and 6 more tests |
| SQLite `record_refund` split | conformance (`concurrent_refunds_record_once`) |
| SQLite deferred `BEGIN` instead of `BEGIN IMMEDIATE` | every concurrent test, failing closed with `database is locked` |
| SQLite writes committed in two halves (outcome, then `used` and counters) | `a_pool_dropped_mid_transaction...` (2 of 3; the third tripped the probe's own pool hack) and `a_killed_writer...` (2 of 3) |
| Postgres `settle` split | conformance, `settle_and_sweep_race...`, crash test |
| Postgres `READ COMMITTED` instead of `SERIALIZABLE` | 6 of 9 Postgres tests. The two double-spend scenarios still passed: the `used` primary key turns the second insert into a `23505`, retried into SPENT |
| Repair round 1, both backends: `prune_counters` DELETE also takes live epochs (`resets_at <= ? OR 1 = 1`) | `pruning_spares_live_counters` only (before it, every test passed) |
| Same: no `resets_at >= 0` guard; NULL read as 0 (`coalesce`); `<` for `<=`; no clock skew subtracted from `now` | `pruning_spares_live_counters` (4 of 4 per backend) |
| Repair round 1, both backends: `outputs_among` matches on `replay_key` and `blinded` only; without `amount`; without `keyset` | `change_outputs_are_matched_whole` (3 of 3 per backend). The conformance suite still passes under all three |

### Running

```sh
~/bnap-protocol/bin/cargo-q nextest run -p bnap-store-tests          # SQLite; Postgres tests skip
docker run -d --rm --name bnap-pg-n5 -e POSTGRES_PASSWORD=test -p 55432:5432 \
  --memory 512m postgres:17-alpine -c shared_buffers=32MB -c max_connections=120
DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres \
  ~/bnap-protocol/bin/cargo-q nextest run -p bnap-store-tests -j 4
docker stop bnap-pg-n5
```

Without `DATABASE_URL` each Postgres test prints `skipped: DATABASE_URL is
not set ...` to stderr and passes, so CI without Postgres stays green. Each
Postgres test opens up to 24 connections: keep `-j` times 24 under the
server's `max_connections` (the stock default is 100). A 256 MB container
with `max_connections=200` was OOM-killed under `-j 8`; 512 MB with 120
connections and `-j 4` ran clean.

Status at hand-off: `cargo-q nextest run -p bnap-store-tests -p
bnap-store-sqlite -p bnap-store-postgres --locked -j 4` with `DATABASE_URL`
set: 45 tests (26 in `bnap-store-tests`, 19 unit tests in the store
crates), all passing, in about 20 s, twice in a row after repair round 1
(the writer child is the one skipped, ignored, test). The Postgres tests
use the default retry budget. Without `DATABASE_URL` the Postgres tests,
the two new ones included, print the skip line and pass.
`cargo-q clippy --workspace --all-targets --locked -- -D warnings` clean,
`cargo-q fmt --all --check` clean, `RUSTDOCFLAGS="-D warnings" cargo-q doc`
clean for the three crates, doctests pass, `RUSTUP_TOOLCHAIN=1.94 cargo-q
check --locked --all-targets` clean for the three crates, `cargo-q deny
--all-features check bans licenses sources` ok and `check advisories` ok
(new duplicate-version warnings only, from sqlx's older `sha2`, `digest`,
`rand`; one `secp256k1`), `ops/leak-guard.sh` clean.

### Enabling Postgres in CI later

Add a job to `.github/workflows/ci.yml` (ubuntu only), with the same
toolchain and nextest setup as the Test job:

```yaml
  postgres:
    name: Postgres store
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17-alpine
        env:
          POSTGRES_PASSWORD: test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres"
          --health-interval 5s --health-timeout 5s --health-retries 12
    env:
      DATABASE_URL: postgres://postgres:test@localhost:5432/postgres
    steps:
      # checkout, toolchain, nextest install: as in the Test job
      - run: cargo nextest run -p bnap-store-tests --locked --test-threads 3 -E 'binary(postgres)'
```

Service containers take no server arguments, so the stock
`max_connections = 100` applies: `--test-threads 3` keeps it at 72 plus
admin connections. The tests need `CREATE SCHEMA` rights on the database.

## Decisions

- **`logic` over a loaded table, not SQL of its own** (above). Cost: a
  method reads its rows one statement at a time (N+1 for the timeout scan
  and for counters); fine at a gate's batch sizes.
- **Postgres: SERIALIZABLE with retries, not row locks.** Row locks cannot
  lock rows that do not exist yet (absent `used` and counter rows), so
  READ COMMITTED would need upserts that pre-create rows plus careful lock
  ordering; SSI gives the serial guarantee for the same code as SQLite.
  `23505` is retried as well because Postgres reports some concurrent
  inserts of one key that way.
- **Every write is durable, not only the commit**: section 12 names
  commits, but 6.4 forbids sending a Response before the settle write is
  durable, so settle, timeout, refund and reservations get the same
  treatment (one setting per backend covers all of them).
- **A COMMIT whose result is lost** (connection dropped in flight) is a
  `StoreError` although it may have committed. The gate answers
  UNAVAILABLE and the client's retry finds the outcome (replay or PENDING),
  never a second action.
- **`prune_counters(now)` is opt-in and outside the trait.** `logic` never
  deletes a counter, so one row per identity per past epoch would
  accumulate forever. It deletes counters whose epoch ended more than a
  clock skew (60 s) before `now` (`resets_at + 60 < now`), which no gate
  within the skew can read or increment again; a FAILED give-back on a
  pruned counter changes nothing. Only a commit creates a counter row, and
  it always writes `resets_at`; a row with `NULL` there (written by other
  means) is never pruned, nor is one whose `resets_at` is at or above 2^63
  (stored negative; only an absurd registry epoch makes one), at any `now`:
  keeping a counter is the safe side. `pruning_spares_live_counters` pins
  the boundary on both backends.
- **Counter rows are deleted at 0**, as `MemoryTable` does.
- **Schema per store on Postgres** comes from `search_path`; the store does
  not qualify table names.
- `fullfsync` is always on for SQLite: correct on macOS, free elsewhere.

## Known gaps

- `used` grows forever, by design (draft-00 6.2 and 12 "Retention": a
  single's record lives as long as the artifact could verify; the store has
  no keyset expiry to go by). A future `forget_used(keyset, before)` needs
  a spec rule first.
- `purge` deletes every eligible record in one transaction; a large backlog
  holds SQLite's write lock (or a long Postgres transaction) for that
  time. Run the sweep often. Batching would be several transactions, which
  the trait does not allow as written.
- Every `settle`, `record_refund`, `commit` replay and `outcome` read loads
  all of a record's change outputs; their count is bounded only by the gate
  (N3 notes: bound outputs per outcome).
- Postgres under a hot key (one rate counter for many concurrent
  requests) aborts and retries often: correct, but latency grows with
  contention, and after `max_retries` the call fails closed. The mixed-load
  test (8 gates on one counter) takes 25 to 35 s on the test box, against
  about 5 s on SQLite.
- SQLite: two processes opening a **new** database file at the same moment
  can race the first migration (one fails at open with a `StoreError`;
  restart it). Not a problem once the schema exists.
- `sql.rs` is near-identical in the two crates without a drift test (only
  `table.rs` has one).
- No in-memory SQLite mode (WAL needs a file).

## Notes for downstream nodes

- **Gate (N9)**: build one store at start-up (`SqliteStore::open(path)` or
  `PostgresStore::connect(url)`) and share it (it is `Clone`, `Send +
  Sync`) across requests and gate instances; pass the same store to
  `outcome::process`, `outcome::settle`, `record_refund`,
  `outcome::sweep` and to `CappedSigner::for_change`. Call
  `outcome::sweep(&store, now, &limits)` periodically and, with it,
  `store.prune_counters(now)` (it never touches a live epoch: the boundary
  is `resets_at + 60 < now`, tested). Every `StoreError` is UNAVAILABLE. Size
  `max_connections` for concurrent requests; SQLite writes serialize
  regardless. Keep the SQLite file on local disk.
- **Wallet (N10)**: the use store is the gate's; nothing here is
  client-side.
- **e2e (N15)**: use either store; for Postgres start the container above
  (or a compose service) and set `DATABASE_URL`. A store per test can use
  its own schema via `PgConnectOptions::options([("search_path", ..)])`,
  as `tests/postgres.rs` does (`Schema`).
- Another `UseStore` implementation can reuse the whole harness:
  `conformance::run(make, &Tokio::new())` and `scenarios::run(make,
  &exec)`, plus the crash tests' pattern, and, if it prunes counters,
  `scenarios::pruning_spares_live_counters`.

## ERRATA candidates (literal draft-00 reading taken)

| # | Where | Ambiguity | What the build does |
| --- | --- | --- | --- |
| N5-1 | 6.3, 12 "Durability" | Section 12 says "Stores MUST make commits durable synchronously", naming only the commit; 6.4 forbids sending a Response before the settle write is durable | Every write method is durable before it returns |
| N5-2 | 6.2 rate/quota counters | No retention rule for counters of past epochs | `prune_counters`, opt-in, one clock skew after the epoch ends |
| N5-3 | 6.3 "one serializable transaction" | A serializable store may abort a transaction for a conflict and run it again; the draft does not say a store may retry | Retried from scratch, invisible to the caller; the result is that of one serial execution |
| N5-4 | 6.3 "If the store cannot be reached" | A commit whose acknowledgement was lost may have committed | Reported as a store failure (UNAVAILABLE); the client's retry is a replay or PENDING |

## Open item for the core owner (observation, no change made)

`bnap_core::test_support::conformance` races calls behind a barrier. On
SQLite, a store whose `settle` decides in one transaction and writes in a
second passes every one of those races, because the busy handler lets the
connection that just committed take the lock again before sleepers wake.
`bnap-store-tests` catches it with `mixed_load_moves_each_outcome_once`
and the crash tests. Core may want a sustained mixed-load scenario of its
own in `conformance::run`.

## Proposal for the core owner: a whole-identity change case in conformance

(Repair round 1; no change to bnap-core made.) The SQL stores load only
the ledger outputs a `reserve_change` request names, which `MemoryStore`
does not do, and `conformance::run` did not notice when that lookup
matched an output on part of its identity (probes above). Any store with a
partial load can make the same mistake, so the case of
`scenarios::change_outputs_are_matched_whole` belongs in
`conformance::run`: one blinded message, a 96 sat outcome under the FAILED
cap, `(k,1,B_)` then `(k,95,B_)` reserved to 96, `(k2,1,B_)` and
`(k,1000000,B_)` over the cap, re-reserving `(k,1,B_)` gives 96 and leaves
the record unchanged. It is a few lines over `UseStore` alone.
