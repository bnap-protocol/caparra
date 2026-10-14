-- The use store of BNAP socket draft-00, sections 6.2 to 6.4: `used[id]`,
-- `counter[key]` and `outcome[ReplayKey]`, with each outcome's counters and
-- its change ledger. Every u64 is stored as the INTEGER with the same 64
-- bits, so the full range round-trips; the store compares them in Rust.

CREATE TABLE used (
    use_id     BLOB NOT NULL PRIMARY KEY CHECK (length(use_id) = 32),
    replay_key BLOB NOT NULL CHECK (length(replay_key) = 32)
) WITHOUT ROWID;

CREATE TABLE counter (
    counter_key BLOB    NOT NULL PRIMARY KEY CHECK (length(counter_key) = 32),
    value       INTEGER NOT NULL,
    resets_at   INTEGER
) WITHOUT ROWID;

CREATE INDEX counter_by_resets_at ON counter (resets_at);

CREATE TABLE outcome (
    replay_key      BLOB    NOT NULL PRIMARY KEY CHECK (length(replay_key) = 32),
    status          INTEGER NOT NULL CHECK (status IN (0, 1, 2)),
    created         INTEGER NOT NULL,
    charged         INTEGER,
    metered_units   INTEGER,
    scheme_result   BLOB,
    response        BLOB,
    settled_at      INTEGER,
    timed_out       INTEGER NOT NULL CHECK (timed_out IN (0, 1)),
    refund_recorded INTEGER NOT NULL CHECK (refund_recorded IN (0, 1)),
    keep_until      INTEGER NOT NULL,
    refund_cap      INTEGER NOT NULL,
    unit            TEXT    NOT NULL,
    change_total    INTEGER NOT NULL,
    change_cap_ok   INTEGER
) WITHOUT ROWID;

CREATE INDEX outcome_by_status_created ON outcome (status, created);

CREATE TABLE outcome_counter (
    replay_key  BLOB    NOT NULL REFERENCES outcome (replay_key) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    counter_key BLOB    NOT NULL CHECK (length(counter_key) = 32),
    PRIMARY KEY (replay_key, position)
) WITHOUT ROWID;

CREATE TABLE change_output (
    replay_key BLOB    NOT NULL REFERENCES outcome (replay_key) ON DELETE CASCADE,
    keyset     BLOB    NOT NULL,
    amount     INTEGER NOT NULL,
    blinded    BLOB    NOT NULL CHECK (length(blinded) = 33),
    PRIMARY KEY (replay_key, keyset, amount, blinded)
) WITHOUT ROWID;
