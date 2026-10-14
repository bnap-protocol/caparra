-- The use store of BNAP socket draft-00, sections 6.2 to 6.4: `used[id]`,
-- `counter[key]` and `outcome[ReplayKey]`, with each outcome's counters and
-- its change ledger. Every u64 is stored as the BIGINT with the same 64
-- bits, so the full range round-trips; the store compares them in Rust.

CREATE TABLE used (
    use_id     BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(use_id) = 32),
    replay_key BYTEA NOT NULL CHECK (octet_length(replay_key) = 32)
);

CREATE TABLE counter (
    counter_key BYTEA  NOT NULL PRIMARY KEY CHECK (octet_length(counter_key) = 32),
    value       BIGINT NOT NULL,
    resets_at   BIGINT
);

CREATE INDEX counter_by_resets_at ON counter (resets_at);

CREATE TABLE outcome (
    replay_key      BYTEA    NOT NULL PRIMARY KEY CHECK (octet_length(replay_key) = 32),
    status          SMALLINT NOT NULL CHECK (status IN (0, 1, 2)),
    created         BIGINT   NOT NULL,
    charged         BIGINT,
    metered_units   BIGINT,
    scheme_result   BYTEA,
    response        BYTEA,
    settled_at      BIGINT,
    timed_out       BOOLEAN  NOT NULL,
    refund_recorded BOOLEAN  NOT NULL,
    keep_until      BIGINT   NOT NULL,
    refund_cap      BIGINT   NOT NULL,
    unit            TEXT     NOT NULL,
    change_total    BIGINT   NOT NULL,
    change_cap_ok   BIGINT
);

CREATE INDEX outcome_by_status_created ON outcome (status, created);

CREATE TABLE outcome_counter (
    replay_key  BYTEA   NOT NULL REFERENCES outcome (replay_key) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    counter_key BYTEA   NOT NULL CHECK (octet_length(counter_key) = 32),
    PRIMARY KEY (replay_key, position)
);

CREATE TABLE change_output (
    replay_key BYTEA  NOT NULL REFERENCES outcome (replay_key) ON DELETE CASCADE,
    keyset     BYTEA  NOT NULL,
    amount     BIGINT NOT NULL,
    blinded    BYTEA  NOT NULL CHECK (octet_length(blinded) = 33),
    PRIMARY KEY (replay_key, keyset, amount, blinded)
);
