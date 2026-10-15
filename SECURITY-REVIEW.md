# Security review B5

A review of the Caparra workspace's money path, parsers and operational
handling of secrets, with fuzzing. To report a vulnerability, see
`SECURITY.md`.

## Scope

Every crate on `develop` except `crates/caparra-gate` and
`crates/bnap-carrier-http`, which were still being built and are left for
a later review. The focus was the money path and every parser that takes
untrusted bytes:

- core: `bnap-core`, `bnap-plug`
- signers: `bnap-signer-file`, `bnap-signer-process`
- stores: `bnap-store-sqlite`, `bnap-store-postgres`
- value schemes: `bnap-scheme-notes`, `bnap-scheme-l402`, `bnap-scheme-mpp`
- rails: `bnap-rail-lnd`, `bnap-rail-nwc`, `bnap-rail-phoenixd`, `bnap-rail-fake`
- attestations: `bnap-scheme-dpop`, `bnap-scheme-webbotauth`
- carrier: `bnap-carrier-mcp`
- client: `caparra-wallet`, `bnap-cli`, `bnap-mcp`

The code was judged against the BNAP spec (`bnap` repository,
`spec/socket-draft-00.md`, `spec/schemes/bnap-notes-draft-00.md`,
`spec/DECISIONS.md`, `spec/ERRATA.md`) and the design notes in `notes/`.

## Method

1. **Fuzzing.** A cargo-fuzz workspace in `fuzz/` (nightly, libFuzzer)
   with twelve targets, one per family of untrusted input. Where a property
   is cheap to state, the targets assert it, not only the absence of a
   panic: canonical BigSize and TLV re-encode to the input, a credential
   survives parse, serialize, parse, a JSON document with a duplicate
   member is never a manifest, base64url decodes only its canonical form.
   Every target ran for 10 minutes. A weekly workflow
   (`.github/workflows/fuzz.yml`) runs each for 5 minutes.
2. **Review with independent lenses.** Three reviewers worked in parallel,
   each with one lens and without the others' output:
   - **Money path:** double spend, over-issue of caps, change and refunds,
     trust in rail amount, unit and finality, store atomicity, replay
     against SPENT, pending timeout, wallet caps.
   - **Cryptography and parsing:** signature malleability (ECDSA low-S,
     strict Ed25519, BIP-340), tagged-hash domain separation, canonical
     encodings, constant-time compares of secrets, duplicate JSON members,
     size limits, integer overflow.
   - **Secrets and operations:** key file permissions, zeroize, leaks
     through `Debug` and logs, socket permissions, timeouts, and DoS
     through unbounded maps or allocation from length prefixes.
3. **Fix and verify.** Every HIGH and MEDIUM finding got a regression test
   that fails before the fix, then the fix. An independent checker
   verified that each test bites (fix reverted: the test fails) and looked
   for regressions.

## Fuzz targets and time

Each target ran 600 seconds (about 2 CPU hours, 338,641,974 executions in total). None crashed, hung or failed an assertion.

| Target | Time | Executions | Coverage (libFuzzer cov) | Crashes |
| --- | --- | --- | --- | --- |
| `credential` | 601 s | 57,512,279 | 904 | none |
| `dpop_jwt` | 601 s | 11,037,116 | 1838 | none |
| `l402_token` | 601 s | 42,511,061 | 755 | none |
| `manifest` | 601 s | 6,503,967 | 1385 | none |
| `mcp_meta` | 601 s | 10,121,213 | 1771 | none |
| `mpp_credential` | 601 s | 17,446,002 | 2335 | none |
| `notes_wire` | 601 s | 15,204,446 | 1018 | none |
| `offer` | 601 s | 29,080,018 | 632 | none |
| `response` | 601 s | 59,135,931 | 514 | none |
| `signer_ipc` | 601 s | 9,438,498 | 2424 | none |
| `tlv_bigsize` | 601 s | 48,542,480 | 355 | none |
| `webbotauth_input` | 601 s | 32,108,963 | 1722 | none |

The corpora started empty. The Offer, Credential and Response targets mostly hit framing errors early, and their coverage is the lowest; seeding them from `crates/bnap-core/tests/data/vectors.json` is the first improvement for the weekly runs.

## Findings

| Severity | Count | Status |
| --- | --- | --- |
| HIGH | 0 | |
| MEDIUM | 3 | fixed, with regression tests |
| LOW | 15 | recorded for follow-up (`notes/b5-security.md`) |

### MEDIUM

- **A1, bnap-scheme-notes: a quote paid on a production rail never
  minted.** NUT-04 `mint` required the rail to report the paid amount in
  `sat`. LND, phoenixd and NWC report msat, so a client who paid a fund
  quote in full could never get the notes. **Fixed:** the paid value is
  converted through `pricing::backed_value` before the comparison.
- **A2, caparra-wallet: refund notes gave cap room back.** The cost of a
  request funded inside the 402 was reduced by the change and refund
  notes the server returned. A hostile origin could refund the value as
  its own notes every time, so only the routing fee counted against the
  per-origin, daily and per-task caps. **Fixed:** change offsets only the
  face value of notes the request spent; sats that went out over Lightning
  count in full.
- **C1, caparra-wallet: the wallet's WAL was world-readable.** SQLite
  created `wallet.db-wal` and `-shm` with the umask's mode before the main
  file was restricted. Until the next checkpoint, the salt, KDF parameters,
  check value and sealed seed were readable by any local user, who could
  then guess the passphrase offline. **Fixed:** the wallet file is created
  with mode 0600 before SQLite opens it (SQLite copies that mode to the
  WAL and SHM files), new directories get 0700, and all three files are
  restricted on create and on open.

### LOW

Fifteen LOW findings are listed with file, line and suggested fix in
`notes/b5-security.md`, ready to file as issues. In short:

- **Carrier:** two MCP carrier conformance gaps. The FAILED settle is not
  run when the OK settle fails, and the notes admission cutoff is not
  applied.
- **Notes held across origins:** no global cap on the notes held across
  all origins.
- **Variable-time compares:** compares on the unblinded note signature and
  on static bearer tokens. Neither is practically measurable.
- **Counter keys:** the non-injective counter key encoding, which is
  already ERRATA N3a-10.
- **Timeouts:** a pay command that can hang outside its timeout.
- **bnap-mcp HTTP mode:** no authentication.
- **Debug and memory:** `Debug` output that prints tokens, and secrets not
  zeroized on drop.
- **Files:** secret files read without a mode check, and key file opens
  without `O_NOFOLLOW` or an owner check.
- **Transport:** phoenixd basic auth allowed over plain http.
- **Store file mode:** the sqlite use store is created with the umask's
  mode.
- **Wallet create:** a failed `Store::create` leaves an empty wallet file
  behind.

## Areas found sound

- **Socket core**
  - `outcome::process` looks up replays before it prices anything.
  - Single IDs answer SPENT. A late settle loses to the pending timeout
    in the same transaction.
  - `record_refund` is first-write-wins.
  - `reserve_change` is bounded by the request cap, `refund_cap` and the
    pinned OK cap.
  - Pricing:
    - takes `min(claimed, backed)`;
    - counts each backing source once;
    - converts msat to sat by flooring;
    - refuses other units.
- **Stores**
  - sqlite runs every method in `BEGIN IMMEDIATE`.
  - postgres runs SERIALIZABLE and retries on serialization, deadlock and
    unique-violation errors.
  - Primary keys on used IDs, outcomes and change outputs.
- **Rails**
  - Only a settled payment counts; LND ACCEPTED is pending.
  - Keysend and AMP are refused.
  - An answer for another payment hash is refused.
  - The RailId is computed from the rail's own bytes.
- **Encodings**
  - Minimal BigSize and tu64.
  - TLV types strictly ascending, with the even/odd and nested-range rules.
  - Canonical base64url everywhere, re-encode checked.
  - I-JSON: a duplicate member is refused at any depth, escaped spellings
    included, in the manifest, MPP, the DPoP header and claims, and MCP
    messages.
  - JCS hashing.
- **Signatures**
  - DPoP:
    - alg allow-list (ES256, EdDSA), so `none` and HMAC are refused;
    - `crit` refused;
    - private JWK members refused;
    - high-S ES256 refused;
    - Ed25519 checked with `verify_strict`.
  - Web Bot Auth:
    - strict structured-field serialization;
    - the label fixed to `sig1`;
    - covered components allow-listed;
    - the keyid is the key's thumbprint;
    - lifetime capped.
  - BIP-340 is verified through libsecp256k1.
  - Each use has its own tagged-hash tag.
- **MACs:** offer MAC, MPP challenge HMAC, phoenixd webhook HMAC and the
  macaroon signature are all compared in constant time.
- **Secrets**
  - Signer key file:
    - must be a regular file with mode 0600, at most 1 MiB;
    - is read into a zeroizing buffer;
    - errors never echo the value.
  - Signer IPC:
    - frames capped at 256 KiB before allocation;
    - idle and I/O timeouts;
    - peer uid checked on both sides;
    - socket directory must not be group- or world-writable.
  - Wallet sealing:
    - argon2id with a random salt;
    - XChaCha20-Poly1305 with a fresh nonce per write;
    - kind and ID bound as associated data.

## Known limitations

- `caparra-gate` and `bnap-carrier-http` were out of scope. They need the
  same review before release.
- Fuzzing ran 10 minutes per target, about two CPU hours in total. That
  is a smoke test, not a campaign. The weekly workflow keeps it running;
  a longer campaign (OSS-Fuzz or a dedicated runner) would find deeper
  states.
- Fuzzing covers parsers and key-free checks. The money path (process,
  settle, change) is covered by the existing property and concurrency
  tests and by the review, not by coverage-guided fuzzing.
- The postgres store and the regtest Lightning rails were reviewed by
  reading, not run (no Docker in the review environment).
- Timing side channels were judged by reading, not measured.
