# Integration notes: B5, security review and fuzzing

Branch `node/b5-security`. Scope: every crate on develop except
`crates/caparra-gate` and `crates/bnap-carrier-http` (built elsewhere,
not touched). Normative spec: `bnap` at `origin/develop`
(`spec/socket-draft-00.md`, `spec/schemes/bnap-notes-draft-00.md`,
`spec/DECISIONS.md`, `spec/ERRATA.md`). The summary for readers outside
the project is `SECURITY-REVIEW.md` at the repository root.

## What changed

| Area | Change |
| --- | --- |
| `fuzz/` | New cargo-fuzz workspace, excluded from the main workspace (`exclude = ["fuzz"]`), nightly only, its own `Cargo.lock`. Twelve targets, listed below. |
| `.github/workflows/fuzz.yml` | Weekly (Monday 03:17 UTC) and manual. One job per target, 5 minutes each; a crash fails the job and uploads the reproducer. |
| `bnap-scheme-webbotauth` | `#[doc(hidden)] pub fn fuzz_check_body(&[u8]) -> bool`: the body parser plus every key-free check of Signature-Input and Signature. Fuzzing entry point only; the private `parse` it calls is unchanged. |
| `bnap-scheme-notes` | A1 fix in `mint.rs` (see findings). Test rail `FakeLn` gains `msat: AtomicBool` to report amounts in msat, as LND, phoenixd and NWC do. |
| `caparra-wallet` | A2 fix in `pay.rs` (`settle_receipt` cost), C1 fix in `store.rs` (file, WAL, directory modes). |

No change to `bnap-core` or `bnap-plug`.

## Fuzz targets

Run with `cd fuzz && cargo +nightly fuzz run -O <target>`. Each asserts
more than "no panic" where a property is cheap to state.

| Target | Parsers | Extra properties |
| --- | --- | --- |
| `tlv_bigsize` | `read_bigsize`, `read_tu64`, `read_lp`, `parse_entry_list`, `TlvStream::parse` (top level and nested) | BigSize re-encodes to the same bytes; a parsed stream serializes back to the input |
| `offer` | `PayEntry`, `AttestEntry`, `NativeEntry`, `Offer::parse`, then `offer_id`, `verify_signature`, `verify_mac`, `check_expiry` | `Offer::bytes` is the input |
| `credential` | `Credential::parse`, `to_bytes`, `context`, `digest`, binding checks | parse, serialize, parse gives the same value |
| `response` | `Response::parse`, `verify_ack`, `ErrorObject::parse` | |
| `manifest` | `parse_strict`, `SignedManifest::parse`, `jcs`, `verify`, `accept` | a document `parse_strict` refuses (duplicate member) is never a manifest |
| `notes_wire` | `Body`, `Witness` against a body, `FundQuote`, `Params`, `parse_scheme_result`, `FundRequest::parse_header` | |
| `l402_token` | `Identifier::parse`, `Token::parse` (macaroon V2 binary and preimage), `Challenge::parse`, `credential_from_authorization` | |
| `mpp_credential` | `json::decode`, `Credential::decode`, `ChargeRequest::decode`, `Challenge::parse`, the MCP carrier's `mpp::credential_value` and `challenge_value` | |
| `dpop_jwt` | `jose::parse_compact`, `proof::check` (with and without an access token), `DpopBody`, `BearerBody` | |
| `webbotauth_input` | `WbaBody::parse`, `fuzz_check_body` | body roundtrip |
| `mcp_meta` | `parse_strict` of a JSON-RPC message, `_meta` credential through `from_b64u` and `Credential::parse_with`, `mpp::credential_token`, `ErrorData::from_value`, `scope::parse_arguments` | base64url decodes only its canonical form |
| `signer_ipc` | `read_frame` over arbitrary bytes, `decode_request`, `decode_reply` | |

### Fuzz results (10 minutes per target)

Every target ran `cargo +nightly fuzz run -O <t> -- -max_total_time=600` on 2026-10-14: about 2 CPU hours and 338,641,974 executions in total. No crash, hang, leak or assertion failure, so no regression test came from fuzzing.

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

## Findings

Three independent reviewer agents ran in parallel, each with one lens and
no access to the others: (a) money path, (b) cryptography and parsing,
(c) secrets and operations. IDs are prefixed by lens.

### HIGH and MEDIUM (all fixed)

| ID | Crate | Severity | File:line | Description | Fix | Test (fails before the fix) | Commit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | bnap-scheme-notes | MEDIUM | `crates/bnap-scheme-notes/src/mint.rs` (`mint`, paid check) | NUT-04 mint required the rail to report unit `sat`; LND, phoenixd and NWC report msat, so a quote paid in full never minted and the operator kept the payment | Compare the paid value through `pricing::backed_value("sat", ..)` (msat floored to sat) | `tests/flows.rs::a_quote_paid_on_an_msat_rail_mints` | `43b7483` |
| A2 | caparra-wallet | MEDIUM | `crates/caparra-wallet/src/pay.rs` (`settle_receipt`, cost) | Change and refund notes were taken off the whole cost, Lightning included. A hostile origin funded in the 402 could hand the value back as its own notes each time, so only the routing fee counted against the caps (bounded per origin only by `max_balance_per_origin`, unbounded across origins) | Change offsets only the face of the notes the request spent; quote value, fee and Lightning sats count in full. Those change notes count again if spent later (double counting, the safe side) | `tests/findings.rs::refund_notes_from_a_funded_402_give_no_cap_room_back` | `41fa77d` |
| C1 | caparra-wallet | MEDIUM | `crates/caparra-wallet/src/store.rs` (`Store::create`, `restrict`) | `wallet.db-wal` and `-shm` were created with the umask mode (0644) before the chmod of the main file; salt, KDF parameters, check value and the sealed seed sat in a world-readable WAL, open to offline passphrase guessing. `~/.bnap` was 0755 | Create the file 0600 with `create_new` before SQLite opens it, new directories 0700, chmod the main, WAL and SHM files on create and open | `store::tests::the_wallet_and_its_wal_are_private` | `5830a0e` |

### LOW and deferred (for GitHub issues)

| ID | Crate | Severity | File:line | Description | Suggested fix |
| --- | --- | --- | --- | --- | --- |
| A3 | bnap-carrier-mcp | LOW | `crates/bnap-carrier-mcp/src/gate.rs:808` (`conclude`) | When the scheme's OK settle fails (a sweep timed the outcome out during the action), `conclude` returns UNAVAILABLE without the FAILED settle and refund that `notes/n6.md` step 4 asks for; the client gets its refund only by replaying after `pending_timeout` | On an OK settle error, take `pending.charge(Status::Failed, 0)`, run the FAILED `settle_scheme`, then `outcome::settle` |
| A4 | bnap-carrier-mcp | LOW | `crates/bnap-carrier-mcp/src/gate.rs:737` | `process` gets `offer.fields()` instead of `bnap_scheme_notes::admission_fields(..)`, so the notes 5.4 admission cutoff is not applied on MCP calls; only matters with an offer lifetime above `pending_timeout + 120` | Apply `admission_fields` for a notes pay entry, as `bnap-scheme-notes/tests/common/mod.rs` does |
| A5 | caparra-wallet | LOW | `crates/caparra-wallet/src/pay.rs:643` | Notes held are wallet balance, not spending: `max_balance_per_origin` bounds them per origin but nothing bounds the total held across origins (explicit `bnap fund` included) | Add a global cap on notes held across origins |
| B1 | bnap-signer-file | LOW | `crates/bnap-signer-file/src/keyset.rs:303` (`NotesKeyset::check`) | `expected.to_bytes() == *c` compares the unblinded signature `a*Y` in variable time; the 33-byte compare sits next to an EC multiplication, so not practically measurable remotely | `subtle::ConstantTimeEq` |
| B2 | bnap-core | LOW | `crates/bnap-core/src/ids.rs:66` (`counter_key`) | `tu64(limit) ‖ tu64(epoch) ‖ tu64(now/epoch)` without length prefixes is not injective (`rate_key(id,5,1,1783311169) == rate_key(id,5,362,1783311169)`); collisions only merge operator-chosen counters (more restrictive). Already ERRATA N3a-10, implemented literally | Spec change: `lp(tu64(..))` or fixed-width integers |
| B3 | bnap-scheme-dpop | LOW | `crates/bnap-scheme-dpop/src/authority.rs` (`StaticAuthority`) | Bearer tokens are `HashMap<String, _>` keys, so the final compare is variable time (SipHash keying makes probing impractical) | Key by `sha256(token)`, or document as test and development only |
| C2 | caparra-wallet | LOW | `crates/caparra-wallet/src/paysource.rs:170` (`CommandSource::pay_invoice`) | `read_to_end` of the child's stdout runs outside the 120 s timeout and is unbounded; a pay command that holds stdout open hangs `fetch_paid` (the reservation stays counted) | One timeout over read and wait; cap stdout with `take(1 MiB)` |
| C3 | bnap-mcp | LOW | `crates/bnap-mcp/src/main.rs:85` | `--http` has no authentication: any local process that reaches the loopback port can spend within the caps (browsers are stopped by rmcp's host check and preflight) | Random bearer token written to a 0600 file, or a 0600 Unix socket |
| C4 | several | LOW | `bnap-scheme-dpop/src/body.rs:66,105`, `bnap-scheme-dpop/src/authority.rs:75`, `caparra-wallet/src/transport.rs:15`, `bnap-signer-process/src/wire.rs` (`Request`) | Derived `Debug` prints bearer tokens, API tokens, credential headers and the note secret; nothing logs them today | Hand-written redacting `Debug` |
| C5 | several | LOW | `bnap-mcp/src/main.rs:52`, `bnap-cli/src/cli.rs:448`, bip39 without `zeroize`, `bnap-scheme-l402` `MacaroonKeys`, `bnap-scheme-mpp` `ChallengeKeys`, carrier `mac_keys`, `bnap-core/src/schnorr.rs:160` `SigningKey`, phoenixd password and webhook secret, NWC URI | Secrets not wiped from memory on drop | `Zeroizing` / `ZeroizeOnDrop`; enable `bip39/zeroize` |
| C6 | rails, bnap-mcp | LOW | `bnap-rail-nwc/src/lib.rs:94`, `bnap-rail-phoenixd/src/lib.rs:81`, `bnap-mcp --passphrase-file`, LND macaroon path | Secret files are read without the mode check the signer key file gets | Reuse `bnap_signer_file::keyfile::read`, or warn |
| C7 | bnap-signer-file | LOW | `crates/bnap-signer-file/src/keyfile.rs:120` | Symlink check and open are two lookups (no `O_NOFOLLOW`); the owner is not checked. Secrecy holds (mode read from the descriptor); integrity against a writable directory does not | Open with `O_NOFOLLOW`, require the owner to be the process uid |
| C8 | bnap-rail-phoenixd | LOW | `crates/bnap-rail-phoenixd/src/lib.rs:310` | `PHOENIXD_URL` may be any `http://` URL, so basic auth can go in clear text off the host | Require https unless the host is loopback |
| C9 | bnap-store-sqlite | LOW | `crates/bnap-store-sqlite` (open) | The gate's use-store file and WAL get the umask mode (receipts, kept answers; no key material) | Create 0600 as in C1 |

Already documented elsewhere and not repeated: the offer-minting flood
that can evict cached MPP-native offers (`notes/n9b.md`), the NWC URI on
argv in `bnap paysource nwc` (`notes/n10.md`), and one invoice per
anonymous priced call (DECISIONS row 24).

## Areas found sound

Recorded so the next review can start from them; details in
`SECURITY-REVIEW.md`. Replay before pricing and SPENT handling in
`outcome::process`; the pending timeout and late settle; `reserve_change`
caps; store transactions (sqlite `BEGIN IMMEDIATE`, postgres SERIALIZABLE
with retries); rail finality (only settled counts, LND ACCEPTED is
pending, keysend and AMP refused); canonical TLV, base64url and JCS;
duplicate JSON members refused everywhere money or a signature depends on
it; DPoP alg allow-list, low-S ES256 and strict Ed25519; Web Bot Auth
strict structured fields; constant-time MAC, HMAC and macaroon compares;
size caps before allocation in every parser and the signer IPC; signer key
file mode and zeroize; wallet sealing (argon2id, XChaCha20-Poly1305, fresh
nonces).

## Quality gate

CHECKER_PLACEHOLDER
