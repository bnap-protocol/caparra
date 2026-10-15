# Integration notes: e2e, the real gate end to end and conformance

Branch `node/e2e` of caparra, with branch `node/e2e-conformance` of bnap
(the conformance runner side, `bnap/notes/e2e-conformance.md`). Normative
source: `bnap/spec/socket-draft-00.md`, `spec/schemes/bnap-notes-draft-00.md`,
`spec/DECISIONS.md`, `spec/ERRATA.md`, `registry/generated/registry.json`.

Docker was available in this sandbox (the daemon had to be started by
hand), so the regtest network of `devenv/regtest` ran for real: bitcoind
and two LND nodes, every payment made from the payer node over a real
channel. No fake-rail variant of the end-to-end flow was added: the
in-process fake-rail flows already exist in `caparra-gate/tests`.

## What is in it

| Area | Change |
| --- | --- |
| `crates/e2e/tests/stack/` | The stack: `bnap-signer --store` and `caparra-gate run` started as processes from this workspace's binaries (built on first use), the LND rail on the payee node, the SQLite use store, the process signer, a mock OpenAI upstream (axum), and a TLS front (tokio-rustls, the test CA in `tests/fixtures`) for clients that fetch HTTPS only |
| `crates/e2e/tests/gate.rs` | Three end-to-end tests (below), feature `regtest` |
| `crates/e2e/tests/conformance.rs` | bnap's `conformance/run.py` against the stack, profiles `server` and `gateway`, without a payer and with `payers/lncli-payer.sh`; runs only when `BNAP_CONFORMANCE` names a bnap checkout |
| `crates/e2e/tests/fixtures/` | A CA certificate and a `localhost` / `127.0.0.1` leaf with its key, valid 100 years. Test material only; the CA key was not kept |
| `bnap-signer-process` | A `keysets` request: the public half of each notes keyset (keys, input fee, final expiry, active). `ProcessSigner::keysets()` |
| `caparra-gate` | `bnap:notes` with the process signer (keyset table from the signer process); NUT-02 `GET {issuer}/v1/keysets` and NUT-01 `GET {issuer}/v1/keys[/{id}]`; fund offers metered on metered routes; L402 and MPP challenges built from the native entries; a scheme settle failure is logged with its reason |
| `bnap-plug` | `CredentialScheme::natives` (additive, defaults to `native`) |
| `bnap-scheme-l402` | Two native entries per pay entry (`l402-macaroon`, binary; `bolt11`); `Challenge::from_natives`, `Challenge::of_entries`, `Challenge::macaroon`, `INVOICE_KIND` |
| `bnap-carrier-mcp`, `caparra-wallet` (pay, testkit) | Build the L402 challenge from the two entries |
| `.github/workflows/ci.yml` | The regtest job (push to develop and main, PRs) builds the gate, signer and CLI binaries before `cargo nextest run -p e2e --features regtest` |

## The end-to-end tests (`tests/gate.rs`)

All against `caparra-gate run` with `[rail] kind = "lnd"`, `[store] kind =
"sqlite"`, `[signer] kind = "process"` and `bnap-signer --store use.db`:

1. `notes_funded_in_the_402_metered_replayed_and_spent`: `BNAP-Fund:
   amount=5000` gets an exact-scope offer with a NUT-23 quote whose invoice
   comes from the payee LND (`lnbcrt50u...`). Unpaid it is BAD_CREDENTIAL and
   nothing runs. Paid from the payer node (`lncli payinvoice`), the quote is
   redeemed on the metered route offer (bnap:notes 8.4): the mock upstream
   answers 850 tokens, the receipt says OK, `metered_units` 850, `charged`
   425, and `Response::check_client` accepts it against the receipt key of
   the manifest the test pinned with `manifest::accept`; the change (4,575
   sat) is recovered with every DLEQ checked. The same credential again is
   a replay: `replayed`, the same status, charge, units, scheme result and
   `settled_at`, the kept answer, no second upstream call. The quote in a
   new credential for another request is SPENT (409). The change spends on a
   second metered call (100 tokens, 50 sat, change recovered); those notes
   in a third credential are SPENT.
2. `one_lightning_payment_via_l402_and_mpp_admits_one_action`: an exact
   route with L402 and MPP; one invoice for both challenges; paid once from
   the payer node; native L402 admitted with a receipt over the native
   envelope (5.4) that verifies against the manifest; replayed; the same
   preimage via native MPP and inside a BNAP credential: SPENT; one
   upstream call.
3. `the_bnap_cli_pays_end_to_end`: the `bnap` binary through the TLS front
   (`SSL_CERT_FILE` = the test CA): `init`, `budget set
   --allow-experimental true`, `paysource command docker compose ... exec
   -T payer lncli ... payinvoice --force --json --fee_limit {max_fee}
   {invoice}`, then `post` on the metered chat route (funds inside the 402,
   `bnap:notes`, charged 425, change kept), `get` on a notes-only route
   (paid from that change, no Lightning), `post` on the L402 / MPP route
   (charged 21), and `receipts verify`: three receipts, all valid.

```text
devenv/regtest/up.sh
cargo build --locked --bins -p caparra-gate -p bnap-signer-process -p bnap-cli
cargo nextest run -p e2e --features regtest
BNAP_CONFORMANCE=../bnap cargo nextest run -p e2e --features regtest --test conformance
```

## Gate-side bugs found and fixed (each with a test that failed first)

| # | Bug | Fix | Test |
| --- | --- | --- | --- |
| E1 | `bnap:notes` refused to start with `signer.kind = "process"`: the gate read the keyset table from the key file, which a separate signer process exists to keep from it (the brief's set-up could not run) | `bnap-signer` answers `keysets` with the public halves; the gate builds its table from them, recomputing each ID from the keys (blind signatures are DLEQ-checked against them as before) | `caparra-gate/tests/notes.rs::notes_work_with_the_process_signer_and_its_store`, `bnap-signer-process/tests/store.rs::the_signer_serves_the_public_halves_of_its_keysets` |
| E2 | A wallet funding inside the 402 could not use its change: the gate served no NUT-01 keys, so `caparra-wallet` failed with `ISSUER` (404) before paying | NUT-02 `GET {issuer}/v1/keysets`, NUT-01 `GET {issuer}/v1/keys` (active) and `/v1/keys/{id}` (active or inputs-only), answered by the gate under the issuer URL's path when it is on the origin, never forwarded | `caparra-gate/tests/notes.rs::the_issuer_serves_its_keysets_and_keys`; `e2e::gate::the_bnap_cli_pays_end_to_end` |
| E3 | The fund-quote offer on a metered route was not metered: a client funding inside the 402 paid the 2,100 sat ceiling for a call metered at 425. Draft-00 7: on a metered route only schemes without atomic refund or `upto` get offers at the ceiling | The fund offer is metered (with the entry's rate) whenever the route's notes entry is | `caparra-gate/tests/notes.rs` (`fund` now expects 425 and the change; it failed with 2,100) |
| E4 | L402 put its whole `WWW-Authenticate` challenge in one `l402-macaroon` entry (the conformance disagreement below) | One entry per artifact | `caparra-gate/tests/gate.rs::a_402_carries_offers_natives_and_required`, `bnap-scheme-l402` tests |

## Decision: the shape of L402 and MPP native entries

Literal reading of draft-00 4.1 ("`kind`: label from the scheme's registry
entry; `data`: the artifact's bytes") with the registry's native kinds:

- **L402**: the registry lists `l402-macaroon` and `bolt11`. The artifacts
  are the macaroon and the invoice; the challenge is a rendering of both.
  N7 was wrong. Now: `l402-macaroon` = the binary V2 macaroon, `bolt11` =
  the BOLT 11 string, both with the L402 entry's `pay_index`. Carriers build
  `L402 version="0", token=..., macaroon=..., invoice=...` from them, and a
  client compares the challenge's macaroon (base64-decoded) and invoice
  with the signed entries (9.3).
- **MPP**: the registry lists `mpp-challenge`; the artifact is the
  challenge, its bytes the `Payment` challenge exactly as issued. N11's
  canonical-JSON re-encoding (and its OfferID-prefixed `id`) was a suite
  invention; the runner was wrong. Unchanged here; the runner now reads the
  entry as a challenge, the OfferID from `opaque` under the HMAC id, the
  invoice from `methodDetails.invoice` (bnap `node/e2e-conformance`). No
  separate `bolt11` entry for MPP: the invoice is inside the challenge.

The `bnap-plug` change: one pay entry needs several artifacts, and
`CredentialScheme::native` returns one. `natives` is a new trait method
with a default that wraps `native`, so no other plug changes. L402
overrides it; `native` returns its first artifact (the macaroon).

Offer size with a real regtest invoice: the exact offer with the macaroon,
the invoice and the MPP challenge stays within `MAX_OFFER`
(`tests/regtest.rs` asserts it).

## Conformance

`conformance/run.py` (bnap) against the stack's gate through the TLS front
(`--target https://localhost:<port>`, the runner trusting the test CA
through `SSL_CERT_FILE`, so `MAN-HTTPS` runs), `--max-wait 400`, routes
`chat`, `status` and `fixed`; with a payer: `payers/lncli-payer.sh` with
`LNCLI` = `lncli` in the payer container, `--max-spend-sat 20000`
(regtest).

| Runner | Profile | Payer | Pass | Fail | Error | Skip |
| --- | --- | --- | --- | --- | --- | --- |
| bnap `develop` (before) | server | none | 57 | 1 | 2 | 35 |
| bnap `develop` (before) | server | lncli | 57 | 1 | 2 | 35 |
| bnap `develop` (before) | gateway | none | 56 | 1 | 2 | 38 |
| bnap `develop` (before) | gateway | lncli | 56 | 1 | 2 | 38 |
| bnap `node/e2e-conformance` (after) | server | none | 59 | 0 | 0 | 36 |
| bnap `node/e2e-conformance` (after) | server | lncli | **65** | **0** | **0** | 30 |
| bnap `node/e2e-conformance` (after) | gateway | none | 58 | 0 | 0 | 39 |
| bnap `node/e2e-conformance` (after) | gateway | lncli | **64** | **0** | **0** | 33 |

Before: the failure (`OFR-NATIVE-MATCH`, SHOULD) and both errors
(`OFR-NATIVE-EMBED` "not a v2 macaroon", `PAY-MPP` JSON decode) were the
native-shape disagreement, and the payer cases skipped because no offer had
a `bolt11` entry. After: every case that ran passed. With the lncli payer
`PAY-L402`, `PAY-OFFER-BINDING`, `PAY-TWO-SCHEMES` (one payment, SPENT the
second time), `PAY-MPP` and `PAY-NATIVE` pass on real regtest payments;
`MAN-HTTPS` passes through the TLS front. Verdict of every run:
"incomplete" (MUST cases skipped, accepted with `--allow-skips`), exit 0.

The remaining skips are by design or the runner's own gaps, not gate
failures:

- 27 MUST cases (`ATT-*`, `RCPT-*`, `REPLAY-*`, `SCOPE-BODY-HASH`,
  `SCOPE-MANIFEST-ORIGIN`) need a route whose DPoP waive admits a key the
  runner makes at random (profile `bnap-conf-dpop-1`); this gate's DPoP
  authority admits registered thumbprints only (`notes/n9a.md`).
- `PAY-METERED`, `NOTES-VALUE`: the runner has no notes wallet yet; the
  e2e tests above cover both on this gate.
- Gateway roles (`GW-TARGET`, `GW-SSE`, `fail`, `slow`, `cache`) need
  routes with DPoP waives and special applications the stack does not
  have; `ERR-CACHE-CONTROL` and `USE-REUSABLE-WINDOW` need the same.
- Without a payer, every payer case skips.

## Configuration used (the stack's `gate.toml`)

`[gate] origin = "https://localhost:<front port>"`, `listen` on 127.0.0.1,
`upstream` the mock; `[store] kind = "sqlite"`; `[signer] kind = "process"`,
`socket` in a 0700 directory; `[[rail]] kind = "lnd"` (payee node, invoice
macaroon, `invoice_expiry_s = 300`); schemes `bnap:notes` (`max_fund_sat =
10000`), `httpauth:L402`, `payment:lightning/charge` (`network =
"regtest"`); routes `chat` (`POST /v1/chat/completions`, route scope,
metered tokens, 500 sat per 1,000 up to 2,100), `status` (`GET /v1/status`,
notes, 10 sat), `fixed` (`POST /v1/fixed`, exact, L402 and MPP, 21 sat);
`[limits] mints_per_minute = 600` (the conformance runner mints many
offers). Online keys live 20 days (a manifest key may not outlive 30 days),
the keyset a year. The manifest is signed with `caparra-gate manifest sign
--keys-from keys.toml`.

## Gaps

- The issuer serves NUT-01 and NUT-02 only: no NUT-23 quotes, NUT-04 mint,
  NUT-09 restore or NUT-07 state on the gate, so `bnap fund` and `bnap
  restore` still cannot run against it. Funding inside the 402 needs none of
  them.
- `caparra-wallet` funds inside the 402 with the fund offer, not the route
  offer; with E3 that offer is metered, so the price is the same.
- The wallet counts a funded call's cost as the whole quote (B5 A2, the
  safe side): `cost_sat` 2,100 for a call charged 425 whose change it holds.
- The conformance test is not in CI: it needs a bnap checkout with the
  runner of `node/e2e-conformance` and takes about 25 minutes (expiry cases
  wait out real offer lifetimes).
- The TLS front is a test fixture; the gate itself still terminates no TLS.

## Checker

**Final verdict: PASS (round 1, at `ae3a481`).** The checker ran
everything again from fresh clones and got the same results: fmt and clippy
clean; workspace nextest 674 passed, 1 skipped; regtest e2e 16 passed;
conformance server/none 59/0/0/36, server/lncli 65/0/0/30, gateway/none
58/0/0/39, gateway/lncli 64/0/0/33 (pass/fail/error/skip); bnap runner
unit tests 66 OK; `mock_gate.py selftest` OK. It also mutated the mock
gate (a wrong OfferID in `opaque`, a sent challenge that differs from its
entry) and confirmed that `OFR-NATIVE-EMBED` and `OFR-NATIVE-MATCH` catch
both. No HIGH or MEDIUM findings, so no second round ran.

Other checks run here: `cargo +1.94 check --workspace --all-targets
--locked` (and `-p e2e --features regtest`) clean; `cargo deny
--all-features check bans licenses sources` ok; leak guard clean in both
repos.

### LOW findings kept open

- L1: the registry's `mpp-challenge` `embeds` text ("the challenge's HMAC'd
  id carries the OfferID") and draft-00 4.2 ("an MPP `id`") do not say that
  the OfferID goes in `opaque` under the HMAC id. A gate that puts it in
  `id` itself now fails `OFR-NATIVE-EMBED`. Needs an ERRATA row and new
  registry wording, which should also say that a `bolt11` entry is optional
  for MPP.
- L2: the mock gate's selftest has no fault for the new MPP shape. Add
  `mpp-opaque-wrong` (caught by `OFR-NATIVE-EMBED`) and
  `mpp-header-differs` (caught by `OFR-NATIVE-MATCH`).
- L3: `tests/conformance.rs` passes without doing anything when
  `BNAP_CONFORMANCE` is unset, as in CI. Either check out bnap in the
  regtest job (once `node/e2e-conformance` merges), or make the test
  ignored.
- L4: the gate's issuer endpoints are matched on the raw path before
  routing. So an empty issuer prefix, or a route under
  `{issuer}/v1/keys*`, gets shadowed. Encoded or trailing-slash variants
  fall through to routing, and HEAD is not served. None of this bypasses
  payment. Fix: refuse such configurations, and match on the normalized
  route path.
- L5 (fixed after the round): a stale comment on the e2e test wallet.
