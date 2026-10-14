# Integration notes: N9a, the HTTP carrier and the gateway

Branch `node/n9a`. Crates `bnap-carrier-http` and `caparra-gate`, the
`Dockerfile`, `examples/`, and (additively) `bnap-signer-process` and one
getter in `bnap-core`. Normative source: `bnap/spec/socket-draft-00.md`
(doc rev 39) sections 4.4 to 10 and 12, with `spec/DECISIONS.md`,
`spec/ERRATA.md` and `registry/generated/registry.json` (digest
`e133cf49...1de261c`, bnap commit `00d0d24`).

## What is in it

| Crate / file | What it holds |
| --- | --- |
| `bnap-carrier-http` | `HttpCarrier` (the `bnap_plug::Carrier` for HTTP: action and route scope per 10.1, credential extraction under the DECISIONS row 30 cap, native credentials in `Authorization`, one value credential per request), `fields` (10.2 field names, `BNAP offer="..."` challenges, `BNAP-Context`), `codec` (strict `b64u`), `client` (offers, natives, receipt and error from an answer; `BNAP-Credential` value), `layer` (`BnapLayer`, a tower `Layer` around any service, and the `Gatekeeper` / `Ticket` traits) |
| `caparra-gate` (lib) | `config` (TOML, validation, route plans), `registry` (embedded export, digest check, effective vectors), `manifest` (check at start, offline signing), `plugs` (signer, use store, rails, schemes from the config), `gate` (the `Gatekeeper`: offers, credentials, natives, `process`, settlement, receipts), `issuer` (the `bnap:notes` issuer tables in SQLite), `proxy` (the reverse proxy front), `server` (start-up and serving, the sweep), `limiter`, `meter` |
| `caparra-gate` (bin) | `run`, `check`, `manifest sign`, `key new` |
| `bnap-signer-process` | `--store` and `--max-keep-s` for `bnap-signer`, `check_ack`, `DEFAULT_MAX_KEEP`, the optional `replay_key` of a `schnorr` request |
| `bnap-core` | `CoreMessage::replay_key()` (additive, see "Change to bnap-core") |
| `Dockerfile`, `.dockerignore` | Multi-stage build of `caparra-gate` and `bnap-signer`, distroless `cc-debian12:nonroot`, uid 65532 |
| `examples/llm-proxy/` | `gate.toml`, `Caddyfile`, `nginx.conf`, a README with the set-up steps |

## Public API

### `bnap-carrier-http`

- `HttpCarrier::new(origin, max_credential)` (capped at 9,216 bytes
  whatever the manifest says), `with_natives(Vec<NativeAuth>)`, `origin`,
  `max_credential`, `natives`, `native(&HeaderMap)`; `Carrier` impl:
  `name` = `http`, `action_scope`, `route_scope`, `extract`, `offer`,
  `receipt`, `error`.
- `HttpRequest::new(&Parts, Bytes, scope_headers)`, `origin_form(&Uri)`.
- `carrier::{error_response, challenge_response, error_body, status_of,
  message}`: whole answers with `BNAP-Error`, `Retry-After`,
  `Cache-Control: private, no-store` and a JSON error body
  (`{"error":{"type":"bnap","code":"SPENT","message":...}}`).
- `fields::{AUTH_SCHEME, BNAP_CREDENTIAL, BNAP_CONTEXT, BNAP_RECEIPT,
  BNAP_ERROR, BNAP_FUND, PAYMENT_RECEIPT, NO_STORE, REQUEST_FIELDS,
  offer_challenge, parse_offer_challenge, combined, credential, context}`.
- `client::{offers, native_challenges, receipt, error, credential_value}`.
- `layer::{BnapLayer, BnapService, BodyLimits, Gatekeeper, GateRequest,
  Admit::{Forward, Answer, Run}, Run, Ticket, Done, Kept, ClientAddr,
  strip_fields, BoxBody}`. The layer buffers the request content, asks the
  gatekeeper, and for a `Run` calls the inner service under
  `Ticket::timeout`, buffers the answer, meters it when the offer is
  metered, settles through the ticket and only then answers with the
  receipt (6.4). `strip_fields` removes every `BNAP-*` field,
  `Payment-Receipt`, `Authentication-Info` and `BNAP` challenges from the
  application's answers (forwarded ones too). Every answer to a request
  that carried `BNAP-Credential` gets `Cache-Control: private, no-store`,
  forwarded ones included (10.2).

### `caparra-gate`

- `config::Config::{parse, load, plan(&Registry) -> Vec<RoutePlan>}`;
  `RoutePlan { section, price, pay: Vec<PayPlan>, attest, manifest }`,
  `PayPlan { scheme, amount, unit, rate, slot, class }`,
  `Slot::{Route, ExactMetered, ExactPlain}`, `Front`, `Upstream`.
- `registry::Registry::{embedded, from_json(text, digest), scheme, rail,
  class, effective}`, `REGISTRY_JSON`, `REGISTRY_DIGEST`.
- `manifest::{check(bytes, &Config, &plans, now) -> Loaded, sign(&Config,
  &plans, &SignInput) -> bytes}`.
- `server::{prepare(&Config, &Clock) -> (Gate, Arc<Plugs>), start(&Config,
  Clock, Option<TcpListener>) -> Running}`, `Running::{stop, wait}`.
- `gate::{Gate, Settings, notes_exact_lifetime, WELL_KNOWN}`.
- `plugs::{build, Plugs, ValuePlug, OutputBound, Clock, system_clock,
  read_hex, read_key32}`; `issuer::GateIssuerStore`; `proxy::{Upstream,
  Allow, strip_hop_by_hop}`; `limiter::Limiter`; `meter::{count,
  asks_for_stream}`.

## Configuration reference

```toml
[gate]
origin = "https://api.example"     # RFC 6454; the manifest origin and the scope target's prefix
listen = "127.0.0.1:8080"
front = "proxy"                    # proxy | forward_auth | auth_request | envoy_ext_authz (refused: stub)
upstream = "http://127.0.0.1:9000" # proxy only; plain http, no path
replay_window_s = 86400            # written by `manifest sign`; the gate reads the manifest's
pending_timeout_s = 300            # idem
offer_lifetime_s = 300             # exact-scope offers (at least 60)
route_offer_lifetime_s = 3600      # route-scope offers (at least 60)
mac_key_file = "mac.key"           # 64 hex
retired_mac_key_files = []
max_request_bytes = 1048576
max_response_bytes = 16777216
keep_response_bytes = 65536        # answers kept for replays; 0 = receipt only
trust_forwarded_for = false        # always on behind an auth front

[manifest]
file = "manifest.json"             # pre-signed by `manifest sign`
root = "<hex>"                     # optional pin of the root key
required = false                   # written by `manifest sign`
max_age_s = 604800

[store]
kind = "sqlite"                    # sqlite | memory (a temporary SQLite file, logged loudly)
path = "use.db"
issuer_path = "use.db.issuer"      # bnap:notes issuer tables (default: path + ".issuer")

[signer]
kind = "file"                      # file (keys = ...) | process (socket = ..., signer_uid = ...)

[[rail]]                           # id, kind = lnd | phoenixd | nwc | fake, invoice_expiry_s,
                                   # lnd: address, cert, macaroon; phoenixd: url, password_file;
                                   # nwc: uri_env; fake: registry (required), seed

[[scheme]]                         # id, rail / rails, enabled, secret_file (L402, MPP),
                                   # realm, network (MPP), max_fund_sat, issuer_url (notes)

[[attest]]                         # id, enabled, keys (DPoP/Bearer thumbprints), tokens,
                                   # agents (Web Bot Auth: url, key)

[pricing]
kind = "table"
table = { chat = { sat = 2100 } }  # overrides the route's price

[[route]]
id = "chat"
match = "POST /v1/chat/completions"
scope = "route"                    # route | exact
upstream = "openai"                # http | openai
price = { sat = 2100 }             # the ceiling on a metered route
metered = true
meter = "tokens"
meter_path = "/usage/total_tokens" # JSON pointer; the default for tokens
rate = 500                         # per 1,000 units (DECISIONS row 13: offer, not manifest)
require = { use = "single" }
accept = ["bnap:notes", "httpauth:L402", "payment:lightning/charge"]
attest = [{ scheme = "httpauth:DPoP", effect = "discount", value = 2000 }]
headers = []
allow_experimental = true
allow_non_bitcoin = false

[limits]
mints_per_minute = 20              # offers with natives and fund quotes, per address
verifies_per_minute = 600          # credentials reaching a plug, per address
verifies_per_offer_per_minute = 6000
max_change_outputs = 64            # per outcome
```

### Start-up refusals

`caparra-gate check` and `run` refuse to start when: the registry export's
`digest` member or its JCS hash is not the pinned digest; the origin is
not an RFC 6454 serialization; a route is unsatisfiable by its enabled
schemes under the effective-vector rule (scheme, every configured rail,
verifiers; unknown counts weakest) or lists an experimental scheme without
`allow_experimental` (bnap-core's `RoutePolicy::select`); a scheme uses a
non-Bitcoin rail kind or unit without `allow_non_bitcoin`; a scheme is
unknown, not implemented, or registered `use = "rate"`; an attestation of
class None would waive, discount or carry a quota, or an effect's value or
epoch is out of range; a quota is configured (no implemented attestation
registers a `quota_id`); a class None pay entry has a price above 0; a
metered route lacks a meter, rate or single price unit, or runs behind an
auth front; the front is `envoy_ext_authz`; a rail invoice outlives the
exact-offer lifetime; the manifest's signature, root pin, origin, `bnap`,
`carriers`, `issued`/`max_age`, routes, limits or keys are wrong (routes
must equal what the configuration resolves to; the offer key must outlive
an offer issued now and the receipt key `pending_timeout`); the signer
does not sign with the manifest's offer key (a probe offer is signed and
verified).

## How a request runs

1. `GET /.well-known/bnap`: the manifest bytes as signed.
2. No route matches: forwarded untouched (application BNAP fields
   stripped). Auth fronts answer 200.
3. A route matches. The target must be in origin form. On an `openai`
   metered route, `"stream": true` is refused (400). Behind an auth front,
   a request with content is refused (400): the gate cannot hash it.
4. Action scope (10.1) over the method, `origin + request-target` as
   received, the content hash (empty content hashes as empty, N3a-7) and
   the route's listed headers (combined as in RFC 9110 5.3).
5. `extract`: `BNAP-Credential` (TOO_LARGE above 12,288 characters, before
   decoding; MALFORMED twice or non-canonical), native `Authorization` for
   L402 / LSAT / `Payment`; both at once is MALFORMED. `BNAP-Context` is
   read here (MALFORMED when not 32 bytes).
6. No credential: a 402 with the route offer (one per route per half
   lifetime, shared, cached), an exact offer per remaining slot (natives
   minted under the per-address mint limit, one invoice per offer via
   `OfferInvoices`, cached by `OfferID`), a fund-quote notes offer when
   `BNAP-Fund` was sent (minted under the same limit, never cached), the
   native challenges verbatim, `BNAP-Error` REQUIRED. When the limit leaves
   no offer at all: 429 RATE_LIMITED with `Retry-After`.
7. A BNAP credential: `Credential::parse_with` (TOO_LARGE, MALFORMED,
   VERSION), `GateOfferCheck::check_credential` with the route's scope (4.4
   steps 1 to 6; offers without a MAC are never accepted: this gate
   publishes none in advance), binding classes from the registry,
   `check_tls_binding(None)` (the gate never sees TLS: a binding is
   BINDING, 5.3), Context and Digest, per-address and per-offer work
   bounds (RATE_LIMITED), then `BNAP-Context` compared (MALFORMED).
8. A native credential: the scheme must be on the route; per-address
   bound; `recover_native`; the offer from the artifact or the cache;
   `check_native`; the native envelope (5.4).
9. Verify the pay part (`CappedSigner::verify_only`), POLICY for a funded
   notes credential on an unlinkable route, confirm every rail reference
   with the scheme's rails of that kind (operator-trusted; notes failures
   through `rail_error`), verify each attestation (no effect when refused,
   UNAVAILABLE when its verifier is down), then `outcome::process` with
   the registry's use model and refund, and `admission_fields` for notes.
10. `Replay`: refund first if due, then the kept answer (or a JSON stub
    when none was kept) with a fresh receipt (`replayed` set).
11. `New`: a `Run` with a `GateTicket`. The layer runs the action; the
    ticket charges (`pending.charge(status, units)`), settles the scheme
    under `CappedSigner::for_change` over an `OutputBound` signer, falls
    back to FAILED if the OK settle fails, records the settlement
    (`outcome::settle`, refund on `AlreadySettled`, FAILED on
    `ChangeOverCap`), keeps the answer up to `keep_response_bytes`, and
    signs the receipt from the `Recorded`. Behind an auth front the ticket
    settles OK at once and the 200 carries the receipt.
12. A sweep every 30 s: `outcome::sweep` and SQLite counter pruning.

Errors that send a fresh offer (BAD_OFFER, STALE, WRONG_SCOPE, REQUIRED)
come as 402 with offers.

## Decisions (literal draft-00 reading where the brief differs)

- **Receipt field.** The brief says `Authentication-Info`; draft-00 10.2
  (and ERRATA row 15) say `BNAP-Receipt`. The gate sends `BNAP-Receipt`,
  and MPP's `Payment-Receipt` next to it (ERRATA row 33).
  `Authentication-Info` is stripped from application answers.
- **Target.** The brief says "normalized absolute URI, Content-Digest";
  draft-00 10.1 (and ERRATA row 16) hash the request-target exactly as
  received and the content itself. The proxy forwards the same
  request-target byte for byte (hyper-util, no URL normalization) and
  refuses to forward if it would change. `Content-Digest` is not read.
- **Experimental schemes.** Every Lightning scheme and `bnap:notes` is
  `maturity = experimental` in the registry. The literal rule ("need
  `allow_experimental` on each route that uses them") is applied to all of
  them, notes included; the overview's Core-1 remark that notes is "on by
  default" is not implemented.
- **Non-Bitcoin.** A scheme is non-Bitcoin when a registered rail kind is
  not `ln`/`onchain` or a unit is not `sat`/`msat`; it needs
  `allow_non_bitcoin` on the route (and is not implemented anyway).
- **Native challenge minting (DECISIONS row 24).** At most one invoice per
  offer (each exact offer has a fresh nonce; `OfferInvoices` shares one
  invoice between L402 and MPP), and per-address mint limits. Error
  answers that owe a fresh offer count against the same limit.
- **Metered routes.** Notes (`refund = atomic`) get the metered
  route-scope offer with the rate; L402 and MPP get a non-metered
  exact-scope offer at the ceiling (draft-00 7, 10.3). An answer that
  cannot be metered (not JSON, no count at the pointer, not 2xx) is
  withheld (502) and settled FAILED with the whole refund.
- **Exact offers carrying notes** live `offer_lifetime_s + pending_timeout
  + 60` s, so the notes admission cutoff (notes 5.4) leaves the client
  `offer_lifetime_s`; the manifest check uses that lifetime for
  `check_offer_lifetime`.
- **Kept answers.** Replays get the kept answer (`status ‖ lp(content type)
  ‖ body` in the outcome record) up to `keep_response_bytes`; otherwise a
  JSON stub `{"bnap":{"replayed":true,"response_kept":false}}` with the
  receipt (6.4 "receipt alone").
- **Auth fronts.** forward_auth / auth_request name the action by
  `X-Forwarded-Method` and `X-Forwarded-Uri`, refuse requests with content,
  admit and settle OK at once (the gate never sees the answer), and are
  refused at start with metered routes. nginx's `auth_request` passes only
  2xx/401/403, so other statuses go as 401 with `BNAP-Status`.
- **Envoy ext_authz** is a documented stub: refused at start.
- **Issuer tables.** `MemoryIssuerStore` is test-only, so the gate has its
  own `GateIssuerStore`: keysets in memory (rebuilt from the signer's key
  file at every start), quotes and signed outputs in SQLite (WAL,
  `synchronous = FULL`).
- **`memory` store** is a temporary SQLite file, not bnap-core's
  test-support `MemoryStore`, with a loud warning.
- **Upstream** is plain HTTP only (no TLS client in the gate); put the gate
  next to the application.
- **TLS binding** is always BINDING: the gate terminates no TLS itself, and
  even behind a TLS listener the exporter is not available through axum.

## Change to bnap-core (flag for the core re-gate)

`CoreMessage::replay_key() -> Option<&ReplayKey>`: set by
`Recorded::unsigned_receipt` (through a private `for_outcome`), `None` for
offers. Additive (one private field, one getter); it lets
`bnap-signer --store` check an ack against its outcome record. Why it is
unavoidable: the Response carries no `ReplayKey`, and the `Signer` trait
takes only the `CoreMessage`, so without it a signer cannot find the
record. No other bnap-core or bnap-plug change.

## bnap-signer: `--store` and `--max-keep-s`

- `--store <sqlite path>` (env `BNAP_SIGNER_STORE`): change only for
  outputs the store reserved for the outcome (`check_reserved`, existing),
  and an ack only when the request names its outcome (`replay_key`), the
  record is settled with no refund due, and the Response states the
  record's status, charge, metered units, scheme result and `settled_at`
  (`check_ack`). Reaching the socket is then not enough to mint change or
  receipts for outcomes that never settled. Offers stay unchecked (they
  need `K_mac`, which the signer does not hold, to be accepted).
- Wire: `schnorr` gains an optional `replay_key` (omitted when `None`, so
  offers to an older signer still work; an older signer refuses acks from
  a newer gate because it denies unknown fields).
- `--max-keep-s` (default 31 days, `DEFAULT_MAX_KEEP`): the change ledger
  keeps an entry at most that long after now, whatever `keep_until` a
  request names.

## Tests

- `bnap-carrier-http`: 20 unit tests (scope vectors of draft-00 14, target
  as received, header combining, size cap before decoding, one value
  credential, no-store on every answer, the layer: settle before answer,
  metering, failure and timeout, forwards, scrubbing, no-store on
  forwarded credentialed requests).
- `caparra-gate` unit: registry digest (tampered export refused), effective
  vectors, issuer tables survive a reopen, limiter, meter, proxy.
- `caparra-gate/tests/gate.rs` (13): manifest served byte for byte and
  verifies; the 402 (route offer metered notes only, exact offer L402 + MPP
  at the ceiling with natives matching the challenges, one invoice); L402
  paid natively, replayed (kept answer, no second action), the same
  payment via MPP natively and inside a BNAP credential SPENT; MPP inside a
  BNAP credential with `Payment-Receipt`, WRONG_SCOPE with a fresh offer;
  an offer for another route WRONG_SCOPE; oversize credential 413; BNAP +
  native MALFORMED; stripped offer and unknown OfferID BAD_OFFER; stream
  refused; untouched forwarding; start-up refusals (unsatisfiable,
  experimental, non-Bitcoin, metered behind auth, ext_authz, class None
  discount); manifest refusals (bad signature, expired, routes differ,
  keys too short); the example configuration resolves; the mint limit.
- `caparra-gate/tests/notes.rs` (4): notes funded inside the 402 (unpaid
  refused, paid admitted, change recovered with the N6 client), spent on
  the metered route offer with a DPoP discount (850 tokens, 425 less 20% =
  340, change recovered), replay (kept answer, same scheme result, no
  second action), SPENT on reuse, a swapped body refused, the change
  spends (425 without the discount); an unmeterable answer (SSE) settled
  FAILED with the whole refund; upstream BNAP fields scrubbed; DPoP waive
  admits with no pay part, a wrong `BNAP-Context` is MALFORMED, an
  unregistered key has no effect (UNDERPAID).
- `caparra-gate/tests/fronts.rs` (2): forward_auth (402, L402 native paid,
  receipt, no application call, content refused, off-route allowed, no
  forwarded request 400); auth_request status mapping.
- `bnap-signer-process/tests/store.rs`: acks need their settled outcome
  (no outcome named, unknown, pending, a changed charge: refused);
  keep_until bounded.

## Conformance (N11 runner, bnap `node/n11`)

`python3 -I conformance/run.py --target http://127.0.0.1:9180 --allow-http
--profile server --payer none --max-wait 400` against a locally started
`caparra-gate run` (fake rail, file signer, SQLite store, routes chat and
fixed): **57 passed, 1 failed (SHOULD), 2 errors (MUST), 35 skipped**.
The failure and both errors are one cross-node disagreement, not a gate
bug: N11 reads an L402 native entry's `data` as the bare macaroon (kind
`l402-macaroon`) plus a separate `bolt11` entry, and the MPP entry's data
as challenge JSON, while N7's adapters put the whole `WWW-Authenticate`
challenge in one entry (`OFR-NATIVE-EMBED` "not a v2 macaroon",
`OFR-NATIVE-MATCH`, `PAY-MPP` JSON decode). The owner has to pick one
reading of "the artifact's bytes" (4.1); the gate sends whatever the
scheme returns. Skips: no payer (`--payer none`), no DPoP key the runner
makes is honoured by this gate's authority (by design: registered keys
only), no roles, no notes wallet in the suite, plain HTTP. Earlier runs
also flagged two configuration points now fixed: keys valid for more than
30 days (`MAN-KEY-LIFETIME`, test keys) and a WRONG_SCOPE 402 without a
fresh offer once the mint limit was used up (now 429 RATE_LIMITED).

## Docker

`docker build -t caparra-gate .` succeeded here (image 96 MB, distroless,
uid 65532), with two sandbox-only workarounds. In this
sandbox Docker Hub rate-limits and Debian mirrors are blocked, so the image
is built with `--build-arg RUST_IMAGE=mirror.gcr.io/library/rust:1.99-slim-bookworm`
and a scratch copy of the Dockerfile that takes `protoc` from the host and
trusts the sandbox proxy's CA; the shipped Dockerfile is unchanged by that.

## Other file touched

`crates/bnap-scheme-notes/Cargo.toml`: its self dev-dependency now goes
through the workspace dependency. With `caparra-gate` as a second user of
`bnap-scheme-notes`, cargo-deny's `workspace-duplicate` ban failed on the
old `path = "."` form; nothing else changes.

## CI status at hand-off

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets
--locked -- -D warnings`, `cargo nextest run --workspace --locked` (552
passed, 1 skipped), `cargo test --workspace --doc --locked`, `cargo deny
--all-features check bans licenses sources`, MSRV `cargo check
--workspace --all-targets --locked` on 1.94: all green. Postgres and
regtest jobs not run here.

## Gaps

- Streaming is not metered: `"stream": true` is refused on metered OpenAI
  routes, and an SSE answer on a metered route is withheld and refunded.
  Trailers and the final `bnap-receipt` event (10.2) are follow-ups. On
  non-metered routes streamed answers are buffered and get the receipt in
  the header.
- Envoy ext_authz is not implemented.
- No NUT endpoints (mint, keys, restore, quote state) yet; wallets take
  keyset keys from the signer's key file in tests.
- `bnap:notes` needs the file signer (the keyset table is read from the key
  file); with the process signer it is refused at start.
- Keyset rotation and quote/output retention sweeps for the issuer tables
  are not scheduled.
- The DPoP / Bearer authority is the static one (registered thumbprints and
  tokens); no RFC 7662 introspection. Web Bot Auth agents are pinned
  statically; no directory fetching.
- HTTPS upstreams are not supported.
- One gate instance per SQLite file; Postgres is not wired (the crate
  exists).
- No hot reload: a new manifest or key needs a restart.

## Checker rounds

### Round 1: FAIL (2 HIGH, 2 MEDIUM), all fixed with a test that failed first

| # | Finding | Fix | Test |
| --- | --- | --- | --- |
| H1 | Auth fronts: a replay answered 200, so the front ran the action again on every replay | A replay behind an auth front answers 409 with the receipt (401 + `BNAP-Status: 409` for nginx) | `fronts::forward_auth_challenges_admits_and_settles_without_the_content` (three replays) |
| H2 | `POST /v1/chat/%63ompletions` matched no route and was forwarded unpaid; uvicorn-style upstreams decode it | Routes match `route_path(path)`: percent-decoded once, dot-segments removed, empty segments collapsed; the scope and the forwarded target stay as received | `gate::encoded_variants_of_a_paid_path_are_still_paid_routes`, unit `route_paths_are_what_an_application_routes` |
| M1 | A binding with no class S scheme came back NOT_OFFERED, not MALFORMED | `check_binding_classes` and `check_tls_binding` run right after parsing, before the offer checks | `gate::a_binding_without_a_class_s_scheme_is_malformed_before_offered_schemes` |
| M2 | Auth fronts: the content guard never fired (the subrequest carries no length) and the scope covered empty content | The front must send `X-Original-Content-Length` (and may send `X-Original-Transfer-Encoding`); missing, non-empty-non-zero, or a transfer coding is refused (400); examples updated | `fronts` (missing and `5` refused) |

Also from round 1: L1 (key-expiry checks untested) now has
`gate::a_manifest_whose_keys_expire_too_soon_is_refused`; L2 `check_ack`
now compares `unit` (test `store::with_the_store_an_ack_needs_its_settled_outcome`,
made to bite); L4 the client address is the rightmost `X-Forwarded-For`
hop.

### LOW findings kept open

- L2 (rest): `check_ack` cannot bind the Response's `digest` or `offer_id`
  (the record holds neither); a socket-only process can get an ack for a
  real settled outcome under another credential's Digest.
- L3: when the OK settle fails and the FAILED fallback succeeds, the
  application's answer is still sent, with a FAILED refunded receipt. No
  client-triggered path was found.
- L5: the manifest is checked only at start; a gate running past
  `issued + max_age` keeps serving it and issuing offers. Restart with a
  new manifest; a runtime check is a follow-up.
- L6: on non-metered routes a buffered `text/event-stream` answer keeps an
  application `event: bnap-receipt` (10.2 says strip it).
- L7: once an address's mint limit is used up, a refusal owed a fresh
  offer on an exact route is 429 RATE_LIMITED, not 402 (DECISIONS row 24
  against 8.2); the N11 run hits it unless `mints_per_minute` is raised.
