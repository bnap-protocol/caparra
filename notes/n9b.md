# Integration notes: N9b, the MCP carrier

Branch `node/n9b`, crate `crates/bnap-carrier-mcp`. Normative source:
`bnap/spec/socket-draft-00.md` (doc rev 39), with the overview's Carriers
table and MCP section (`spec/overview-v0.5.md`), `registry/carriers.toml`
(`carrier.mcp`) and the registry entries of the schemes used. External:
the MPP MCP transport as the `mpp` crate 0.15.1 implements it (`src/mcp.rs`:
codes -32042 and -32043, `_meta` keys `org.paymentauth/credential` and
`org.paymentauth/receipt`, `error.data.httpStatus` and `challenges` with
`request` as a JSON object); the transport draft itself could not be
fetched from this sandbox. MCP itself through rmcp 3.5.1.

**No change to `bnap-core` or `bnap-plug`.** Everything is built on the N3
API (`notes/n3-core.md`) the way `e2e::Gate` (N7) runs it.

## What the crate does

`PricedTools<H>` wraps any rmcp `ServerHandler`. The operator prices tools
on a `Gate`; every call to a priced tool runs the socket's flow, and every
other request goes to the inner handler unchanged:

1. **No credential:** a JSON-RPC error `-32042` with `error.data` =
   `{httpStatus: 402, challenges: [...], "org.bnap/error": b64u(REQUIRED)}`.
   `challenges` holds one BNAP entry `{"org.bnap/offer": b64u(Offer)}` (a
   fresh exact-scope offer for this tool and these arguments) and, for
   `payment:lightning/charge`, the MPP challenge object of the offer's
   native entry (`request` as JSON). The tool does not run.
2. **A credential** in `params._meta["org.bnap/credential"]` (b64u of a
   BNAP Credential) or, natively, `params._meta["org.paymentauth/credential"]`
   (the MPP MCP credential object): the 4.4 checks, binding, scheme
   `verify`, every rail reference confirmed, `outcome::process`, the tool
   (at most `pending_timeout`), the scheme's settle, `outcome::settle`, and
   the receipt signed from the recorded outcome. Both credential keys are
   removed from `_meta` before the tool runs.
3. **The answer** is the tool's result with `result._meta["org.bnap/receipt"]`
   = b64u(Response), plus `result._meta["org.paymentauth/receipt"]` (the
   decoded `Payment-Receipt` object) when the credential came natively in
   the MPP key. A tool that fails (an rmcp error) answers with its error,
   the receipt in `error.data["org.bnap/receipt"]`.
4. **A refusal** is a JSON-RPC error with `httpStatus` (8.2) and
   `"org.bnap/error"`, never a receipt, and a fresh offer when a new payment
   can answer it.

## Public API

| Item | What it is |
| --- | --- |
| `PricedTools::new(inner, Arc<Gate>)`, `inner`, `gate` | The wrapper; implements `ServerHandler`, forwarding every method |
| `router(path, gate, StreamableHttpServerConfig, StrictConfig, factory)` | An axum `Router`: rmcp's streamable HTTP service (stateless, JSON responses) at `path`, behind the strict JSON layer |
| `Gate::builder(server_uri, store, signer, offer_key, receipt_key, mac_key)` | `GateBuilder`: `.scheme(SchemeConfig)`, `.rail(Arc<dyn FundingRail>)`, `.tool(name, ToolPrice)`, `.limits(Limits)`, `.retained_mac_key(k)`, `.offer_lifetime(s)`, `.clock(Clock)`, `.max_kept(bytes)`, `.offer_cache(n)`, `.build() -> Result<Gate, ConfigError>` |
| `Gate::call(params, Presented, strict, action)` | One priced call, for other transports or tests; `price(tool)`, `scope(tool, args)`, `config()` |
| `Presented { bnap, mpp }` | What `_meta` carried |
| `SchemeConfig::new(plug, BindingClass, UseModel, Refund)`, `.with_properties(EffectiveVector)` | A scheme and its registry facts |
| `ToolPrice::new().pay(scheme, amount, unit).attest(AttestEntry).require(Require)`, `Price` | A tool's price |
| `GateConfig`, `ConfigError`, `Clock`, `system_clock`, `DEFAULT_OFFER_LIFETIME` (300), `DEFAULT_MAX_KEPT` (64 KiB), `DEFAULT_OFFER_CACHE` (4096) | Configuration |
| `scope::{action_scope, action_scope_json, route_scope, parse_arguments, arguments_jcs, SCOPE_TAG, ROUTE_TAG, ScopeError, MAX_EXACT_INTEGER}` | The scopes |
| `wire::{CREDENTIAL, RECEIPT, OFFER, ERROR, MPP_CREDENTIAL, MPP_RECEIPT, CHALLENGES, HTTP_STATUS, PAYMENT_REQUIRED, VERIFICATION_FAILED, INVALID_PARAMS, INTERNAL_ERROR, jsonrpc_code, carries_offer, message, ErrorData, b64u, from_b64u, B64Error}` | Wire keys and codes |
| `mpp::{challenge_value, credential_token, credential_value, receipt_value, CredentialShape}` | MPP MCP forms of `payment:lightning/charge` |
| `strict::{strict_json, StrictConfig, StrictJson, DEFAULT_MAX_BODY}` | The strict JSON layer |
| `client::{PaymentError (read, payable), bnap_meta, mpp_meta, receipt}` | Client helpers on plain JSON |

## The scope (provisional)

```text
action scope = H_"bnap/scope/mcp"( lp(server URI) ‖ lp(tool name) ‖ lp(H(JCS(arguments))) )
route scope  = H_"bnap/route/mcp"( lp(server URI) ‖ lp(route id) )
```

Written the way draft-00 10.1 writes the HTTP scopes; no BNAP document
defines it yet (the MCP carrier note will), so tags and layout may change.

- **server URI** is the URI the operator configures (`Gate::builder`),
  never what the server sees, so the scope holds behind a front.
- **tool name** is `params.name` as sent.
- **arguments** is `params.arguments`, JCS (RFC 8785,
  `serde_json_canonicalizer`); absent arguments are `{}`. JCS makes
  equivalent JSON equal (member order, whitespace, `2` vs `2.0`, `e`
  vs `e`) and different JSON different. An integer above 2⁵³ in magnitude
  is refused (MALFORMED): JCS would round it, so two different calls would
  share a scope.
- **Duplicate member names** are refused at any depth, in the whole
  message, before rmcp parses it (the strict layer, below).

Pinned value: `the_scope_is_pinned` in `src/scope.rs` (computed
independently in Python from the formula).

## Wire forms and codes

| Message | Place |
| --- | --- |
| Offer | `{"org.bnap/offer": b64u(Offer)}` entries in `error.data.challenges` |
| MPP challenge | MPP MCP challenge objects in the same `challenges` array |
| Error | `error.data["org.bnap/error"]` = b64u(Error), `error.data.httpStatus` = the 8.2 status |
| Credential | `params._meta["org.bnap/credential"]` = b64u(Credential) |
| MPP credential | `params._meta["org.paymentauth/credential"]` = the MPP MCP credential object |
| Receipt | `result._meta["org.bnap/receipt"]` = b64u(Response); on a tool error, `error.data["org.bnap/receipt"]` |
| MPP receipt | `result._meta["org.paymentauth/receipt"]`, natives only |

| BNAP code | JSON-RPC | Fresh offer |
| --- | --- | --- |
| REQUIRED | -32042 payment required | yes |
| BAD_OFFER, STALE, WRONG_SCOPE, NOT_OFFERED, POLICY, UNDERPAID, BAD_CREDENTIAL, SPENT | -32043 verification failed | yes |
| VERSION, MALFORMED, TOO_LARGE, BINDING | -32602 invalid params | no |
| PENDING, RATE_LIMITED, UNAVAILABLE | -32603 internal error | no (`retry_after` in the Error object for the first two) |

## Configuration reference

```rust
let gate = Gate::builder("https://api.example/mcp", store, signer, offer_key, receipt_key, k_mac)
    .scheme(SchemeConfig::new(l402, BindingClass::O, UseModel::Single, Refund::None))
    .scheme(SchemeConfig::new(mpp, BindingClass::O, UseModel::Single, Refund::None))
    .scheme(SchemeConfig::new(dpop, BindingClass::A, UseModel::Reusable, Refund::None))
    .rail(ln_rail)                                   // confirms every `ln` reference
    .tool("weather", ToolPrice::new().pay("httpauth:L402", 21, "sat")
                                     .pay("payment:lightning/charge", 21, "sat"))
    .tool("agent", ToolPrice::new().attest(AttestEntry::new("httpauth:DPoP", Effect::Waive)))
    .limits(limits_from_manifest)
    .build()?;
let app = router("/mcp", Arc::new(gate), rmcp_config_with_allowed_hosts,
                 StrictConfig::default(), || MyTools::new());
```

- Registry facts (class, model, refund, property vector) come from the
  operator, never from a plug. `SchemeConfig::new` sets every property to
  its weakest, so a tool with a `require` admits a scheme only once
  `.with_properties(EffectiveVector::compute(..))` gives its real vector.
- Lightning schemes share one `OfferInvoices` (N7); the rail given to
  `.rail` is the plain rail, which confirms.
- `build` refuses a tool that names an unconfigured scheme, a tool with
  neither a pay entry nor a waive, limits that fail `validate` or
  `check_offer_lifetime`, and no MAC key.
- `rmcp`'s `allowed_hosts` defaults to loopback; public deployments set it.

## Decisions made

- **One `challenges` array.** The brief asks for the MPP shape plus "a BNAP
  offer entry". Each offer is an entry `{"org.bnap/offer": b64u}` in
  `error.data.challenges`, next to the MPP challenge objects. An MPP client
  skips entries that are not challenges (the `mpp` crate's
  `extract_challenges_from_data` does), and a BNAP client reads one array.
- **Code mapping** follows the `mpp` crate: -32042 only for "no
  credential"; every refusal a new payment can answer is -32043 with a
  fresh offer (the client pays again on both, never on PENDING); malformed
  input is -32602; the rest -32603. `httpStatus` is the draft-00 8.2 status
  of the BNAP code (so SPENT is -32043 with 409, POLICY -32043 with 403).
- **Strict JSON in front of rmcp.** rmcp keeps the last of two duplicate
  members, so the check runs on the raw body (`strict_json`, using
  `bnap_core::manifest::parse_strict`). It marks the request
  (`StrictJson` in the HTTP extensions, which rmcp passes to the handler in
  `http::request::Parts`), and the gate refuses a priced call without the
  mark (UNAVAILABLE, logged): a priced tool served without the layer never
  runs. A duplicate anywhere in the message (arguments, `_meta`, the
  envelope) is refused, for free and priced tools alike, with -32602,
  `httpStatus` 400, MALFORMED.
- **Exact-scope offers only.** Every challenge is an exact-scope offer for
  the tool and its arguments, with each class O scheme's native. Route
  offers (class S and A only, 4.3) are not issued yet; `route_scope` is
  defined for when they are.
- **Offer cache, literally 5.1.** Only offers that carry natives are
  cached (bounded, expired ones dropped first). An offer without natives
  (such as a DPoP-only tool) is not cached, so the credential carries it
  inline.
- **Replays return the kept result.** The tool's result (or error) is kept
  in the outcome record as JSON (`Settlement::with_response`), up to
  `max_kept` bytes; a replay inside the record window returns it with a
  fresh receipt over the replaying request's Digest, `replayed` set and
  the original `settled_at`, `charged` and `scheme_result` (6.4). A result
  that was not kept is answered with the receipt alone: an empty result
  for OK, a -32603 error carrying the receipt for FAILED.
- **What counts as FAILED.** The outcome is FAILED when the tool returns
  an rmcp error, a result with `isError: true`, a non-complete response
  (input required or a task: a priced tool must complete in one call), or
  runs past `pending_timeout` (the action is dropped, 6.4). Each still
  reaches commit, so each answer carries a receipt.
- **No TLS binding.** A credential with `binding` is BINDING (5.3: the
  gate cannot see the client's TLS session through MCP).
- **Two credentials** (both keys present) are MALFORMED (5.4), even if the
  BNAP one carries only attestations.
- **The MPP native token.** The MCP credential object is turned back into
  the HTTP token `b64u(JCS(credential))`, with `challenge.request` and
  `meta` re-encoded as `b64u(JCS(..))` (`opaque` wins when both are sent
  and must match `meta`). That token is the native credential bytes of the
  registry entry: the scheme reads it strictly, and the native Context,
  Digest and `ReplayKey` cover it, so every spelling of one MPP credential
  is one credential.
- **The credential keys never reach the tool**: they are removed from
  `_meta` before the inner handler runs.
- **The scope's arguments are rmcp's parsed `params.arguments`**, the value
  the tool receives, after the strict layer guaranteed no member was
  folded.

## ERRATA candidates (literal draft-00 reading taken)

| # | Where | Ambiguity | What N9b does |
| --- | --- | --- | --- |
| N9b-1 | overview, Carriers: MCP; draft-00 10.1 | No layout or tag for the MCP scope | `H_"bnap/scope/mcp"(lp(URI) ‖ lp(tool) ‖ lp(H(JCS(args))))`, provisional |
| N9b-2 | draft-00 8.2 "402, fresh offer" for 4 codes only | Whether NOT_OFFERED, UNDERPAID, BAD_CREDENTIAL, SPENT, POLICY carry an offer | They do over MCP: -32043 means "pay again" to MPP clients, so it always carries a fresh offer |
| N9b-3 | draft-00 5.4 "more than one value credential" | A BNAP Credential with only attestations next to an MPP credential | MALFORMED |
| N9b-4 | draft-00 6.4 "a carrier that did not keep the response" | What the receipt-alone answer looks like in MCP | An empty result (OK) or a -32603 error with the receipt (FAILED) |
| N9b-5 | draft-00 8.1 status FAILED | Whether a tool's own error result (`isError`) is FAILED | Yes |
| N9b-6 | draft-00 5.1 offer cache | DPoP-only exact offers have no natives, so they are not cached | The credential must carry the offer inline |

## Tests

`cargo test -p bnap-carrier-mcp`: 30 tests.

| Where | What |
| --- | --- |
| `src/scope.rs` (7) | pinned scope; member order, whitespace and number spelling do not change it; every input does (URI, tool, arguments, absent vs present); length prefixes; route vs action; duplicates at any depth refused; non-objects; integers above 2⁵³ |
| `src/wire.rs` (3) | canonical base64url only, length checked before decoding; every socket code has a JSON-RPC code and a message, PENDING never carries an offer; `ErrorData` round trip with the BNAP entry in `challenges` |
| `src/mpp.rs` (4) | challenge object with `request` as JSON; every MCP spelling of a credential gives one token; malformed credentials refused; receipt object |
| `tests/mcp.rs` (16) | over rmcp's streamable HTTP server and rmcp's own client: a free tool runs; a priced call without credential gets -32042, `httpStatus` 402, the MPP challenge and the BNAP offer, and does not run; L402 as a BNAP Credential pays once, the tool never sees the credential, the receipt verifies, and the replay returns the kept result with `replayed` and the original `settled_at`; altered arguments (value, extra member, none, name case) are WRONG_SCOPE with a fresh offer and the credential still works for its own call; equivalent JSON (order, `2.0`) admits; a credential for one tool (BNAP or MPP native) is WRONG_SCOPE on another; MPP native pays and returns both receipts, replay too; one payment under L402 then MPP admits one call (SPENT, 409); an unpaid invoice is BAD_CREDENTIAL and never runs; a DPoP waive admits with charge 0, its replay is answered from the record, an unregistered key is UNDERPAID; a failing tool settles FAILED with its receipt; an expired offer is STALE; two credentials, bad encodings, oversize, a TLS binding and an unknown `OfferID` are refused before anything runs; duplicate members (in arguments, nested, through a `\u` escape, in `_meta`) are refused before rmcp for priced and free tools; a `\u` escaped argument is the same argument; without the strict layer a priced tool never runs (UNAVAILABLE) while free tools do |

## Status at hand-off

See "Checker" below for the final verdict.

- `cargo test -p bnap-carrier-mcp --locked`: 30 passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: clean
  (protoc installed in the sandbox for `bnap-rail-lnd`).
- `cargo fmt --all --check`: clean.
- `RUSTUP_TOOLCHAIN=1.94 cargo check -p bnap-carrier-mcp --all-targets --locked`: clean.
- `cargo deny check bans licenses sources`: ok (existing warnings only:
  unused workspace deps `mpp`, `tower-http`).
- `sh ops/leak-guard.sh`: clean.
- Docker was not needed.

## Known gaps

- No route-scope offers; every priced call costs one round trip for its
  offer.
- No GREASE record in issued offers (draft-00 2, SHOULD).
- Every unauthenticated call to a priced tool issues an offer, and a
  Lightning offer mints an invoice: per-client limits (section 12,
  DECISIONS row 24) are the deployment's, in front of the router.
- No metering: offers are never metered and `metered_units` is never set.
- The strict layer serves the streamable HTTP transport only; over stdio
  or another transport the gate refuses priced calls (no `StrictJson`
  mark). `Gate::call` takes `strict` for a transport that checks itself.
- `require` is checked against the vector the operator gives
  `SchemeConfig`; the gate does not compute vectors from the registry
  export.
- The MPP problem-details object (`data.problem`) of the MPP MCP transport
  is not sent; MPP clients read the code and `challenges`.
- The MPP MCP transport draft could not be fetched here; the shapes follow
  the `mpp` crate 0.15.1.
- `mpp` and `tower-http` stay unused workspace dependencies (cargo-deny
  warns), as before this node.

## Checker

(filled in after the quality gate)
