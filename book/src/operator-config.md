# Operator config reference

`caparra-gate` reads one TOML file, given with `--config` (or the
`CAPARRA_CONFIG` environment variable). Unknown keys are an error. Relative
paths are resolved from the directory the gate runs in. Secrets never sit
in the file itself: keys name files that hold them, or, for NWC, an
environment variable.

`caparra-gate check --config gate.toml` runs every start-up check and
exits 0 when the gate would start. Two complete examples are in the
repository: `examples/quickstart/gate.toml` (fake rail, local) and
`examples/llm-proxy/gate.toml` (phoenixd, process signer, a metered
OpenAI-compatible route).

## `[gate]`

| Key | Default | Meaning |
| --- | --- | --- |
| `origin` | required | The origin the manifest is issued for, as an RFC 6454 serialization (`https://api.example`) |
| `listen` | `127.0.0.1:8080` | The address to serve on |
| `front` | `proxy` | `proxy` (reverse proxy to `upstream`), `forward_auth` (Caddy), `auth_request` (nginx); `envoy_ext_authz` is refused at start |
| `upstream` | none | The application, `http://host:port` with no path; plain HTTP only; `proxy` front only |
| `replay_window_s` | 86400 | Must equal the manifest's value (`manifest sign` writes it) |
| `pending_timeout_s` | 300 | Must exceed the longest action; must equal the manifest's value |
| `offer_lifetime_s` | 300 | Lifetime of exact-scope offers, at least 60 |
| `route_offer_lifetime_s` | 3600 | Lifetime of route-scope offers, at least 60 |
| `mac_key_file` | required | File holding `K_mac`, 64 hex (`caparra-gate key new`) |
| `retired_mac_key_files` | `[]` | Retired `K_mac` files, kept until every offer made under them has expired |
| `max_request_bytes` | 1048576 | Largest request content the gate buffers |
| `max_response_bytes` | 16777216 | Largest application answer the gate buffers |
| `keep_response_bytes` | 65536 | Answers up to this size are kept for replays; 0 keeps the receipt only |
| `trust_forwarded_for` | `false` | Take the client address from the rightmost `X-Forwarded-For` hop; set it only behind a trusted front; always on behind an auth front |

## `[manifest]`

| Key | Default | Meaning |
| --- | --- | --- |
| `file` | required | The manifest made offline by `caparra-gate manifest sign`, served byte for byte at `/.well-known/bnap` |
| `root` | none | The root public key (64 hex) the manifest must be signed by; recommended |
| `required` | `false` | The `required` flag `manifest sign` writes: clients then pay this origin only through BNAP offers |
| `max_age_s` | 604800 | The manifest's `max_age`, at most 30 days |

The gate refuses to start when the manifest's signature, root, origin,
routes, limits or keys do not match the configuration, when it has expired,
or when the signer cannot sign with its offer and receipt keys.

## `[store]`

| Key | Default | Meaning |
| --- | --- | --- |
| `kind` | `sqlite` | `sqlite`, or `memory` (a temporary SQLite file, for tests, logged loudly) |
| `path` | none | The SQLite file of the use store |
| `issuer_path` | `path` + `.issuer` | The SQLite file of the `bnap:notes` issuer tables |

The PostgreSQL store exists as a crate but is not wired into the gate yet.

## `[signer]`

| Key | Meaning |
| --- | --- |
| `kind` | `file` or `process` |
| `keys` | `file`: the signer key file (mode 0600; see `crates/bnap-signer-file`) |
| `socket` | `process`: the Unix socket of `bnap-signer` |
| `signer_uid` | `process`: the user `bnap-signer` runs as; the gate checks the peer |

`bnap:notes` needs the `file` signer for now.

## `[[rail]]`

| Key | Meaning |
| --- | --- |
| `id` | The name schemes refer to |
| `kind` | `lnd`, `phoenixd`, `nwc` or `fake` |
| `invoice_expiry_s` | Invoice lifetime; must not outlive an exact-scope offer |
| `address`, `cert`, `macaroon` | `lnd`: gRPC address, TLS certificate file, macaroon file |
| `url`, `password_file` | `phoenixd`: HTTP API URL and the file holding its password |
| `uri_env` | `nwc`: the environment variable that holds the NWC URI (default `NWC_URI`) |
| `registry`, `seed` | `fake`: the registry rail entry it claims to be (required, for example `ln:lnd`) and an optional 64-hex seed |

The fake rail moves no money and logs a warning at start.

## `[[scheme]]`

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | required | `bnap:notes`, `httpauth:L402` or `payment:lightning/charge` |
| `rail` / `rails` | | The rail or rails it settles over |
| `enabled` | `true` | |
| `secret_file` | | L402 and MPP: file holding the scheme's secret, 64 hex |
| `realm` | origin's host | MPP: the challenge realm |
| `network` | `mainnet` | MPP: `mainnet`, `signet` or `regtest` |
| `max_fund_sat` | | `bnap:notes`: funding inside the 402 up to this many sat |
| `issuer_url` | `<origin>/cashu` | `bnap:notes`: the issuer's Cashu API base |

## `[[attest]]`

| Key | Meaning |
| --- | --- |
| `id` | `httpauth:DPoP`, `httpauth:Bearer` or `httpsig:web-bot-auth` |
| `enabled` | Default `true` |
| `keys` | DPoP and Bearer: base64url JWK thumbprints of registered keys |
| `tokens` | DPoP and Bearer: access tokens, `{ token = "...", jkt = "..." }`; with `jkt` the token is bound to that key |
| `agents` | Web Bot Auth: `{ url = "...", key = "<64 hex Ed25519 public key>" }` entries |

Keys and agents are static lists; there is no token introspection or key
directory fetching yet.

## `[[route]]`

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | required | The route ID, part of the route scope |
| `match` | required | A method, a space and a path, such as `POST /v1/chat/completions`; `/*` matches every path below |
| `scope` | `route` | `route` (one shared offer) or `exact` (an offer per request, bound to its content) |
| `price` | | `{ sat = N }`: the price per call, or the ceiling on a metered route |
| `metered` | `false` | The charge is set at settlement by the meter |
| `meter` | | The meter's name, such as `tokens` |
| `meter_path` | `/usage/total_tokens` for `tokens` | JSON pointer to the count in the answer |
| `rate` | | Price per 1,000 meter units, sent in the offer |
| `require` | `{}` | Required scheme properties, such as `{ use = "single" }` |
| `accept` | `[]` | Value schemes, in preference order |
| `attest` | `[]` | `{ scheme, effect, value?, epoch? }` with `effect` one of `required`, `waive`, `discount` (value in basis points) or `quota` |
| `headers` | `[]` | Request fields hashed into the scope, lower case |
| `allow_experimental` | `false` | Needed for every Lightning scheme and `bnap:notes`, which the registry marks experimental |
| `allow_non_bitcoin` | `false` | Needed for schemes on non-Bitcoin rails or units |
| `upstream` | `http` | `http`, or `openai` for OpenAI-compatible APIs (metering by tokens; `"stream": true` refused on metered routes) |

A route that its enabled schemes cannot satisfy refuses to start.

## `[pricing]`

| Key | Meaning |
| --- | --- |
| `kind` | `table` |
| `table` | `{ <route id> = { sat = N } }`: overrides a route's price |

## `[limits]`

Per client address, per minute (draft-00 section 12, DECISIONS row 24).

| Key | Default | Meaning |
| --- | --- | --- |
| `mints_per_minute` | 20 | Offers that mint an invoice, and fund quotes |
| `verifies_per_minute` | 600 | Credentials that reach a scheme plug |
| `verifies_per_offer_per_minute` | 6000 | The same, per offer (route offers are shared) |
| `max_change_outputs` | 64 | Most change outputs one outcome may have signed |

## Defaults from the specification

| Setting | Default | Source |
| --- | --- | --- |
| `pending_timeout` | 300 s | Provisional decision for ERRATA row 21 |
| `replay_window` | 86,400 s | Provisional decision for ERRATA row 21 |
| Manifest `max_age` | at most 2,592,000 s (30 days) | draft-00 9.1 |
| Credential size on HTTP | at most 9,216 bytes; larger is `TOO_LARGE` | Provisional decision for ERRATA row 30 |
