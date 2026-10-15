# Changelog

All notable changes to this workspace are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crates are
alpha and do not follow semantic versioning yet. Once crates are
published, release-plz also writes a changelog per crate under
`crates/<name>/CHANGELOG.md`.

## [Unreleased]

## [0.1.0-alpha] - 2026-10-15

The first alpha. It is **not audited** and is meant for regtest and test
use only: do not use it with mainnet money. The crates are **not on
crates.io yet**; the release consists of the binaries `caparra-gate`,
`bnap` and `bnap-mcp`, built by dist with GitHub artifact attestations.
Caparra tracks BNAP draft-00, and every interface can change.

### Added

- `bnap-core`: the BNAP socket of draft-00. Offers, credentials and
  envelopes in TLV, Responses and receipts, the signed manifest with I-JSON
  and JCS, OfferID, Context, Digest and ReplayKey, pricing, the use and
  outcome model (`process`, `settle`, `sweep`), change caps. Checked
  against the specification's test vectors.
- `bnap-plug`: the plug traits for schemes, rails, stores, signers and
  carriers, with a capped signer for scheme settlement.
- Value schemes: `bnap:notes` (`bnap-scheme-notes`, blind notes with
  change and funding inside the 402), `httpauth:L402`
  (`bnap-scheme-l402`) and `payment:lightning/charge`
  (`bnap-scheme-mpp`).
- Attestation schemes: `httpauth:DPoP` and `httpauth:Bearer`
  (`bnap-scheme-dpop`), `httpsig:web-bot-auth`
  (`bnap-scheme-webbotauth`), with static key registries.
- Rails: LND over gRPC, phoenixd, Nostr Wallet Connect, and an in-memory
  fake rail for tests.
- Use stores: SQLite and PostgreSQL, with a shared conformance suite
  (`bnap-store-tests`).
- Signers: a key file signer and a process signer over a Unix socket
  (binary `bnap-signer`).
- Carriers: HTTP (`bnap-carrier-http`, a tower layer) and MCP
  (`bnap-carrier-mcp`, priced tools around an rmcp server).
- `caparra-gate`: the gate, as a reverse proxy or behind Caddy
  `forward_auth` or nginx `auth_request`, with offline manifest signing,
  start-up checks, metered OpenAI-style routes and per-address limits.
- `caparra-wallet`: the client wallet with manifest pinning, a spending
  policy with per-request, per-task, per-origin and daily caps, notes
  funding and restore from a mnemonic, receipts, and encrypted storage.
- `bnap` (crate `bnap-cli`) and `bnap-mcp` (an MCP server with the
  `fetch_paid`, `budget` and `receipts` tools).
- `e2e` tests and a regtest Lightning network in `devenv/regtest/`: the
  real gate, process signer and `bnap` CLI end to end over LND on regtest
  (notes funded inside the 402, metered, replayed and spent; one Lightning
  payment through L402 and MPP admitting one action; the CLI paying through
  a TLS front), plus a conformance run with bnap's runner.
- `bnap-signer-process`: a `keysets` request that serves the public half of
  each notes keyset, so the gate runs `bnap:notes` with the process signer.
- `caparra-gate`: the issuer's NUT-02 `GET {issuer}/v1/keysets` and NUT-01
  `GET {issuer}/v1/keys[/{id}]`, answered by the gate when the issuer URL is
  on its origin, so a wallet funding inside the 402 can spend its change.
- Examples: `examples/quickstart/` (fake rail) and `examples/llm-proxy/`
  (an OpenAI-compatible endpoint, with Caddy and nginx fronts).
- Fuzzing: twelve cargo-fuzz targets in `fuzz/`, run weekly in CI.
- Security review B5 (`SECURITY-REVIEW.md`) with its MEDIUM findings
  fixed; open LOW findings in `KNOWN-ISSUES.md`.
- CI (leak guard, DCO, rustfmt, clippy, tests on Linux and macOS, MSRV
  1.94, cargo-deny, book, regtest), the mdBook guide, and a dist release
  workflow that builds the binaries on a `v*` tag and publishes no crate.

### Changed

- `caparra-gate`: fund offers on metered routes are metered too, so a
  client funding inside the 402 pays the metered charge, not the route's
  ceiling.
- L402 native entries: one entry per artifact, `l402-macaroon` (the binary
  V2 macaroon) and `bolt11` (the invoice). `CredentialScheme::natives`
  (`bnap-plug`) lets one pay entry carry several artifacts; carriers and
  the wallet build the L402 challenge from both entries.

[Unreleased]: https://github.com/bnap-protocol/caparra/compare/v0.1.0-alpha...develop
[0.1.0-alpha]: https://github.com/bnap-protocol/caparra/releases/tag/v0.1.0-alpha
