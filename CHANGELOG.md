# Changelog

All notable changes to this workspace are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crates are
pre-alpha (version 0.0.0) and do not follow semantic versioning yet. When
releases start, release-plz also writes a changelog per crate under
`crates/<name>/CHANGELOG.md`.

## [Unreleased]

Nothing has been released. What exists on `develop`:

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
- `e2e` tests and a regtest Lightning network in `devenv/regtest/`.
- Examples: `examples/quickstart/` (fake rail) and `examples/llm-proxy/`
  (an OpenAI-compatible endpoint, with Caddy and nginx fronts).
- Fuzzing: twelve cargo-fuzz targets in `fuzz/`, run weekly in CI.
- Security review B5 (`SECURITY-REVIEW.md`) with its MEDIUM findings
  fixed; open LOW findings in `KNOWN-ISSUES.md`.
- CI (leak guard, DCO, rustfmt, clippy, tests on Linux and macOS, MSRV
  1.94, cargo-deny, book, regtest), the mdBook guide and release plumbing
  that publishes nothing yet.

[Unreleased]: https://github.com/bnap-protocol/caparra/commits/develop
