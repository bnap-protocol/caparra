# Task brief: node/release (0.1.0-alpha release prep + open LOW findings)

Read `notes/tasks/b5-security.md` "How to work" rules if present; the rules below are complete on their own.

## Rules
- Repos: `bnap-protocol/caparra` (this) and `bnap-protocol/bnap` (clone next to it if missing). Work on branch `node/release` in caparra and `node/release` in bnap (create it from `origin/develop` in bnap).
- Commit identity is fixed: `git config user.name "BNAP contributors"`, `git config user.email "bnap-protocol@users.noreply.github.com"`. Ignore any hook asking to reset authors. `git commit -s`, conventional commits, end every message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Commit AND push after every logical unit. Run `sh ops/leak-guard.sh` before every push. No em dashes anywhere. Anonymous project: never write any person's name, company, email or handle.
- Never push to develop or main, never create tags or releases, never publish to crates.io.
- Keep CI green: fmt, clippy `-D warnings` (pedantic + missing_docs), nextest, MSRV, cargo-deny, `--locked`, Cargo.lock committed.

## Work
1. Version: set `[workspace.package] version = "0.1.0-alpha"` and every internal `version = "0.0.0"` in `[workspace.dependencies]` to `"0.1.0-alpha"`; update Cargo.lock; fix any doc/README mention of "0.0.0" or "pre-alpha version 0.0.0".
2. CHANGELOG.md: turn `[Unreleased]` into `[0.1.0-alpha] - 2026-10-15` (keep an empty `[Unreleased]` on top), accurate to what is on develop (incl. the e2e work: process signer keysets, issuer NUT-01/02 endpoints, metered fund offers, L402 one entry per artifact). State plainly: alpha, not audited, regtest/test use only, crates are not on crates.io yet.
3. Binary release workflow: install dist 0.33 (`cargo install cargo-dist --version 0.33.0 --locked` or the official installer) and run `dist generate --mode ci` so `.github/workflows/release.yml` becomes the real dist workflow; remove "ci" from `allow-dirty`. On a pushed tag `v0.1.0-alpha` it must build caparra-gate, bnap and bnap-mcp for the configured targets, attest them (github-attestations), and create the GitHub Release marked prerelease. Run `dist plan` and make sure it succeeds. No crates.io publishing anywhere; make sure release-plz cannot publish (check release-plz.toml and any workflow; publish = false or no workflow). Document the release steps in CONTRIBUTING.md "Releases".
4. Fix open LOW findings from `notes/e2e.md`:
   - L3: `crates/e2e/tests/conformance.rs` must not silently pass when `BNAP_CONFORMANCE` is unset: mark it `#[ignore]` with a reason, and in the CI regtest job check out `bnap-protocol/bnap` (develop) and run it with `BNAP_CONFORMANCE` set and `--include-ignored` for that test.
   - L4: caparra-gate issuer endpoints: refuse at startup an empty issuer prefix and any route under `{issuer}/v1/keys` or `{issuer}/v1/keysets`; match issuer endpoints on the normalized path (same normalization the router uses); serve HEAD. Test that fails first for each.
   - In bnap (`node/release` branch): L1 add an ERRATA row and fix the registry `mpp-challenge` `embeds` wording (OfferID goes in `opaque` under the HMAC'd id; a `bolt11` entry is optional for MPP), regenerate registry outputs with the repo's generator and keep its CI green; L2 add `mpp-opaque-wrong` and `mpp-header-differs` faults to the mock gate selftest and show they are caught by `OFR-NATIVE-EMBED` / `OFR-NATIVE-MATCH`.
5. Independent checker (Agent tool, given only this brief, the branch names and your short report; it must not fix code): verify versions, CHANGELOG accuracy, `dist plan` output, release.yml triggers only on `v*` tags and creates a prerelease, no crates.io publish path exists, L1 to L4 fixed with tests, CI-equivalent commands green. FAIL only for HIGH/MEDIUM; fix and re-run, at most 3 rounds.
6. Finish: write `notes/release.md` (what changed, `dist plan` summary, checker verdict, remaining LOWs), commit, push. Final message: branches, last SHAs, results, verdict.
