# Release notes: node/release (0.1.0-alpha prep)

Branch `node/release` of caparra, with branch `node/release` of bnap
(created from bnap `develop`). Brief: `notes/tasks/release.md`. No tag,
release or crates.io publish was made; nothing was pushed to `develop` or
`main`.

## What changed

| Unit | caparra | bnap |
| --- | --- | --- |
| Version | `[workspace.package] version` and every internal workspace dependency set to `0.1.0-alpha`; `Cargo.lock` and the internal entries of `fuzz/Cargo.lock` updated; README, SECURITY.md, KNOWN-ISSUES.md and the book introduction say alpha (0.1.0-alpha), not audited | |
| CHANGELOG | `[0.1.0-alpha] - 2026-10-15` under an empty `[Unreleased]`: e2e work (process signer keysets, issuer NUT-01/02 endpoints, metered fund offers, one L402 native entry per artifact), a Changed and a Fixed section; alpha, not audited, regtest and test use only, no crate on crates.io | Unreleased notes mention ERRATA row 35 and the two new faults |
| Binary release | `dist generate --mode ci` (dist 0.33.0) output in `.github/workflows/v-release.yml`; "ci" removed from `allow-dirty` (the key is gone); `tag-namespace = "v"`, `pr-run-mode = "skip"`; `bnap-signer-process` opts out with `[package.metadata.dist] dist = false`; protoc for the build runners (apt, homebrew); a `dist-plan` CI job; CONTRIBUTING.md "Releases" lists the release steps | |
| L1 | Embedded registry export synced (gate and wallet) and its digest pin updated | `mpp-challenge` `embeds` wording (OfferID in `opaque` under the HMAC'd `id`), `bolt11` optional for MPP, ERRATA row 35, `registry/generated/registry.json` regenerated with `validate.py --export` |
| L2 | | Faults `mpp-opaque-wrong` (caught by `OFR-NATIVE-EMBED`) and `mpp-header-differs` (caught by `OFR-NATIVE-MATCH`, a SHOULD case, so the selftest accepts it as caught without exit 1) |
| L3 | `tests/conformance.rs` is `#[ignore]` with a reason and panics under `--include-ignored` when `BNAP_CONFORMANCE` is unset or empty; the CI regtest job checks out bnap `develop` and runs it with `--include-ignored` (timeout 90 min, reports kept as an artifact) | |
| L4 | The gate refuses to start when the notes issuer URL is the origin's root or a route lies under `{issuer}/v1/keys` or `{issuer}/v1/keysets`; issuer endpoints match on `route_path` (trailing slash ignored); HEAD is served. Tests `the_issuer_endpoints_match_the_normalized_path_and_serve_head` and `the_gate_refuses_an_issuer_path_that_is_empty_or_shadowed`, both failed first (the HEAD assertion too, checked on its own) | |

### Deviation: workflow file name

dist 0.33 generates the trigger `'**[0-9]+.[0-9]+.[0-9]+*'`, which would
also fire on release-plz's `<crate>-v<version>` tags. `tag-namespace = "v"`
is the only setting that limits it to `'v**[0-9]+.[0-9]+.[0-9]+*'`, and with
it dist names the file `v-release.yml` (no rename option). The placeholder
`release.yml` was removed. The checker accepted this.

## dist plan

`dist plan` succeeds and announces `v0.1.0-alpha` with exactly `bnap-cli`
(binary `bnap`), `bnap-mcp` and `caparra-gate`, each as a `.tar.xz` with a
sha256 for `aarch64-apple-darwin` (macos-14), `aarch64-unknown-linux-gnu`
(ubuntu-22.04-arm) and `x86_64-unknown-linux-gnu` (ubuntu-22.04), plus
`source.tar.gz` and `sha256.sum`. `announcement_is_prerelease` is true for
the tag, so the host job runs `gh release create ... --prerelease`. The
build jobs attest with `actions/attest@v4`. No crates.io path:
`release-plz.toml` keeps `publish = false` and no workflow runs release-plz
or `cargo publish`.

## Checks

fmt, clippy `-D warnings` (workspace, and e2e with `regtest`), nextest 677
passed and 1 skipped, doctests, MSRV 1.94 check, cargo-deny bans, licenses
and sources, workflow YAML, leak guard in both repos. bnap: registry
`--check` and 27 validator tests, mock gate selftest OK, 66 conformance
unit tests OK. The conformance run itself (regtest, about 25 minutes) was
not run here; the CI regtest job runs it.

## Checker

**Verdict: PASS (round 1).** No HIGH or MEDIUM findings.

## Remaining LOWs

- `notes/n12-ci-docs.md` still calls `release.yml` a placeholder
  (historical note).
- The embedded registry is pinned to bnap `ce73bc8` on bnap
  `node/release`; merge bnap `node/release` so that commit and ERRATA row 35
  reach bnap `develop`.
- The L4 test covers HEAD, but only removing HEAD on its own shows that
  assertion failing.
- Some lines are left long in the bnap CHANGELOG entry and the
  `conformance.rs` doc comment (cosmetic).
- Draft-00 4.2 still says "an MPP `id`"; ERRATA row 35 asks for the
  wording in the next revision.
