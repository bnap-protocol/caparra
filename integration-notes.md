# Integration notes: N12 (CI, docs and release plumbing), caparra

Branch `node/n12-ci-docs`. N12 touches no crate source. Everything below is
repository plumbing that every other node's code now runs through.

## What N12 added

| Path | What it is |
| --- | --- |
| `.github/workflows/ci.yml` | CI on push and pull request to `develop` and `main` |
| `.github/workflows/pages.yml` | Builds `book/` and deploys it to GitHub Pages on push to `main` |
| `.github/workflows/release.yml` | Owner-gated placeholder for `v*` tags; fails on purpose |
| `.github/dependabot.yml` | Weekly cargo and GitHub Actions updates against `develop` |
| `deny.toml` | cargo-deny policy: advisories, licenses, bans, sources |
| `release-plz.toml` | Per-crate changelogs and tags; publishing off |
| `Cargo.toml` | `[workspace.metadata.dist]` and `[profile.dist]`, appended at the end |
| `book/` | mdBook 0.5 guide (`book.toml`, `src/`), plus `book/linkcheck.py` |
| `README.md`, `CONTRIBUTING.md` | Docs for the book, CI jobs, dependency rules, releases |

No public Rust API. The "API" downstream nodes get is the CI contract below.

## CI contract (read this before your first push)

| Job | Command | Blocks merge |
| --- | --- | --- |
| Leak guard | `sh ops/leak-guard.sh --pre-push origin` over tracked files and the commits of the push or PR; plus a DCO check on PRs | yes |
| Rustfmt | `cargo fmt --all --check` | yes |
| Clippy | `cargo clippy --workspace --all-targets --locked -- -D warnings` | yes |
| Test (ubuntu, macos) | `cargo nextest run --workspace --locked --no-tests=warn`, then `cargo test --workspace --doc --locked` | yes |
| MSRV (Rust 1.94) | `cargo check --workspace --all-targets --locked` with `RUSTUP_TOOLCHAIN=1.94` | yes |
| cargo-deny (advisories) | `cargo deny --all-features check advisories` | no (`continue-on-error`, still shows red) |
| cargo-deny (bans licenses sources) | `cargo deny --all-features check bans licenses sources` | yes |
| Book | `mdbook build book`, then `python3 -I book/linkcheck.py book/book` | yes |
| Regtest e2e | see below; skipped while `devenv/regtest/compose.yml` is absent | yes, once it runs |

Things that will bite a downstream node:

1. **Clippy pedantic and `missing_docs` are errors in CI.** The workspace sets
   `clippy::pedantic = warn` and `missing_docs = warn`; CI adds `-D warnings`.
   Every public item needs a doc comment and the code must be pedantic-clean
   (`module_name_repetitions` and `missing_errors_doc` are allowed).
2. **MSRV is 1.94, the pinned toolchain is 1.99.0.** Standard library APIs
   stabilised after 1.94 compile locally and fail the MSRV job. Check with
   `cargo-q +1.94 check -p <crate>` when unsure (install 1.94 once with `rustup toolchain install 1.94 --profile minimal`).
3. **`--locked` everywhere.** Commit `Cargo.lock` with every dependency change.
   A merge that leaves the lock file stale turns CI red, which is intended.
4. **nextest runs each test in its own process** and does not run doctests;
   the separate `cargo test --doc` step does. `--no-tests=warn` keeps stub
   crates green; it does not hide failing tests.
5. **cargo-deny `bans`:** `secp256k1` and `secp256k1-sys` may appear in one
   version only (take it through `bitcoin::secp256k1`).
   `[bans.workspace-dependencies] duplicates = "deny"`: a member that pins its
   own version of a dependency that `[workspace.dependencies]` already has
   fails. `unused = "warn"` for now (most workspace deps are unused while the
   crates are stubs); flip it to `"deny"` once the crates are real.
6. **cargo-deny `sources`:** crates.io only. A git dependency fails CI until it
   is added to `[sources] allow-git` with a reason.
7. **cargo-deny `licenses`:** allowed are MIT, MIT-0, Apache-2.0 (also with
   LLVM-exception), BSD-2-Clause, BSD-3-Clause, 0BSD, ISC, Unicode-3.0,
   Unicode-DFS-2016, CC0-1.0, Zlib, MPL-2.0 and CDLA-Permissive-2.0. Anything
   else (for example OpenSSL, GPL, AGPL) fails. Unpublished members
   (`publish = false`) are not license checked.

### Regtest job contract (for the node that adds `devenv/regtest/`)

- The job runs only when `devenv/regtest/compose.yml` exists (a detect job sets
  an output; without the file the `Regtest e2e` job shows as skipped).
- Steps: `docker compose -f devenv/regtest/compose.yml up -d`, then
  `cargo nextest run -p e2e --features regtest --locked`, logs on failure,
  `docker compose ... down -v` always. ubuntu-latest only, 45 minute timeout.
- CI does **not** wait for service health (`up -d` without `--wait`, because
  one-shot setup containers would make `--wait` fail). The e2e tests, or a
  service healthcheck plus a test-side retry loop, must wait for readiness.
- The package must be named exactly `e2e` with a `regtest` feature. It lives
  under `crates/` (the members glob), so the normal Test job also builds it
  **without** the feature: gate every regtest test with
  `#[cfg(feature = "regtest")]` so it compiles and is skipped there. Clippy
  runs without `--all-features`, so regtest-only code is not linted by CI.
- Give it `publish = false` in its `Cargo.toml` so release-plz and the
  license check ignore it.

## Release plumbing (owner-gated, nothing publishes)

- **release-plz** (`release-plz.toml`): changelog per crate at
  `crates/<name>/CHANGELOG.md`, git tag per crate `<crate>-v<version>`,
  `git_release_enable = false` (dist owns GitHub Releases), `publish = false`
  until crates.io trusted publishing is configured, `release_always = false`.
  No workflow runs release-plz yet. When the owner adds one: `id-token: write`
  and no `CARGO_REGISTRY_TOKEN`, then set `publish = true`. Crates that must
  never be released need `publish = false` in their own `Cargo.toml`.
  Note the shared `version.workspace = true`: release-plz bumps the workspace
  version, so all crates move together.
- **dist** (`[workspace.metadata.dist]`, dist 0.33.0, written by hand, no
  `dist init`): `packages = ["caparra-gate", "bnap-cli", "bnap-mcp"]` (the
  binaries `caparra-gate`, `bnap`, `bnap-mcp`), targets
  `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `installers = []` (shell and homebrew planned,
  off for now), `github-attestations = true`, `allow-dirty = ["ci"]` because
  `release.yml` is a hand-written placeholder. `[profile.dist]` inherits
  `release` with thin LTO. If a binary crate is added or renamed, update
  `packages`. Binaries must cross-build for arm64 Linux: prefer rustls, avoid
  system OpenSSL.
- **`release.yml`** triggers on `v*` tags only, prints what the tag would
  release and exits 1 on purpose, so a tag is never mistaken for a release.
  Its header lists the owner's enable steps (`dist generate --mode ci`, drop
  `allow-dirty`, a `release` environment with the owner as reviewer, a tag
  rule for `v*`). Per-crate release-plz tags do not match `v*`.

## Book

`book/` is an mdBook 0.5 guide: Introduction, Quickstart, Operator config
reference, Agent usage, Architecture. `create-missing = false`, so a SUMMARY
entry without a file is a build error. Placeholders are marked **TODO** (grep
for `TODO`); the node that ships a feature fills its section:

- Quickstart steps 1 to 6 (install, protect a service, pay, agent, regtest).
- Operator config: the page shows the overview's target shape as valid TOML;
  replace it with a key-by-key reference generated from the `caparra-gate`
  config types. Defaults stated there come from `spec/DECISIONS.md` (21, 30).
- Agent usage: `bnap-mcp` tools, `bnap` subcommands, `caparra-wallet` example.
- Architecture: replace the layering sketch with the real dependency graph.

`book/linkcheck.py` (stdlib) fails CI on a broken relative link in the built
HTML. Pages deploys only from `main`.

## Decisions made

- Toolchains are installed with plain `rustup` (`rustup toolchain install`
  reads `rust-toolchain.toml`; `|| rustup show` covers older rustup), so every
  `uses:` is pinned to a major version and no third-party toolchain action is
  needed. The MSRV job overrides the toolchain with `RUSTUP_TOOLCHAIN` so the
  rust-cache key also uses 1.94.
- Action majors were checked against the GitHub releases API on 2026-10-13:
  `actions/checkout@v7`, `actions/configure-pages@v6`,
  `actions/upload-pages-artifact@v5`, `actions/deploy-pages@v5`,
  `Swatinem/rust-cache@v2`, `taiki-e/install-action@v2`,
  `EmbarkStudios/cargo-deny-action@v2`. mdBook is pinned to `0.5` in CI to
  match the local Homebrew bottle (0.5.4).
- The CI leak guard runs in pre-push mode so commit metadata (author emails,
  messages) is scanned too, not only the tracked tree.
- DCO check on pull requests: presence of `Signed-off-by:` on every non-merge
  commit; skipped for Dependabot and `release-plz-*` branches, whose commits
  are not signed off. Orchestrator merge commits are not checked.
- Advisories are reported but not blocking, following the cargo-deny-action
  recommendation, so a new RustSec entry does not stall unrelated merges.
  Bans, licenses and sources block.
- License allowlist: the requested families plus MIT-0, 0BSD,
  `Apache-2.0 WITH LLVM-exception`, Unicode-DFS-2016 and
  CDLA-Permissive-2.0 (webpki-roots, pulled in by rustls-based sqlx and
  reqwest builds). Drop any of them if the owner prefers a shorter list.
- Dependabot groups patch bumps only; minor and major bumps come one per PR,
  since most of the tree is 0.x where a minor bump breaks.

## Known gaps

- Nothing was pushed, so no workflow has run on GitHub yet. YAML parses
  (Ruby Psych) and the shell steps were exercised locally where possible.
- Not run locally: `dist plan` (dist is not installed, per the node brief),
  release-plz, and `cargo deny check advisories` (it clones the RustSec
  database). See the verification section of the N12 report for what was run.
- The DCO check does not compare the sign-off identity with the author.
- No Windows job; dist targets no Windows either.
- `book/` chapters are stubs by design.

## ERRATA candidates (spec not edited)

| Where | Observation | What N12 did |
| --- | --- | --- |
| `spec/overview-v0.5.md`, "One config, any mix" | The example config is not valid TOML: it puts several keys on one line separated by `;` | The operator config page shows the same shape as valid TOML, one key per line, marked as a target shape |
