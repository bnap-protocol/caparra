# Integration notes: node/docs, README and repo hygiene (caparra and bnap)

Branch `node/docs` in both repositories. No crate source changed. One test
was added in `caparra-gate` (below).

## What changed

### caparra

| Path | What it is |
| --- | --- |
| `README.md` | Rewritten: pitch, what BNAP is, badges (CI, license, MSRV, docs), a quickstart on the fake rail, architecture (mermaid) and crate table, agent use through `bnap-mcp`, security model, status and roadmap, links, contributing, license |
| `examples/quickstart/gate.toml` | One route `GET /hello.txt` at 21 sat, L402 and `payment:lightning/charge` over the fake rail, file signer, SQLite store; paths relative to the run directory |
| `examples/quickstart/setup.sh` | Writes root, backup, `K_mac`, L402 and MPP keys with `caparra-gate key new`, a `keys.toml` with offer and receipt keys valid 7 days, and runs `caparra-gate manifest sign` |
| `crates/caparra-gate/tests/gate.rs` | `the_quickstart_configuration_resolves`: parses and plans `examples/quickstart/gate.toml` (one route, two pay entries), so the example cannot rot |
| `KNOWN-ISSUES.md` | Every open LOW finding from `notes/*.md` (38: B5 15, N9a 10, N9b 7, N10 6) with crate and suggested fix, the errata candidates from the notes that need an owner decision, the 8 provisional DECISIONS rows and the 8 ERRATA rows marked "owner decision needed" |
| `CHANGELOG.md` | Keep a Changelog, Unreleased section summarizing the workspace |
| `.github/ISSUE_TEMPLATE/` | `bug_report.yml`, `feature_request.yml`, `config.yml` (blank issues off; security to private vulnerability reporting; spec questions to the bnap repository) |
| `.github/pull_request_template.md` | What, spec reference, checklist (DCO, tests, fmt/clippy/nextest, lock file, docs, leak guard) |
| `.github/CODEOWNERS` | Comment only: no owners until an organization team exists |
| `book/src/introduction.md`, `quickstart.md` | Match the README; quickstart steps 1 to 5 are the README run, step 6 is regtest |
| `book/src/operator-config.md` | Replaced the target-shape sketch (keys that did not exist: `env:`/`file:` values, `front = "standalone"`, postgres) with a key-by-key reference read from `crates/caparra-gate/src/config.rs` |
| `book/src/agent-usage.md` | The three `bnap-mcp` tools, an `mcpServers` snippet, the `bnap` commands and environment, the wallet library entry points |

`.github/FUNDING.yml` does not exist in either repository.

### bnap

| Path | What it is |
| --- | --- |
| `README.md` | What the protocol is, document map, how to run the conformance suite, implementations, how spec and registry changes are proposed, licenses |
| `.github/ISSUE_TEMPLATE/` | `bug_report.yml`, `feature_request.yml`, `spec_question.yml`, `config.yml` (security to private vulnerability reporting, Caparra bugs to caparra) |
| `.github/pull_request_template.md`, `.github/CODEOWNERS` | As in caparra, with the vector, registry and conformance checks |
| `CHANGELOG.md` | Keep a Changelog, Unreleased section |
| `book/src/index.md` | Introduction matched to the README; links `bnap:notes` draft-00; registry and conformance section |

## Verified commands

All run in this sandbox on `node/docs` (equal to `develop` plus these docs):

- `cargo build --locked -p caparra-gate -p bnap-cli -p bnap-mcp` (needs
  `protoc`).
- The quickstart: `setup.sh`, `caparra-gate check` (prints `ok: ...`),
  `caparra-gate run`, `curl` of `/.well-known/bnap` (the manifest), of
  `/hello.txt` (402 with `BNAP offer=`, `L402` and `Payment` challenges,
  `BNAP-Error`, `Cache-Control: private, no-store`) and of `/` (forwarded).
- `bnap init`, `bnap budget set --allow-experimental true --per-request 100`,
  `bnap budget show`, and `bnap get http://...` refused with
  `error[BAD_INPUT]: Paid requests go over https only.` (exit 2).
- `bnap-mcp --wallet ... --passphrase-file ...` over stdio: `initialize`
  and `tools/list` return exactly `budget`, `fetch_paid`, `receipts`.
- `cargo test --locked -p caparra-gate --test gate --test notes` (23 + 4
  passed) and `cargo test --locked -p caparra-wallet --test flows` (10
  passed).
- bnap: `python3 -I conformance/run.py --target http://127.0.0.1:9188
  --allow-http --profile server` against `conformance/mock_gate.py serve
  --port 9188`: 85 passed, 0 failed, 10 MUST skipped (no payer), verdict
  incomplete. `python3 -I registry/validate.py --check` passes.
- `mdbook build book` and `book/linkcheck.py` in both repositories: 0
  broken links. Leak guard clean before every push.

## Decisions

- **The quickstart cannot end in a paid `bnap get`.** The wallet's
  transport is HTTPS only (`HttpsTransport`, rustls with web roots, so a
  local CA is not trusted), the gate terminates no TLS, and the fake rail
  can be paid only by code holding the `FakeRail` in process (no endpoint
  pays it). The quickstart therefore shows the gate, the 402 and the
  wallet's refusal, and points to the tests that run the paid round trip
  on the fake rail. Making the README's literal `bnap get` work would need
  a code change (a loopback-HTTP escape in the wallet and a pay endpoint
  for the fake rail), which is out of a docs node's scope and weakens a
  security property; left to the owner.
- **Crate status column** is grounded in the notes: "security reviewed"
  means in the scope of B5 (`SECURITY-REVIEW.md`), which excluded
  `caparra-gate` and `bnap-carrier-http`.
- **`bnap:notes` "default"** is stated as the protocol's default scheme;
  Caparra itself needs `allow_experimental` for it like every scheme (N9a).
- **Roadmap** v0.6 and v0.7 are copied from `spec/overview-v0.5.md`,
  "Roadmap and standardization".
- **KNOWN-ISSUES IDs** keep the notes' IDs with a node prefix (`B5-`,
  `N9a-`, `N9b-`, `N10-`) because N9a and B5 both use bare `L<n>`.

## Gaps and points for the owner

- **Anonymity:** every verbatim spec file in bnap (`spec/socket-draft-00.md`,
  `overview-v0.5.md`, `schemes/bnap-notes.md`, `history/v0.2.md`,
  `history/v0.3.md`) carries a personal first name in its header comment
  (line 8) and byline (line 13). The leak guard does not match the bare
  first name. Not edited here (verbatim spec text); the owner should scrub
  it and add it to the leak guard's identifiers.
- `spec/README.md` (bnap) does not list `schemes/bnap-notes-draft-00.md`
  or `DECISIONS.md` in its file table; the new README's document map does.
- `book/src/architecture.md` still has its layering sketch and TODO; the
  README carries the mermaid diagram (mdBook does not render mermaid
  without a preprocessor).
- No Docker here: the regtest steps in the book were not run.
- Checker results: see below.
