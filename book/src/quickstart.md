# Quickstart

> **TODO:** every step below is a placeholder. Each one is written for real by
> the change that makes it work, and this note goes away when the last step
> runs end to end.

The goal: protect a local HTTP service with `caparra-gate`, then pay for a
request with the `bnap` CLI, first against the in-memory fake rail and then
against a local regtest Lightning setup.

## 1. Install the binaries

Release archives for `caparra-gate`, `bnap` and `bnap-mcp` will be published
on GitHub Releases for macOS on Apple silicon and for Linux on x86-64 and
arm64. Until then, build them from a checkout of the repository:

```sh
cargo install --locked --path crates/caparra-gate
cargo install --locked --path crates/bnap-cli
cargo install --locked --path crates/bnap-mcp
```

> **TODO:** replace with the release download once binary releases are
> enabled.

## 2. Start a service to protect

Any HTTP service works. For a first try, run a trivial local one:

```sh
python3 -m http.server 8080
```

## 3. Put the gate in front of it

> **TODO:** a minimal config with one priced route, the fake rail and the
> SQLite store, and the command that starts `caparra-gate` with it. See the
> [operator config reference](operator-config.md) for the planned shape.

## 4. Pay for a request

> **TODO:** use `bnap` to fetch the gate's manifest, request the priced
> route, receive the offer, pay it and print the receipt.

## 5. Let an agent pay

> **TODO:** register `bnap-mcp` with an MCP host and let an agent make the
> same paid request. See [agent usage](agent-usage.md).

## 6. Run against regtest

> **TODO:** start the local regtest stack (`devenv/regtest/compose.yml`,
> started with `docker compose up -d`), switch the gate to a real Lightning
> rail, and repeat step 4. CI runs the same stack in its `regtest` job.
