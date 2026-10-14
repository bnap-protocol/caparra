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

`devenv/regtest/` is a small Lightning network in Docker: one bitcoind and two
LND nodes, `payer` and `payee`. The payee is the operator's node; the
`bnap-rail-lnd` plug talks to it over gRPC on `127.0.0.1:10009`.

```sh
devenv/regtest/up.sh          # start, fund the payer, open a payer -> payee channel
. devenv/regtest/.state/env   # BNAP_REGTEST_LND_ADDRESS, _CERT, _MACAROON
cargo nextest run -p e2e --features regtest
devenv/regtest/down.sh        # stop and delete everything
```

`up.sh` is idempotent: it waits until every container is healthy, mines to
the payer until it can pay, opens the channel once, and copies the payee's
`tls.cert` and `invoice.macaroon` to `devenv/regtest/.state/`. The e2e tests
run it themselves, so CI only starts the stack (`docker compose up -d`) and
runs them. They create an invoice through the LND rail, pay it from the
payer with `lncli`, check that the rail reports it final with its amount, and
present the one payment through L402 and `payment:lightning/charge`: one
action is admitted, the other credential is `SPENT`.

> **TODO:** switch the gate to the LND rail (the address, cert and macaroon
> above) and repeat step 4.
