# Quickstart

This puts `caparra-gate` in front of a local file server with one priced
path, using the fake rail, which moves no money. It is the same run as the
quickstart in the repository's README, and every command below was run
as written.

You need Rust (the toolchain is pinned in `rust-toolchain.toml`), `protoc`
(the LND rail compiles `.proto` files at build time), `curl` and Python 3.

## 1. Build the binaries

Binary releases are not published yet. Build from a checkout:

```sh
git clone https://github.com/bnap-protocol/caparra.git
cd caparra
cargo build --locked -p caparra-gate -p bnap-cli -p bnap-mcp
export PATH="$PWD/target/debug:$PATH"
```

This builds `caparra-gate`, `bnap` and `bnap-mcp`. The first build takes a
few minutes.

## 2. Configure the gate and sign its manifest

`examples/quickstart/gate.toml` protects `GET /hello.txt` at 21 sat, payable
with `httpauth:L402` or `payment:lightning/charge` over the fake rail, with a
file signer and a SQLite use store. Paths in it are relative to the
directory the gate runs in.

```sh
mkdir -p target/quickstart/www && cd target/quickstart
cp ../../examples/quickstart/gate.toml .
sh ../../examples/quickstart/setup.sh
caparra-gate check --config gate.toml
```

`setup.sh` makes the root and backup keys, `K_mac`, the L402 and MPP
secrets (each with `caparra-gate key new`), a signer key file `keys.toml`
with an offer key and a receipt key valid for 7 days, and then signs the
manifest:

```sh
caparra-gate manifest sign --config gate.toml --root-key root.key \
  --backup "$(cat backup.pub)" --seq 1 --keys-from keys.toml --out manifest.json
```

`caparra-gate check` runs every start-up check and prints
`ok: caparra-gate would start with gate.toml`. It warns that the fake rail
is in use. In production the root key never touches the gate's host; see
`examples/llm-proxy/README.md`.

## 3. Start a service and the gate

```sh
echo 'hello, paid world' > www/hello.txt
python3 -m http.server 9000 --bind 127.0.0.1 --directory www &
caparra-gate run --config gate.toml &
```

## 4. See what a client gets

```sh
curl -s http://127.0.0.1:8080/.well-known/bnap   # the manifest, byte for byte as signed
curl -si http://127.0.0.1:8080/hello.txt          # 402 Payment Required
curl -s http://127.0.0.1:8080/                    # no route: forwarded unpaid
```

The 402 carries three `WWW-Authenticate` challenges (a `BNAP offer=...`, the
L402 challenge and the `Payment` challenge, which share one invoice), the
field `BNAP-Error` with the code `REQUIRED`, and `Cache-Control: private,
no-store`.

## 5. Make a wallet and try to pay

```sh
export BNAP_WALLET="$PWD/wallet.db" BNAP_PASSPHRASE='use a long passphrase'
bnap init
bnap budget set --allow-experimental true --per-request 100
bnap budget show
bnap get http://127.0.0.1:8080/hello.txt
```

`bnap init` shows the 12-word mnemonic once. A new wallet pays nothing
until `--allow-experimental true`, because every scheme in the registry is
still experimental. The last command fails with
`error[BAD_INPUT]: Paid requests go over https only.`: the wallet pays only
over HTTPS, and the gate does not terminate TLS. The fake rail's invoices can
also be paid only from inside the process that holds it. The paid round
trip on the fake rail (402, payment, admission, replay, `SPENT`, receipt,
notes with change) therefore runs in the tests:

```sh
cargo test --locked -p caparra-gate --test gate --test notes
cargo test --locked -p caparra-wallet --test flows
```

To pay for real, serve the gate on a public HTTPS origin behind a TLS
proxy, use an `lnd`, `phoenixd` or `nwc` rail, and give the wallet a pay
source with `bnap paysource nwc` (or `BNAP_NWC_URI`) or
`bnap paysource command ...`. Agents use the same wallet through
`bnap-mcp`; see [agent usage](agent-usage.md).

## 6. Run the Lightning rails on regtest

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

To point a gate at that node, change its `[[rail]]` to `kind = "lnd"` with
`address`, `cert` and `macaroon` (see the
[operator config reference](operator-config.md)). The wallet still needs an
HTTPS origin, so a full client run also needs a TLS proxy in front of the
gate.
