# The LLM inference proxy

`caparra-gate` in front of an OpenAI-compatible endpoint, as in draft-00
section 10.3.

## Set up

On the offline machine that holds the root key:

```sh
caparra-gate key new --out root.key        # prints the root's public key
caparra-gate key new --out backup.key      # keep apart from the root
```

On the gate's host:

```sh
caparra-gate key new --out /etc/caparra/mac.key
caparra-gate key new --out /etc/caparra/l402.key
caparra-gate key new --out /etc/caparra/mpp.key
```

Write the signer's key file (`keys.toml`, mode 0600, owned by the signer's
user) with one offer key and one receipt key, each with a `not_after`
(see `crates/bnap-signer-file`), and the notes keysets. Then sign the
manifest offline from the same `gate.toml`:

```sh
caparra-gate manifest sign --config gate.toml --root-key root.key \
  --backup <backup public key> --seq 1 --keys-from keys.toml --out manifest.json
```

The manifest lists exactly the routes the configuration resolves to; the
gate refuses to start with a manifest whose routes, origin, root or keys
do not match, or that has expired. Sign a new one (higher `--seq`) after
every route change and before the online keys expire.

## Run

```sh
bnap-signer --keys keys.toml --socket /run/caparra-signer/signer.sock \
  --socket-group <gate group> --allow-uid <gate uid> --store /var/lib/caparra/use.db
caparra-gate check --config gate.toml   # every start-up check, then exit
caparra-gate run --config gate.toml
```

With `--store`, the signer signs change only for outputs the gate
reserved in the use store, and an ack only for a Response that states its
settled outcome record.

## What a client sees

`POST /v1/chat/completions` without a credential gets a 402 with a
route-scope offer (`bnap:notes`, metered, 2,100 sat ceiling at 500 sat per
1,000 tokens, the DPoP discount), an exact-scope offer at the ceiling for
L402 and `payment:lightning/charge` with one shared invoice, the two native
challenges, and `BNAP-Error` REQUIRED. A request with `BNAP-Fund` also gets
an exact-scope notes offer carrying a fund quote. Requests with
`"stream": true` are refused on the metered route: streaming is not
metered by this build.
