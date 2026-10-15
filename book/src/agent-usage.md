# Agent usage

An agent meets BNAP when a service answers a request with an offer instead of
the result. The wallet picks a scheme the policy allows, attaches a
credential to the retried request, and gets the result plus a signed
receipt. Caparra gives agents three ways to do that, all over the same
wallet file.

The wallet pays only `https` URLs, only after it has pinned the origin's
manifest, and only within its caps: per request, per task, per origin
(24 h) and daily. A new wallet pays nothing until its owner runs
`bnap budget set --allow-experimental true`, because every scheme in the
registry is still experimental.

## Through MCP: `bnap-mcp`

`bnap-mcp` is an MCP server over a wallet made with `bnap init`. The model
never chooses a scheme and never sees a key, the seed or a pay source
secret. It has exactly three tools:

| Tool | Arguments | Result |
| --- | --- | --- |
| `fetch_paid` | `url`, `method?`, `body?`, `max_sat?` | Status, content type, body (text or base64, at most 256 KiB) and the payment |
| `budget` | `action?` (`get`, the default, or `set`), `cap?` (`per-request`, `per-task`, `per-origin`, `daily`), `sat?`, `origin?` | Owner caps, session caps, caps in force, what is left, notes held; `set` only narrows (above the owner's cap is `ABOVE_HARD_CAP`) |
| `receipts` | `action?` (`list`, the default, or `verify`), `id?` | Receipt summaries, or a third-party check of them |

Unknown arguments are refused, so a call that names a scheme fails.
Refusals come back as tool errors with structured content
`{"error": {...}}` carrying the same codes as the CLI.

Register it with an MCP client that reads an `mcpServers` configuration:

```json
{
  "mcpServers": {
    "bnap": {
      "command": "bnap-mcp",
      "args": [
        "--wallet", "/home/you/.bnap/wallet.db",
        "--passphrase-file", "/home/you/.bnap/passphrase"
      ]
    }
  }
}
```

It serves over stdio by default. `--http 127.0.0.1:PORT` serves streamable
HTTP at `/mcp` on a loopback address only. That mode has no authentication:
any local process that reaches the port can spend within the caps.
`--task NAME` groups runs under one per-task cap; otherwise each run is its
own task.

## From scripts: the `bnap` CLI

```text
bnap [--wallet PATH] [--task NAME] [--json] <command>

init [--slot N]                         create a wallet, show the mnemonic once
fund <origin> <sat> [--issuer URL]      buy notes at an origin over Lightning
get|post <url> [--max-sat N] [-H 'Name: value'] [-d TEXT | --data-file F]
budget [show [--origin O] | set ...]    caps and policy
receipts [list | verify [ID]]
restore --origin O... [--issuer URL]    recover notes from the seed
resume                                  finish paid requests that got no final answer
paysource [show | nwc [URI] | command ARGV... | none]
```

Environment: `BNAP_WALLET` (default `~/.bnap/wallet.db`), `BNAP_PASSPHRASE`
(otherwise a prompt), `BNAP_TASK`, `BNAP_MNEMONIC` (for `restore`) and
`BNAP_NWC_URI` (safer than passing the URI on the command line). Every
refusal prints `error[CODE]: message`; `--json` prints
`{"ok": false, "error": {...}}`. Exit status 2 means the caller can fix it
(input, policy, budget, wallet), 3 means try later, 1 anything else.

## Embedded: `caparra-wallet`

`caparra-wallet` is the library both binaries use. `Wallet::create` and
`Wallet::open` handle the encrypted wallet file, `Wallet::fetch` takes a
`FetchRequest { method, url, headers, body, max_sat }` and returns a
`FetchResult` with the status, headers, body and the payment, and
`Wallet::receipts` lists what was paid. See the crate's rustdoc and
`crates/caparra-wallet/tests/flows.rs` for complete flows.

## Rules every client follows

These come from BNAP draft-00 (section 9.3) and hold whichever of the three
ways an agent uses:

- Fetch the origin's manifest over HTTPS, at most once per five minutes, and
  pin its root and backup keys.
- Accept an offer only if its offer key is listed in the pinned manifest with
  use `offer` and has not passed its `not_after`, and the offer passes the
  checks of draft-00 section 4.4.
- Once an origin's manifest has set `required`, pay that origin only through a
  BNAP offer, never through a bare native payment header.
- Pay a native challenge only if its bytes equal a native entry of an offer
  that passed the checks, or when there is no pin for the origin yet.
