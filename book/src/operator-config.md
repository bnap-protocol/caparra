# Operator config reference

> **TODO:** this page is a stub. The reference is filled in, key by key, as
> `caparra-gate` gains its configuration types. Until then everything below is
> the target shape taken from the BNAP v0.5 overview, not a working config.

`caparra-gate` reads one TOML file. The file says which origin the gate
protects, how its manifest is signed, where uses are stored, which key signs
offers and receipts, and which schemes, rails and attestations a client may
use.

## Sections

| Section | Purpose | Status |
| --- | --- | --- |
| `[gate]` | Protected origin, how the gate is fronted, replay and pending timeouts | TODO |
| `[manifest]` | Root and backup keys, maximum age, the `bnap-required` flag | TODO |
| `[store]` | Use store: `postgres` or `sqlite`, durability | TODO |
| `[signer]` | Offer and receipt signer: `file` or `process` | TODO |
| `[[rail]]` | One entry per settlement rail: `phoenixd`, `nwc`, `lnd`, `fake` | TODO |
| `[[scheme]]` | One entry per credential scheme and the rails it may use | TODO |
| `[[attest]]` | Attestation schemes, such as Web Bot Auth | TODO |
| `[pricing]` | How prices are computed, for example from a table file | TODO |
| `[judge]` | Admission decisions beyond price | TODO |

## Values that refer to secrets

Secrets never sit in the config file itself. A value can point elsewhere:

- `env:NAME` reads the value from the environment variable `NAME`.
- `file:/path` reads it from a file.

## Defaults

These follow BNAP draft-00 and the provisional decisions recorded in the
specification repository (`spec/DECISIONS.md`):

| Setting | Default | Source |
| --- | --- | --- |
| `pending_timeout` | 300 s | Decision for ERRATA 21. Must exceed the longest action on a route, streams included (draft-00 6.4) |
| `replay_window` | 86,400 s | Decision for ERRATA 21 |
| Manifest `max_age` | at most 2,592,000 s (30 days) | draft-00 9.1 |
| Credential size on HTTP | at most 9,216 bytes; larger is refused with `TOO_LARGE` | Decision for ERRATA 30 |

The two timeouts are published in the manifest under `limits`, so clients see
the same values the gate enforces.

## Example

A sketch of a gate in front of one API, paid with ecash notes or L402 over a
phoenixd node. Key names will change as the configuration types are written.

```toml
[gate]
origin = "https://api.example"
front = "standalone"
replay_window_s = 86400
pending_timeout_s = 300

[manifest]
root_key = "file:/etc/caparra/root.pub"
backup_key = "file:/etc/caparra/backup.pub"
max_age_s = 604800
bnap_required = true

[store]
kind = "postgres"
url = "env:DATABASE_URL"
durability = "sync"

[signer]
kind = "process"
socket = "unix:///run/caparra-signer.sock"

[[rail]]
id = "ln"
kind = "phoenixd"
url = "http://127.0.0.1:9740"

[[scheme]]
id = "bnap:notes"
rails = ["ln"]
max_fund_sat = 10000

[[scheme]]
id = "httpauth:L402"
rail = "ln"

[[attest]]
id = "httpsig:web-bot-auth"

[pricing]
kind = "table"
file = "prices.toml"
```

> **TODO:** document every key with its type, default and validation rule,
> generated from the `caparra-gate` config types so that this page cannot
> drift from the code.
