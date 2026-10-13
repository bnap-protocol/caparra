# Architecture

Caparra is a host for plugs: the BNAP socket sits in one small crate, every
plug point is a Rust trait, and the binaries assemble the plugs an operator
chooses. This page maps the BNAP v0.5 overview's crate plan onto the
workspace.

## Crate map

The overview groups the crates into families:

| Family | Role | Workspace crates today |
| --- | --- | --- |
| `bnap-core` | The socket: Offer, envelope, Digest, use store logic, outcome state machine, receipts, test vectors | `bnap-core` |
| `bnap-plug` | The plug traits, plus the WIT interface definition generated from them | `bnap-plug` |
| `bnap-scheme-*` | Credential schemes | `bnap-scheme-notes`, `bnap-scheme-l402`, `bnap-scheme-mpp`, `bnap-scheme-webbotauth`, `bnap-scheme-dpop` |
| `bnap-rail-*` | Settlement rails | `bnap-rail-phoenixd`, `bnap-rail-nwc`, `bnap-rail-lnd`, `bnap-rail-fake` |
| `bnap-store-*` | Use stores | `bnap-store-postgres`, `bnap-store-sqlite`, `bnap-store-tests` |
| `bnap-signer-*` | Offer and receipt signers | `bnap-signer-file`, `bnap-signer-process` |
| `bnap-carrier-*` | Carriers that move BNAP messages | `bnap-carrier-http`, `bnap-carrier-mcp` |
| Applications | The gateway, the client wallet, the MCP server and the CLI | `caparra-gate`, `caparra-wallet`, `bnap-mcp`, `bnap-cli` |

### Workspace crates

| Crate | Kind | Role |
| --- | --- | --- |
| `bnap-core` | library | Core protocol types, encoding and verification logic, free of I/O |
| `bnap-plug` | library | Plug traits that connect signers, stores, schemes, rails and carriers to the core |
| `bnap-scheme-notes` | library | Payment scheme that accepts Cashu ecash notes (`bnap:notes`, the default scheme) |
| `bnap-scheme-l402` | library | L402: macaroon plus Lightning invoice |
| `bnap-scheme-mpp` | library | The Machine Payments Protocol (MPP) |
| `bnap-scheme-webbotauth` | library | Web Bot Auth, based on HTTP Message Signatures |
| `bnap-scheme-dpop` | library | Proof of possession based on DPoP (RFC 9449) |
| `bnap-rail-phoenixd` | library | Settlement through a phoenixd Lightning node |
| `bnap-rail-nwc` | library | Settlement over Nostr Wallet Connect (NIP-47) |
| `bnap-rail-lnd` | library | Settlement through an LND node over gRPC |
| `bnap-rail-fake` | library | In-memory rail for tests and local development |
| `bnap-store-postgres` | library | PostgreSQL use store |
| `bnap-store-sqlite` | library | SQLite use store |
| `bnap-store-tests` | library | Conformance suite every use store must pass |
| `bnap-signer-file` | library | Signer backed by a key file on local disk |
| `bnap-signer-process` | library | Signer that delegates to an external process |
| `bnap-carrier-http` | library | BNAP messages in HTTP requests and responses |
| `bnap-carrier-mcp` | library | BNAP messages in MCP tool calls and results |
| `caparra-gate` | binary `caparra-gate` | Gate in front of an HTTP or MCP service that enforces payment and authorization |
| `caparra-wallet` | library | Client wallet that holds funds and answers payment challenges |
| `bnap-mcp` | binary `bnap-mcp` | MCP server exposing wallet and payment tools to agents |
| `bnap-cli` | binary `bnap` | Command-line tool for inspecting, paying and testing BNAP flows |

The three binaries are the ones release builds ship.

### Planned, not in the workspace yet

The overview also names plugs that have no crate yet: the `x402`, `privpass`
and `oauth` schemes; the `ldk`, `ark` and `fedimint` rails plus the
off-by-default `x402-evm` and `mpp-card` rails; a KMS-unwrap signer; and SASL
and Nostr carriers.

## How the pieces fit

```text
           caparra-gate   caparra-wallet   bnap-mcp   bnap (bnap-cli)
                 \              |              |          /
                  +-------------+--------------+---------+
                                |
      schemes   rails   stores   signers   carriers      (the plugs)
                                |
                            bnap-plug                    (the plug traits)
                                |
                            bnap-core                    (the socket, no I/O)
```

The socket owns everything that must be computed one way only. Per the
overview, only `bnap-core` computes the OfferID, Context, Digest and
ReplayKey, prefixes use IDs, compares value with price, commits uses and
builds every message the signer signs. A scheme gets a capped signer that can
verify notes and sign blinded outputs up to the change cap `bnap-core`
computed, and nothing more. Every other plug gets read access to what it
needs and returns data.

> **TODO:** replace the sketch above with the dependency graph the crates
> actually have once they depend on each other, and link each plug trait to
> its rustdoc.

## Ways to load a plug

| Way | For | Isolation | Planned release |
| --- | --- | --- | --- |
| Compiled in (Cargo features) | First-party plugs | Same process | v0.5 |
| Sidecar over gRPC or HTTP, same interface | Any language and heavy dependencies | Separate process | v0.6 |
| WASM component (WIT world `bnap:plug`) | Third-party schemes, pricers and judges | Sandbox with fuel and memory limits | v0.7 |

## Fronts

Operators on any stack can put `caparra-gate` in front of a service as a
standalone proxy or behind Envoy `ext_authz`, Caddy `forward_auth` or nginx
`auth_request`, so they need no Rust of their own.

## Workspace rules

- One `secp256k1` per dependency tree, taken through the `bitcoin` re-export
  (`bitcoin::secp256k1`). `cargo deny` fails CI on a second copy.
- Shared dependency versions live in `[workspace.dependencies]`; member crates
  use `dep.workspace = true`.
- The minimum supported Rust version is 1.94. CI checks it on every push.
- `unsafe` code is forbidden workspace-wide.
