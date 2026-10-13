# Introduction

Caparra is the Rust reference implementation of BNAP, an open protocol for
paying for and authorizing machine-to-machine requests over HTTP and MCP. A
server states what a request costs and which proofs it accepts; a client
attaches a payment or an authorization proof (ecash notes, L402, MPP and
others); the server verifies that proof before it serves the request.

Caparra is built as a host for plugs. The protocol core, the socket, lives in
one small crate. Every plug point (credential schemes, settlement rails,
storage, signers, carriers, pricing and admission) is a Rust trait, so an
operator can mix the parts they need without forking the core.

> [!WARNING]
> Caparra is pre-alpha and tracks BNAP draft-00. The crates are still being
> written, nothing is published yet, and every interface in this guide can
> change without notice.

## What is in this guide

- [Quickstart](quickstart.md): install the binaries, put `caparra-gate` in
  front of a service and pay for a first request.
- [Operator config reference](operator-config.md): the configuration file that
  `caparra-gate` reads.
- [Agent usage](agent-usage.md): how agents pay through `bnap-mcp`, the `bnap`
  CLI or the wallet library.
- [Architecture](architecture.md): the crate map and how the pieces fit.

Sections marked **TODO** are placeholders. They are filled in as the crates
they describe land.

## The specification

The protocol is specified in the
[bnap repository](https://github.com/bnap-protocol/bnap). The normative text
is `spec/socket-draft-00.md`; where it and the v0.5 design overview differ,
draft-00 wins. Caparra follows draft-00, the errata and the provisional
decisions recorded next to it. The rendered specification is published at
<https://bnap-protocol.github.io/bnap/>.

## Source and license

The source lives at <https://github.com/bnap-protocol/caparra>. Caparra is
licensed under either of MIT or Apache-2.0, at your option. Contributions are
welcome; see `CONTRIBUTING.md` in the repository for the workflow, the
Developer Certificate of Origin and the checks every pull request runs.
