# Introduction

Caparra is the Rust reference implementation of BNAP, an open protocol for
priced and permissioned requests between machines over HTTP and MCP. A
server answers a request with HTTP 402 and a signed offer that names the
price and the schemes it accepts. The client attaches one credential to the
retried request: a payment (blind ecash notes, L402 or MPP) and, if it
wants, attestations such as DPoP or Web Bot Auth. The server records each
payment as used once only, runs the action, and answers with a signed
receipt.

BNAP's default scheme is `bnap:notes`: blind notes bought over Lightning,
so the server does not learn which payment funded which request.

Caparra is built as a host for plugs. The protocol core, the socket, lives in
one small crate without I/O. Every plug point (credential schemes,
settlement rails, storage, signers and carriers) is a Rust trait, so an
operator can mix the parts they need without forking the core.

> [!WARNING]
> Caparra is pre-alpha and tracks BNAP draft-00. Nothing is published to
> crates.io, every interface in this guide can change without notice, and
> it is not ready for mainnet money. Open findings are listed in
> `KNOWN-ISSUES.md` in the repository.

## What is in this guide

- [Quickstart](quickstart.md): build the binaries, put `caparra-gate` in
  front of a local service on the fake rail, and see what a client gets.
- [Operator config reference](operator-config.md): the configuration file that
  `caparra-gate` reads.
- [Agent usage](agent-usage.md): how agents pay through `bnap-mcp`, the `bnap`
  CLI or the wallet library.
- [Architecture](architecture.md): the crate map and how the pieces fit.

Sections marked **TODO** are placeholders. They are filled in as the
features they describe land.

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
