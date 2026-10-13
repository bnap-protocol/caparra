# Agent usage

> **TODO:** this page is a stub. It is filled in as `caparra-wallet`,
> `bnap-mcp` and the `bnap` CLI land.

An agent meets BNAP when a service answers a request with an offer instead of
the result. The agent picks a scheme it can pay with, attaches a credential to
the retried request, and gets the result plus a signed receipt. Caparra gives
agents three ways to do that.

## Through MCP: `bnap-mcp`

`bnap-mcp` is an MCP server that exposes wallet and payment tools to an agent.
The agent's host runs it next to the model, and the model calls its tools when
a service asks for payment.

> **TODO:** list the tools with their arguments and results, show how to
> register the server with an MCP host, and document how spending budgets and
> per-origin limits are set.

## From scripts: the `bnap` CLI

The `bnap` command line tool (crate `bnap-cli`) inspects offers, pays for
requests and tests BNAP flows from a shell.

> **TODO:** document the subcommands, starting with fetching and verifying a
> manifest, decoding an offer and paying for one request.

## Embedded: `caparra-wallet`

`caparra-wallet` is the client wallet library. It holds funds, answers payment
challenges and keeps the pins and receipts a client needs.

> **TODO:** show the minimal Rust example: build a wallet, make a request
> through it, read the receipt.

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
