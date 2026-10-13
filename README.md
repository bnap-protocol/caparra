# Caparra

Caparra is the Rust reference implementation of BNAP, an open protocol for
paying for and authorizing machine-to-machine requests over HTTP and MCP. It is
a Cargo workspace with a protocol core, pluggable payment schemes (ecash notes,
L402, MPP and others), settlement rails, storage backends, HTTP and MCP
carriers, a gate that sits in front of a service, a client wallet and a
command-line tool.

**Status:** pre-alpha, draft-00. The crates are stubs and nothing is published yet.

[![CI](https://github.com/bnap-protocol/caparra/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/bnap-protocol/caparra/actions/workflows/ci.yml)

## Documentation

The guide in [`book/`](book/src/SUMMARY.md) covers the quickstart, the
operator configuration, agent usage and the crate architecture. Every push to
`main` publishes it to https://bnap-protocol.github.io/caparra/ (once GitHub
Pages is switched on for the repository). Build it locally with
[mdBook](https://rust-lang.github.io/mdBook/) 0.5:

```sh
mdbook build book    # or: mdbook serve book
```

## Building

The toolchain is pinned in `rust-toolchain.toml`; the minimum supported Rust
version is 1.94.

```sh
cargo build --workspace
cargo nextest run --workspace    # or: cargo test --workspace
```

## Related repositories

- Caparra (this repository): https://github.com/bnap-protocol/caparra
- The BNAP specification: https://github.com/bnap-protocol/bnap

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Unless you explicitly state otherwise, any contribution you submit
for inclusion is dual-licensed as above, without any additional terms or
conditions.
