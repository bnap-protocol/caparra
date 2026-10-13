# Caparra

Caparra is the Rust reference implementation of BNAP, an open protocol for
paying for and authorizing machine-to-machine requests over HTTP and MCP. It is
a Cargo workspace with a protocol core, pluggable payment schemes (ecash notes,
L402, MPP and others), settlement rails, storage backends, HTTP and MCP
carriers, a gate that sits in front of a service, a client wallet and a
command-line tool.

**Status:** pre-alpha, draft-00. The crates are stubs and nothing is published yet.

## Related repositories

- Caparra (this repository): https://github.com/bnap-protocol/caparra
- The BNAP specification: https://github.com/bnap-protocol/bnap

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Unless you explicitly state otherwise, any contribution you submit
for inclusion is dual-licensed as above, without any additional terms or
conditions.
