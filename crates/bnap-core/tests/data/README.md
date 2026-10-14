# Test data

## vectors.json

Copied unchanged from the spec repository, `bnap/vectors/vectors.json`, at
commit `14bbd5e` ("test(vectors): add the draft-00 test vectors"), sha256
`f21ff83aae5e3bafda1480498b771bb21607faecd4485169c4acb0ad4094ae14`. It is
the output of `python3 -I reference/python/bnap_ref.py`. `tests/vectors.rs`
rebuilds every value in it from the same inputs the reference uses.

If the spec repository regenerates the vectors, copy the file again and
update the commit and hash above.

## bip340-test-vectors.csv

The official BIP-340 test vectors, `bip-0340/test-vectors.csv` from the
Bitcoin Improvement Proposals repository (github.com/bitcoin/bips), by
Pieter Wuille, Jonas Nick and Tim Ruffing, licensed BSD-2-Clause as BIP-340
is. Rows 0 to 18, with the upstream header and comments. The values were
taken from the copy that rust-secp256k1 0.30.0 embeds in its own test suite,
and the header, every comment and the public keys of rows 5 and 14 were
checked against the upstream file.

Rows 15 to 18 sign messages that are not 32 bytes long. The secp256k1 0.29
API that `bitcoin` 0.32 re-exports signs and verifies 32-byte messages only,
so `tests/bip340.rs` skips those four rows; every message the socket signs
is a 32-byte tagged hash.
