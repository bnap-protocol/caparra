//! BigSize, tu64, lp and TLV streams: never panic, and a stream that parses
//! serializes back to the same bytes (one canonical form).
#![no_main]

use bnap_core::encoding::{read_bigsize, read_lp, read_tu64, write_bigsize};
use bnap_core::tlv::{StreamKind, TlvStream, parse_entry_list};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((v, n)) = read_bigsize(data) {
        let mut out = Vec::new();
        write_bigsize(&mut out, v);
        assert_eq!(out.as_slice(), &data[..n], "BigSize is not canonical");
    }
    if let Ok(v) = read_tu64(data, 1) {
        assert!(data.len() <= 8);
        let _ = v;
    }
    let _ = read_lp(data);
    let _ = parse_entry_list(data);
    for kind in [StreamKind::TopLevel, StreamKind::Nested] {
        if let Ok(s) = TlvStream::parse(data, kind) {
            assert_eq!(s.to_bytes(), data, "TLV stream does not roundtrip");
        }
    }
});
