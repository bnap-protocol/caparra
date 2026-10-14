//! The notes scheme's TLV records: body, witness against the body, fund
//! quote, params, scheme result and the fund header.
#![no_main]

use bnap_scheme_notes::FundRequest;
use bnap_scheme_notes::wire::{Body, FundQuote, Params, Witness, parse_scheme_result};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the input into a body and a witness.
    if let Some((&cut, rest)) = data.split_first() {
        let cut = usize::from(cut).min(rest.len());
        let (b, w) = rest.split_at(cut);
        if let Ok(body) = Body::parse(b) {
            let _ = Witness::parse(w, &body);
        }
    }
    let _ = Body::parse(data);
    let _ = FundQuote::parse(data);
    let _ = Params::parse(data);
    let _ = parse_scheme_result(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = FundRequest::parse_header(s);
    }
});
