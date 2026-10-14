//! DPoP proof JWT (compact JWS, header and claims) and the scheme bodies.
#![no_main]

use bnap_core::hash::Context;
use bnap_scheme_dpop::body::{BearerBody, DpopBody};
use bnap_scheme_dpop::jose::parse_compact;
use bnap_scheme_dpop::proof::{ProofCheck, check};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_compact(data);
    let ctx = Context::from([3u8; 32]);
    for token in [None, Some("token")] {
        let _ = check(
            data,
            &ProofCheck {
                context: &ctx,
                now: 1_700_000_000,
                max_age: Some(300),
                access_token: token,
            },
        );
    }
    if let Ok(b) = DpopBody::parse(data) {
        let _ = b.to_bytes();
    }
    let _ = BearerBody::parse(data);
});
