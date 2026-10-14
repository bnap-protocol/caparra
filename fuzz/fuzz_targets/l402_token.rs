//! L402 token (macaroon and preimage), identifier and the challenge header.
#![no_main]

use bnap_scheme_l402::{Challenge, Identifier, Token, credential_from_authorization};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Identifier::parse(data);
    if let Ok(t) = Token::parse(data) {
        let _ = t.macaroon();
        let _ = format!("{t:?}");
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Challenge::parse(s);
        if let Some(c) = credential_from_authorization(s) {
            let _ = Token::parse(c.as_bytes());
        }
    }
});
