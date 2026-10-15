//! MPP credential JSON, charge request, challenge header and the strict
//! JSON decoder, plus the MCP carrier's view of an MPP credential.
#![no_main]

use bnap_scheme_mpp::{Challenge, ChargeRequest, Credential, credential_from_authorization, json};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = json::decode(data);
    let _ = Credential::decode(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ChargeRequest::decode(s);
        let _ = Challenge::parse(s);
        if let Some(c) = credential_from_authorization(s) {
            let _ = Credential::decode(c.as_bytes());
        }
        let _ = bnap_carrier_mcp::mpp::credential_value(s);
        let _ = bnap_carrier_mcp::mpp::challenge_value(s);
    }
});
