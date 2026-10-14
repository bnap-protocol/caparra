//! The MCP carrier's untrusted input: the strict JSON check, the base64url
//! credential in `_meta`, the credential inside, tool arguments and the
//! MPP credential shape.
#![no_main]

use bnap_carrier_mcp::{mpp, scope, wire};
use bnap_core::credential::{Credential, CredentialParse};
use bnap_core::manifest::parse_strict;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = parse_strict(data) {
        if let Some(meta) = v.get("params").and_then(|p| p.get("_meta")) {
            if let Some(text) = meta.get(wire::CREDENTIAL).and_then(|c| c.as_str()) {
                if let Ok(bytes) = wire::from_b64u(text, 9216) {
                    let _ = Credential::parse_with(
                        &bytes,
                        &CredentialParse {
                            max_credential: 9216,
                            known_ext_types: &[],
                        },
                    );
                }
            }
            if let Some(m) = meta.get(wire::MPP_CREDENTIAL) {
                let _ = mpp::credential_token(m);
            }
        }
        let _ = wire::ErrorData::from_value(&v);
    }
    let _ = scope::parse_arguments(data);
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(b) = wire::from_b64u(s, 9216) {
            assert_eq!(wire::b64u(&b), s, "base64url is not canonical");
        }
    }
});
