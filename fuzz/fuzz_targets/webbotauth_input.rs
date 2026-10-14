//! Web Bot Auth body and every key-free check of its Signature-Input and
//! Signature fields.
#![no_main]

use bnap_scheme_webbotauth::body::WbaBody;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(b) = WbaBody::parse(data) {
        assert_eq!(WbaBody::parse(&b.to_bytes()).ok().as_ref(), Some(&b));
    }
    let _ = bnap_scheme_webbotauth::fuzz_check_body(data);
});
