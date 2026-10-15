//! Manifest JSON (duplicate members included), its JCS and signature, and
//! the 9.3 accept rule.
#![no_main]

use bnap_core::manifest::{SignedManifest, accept, parse_strict};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if parse_strict(data).is_err() {
        assert!(
            SignedManifest::parse(data).is_err(),
            "lenient manifest parse"
        );
    }
    if let Ok(m) = SignedManifest::parse(data) {
        let _ = m.jcs();
        let _ = m.verify();
        let _ = m.hash();
    }
    let _ = accept(None, "https://example.com", data, 1_700_000_000);
});
