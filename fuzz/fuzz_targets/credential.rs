//! Credential: parse, re-serialize (the builder runs the same rules), and
//! the Context and Digest formulas.
#![no_main]

use bnap_core::credential::Credential;
use bnap_core::hash::{OfferId, Scope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Credential::parse(data) {
        let again = c.to_bytes().expect("a parsed credential serializes");
        let back = Credential::parse(&again).expect("a serialized credential parses");
        assert_eq!(back, c);
        let ctx = c.context(&OfferId::from([1u8; 32]), &Scope::from([2u8; 32]));
        let _ = c.digest(&ctx);
        let _ = c.check_tls_binding(None);
        let _ = c.check_binding_classes(|_| None);
    }
});
