//! Offer and its entry parsers, then every check that reads the parsed
//! offer.
#![no_main]

use bnap_core::offer::{AttestEntry, NativeEntry, Offer, PayEntry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PayEntry::parse(data);
    let _ = AttestEntry::parse(data);
    let _ = NativeEntry::parse(data);
    if let Ok(o) = Offer::parse(data) {
        assert_eq!(o.bytes(), data);
        let _ = o.offer_id();
        let _ = o.signed_bytes();
        let _ = o.verify_signature();
        let _ = o.verify_mac(&[[7u8; 32]]);
        let _ = o.check_expiry(1_700_000_000, None);
        let _ = o.check_expiry(u64::MAX, None);
        let _ = o.check_expiry(0, Some("notes"));
    }
});
