//! Response (receipt) and the 8.2 Error object.
#![no_main]

use bnap_core::error::ErrorObject;
use bnap_core::response::Response;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Response::parse(data) {
        let _ = r.ack_message();
        let _ = r.verify_ack();
    }
    if let Ok(e) = ErrorObject::parse(data) {
        let _ = e.socket_code();
        let _ = e.to_bytes();
    }
});
