//! The signer process IPC: frame reading (length prefix) and the request
//! and reply decoders.
#![no_main]

use std::sync::OnceLock;
use std::time::Duration;

use bnap_signer_process::wire::{decode_reply, decode_request, read_frame};
use libfuzzer_sys::fuzz_target;

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = decode_request(data);
    let _ = decode_reply(data);
    let mut r = data;
    rt().block_on(async {
        while let Ok(frame) =
            read_frame(&mut r, Duration::from_secs(1), Duration::from_secs(1)).await
        {
            let _ = decode_request(&frame);
        }
    });
});
