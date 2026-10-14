//! The `bnap-mcp` binary's start-up rules.

#![allow(clippy::missing_panics_doc, missing_docs)]

use std::process::Command;

#[tokio::test]
async fn http_is_served_on_loopback_only_and_needs_the_passphrase() {
    let kit = caparra_wallet::testkit::Kit::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.db");
    caparra_wallet::Wallet::create(&path, "pw", &kit.options("t"))
        .await
        .unwrap();
    let run = |args: &[&str], pass: Option<&str>| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_bnap-mcp"));
        c.arg("--wallet")
            .arg(&path)
            .args(args)
            .env_remove("BNAP_PASSPHRASE");
        if let Some(p) = pass {
            c.env("BNAP_PASSPHRASE", p);
        }
        c.output().unwrap()
    };
    let o = run(&["--http", "0.0.0.0:0"], Some("pw"));
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("loopback"));
    let o = run(&[], None);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("BNAP_PASSPHRASE"));
    let o = run(&[], Some("wrong"));
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("LOCKED"));
}
