//! The `bnap` binary, run as a person or a script would.

#![allow(clippy::missing_panics_doc, missing_docs)]

use std::path::Path;
use std::process::{Command, Output};

const PASS: &str = "correct horse battery";

fn bnap(wallet: &Path, args: &[&str]) -> Output {
    bnap_env(wallet, args, PASS)
}

fn bnap_env(wallet: &Path, args: &[&str], pass: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bnap"))
        .arg("--wallet")
        .arg(wallet)
        .args(args)
        .env("BNAP_PASSPHRASE", pass)
        .env_remove("BNAP_WALLET")
        .env_remove("BNAP_TASK")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(o)))
}

#[test]
fn init_shows_the_mnemonic_once_and_nothing_else_ever_does() {
    let dir = tempfile::tempdir().unwrap();
    let w = dir.path().join("w.db");
    let o = bnap(&w, &["--json", "init"]);
    assert!(o.status.success(), "{}", text(&o));
    let v = json(&o);
    let words: Vec<String> = v["mnemonic"]
        .as_str()
        .unwrap()
        .split(' ')
        .map(str::to_owned)
        .collect();
    assert_eq!(words.len(), 12);
    let again = bnap(&w, &["init"]);
    assert_eq!(again.status.code(), Some(2));
    assert!(
        text(&again).starts_with("error[WALLET_EXISTS]"),
        "{}",
        text(&again)
    );
    // A NWC secret and the seed never come back out.
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let uri = format!("nostr+walletconnect://abcd?relay=wss://relay.example&secret={secret}");
    let o = bnap(&w, &["paysource", "nwc", &uri]);
    assert!(o.status.success(), "{}", text(&o));
    let phrase = words.join(" ");
    for args in [
        &["paysource"][..],
        &["--json", "paysource"],
        &["budget"],
        &["--json", "budget"],
        &["receipts"],
        &["--json", "receipts", "verify"],
    ] {
        let o = bnap(&w, args);
        assert!(o.status.success(), "{args:?}: {}", text(&o));
        let t = text(&o);
        assert!(!t.contains(secret), "{args:?} printed the NWC secret");
        assert!(!t.contains(&phrase), "{args:?} printed the seed");
    }
    let raw = std::fs::read(&w).unwrap();
    let raw = String::from_utf8_lossy(&raw);
    assert!(!raw.contains(secret) && !raw.contains(&words[0..3].join(" ")));
}

#[test]
fn a_wrong_passphrase_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = dir.path().join("w.db");
    assert!(bnap(&w, &["init"]).status.success());
    let o = bnap_env(&w, &["budget"], "wrong");
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).starts_with("error[LOCKED]"), "{}", text(&o));
    let o = bnap(&dir.path().join("none.db"), &["budget"]);
    assert!(text(&o).starts_with("error[NO_WALLET]"), "{}", text(&o));
}

#[test]
fn budget_set_and_show() {
    let dir = tempfile::tempdir().unwrap();
    let w = dir.path().join("w.db");
    assert!(bnap(&w, &["init"]).status.success());
    let o = bnap(
        &w,
        &[
            "budget",
            "set",
            "--per-request",
            "42",
            "--daily",
            "900",
            "--require",
            "link-payment=unlinkable",
            "--linkable",
            "never",
            "--deny-scheme",
            "httpauth:L402",
            "--allow-experimental",
            "true",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("per request         42        42    42"),
        "{}",
        text(&o)
    );
    let v = json(&bnap(&w, &["--json", "budget"]));
    let b = &v["budget"];
    assert_eq!(b["hard"]["per_request"], 42);
    assert_eq!(b["hard"]["daily"], 900);
    assert_eq!(b["policy"]["require"]["link-payment"], "unlinkable");
    assert_eq!(b["policy"]["linkable"], "never");
    assert_eq!(b["policy"]["allow_experimental"], true);
    assert!(
        !b["policy"]["allowed_schemes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "httpauth:L402")
    );
    for bad in [
        &["budget", "set", "--require", "colour=blue"][..],
        &["budget", "set", "--require", "binding=Q"],
        &["budget", "set", "--allow-scheme", "vnd.example.any"],
        &["budget", "set", "--linkable", "sometimes"],
    ] {
        let o = bnap(&w, bad);
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
        assert!(text(&o).starts_with("error[BAD_INPUT]"), "{}", text(&o));
    }
}

#[test]
fn requests_are_checked_before_anything_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let w = dir.path().join("w.db");
    assert!(bnap(&w, &["init"]).status.success());
    let o = bnap(&w, &["get", "http://api.example/x"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).starts_with("error[BAD_INPUT]"), "{}", text(&o));
    let o = bnap(
        &w,
        &[
            "--json",
            "get",
            "https://api.example/x",
            "--max-sat",
            "1000000",
        ],
    );
    assert_eq!(o.status.code(), Some(2));
    let v = json(&o);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "ABOVE_HARD_CAP");
    assert_eq!(v["error"]["remaining"], 100);
}
