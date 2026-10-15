//! The bnap conformance runner (`conformance/run.py` of the bnap
//! repository) against the real gate of `tests/stack`: profiles `server`
//! and `gateway`, without a payer and with `conformance/payers/lncli-payer.sh`
//! paying from the regtest payer node.
//!
//! Needs the `regtest` feature, Docker, Python 3.11 and a checkout of the
//! bnap repository named by `BNAP_CONFORMANCE` (its root); without it the
//! test does nothing. Reports go to `BNAP_CONFORMANCE_REPORT` (default: a
//! temporary directory) as `<profile>-<payer>/report.json`.
//!
//! ```text
//! BNAP_CONFORMANCE=../bnap cargo nextest run -p e2e --features regtest --test conformance
//! ```
//!
//! The test fails when a MUST or SHOULD case fails or errors; MUST cases the
//! gate cannot reach (no `DPoP` key the runner makes is registered here, no
//! roles, no notes wallet in the runner) are skips, as `--allow-skips`
//! reads them.

#![cfg(feature = "regtest")]

mod stack;

use std::path::PathBuf;
use std::process::Command;

use stack::{Stack, devenv, fixtures};

#[tokio::test(flavor = "multi_thread")]
async fn the_conformance_runner_passes_against_the_gate() {
    let Some(bnap) = std::env::var_os("BNAP_CONFORMANCE").map(PathBuf::from) else {
        eprintln!("BNAP_CONFORMANCE is not set: the conformance run is skipped");
        return;
    };
    let s = Stack::start().await;
    let out = std::env::var_os("BNAP_CONFORMANCE_REPORT")
        .map_or_else(|| s.dir.path().join("conformance"), PathBuf::from);
    let lncli = format!(
        "docker compose -f {} exec -T payer lncli --network=regtest",
        devenv().join("compose.yml").display()
    );
    let mut failed = Vec::new();
    for profile in ["server", "gateway"] {
        for payer in ["none", "lncli"] {
            let report = out.join(format!("{profile}-{payer}"));
            let mut cmd = Command::new("python3");
            cmd.arg("-I")
                .arg(bnap.join("conformance/run.py"))
                .args(["--target", &s.origin, "--profile", profile])
                .arg("--report")
                .arg(&report)
                .args(["--max-wait", "400", "--allow-skips"])
                .env("SSL_CERT_FILE", fixtures().join("ca.pem"))
                .env("LNCLI", &lncli)
                .current_dir(&bnap);
            if payer == "lncli" {
                cmd.arg("--payer")
                    .arg(format!(
                        "cmd:{}",
                        bnap.join("conformance/payers/lncli-payer.sh").display()
                    ))
                    .args(["--max-spend-sat", "200"]);
            }
            let o = cmd.output().expect("run conformance/run.py");
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            println!(
                "== {profile}, payer {payer}: exit {:?}\n{text}",
                o.status.code()
            );
            eprintln!("{}", String::from_utf8_lossy(&o.stderr));
            let r: serde_json::Value =
                serde_json::from_slice(&std::fs::read(report.join("report.json")).unwrap())
                    .unwrap();
            for c in r["results"].as_array().into_iter().flatten() {
                let status = c["status"].as_str().unwrap_or("");
                if status == "fail" || status == "error" {
                    failed.push(format!(
                        "{profile}/{payer} {} ({}): {}",
                        c["id"].as_str().unwrap_or("?"),
                        c["level"].as_str().unwrap_or("?"),
                        c["detail"].as_str().unwrap_or("")
                    ));
                }
            }
        }
    }
    assert!(
        failed.is_empty(),
        "{} conformance cases failed:\n{}\n{}",
        failed.len(),
        failed.join("\n"),
        s.gate_log()
    );
}
