//! The `bnap` binary.

use std::process::ExitCode;

use clap::Parser as _;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = bnap_cli::cli::Cli::parse();
    let out = bnap_cli::cli::run(&cli).await;
    ExitCode::from(bnap_cli::cli::emit(&out))
}
