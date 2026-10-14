//! The `bnap-mcp` binary: the three BNAP tools over stdio, or over
//! streamable HTTP on a loopback address.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use bnap_mcp::BnapTools;
use caparra_wallet::{HttpsTransport, Options, Wallet};
use clap::Parser;
use rmcp::ServiceExt as _;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

/// Serves `fetch_paid`, `budget` and `receipts` over MCP.
#[derive(Debug, Parser)]
#[command(name = "bnap-mcp", version, about)]
struct Args {
    /// The wallet file (made with `bnap init`).
    #[arg(long, env = "BNAP_WALLET")]
    wallet: Option<PathBuf>,
    /// The task this server's payments count against.
    #[arg(long, env = "BNAP_TASK", default_value = "mcp")]
    task: String,
    /// Serve streamable HTTP at this loopback address instead of stdio.
    #[arg(long)]
    http: Option<SocketAddr>,
    /// A file holding the wallet passphrase; `BNAP_PASSPHRASE` otherwise.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

fn fail(m: &str) -> ExitCode {
    eprintln!("bnap-mcp: {m}");
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs go to stderr: stdout is the MCP channel in stdio mode.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("BNAP_LOG"))
        .init();
    let args = Args::parse();
    let path = args.wallet.clone().unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
            .join(".bnap")
            .join("wallet.db")
    });
    let pass = match &args.passphrase_file {
        Some(f) => match std::fs::read_to_string(f) {
            Ok(p) => p.trim_end_matches(['\n', '\r']).to_owned(),
            Err(e) => return fail(&format!("cannot read the passphrase file: {e}")),
        },
        None => match std::env::var("BNAP_PASSPHRASE") {
            Ok(p) => p,
            Err(_) => return fail("set BNAP_PASSPHRASE or --passphrase-file"),
        },
    };
    let transport = match HttpsTransport::new() {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let mut opts = Options::new(Arc::new(transport));
    opts.task = args.task.clone();
    let wallet = match Wallet::open(&path, &pass, &opts).await {
        Ok(w) => Arc::new(w),
        Err(e) => return fail(&e.to_string()),
    };
    drop(pass);
    let tools = BnapTools::new(wallet);
    match args.http {
        None => {
            let running = match tools.serve(rmcp::transport::stdio()).await {
                Ok(r) => r,
                Err(e) => return fail(&e.to_string()),
            };
            if let Err(e) = running.waiting().await {
                return fail(&e.to_string());
            }
        }
        Some(addr) => {
            // Anyone who reaches the endpoint spends within the caps: only
            // loopback is served.
            if !addr.ip().is_loopback() {
                return fail("--http serves loopback addresses only");
            }
            let service: StreamableHttpService<BnapTools, LocalSessionManager> =
                StreamableHttpService::new(
                    move || Ok(tools.clone()),
                    Arc::default(),
                    StreamableHttpServerConfig::default(),
                );
            let router = axum::Router::new().nest_service("/mcp", service);
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => return fail(&e.to_string()),
            };
            eprintln!("bnap-mcp: serving http://{addr}/mcp");
            if let Err(e) = axum::serve(listener, router).await {
                return fail(&e.to_string());
            }
        }
    }
    ExitCode::SUCCESS
}
