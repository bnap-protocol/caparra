//! `bnap-signer`: serves a key file's keys on a Unix socket.
//!
//! ```text
//! bnap-signer --keys /path/to/keys.toml --socket /run/bnap/signer.sock
//! ```
//!
//! The key file must be mode `0600` or stricter; the socket is created mode
//! `0600` in a directory others cannot write. Logs go to stderr (filter
//! with `RUST_LOG`) and never hold a secret or a request's contents.
//! SIGINT or SIGTERM stops it and removes the socket.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("bnap-signer serves a Unix socket and runs on Unix only");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use bnap_signer_file::FileSigner;
    use bnap_signer_process::{ServeOptions, Server, SignerSocket};
    use clap::Parser;
    use tracing_subscriber::EnvFilter;

    /// Serves a BNAP key file's keys on a Unix socket.
    #[derive(Debug, Parser)]
    #[command(name = "bnap-signer", version)]
    struct Args {
        /// The key file (TOML, mode 0600).
        #[arg(long, env = "BNAP_SIGNER_KEYS")]
        keys: PathBuf,
        /// The socket to listen on.
        #[arg(long, env = "BNAP_SIGNER_SOCKET")]
        socket: PathBuf,
        /// Another user ID whose processes may connect (repeatable).
        #[arg(long = "allow-uid")]
        allow_uid: Vec<u32>,
        /// The most connections served at once.
        #[arg(long, default_value_t = 64)]
        max_connections: usize,
        /// Milliseconds to read the rest of a frame, or write one.
        #[arg(long, default_value_t = 5_000)]
        io_timeout_ms: u64,
        /// Milliseconds a connection may wait between requests.
        #[arg(long, default_value_t = 30_000)]
        idle_timeout_ms: u64,
    }

    pub fn main() -> ExitCode {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
        let args = Args::parse();
        let signer = match FileSigner::load(&args.keys) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::from(2);
            }
        };
        for k in signer.keys() {
            tracing::info!(key = %k.public_key(), r#use = k.key_use().as_str(), "holding key");
        }
        for ks in signer.keysets() {
            tracing::info!(
                keyset = %hex::encode(ks.id()),
                active = ks.active(),
                final_expiry = ks.final_expiry(),
                "holding keyset"
            );
        }
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("cannot start the runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        let options = ServeOptions {
            io_timeout: Duration::from_millis(args.io_timeout_ms),
            idle_timeout: Duration::from_millis(args.idle_timeout_ms),
            max_connections: args.max_connections,
            allowed_uids: args.allow_uid,
            store: None,
        };
        runtime.block_on(async move {
            let socket = match SignerSocket::bind(&args.socket) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("{e}");
                    return ExitCode::from(2);
                }
            };
            tracing::info!(socket = %socket.path().display(), "listening");
            let server = Arc::new(Server::new(Arc::new(signer), options));
            match server.serve(socket, shutdown()).await {
                Ok(()) => {
                    tracing::info!("stopped");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    tracing::error!("serving failed: {e}");
                    ExitCode::FAILURE
                }
            }
        })
    }

    /// SIGINT or SIGTERM.
    async fn shutdown() {
        let term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match term {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
}
