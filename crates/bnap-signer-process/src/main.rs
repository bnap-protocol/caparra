//! `bnap-signer`: serves a key file's keys on a Unix socket.
//!
//! ```text
//! bnap-signer --keys /path/to/keys.toml --socket /run/bnap/signer.sock
//! ```
//!
//! The key file must be mode `0600` or stricter; the socket is created in a
//! directory the group and others cannot write (a sticky one such as `/tmp`
//! is refused), mode `0600`: only the signer's own user can connect.
//!
//! To keep the keys from the gate, run the signer as a user of its own and
//! let the gate's user in:
//!
//! ```text
//! bnap-signer --keys /etc/bnap/keys.toml --socket /run/bnap-signer/signer.sock \
//!     --socket-group GATE_GID --allow-uid GATE_UID
//! ```
//!
//! The socket is then mode `0660` with group `GATE_GID` (the signer's user
//! must be a member), and of the processes that can reach it only those of
//! the signer's user and `GATE_UID` are served. The directory must let that
//! group search it (for example `0750`, owned by the signer's user with
//! group `GATE_GID`). Logs go to stderr (filter with `RUST_LOG`) and never
//! hold a secret or a request's contents. SIGINT or SIGTERM stops it and
//! removes the socket.

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
    use bnap_signer_process::{ServeOptions, Server, SignerSocket, SocketAccess};
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
        /// A user ID, besides the signer's own, whose processes are served
        /// (repeatable): the gate's. Needs --socket-group, which lets them
        /// reach the socket.
        #[arg(long = "allow-uid", requires = "socket_group")]
        allow_uid: Vec<u32>,
        /// A group ID (numeric) the gate's user is in: the socket is created
        /// mode 0660 with this group instead of 0600, and of its members
        /// only the --allow-uid users are served. The signer's user must be
        /// a member too. Needs --allow-uid.
        #[arg(long, requires = "allow_uid")]
        socket_group: Option<u32>,
        /// The most connections served at once.
        #[arg(long, default_value_t = 64)]
        max_connections: usize,
        /// Milliseconds to read the rest of a frame, or write one.
        #[arg(long, default_value_t = 5_000)]
        io_timeout_ms: u64,
        /// Milliseconds a connection may wait between requests.
        #[arg(long, default_value_t = 30_000)]
        idle_timeout_ms: u64,
        /// The gate's SQLite use store. With it, change is signed only for
        /// outputs the store reserved for the outcome, and an ack only for a
        /// Response that states its settled outcome record: reaching the
        /// socket is then no longer enough to mint change or receipts.
        #[arg(long, env = "BNAP_SIGNER_STORE")]
        store: Option<PathBuf>,
        /// Seconds a change ledger entry may be kept after now, whatever
        /// `keep_until` a request names.
        #[arg(long, default_value_t = bnap_signer_process::DEFAULT_MAX_KEEP.as_secs())]
        max_keep_s: u64,
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
        let store: Option<Arc<dyn bnap_core::store::UseStore>> = match &args.store {
            None => None,
            Some(path) => match runtime.block_on(bnap_store_sqlite::SqliteStore::open(path)) {
                Ok(s) => {
                    tracing::info!(store = %path.display(), "checking change and acks against the use store");
                    Some(Arc::new(s))
                }
                Err(e) => {
                    tracing::error!("use store {}: {e}", path.display());
                    return ExitCode::from(2);
                }
            },
        };
        let options = ServeOptions {
            io_timeout: Duration::from_millis(args.io_timeout_ms),
            idle_timeout: Duration::from_millis(args.idle_timeout_ms),
            max_connections: args.max_connections,
            store,
            max_keep: Duration::from_secs(args.max_keep_s),
        };
        let access = match args.socket_group {
            Some(gid) => SocketAccess::Group {
                gid,
                uids: args.allow_uid,
            },
            None => SocketAccess::Owner,
        };
        runtime.block_on(async move {
            let socket = match SignerSocket::bind_with(&args.socket, access) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("{e}");
                    return ExitCode::from(2);
                }
            };
            let access = socket.access();
            tracing::info!(
                socket = %socket.path().display(),
                mode = format_args!("{:o}", access.mode()),
                allowed_uids = ?access.allowed_uids(),
                "listening"
            );
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
