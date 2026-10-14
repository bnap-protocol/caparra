//! `caparra-gate`: the BNAP gate.
//!
//! ```text
//! caparra-gate run --config gate.toml
//! caparra-gate check --config gate.toml
//! caparra-gate manifest sign --config gate.toml --root-key root.key \
//!     --backup <hex key> --seq 1 --keys-from keys.toml --out manifest.json
//! caparra-gate key new --out mac.key
//! ```

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bnap_core::manifest::{KeyUse, ManifestKey};
use bnap_core::schnorr::{Key, SigningKey};
use caparra_gate::config::Config;
use caparra_gate::manifest::SignInput;
use caparra_gate::plugs::{read_key32, system_clock};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "caparra-gate", version, about = "The BNAP gate")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check everything, then serve.
    Run {
        /// The configuration file.
        #[arg(long, env = "CAPARRA_CONFIG")]
        config: PathBuf,
    },
    /// Check everything (configuration, registry, manifest, plugs, signer)
    /// and exit: 0 when the gate would start.
    Check {
        /// The configuration file.
        #[arg(long, env = "CAPARRA_CONFIG")]
        config: PathBuf,
    },
    /// The manifest.
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// Keys.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Sign the manifest of a configuration with the offline root key.
    /// Run it where the root key lives, never on the gate's host.
    Sign {
        /// The configuration file (its routes, origin and limits).
        #[arg(long)]
        config: PathBuf,
        /// File holding the root key's secret, 64 hex.
        #[arg(long)]
        root_key: PathBuf,
        /// The backup key, 64 hex (its public half only).
        #[arg(long)]
        backup: String,
        /// Sequence number, higher than any manifest signed before.
        #[arg(long)]
        seq: u64,
        /// An online key: `offer:<hex>:<not_after>` or
        /// `receipt:<hex>:<not_after>`.
        #[arg(long = "key")]
        keys: Vec<String>,
        /// Take the online keys (and their `not_after`) from a signer key
        /// file instead.
        #[arg(long)]
        keys_from: Option<PathBuf>,
        /// Where to write the manifest.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Write 32 random bytes as hex to a new file (mode 0600) and print the
    /// BIP-340 public key, for a root, backup, `K_mac` or scheme secret.
    New {
        /// The file to create; it must not exist.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("caparra-gate: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::Run { config } => {
            let cfg = Config::load(&config)?;
            runtime()?.block_on(async {
                let running = caparra_gate::server::start(&cfg, system_clock(), None).await?;
                tokio::select! {
                    () = shutdown_signal() => {
                        tracing::info!("stopping");
                        running.stop().await;
                    }
                }
                Ok(())
            })
        }
        Cmd::Check { config } => {
            let cfg = Config::load(&config)?;
            runtime()?.block_on(async {
                caparra_gate::server::prepare(&cfg, &system_clock()).await?;
                println!("ok: caparra-gate would start with {}", config.display());
                Ok(())
            })
        }
        Cmd::Manifest {
            cmd:
                ManifestCmd::Sign {
                    config,
                    root_key,
                    backup,
                    seq,
                    keys,
                    keys_from,
                    out,
                },
        } => sign(
            &config,
            &root_key,
            &backup,
            seq,
            &keys,
            keys_from.as_deref(),
            &out,
        ),
        Cmd::Key {
            cmd: KeyCmd::New { out },
        } => new_key(&out),
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_key_arg(s: &str) -> anyhow::Result<ManifestKey> {
    let mut it = s.splitn(3, ':');
    let (Some(u), Some(k), Some(t)) = (it.next(), it.next(), it.next()) else {
        anyhow::bail!("--key {s:?}: write use:hex:not_after");
    };
    let key_use = match u {
        "offer" => KeyUse::Offer,
        "receipt" => KeyUse::Receipt,
        _ => anyhow::bail!("--key {s:?}: use is offer or receipt"),
    };
    Ok(ManifestKey {
        kid: Key::from_hex(k).map_err(|_| anyhow::anyhow!("--key {s:?}: not a hex key"))?,
        key_use,
        not_after: t.parse()?,
    })
}

#[allow(clippy::too_many_arguments)]
fn sign(
    config: &Path,
    root_key: &Path,
    backup: &str,
    seq: u64,
    keys: &[String],
    keys_from: Option<&Path>,
    out: &Path,
) -> anyhow::Result<()> {
    let cfg = Config::load(config)?;
    let registry = caparra_gate::registry::Registry::embedded()?;
    let plans = cfg.plan(&registry)?;
    let mut listed: Vec<ManifestKey> = keys
        .iter()
        .map(|k| parse_key_arg(k))
        .collect::<Result<_, _>>()?;
    if let Some(path) = keys_from {
        let signer = bnap_signer_file::FileSigner::load(path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        for k in signer.keys() {
            let not_after = k.not_after().ok_or_else(|| {
                anyhow::anyhow!("{}: every key needs not_after to be listed", path.display())
            })?;
            listed.push(ManifestKey {
                kid: k.public_key(),
                key_use: k.key_use().clone(),
                not_after,
            });
        }
    }
    let root = SigningKey::from_secret_bytes(&read_key32(root_key)?)
        .map_err(|e| anyhow::anyhow!("root key: {e}"))?;
    let backup = Key::from_hex(backup).map_err(|_| anyhow::anyhow!("--backup is not a hex key"))?;
    let now = system_clock()();
    let bytes = caparra_gate::manifest::sign(
        &cfg,
        &plans,
        &SignInput {
            root,
            backup,
            seq,
            keys: listed,
            issued: now,
            aux: rand::random(),
        },
    )?;
    std::fs::write(out, &bytes)?;
    println!("wrote {} (seq {seq}, issued {now})", out.display());
    Ok(())
}

fn new_key(out: &Path) -> anyhow::Result<()> {
    let secret: [u8; 32] = loop {
        let s: [u8; 32] = rand::random();
        if SigningKey::from_secret_bytes(&s).is_ok() {
            break s;
        }
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(out)?;
    writeln!(f, "{}", hex::encode(secret))?;
    let public = SigningKey::from_secret_bytes(&secret)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .public_key();
    println!("{public}");
    Ok(())
}
