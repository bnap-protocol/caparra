//! The `bnap` command line.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use caparra_wallet::policy::{Linkability, VALUE_SCHEMES};
use caparra_wallet::{
    CapKind, Code, FetchRequest, HttpsTransport, Options, PaySourceConfig, Refusal, Wallet,
    verify_receipt,
};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::render;

/// Pays for HTTP requests with BNAP, within caps you set.
#[derive(Debug, Parser)]
#[command(name = "bnap", version, about)]
pub struct Cli {
    /// The wallet file.
    #[arg(long, env = "BNAP_WALLET", global = true)]
    pub wallet: Option<PathBuf>,
    /// The task payments count against (the per-task cap). Each command
    /// is its own task unless a name groups several.
    #[arg(long, env = "BNAP_TASK", global = true)]
    pub task: Option<String>,
    /// Print JSON for scripts.
    #[arg(long, global = true)]
    pub json: bool,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a wallet with a new seed; shows the mnemonic once.
    Init {
        /// This device's counter slot (another device on the same seed
        /// takes another slot).
        #[arg(long, default_value_t = 0)]
        slot: u16,
    },
    /// Buy notes at an origin over Lightning.
    Fund {
        /// The origin, such as `https://api.example`.
        origin: String,
        /// Sat to buy.
        sat: u64,
        /// The notes issuer URL, when the manifest does not lead to it.
        #[arg(long)]
        issuer: Option<String>,
    },
    /// GET a URL, paying if it asks and the policy allows.
    Get(FetchArgs),
    /// POST to a URL, paying if it asks and the policy allows.
    Post(FetchArgs),
    /// Show or set the spending caps and the policy.
    Budget {
        /// `show` (the default) or `set`.
        #[command(subcommand)]
        action: Option<BudgetAction>,
    },
    /// List or verify receipts.
    Receipts {
        /// `list` (the default) or `verify`.
        #[command(subcommand)]
        action: Option<ReceiptsAction>,
    },
    /// Restore notes from the seed (into a new wallet from a mnemonic, or
    /// into this one).
    Restore {
        /// Origins to restore (repeatable); the recorded sites when absent.
        #[arg(long = "origin")]
        origins: Vec<String>,
        /// The notes issuer URL, when the manifest does not lead to it.
        #[arg(long)]
        issuer: Option<String>,
        /// Counter slots to scan besides 0 and this device's (repeatable):
        /// the slots other devices on the same seed used.
        #[arg(long = "slot")]
        slots: Vec<u16>,
    },
    /// Replay paid requests that got no final answer, mint paid quotes.
    Resume,
    /// Show or set the Lightning pay source.
    Paysource {
        /// What to set.
        #[command(subcommand)]
        action: Option<PaySourceAction>,
    },
}

/// A paid fetch.
#[derive(Debug, Args)]
pub struct FetchArgs {
    /// An `https://` URL.
    pub url: String,
    /// The most this request may cost, sat (never above the per-request cap).
    #[arg(long)]
    pub max_sat: Option<u64>,
    /// A header field, `Name: value` (repeatable).
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    /// Content to send.
    #[arg(short = 'd', long)]
    pub data: Option<String>,
    /// Send this file's content.
    #[arg(long, conflicts_with = "data")]
    pub data_file: Option<PathBuf>,
}

/// Budget actions.
#[derive(Debug, Subcommand)]
pub enum BudgetAction {
    /// Show the caps, what they leave, and the policy.
    Show {
        /// Show what is left for this origin.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Change the caps or the policy (a person's decision, never a model's).
    Set(Box<BudgetSet>),
}

/// What `bnap budget set` changes.
#[derive(Debug, Args, Default)]
pub struct BudgetSet {
    /// Most one request may cost, sat.
    #[arg(long)]
    pub per_request: Option<u64>,
    /// Most one origin may get in 24 hours, sat.
    #[arg(long)]
    pub per_origin_day: Option<u64>,
    /// Most one task may spend, sat.
    #[arg(long)]
    pub per_task: Option<u64>,
    /// Most all origins together may get in 24 hours, sat.
    #[arg(long)]
    pub daily: Option<u64>,
    /// Allow a value scheme (repeatable).
    #[arg(long)]
    pub allow_scheme: Vec<String>,
    /// Forbid a value scheme (repeatable).
    #[arg(long)]
    pub deny_scheme: Vec<String>,
    /// Require a property, `property=value` (repeatable).
    #[arg(long)]
    pub require: Vec<String>,
    /// Drop a required property (repeatable).
    #[arg(long)]
    pub unrequire: Vec<String>,
    /// `never`, `fallback` or `allow`.
    #[arg(long)]
    pub linkable: Option<String>,
    /// Sat added to a linkable scheme's cost when ranking.
    #[arg(long)]
    pub linkable_penalty: Option<u64>,
    /// Allow experimental schemes.
    #[arg(long)]
    pub allow_experimental: Option<bool>,
    /// Send this attestation when offered (repeatable).
    #[arg(long)]
    pub attest: Vec<String>,
    /// Stop sending this attestation (repeatable).
    #[arg(long)]
    pub no_attest: Vec<String>,
    /// Most notes held at one origin, sat.
    #[arg(long)]
    pub max_balance: Option<u64>,
    /// Routing fee ceiling, fixed part, sat.
    #[arg(long)]
    pub fee_base: Option<u64>,
    /// Routing fee ceiling, proportional part, ppm.
    #[arg(long)]
    pub fee_ppm: Option<u64>,
}

/// Receipt actions.
#[derive(Debug, Subcommand)]
pub enum ReceiptsAction {
    /// List receipts.
    List,
    /// Check receipts as a third party would.
    Verify {
        /// One receipt; all when absent.
        id: Option<String>,
    },
}

/// Pay source actions.
#[derive(Debug, Subcommand)]
pub enum PaySourceAction {
    /// Show the pay source (secrets hidden).
    Show,
    /// Nostr Wallet Connect: the `nostr+walletconnect://` URI.
    Nwc {
        /// The URI; read from `BNAP_NWC_URI` when absent.
        uri: Option<String>,
    },
    /// A command that pays an invoice, such as `lncli payinvoice --force --json`.
    Command {
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// No pay source.
    None,
}

/// What a command printed, and its exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// For stdout.
    pub stdout: Vec<u8>,
    /// For stderr.
    pub stderr: String,
    /// Exit status.
    pub status: u8,
}

fn ok_text(s: &str) -> Outcome {
    Outcome {
        stdout: format!("{s}\n").into_bytes(),
        stderr: String::new(),
        status: 0,
    }
}

fn ok_json(v: &Value) -> Outcome {
    Outcome {
        stdout: format!("{v}\n").into_bytes(),
        stderr: String::new(),
        status: 0,
    }
}

/// How a refusal is printed.
#[must_use]
pub fn refused(r: &Refusal, json: bool) -> Outcome {
    if json {
        Outcome {
            stdout: format!("{}\n", render::refusal_json(r)).into_bytes(),
            stderr: String::new(),
            status: r.code.exit_status(),
        }
    } else {
        Outcome {
            stdout: Vec::new(),
            stderr: format!("{}\n", render::refusal(r)),
            status: r.code.exit_status(),
        }
    }
}

fn default_path() -> PathBuf {
    std::env::var_os("HOME")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join(".bnap")
        .join("wallet.db")
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>, Refusal> {
    if let Ok(p) = std::env::var("BNAP_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    let p = Zeroizing::new(
        rpassword::prompt_password("Wallet passphrase: ").map_err(|e| {
            Refusal::bad_input(format!(
                "Cannot read the passphrase: {e}. Set BNAP_PASSPHRASE."
            ))
        })?,
    );
    if confirm {
        let again = Zeroizing::new(
            rpassword::prompt_password("Again: ")
                .map_err(|e| Refusal::bad_input(format!("Cannot read the passphrase: {e}.")))?,
        );
        if *again != *p {
            return Err(Refusal::bad_input("The passphrases differ."));
        }
    }
    Ok(p)
}

fn options(cli: &Cli) -> Result<Options, Refusal> {
    let t = HttpsTransport::new().map_err(Refusal::network)?;
    let mut o = Options::new(Arc::new(t));
    o.task = cli
        .task
        .clone()
        .unwrap_or_else(|| format!("cli-{}", &caparra_wallet::wallet::random_id()[..8]));
    Ok(o)
}

async fn open(cli: &Cli, path: &std::path::Path) -> Result<Wallet, Refusal> {
    let p = passphrase(false)?;
    Wallet::open(path, &p, &options(cli)?).await
}

fn parse_header(h: &str) -> Result<(String, String), Refusal> {
    let (n, v) = h
        .split_once(':')
        .ok_or_else(|| Refusal::bad_input(format!("A header is `Name: value`, not `{h}`.")))?;
    Ok((n.trim().to_owned(), v.trim().to_owned()))
}

fn fetch_request(method: &str, a: &FetchArgs) -> Result<FetchRequest, Refusal> {
    let body = match (&a.data, &a.data_file) {
        (Some(d), _) => d.clone().into_bytes(),
        (None, Some(f)) => std::fs::read(f)
            .map_err(|e| Refusal::bad_input(format!("Cannot read {}: {e}.", f.display())))?,
        (None, None) => Vec::new(),
    };
    Ok(FetchRequest {
        method: method.into(),
        url: a.url.clone(),
        headers: a
            .headers
            .iter()
            .map(|h| parse_header(h))
            .collect::<Result<_, _>>()?,
        body,
        max_sat: a.max_sat,
    })
}

/// Applies `bnap budget set` to a policy.
pub fn apply_set(p: &mut caparra_wallet::Policy, s: &BudgetSet) -> Result<(), Refusal> {
    for (kind, v) in [
        (CapKind::PerRequest, s.per_request),
        (CapKind::PerOrigin, s.per_origin_day),
        (CapKind::PerTask, s.per_task),
        (CapKind::Daily, s.daily),
    ] {
        if let Some(v) = v {
            p.caps.set(kind, v);
        }
    }
    for a in &s.allow_scheme {
        if !VALUE_SCHEMES.contains(&a.as_str()) {
            return Err(Refusal::bad_input(format!(
                "This wallet cannot pay with {a}; it can pay with {}.",
                VALUE_SCHEMES.join(", ")
            )));
        }
        if !p.allowed_schemes.contains(a) {
            p.allowed_schemes.push(a.clone());
        }
    }
    p.allowed_schemes.retain(|x| !s.deny_scheme.contains(x));
    for r in &s.require {
        let (k, v) = r.split_once('=').ok_or_else(|| {
            Refusal::bad_input(format!("A requirement is `property=value`, not `{r}`."))
        })?;
        caparra_wallet::Policy::check_requirement(k, v)?;
        p.require.insert(k.to_owned(), v.to_owned());
    }
    for k in &s.unrequire {
        p.require.remove(k);
    }
    if let Some(l) = &s.linkable {
        p.linkable = Linkability::parse(l)
            .ok_or_else(|| Refusal::bad_input("--linkable is never, fallback or allow."))?;
    }
    if let Some(v) = s.linkable_penalty {
        p.linkable_penalty_sat = v;
    }
    if let Some(v) = s.allow_experimental {
        p.allow_experimental = v;
    }
    for a in &s.attest {
        if !caparra_wallet::policy::ATTEST_SCHEMES.contains(&a.as_str()) {
            return Err(Refusal::bad_input(format!(
                "This wallet cannot send the attestation {a}; it can send {}.",
                caparra_wallet::policy::ATTEST_SCHEMES.join(", ")
            )));
        }
        if !p.attest.contains(a) {
            p.attest.push(a.clone());
        }
    }
    p.attest.retain(|x| !s.no_attest.contains(x));
    if let Some(v) = s.max_balance {
        p.max_balance_per_origin = v;
    }
    if let Some(v) = s.fee_base {
        p.fee.base_sat = v;
    }
    if let Some(v) = s.fee_ppm {
        p.fee.ppm = v;
    }
    Ok(())
}

fn fetch_outcome(r: &caparra_wallet::FetchResult, json: bool) -> Outcome {
    let status = u8::from(!(200..300).contains(&r.status));
    if json {
        let body = match std::str::from_utf8(&r.body) {
            Ok(t) => json!({ "text": t }),
            Err(_) => {
                json!({ "base64": base64::engine::general_purpose::STANDARD.encode(&r.body) })
            }
        };
        let mut o = ok_json(&json!({
            "ok": true,
            "status": r.status,
            "payment": r.payment,
            "body": body,
        }));
        o.status = status;
        return o;
    }
    Outcome {
        stdout: r.body.clone(),
        stderr: r
            .payment
            .as_ref()
            .map(|p| format!("{}\n", render::payment(p)))
            .unwrap_or_default(),
        status,
    }
}

/// Runs a command.
pub async fn run(cli: &Cli) -> Outcome {
    match run_inner(cli).await {
        Ok(o) => o,
        Err(r) => refused(&r, cli.json),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_inner(cli: &Cli) -> Result<Outcome, Refusal> {
    let path = cli.wallet.clone().unwrap_or_else(default_path);
    let json = cli.json;
    match &cli.command {
        Command::Init { slot } => {
            let p = passphrase(true)?;
            let (w, words) = Wallet::create(&path, &p, &options(cli)?).await?;
            w.set_slot(*slot).await?;
            let shown = path.display().to_string();
            Ok(if json {
                ok_json(&json!({ "ok": true, "wallet": shown, "mnemonic": *words }))
            } else {
                ok_text(&render::mnemonic(&words, &shown))
            })
        }
        Command::Fund {
            origin,
            sat,
            issuer,
        } => {
            let w = open(cli, &path).await?;
            let f = w.fund(origin, *sat, issuer.as_deref()).await?;
            Ok(if json {
                ok_json(&json!({ "ok": true, "fund": f }))
            } else {
                ok_text(&render::funded(&f))
            })
        }
        Command::Get(a) => {
            let w = open(cli, &path).await?;
            let r = w.fetch(fetch_request("GET", a)?).await?;
            Ok(fetch_outcome(&r, json))
        }
        Command::Post(a) => {
            let w = open(cli, &path).await?;
            let r = w.fetch(fetch_request("POST", a)?).await?;
            Ok(fetch_outcome(&r, json))
        }
        Command::Budget { action } => {
            let w = open(cli, &path).await?;
            let origin = match action {
                Some(BudgetAction::Set(s)) => {
                    w.set_policy(|p| apply_set(p, s)).await?;
                    None
                }
                Some(BudgetAction::Show { origin }) => origin.clone(),
                None => None,
            };
            let b = w.budget(origin.as_deref()).await?;
            Ok(if json {
                ok_json(&json!({ "ok": true, "budget": b }))
            } else {
                ok_text(&render::budget(&b))
            })
        }
        Command::Receipts { action } => {
            let w = open(cli, &path).await?;
            match action {
                None | Some(ReceiptsAction::List) => {
                    let list: Vec<_> = w
                        .receipts()
                        .await?
                        .iter()
                        .map(caparra_wallet::wallet::ReceiptSummary::from)
                        .collect();
                    Ok(if json {
                        ok_json(&json!({ "ok": true, "receipts": list }))
                    } else {
                        ok_text(&render::receipts(&list))
                    })
                }
                Some(ReceiptsAction::Verify { id }) => {
                    let recs = match id {
                        Some(id) => vec![w.receipt(id).await?],
                        None => w.receipts().await?,
                    };
                    let results: Vec<(String, Result<(), String>)> = recs
                        .iter()
                        .map(|r| (r.id.clone(), verify_receipt(r)))
                        .collect();
                    let bad = results.iter().any(|(_, r)| r.is_err());
                    let mut o = if json {
                        let v: Vec<Value> = results
                            .iter()
                            .map(|(id, r)| json!({ "id": id, "valid": r.is_ok(), "error": r.as_ref().err() }))
                            .collect();
                        ok_json(&json!({ "ok": !bad, "receipts": v }))
                    } else {
                        ok_text(&render::verified(&results))
                    };
                    if bad {
                        o.status = Code::BadReceipt.exit_status();
                    }
                    Ok(o)
                }
            }
        }
        Command::Restore {
            origins,
            issuer,
            slots,
        } => {
            let w = if path.exists() {
                open(cli, &path).await?
            } else {
                let words = match std::env::var("BNAP_MNEMONIC") {
                    Ok(m) => Zeroizing::new(m),
                    Err(_) => Zeroizing::new(
                        rpassword::prompt_password("Mnemonic (12 or 24 words): ").map_err(|e| {
                            Refusal::bad_input(format!(
                                "Cannot read the mnemonic: {e}. Set BNAP_MNEMONIC."
                            ))
                        })?,
                    ),
                };
                let p = passphrase(true)?;
                Wallet::create_from_mnemonic(&path, &p, &words, &options(cli)?).await?
            };
            if origins.is_empty() {
                return Err(Refusal::bad_input(
                    "Name the origins to restore with --origin <https://...>.",
                ));
            }
            let r = w.restore(origins, issuer.as_deref(), slots).await?;
            Ok(if json {
                ok_json(&json!({ "ok": true, "restored": r }))
            } else {
                ok_text(&render::restored(&r))
            })
        }
        Command::Resume => {
            let w = open(cli, &path).await?;
            let r = w.resume().await?;
            Ok(if json {
                ok_json(&json!({ "ok": true, "resumed": r }))
            } else {
                ok_text(&render::resumed(&r))
            })
        }
        Command::Paysource { action } => {
            let w = open(cli, &path).await?;
            match action {
                None | Some(PaySourceAction::Show) => {}
                Some(PaySourceAction::Nwc { uri }) => {
                    let uri = match uri {
                        Some(u) => u.clone(),
                        None => std::env::var("BNAP_NWC_URI").map_err(|_| {
                            Refusal::bad_input("Give the NWC URI, or set BNAP_NWC_URI.")
                        })?,
                    };
                    if !uri.starts_with("nostr+walletconnect://") {
                        return Err(Refusal::bad_input(
                            "An NWC URI starts with nostr+walletconnect://.",
                        ));
                    }
                    w.set_pay_source(PaySourceConfig::Nwc { uri }).await?;
                }
                Some(PaySourceAction::Command { argv }) => {
                    w.set_pay_source(PaySourceConfig::Command { argv: argv.clone() })
                        .await?;
                }
                Some(PaySourceAction::None) => w.set_pay_source(PaySourceConfig::None).await?,
            }
            let d = w.config().await?.pay_source.describe();
            Ok(if json {
                ok_json(&json!({ "ok": true, "pay_source": d }))
            } else {
                ok_text(&format!("pay source: {d}"))
            })
        }
    }
}

/// Writes an outcome and returns the exit status.
#[must_use]
pub fn emit(o: &Outcome) -> u8 {
    let _ = std::io::stdout().write_all(&o.stdout);
    let _ = std::io::stdout().flush();
    if !o.stderr.is_empty() {
        let _ = std::io::stderr().write_all(o.stderr.as_bytes());
    }
    o.status
}
