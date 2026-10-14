//! The `bnap` command: a BNAP wallet on the command line.
//!
//! `bnap init` makes a wallet (the mnemonic is shown once), `bnap fund`
//! buys notes, `bnap get` and `bnap post` pay for requests within the
//! caps, `bnap budget` shows and sets them, `bnap receipts` lists and
//! verifies what was paid, `bnap restore` recovers notes from the seed and
//! `bnap resume` finishes requests that got no answer. Every refusal is
//! one short line with its code; `--json` prints the same facts for
//! scripts.

// `Refusal` is the wallet's one error; see caparra-wallet.
#![allow(clippy::result_large_err)]

pub mod cli;
pub mod render;
