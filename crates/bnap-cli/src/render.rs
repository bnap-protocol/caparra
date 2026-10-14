//! What the CLI prints: one short actionable line per refusal, a summary
//! per payment, and the same facts as JSON for scripts (`--json`).
//!
//! Server text is never printed: a socket error's `detail` is not part of
//! a [`Refusal`], only its codes are.

use std::fmt::Write as _;

use caparra_wallet::notes_ops::{FundReport, RestoreReport};
use caparra_wallet::wallet::{BudgetView, ReceiptSummary};
use caparra_wallet::{Payment, Refusal, ResumeOutcome};
use serde_json::{Value, json};

/// A refusal for people: `error[CODE]: message`, then the facts a person
/// acts on.
#[must_use]
pub fn refusal(r: &Refusal) -> String {
    let mut s = format!("error[{}]: {}", r.code, r.message);
    if let Some(c) = &r.scheme_code {
        let _ = write!(s, "\n  scheme code: {c}");
    }
    if let (Some(cap), Some(left)) = (r.cap, r.remaining) {
        let _ = write!(s, "\n  {} cap: {left} sat left", cap.as_str());
    }
    if let Some(p) = &r.property {
        let _ = write!(s, "\n  property: {p}");
    }
    if let Some(t) = r.retry_after {
        let _ = write!(s, "\n  retry after: {t} s");
    }
    s
}

/// A refusal for scripts.
#[must_use]
pub fn refusal_json(r: &Refusal) -> Value {
    json!({ "ok": false, "error": r })
}

/// A payment, one line.
#[must_use]
pub fn payment(p: &Payment) -> String {
    let scheme = p.scheme.as_deref().unwrap_or("attestations only");
    let unit = p.unit.as_deref().unwrap_or("sat");
    let outcome = if p.ok {
        "OK"
    } else {
        "FAILED, refunded as the scheme allows"
    };
    let replay = if p.replayed { " (replayed)" } else { "" };
    format!(
        "paid {} sat to {} with {scheme}: charged {} {unit}, action {outcome}{replay}; receipt {}",
        p.cost_sat, p.origin, p.charged, p.receipt
    )
}

/// `bnap budget`.
#[must_use]
pub fn budget(b: &BudgetView) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "caps (sat)        hard  in force  left");
    for (name, hard, eff, left) in [
        (
            "per request",
            b.hard.per_request,
            b.effective.per_request,
            b.remaining.per_request,
        ),
        (
            "per task",
            b.hard.per_task,
            b.effective.per_task,
            b.remaining.per_task,
        ),
        (
            "per origin/24h",
            b.hard.per_origin_day,
            b.effective.per_origin_day,
            b.remaining.per_origin_day,
        ),
        ("daily", b.hard.daily, b.effective.daily, b.remaining.daily),
    ] {
        let _ = writeln!(s, "  {name:<15} {hard:>6} {eff:>9} {left:>5}");
    }
    let p = &b.policy;
    let _ = writeln!(
        s,
        "task: {}; spent in the last 24 h: {} sat",
        b.task, b.spent_24h
    );
    let _ = writeln!(s, "schemes: {}", p.allowed_schemes.join(", "));
    let req: Vec<String> = p.require.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let _ = writeln!(
        s,
        "require: {}",
        if req.is_empty() {
            "nothing".into()
        } else {
            req.join(", ")
        }
    );
    let _ = writeln!(
        s,
        "linkable: {} (penalty {} sat); experimental: {}",
        p.linkable,
        p.linkable_penalty_sat,
        if p.allow_experimental {
            "allowed"
        } else {
            "refused"
        }
    );
    let _ = writeln!(
        s,
        "attestations: {}",
        if p.attest.is_empty() {
            "none".into()
        } else {
            p.attest.join(", ")
        }
    );
    let _ = writeln!(
        s,
        "routing fee ceiling: {} sat + {} ppm; notes per origin at most {} sat",
        p.fee.base_sat, p.fee.ppm, p.max_balance_per_origin
    );
    let _ = writeln!(s, "pay source: {}", p.pay_source);
    if b.balances.is_empty() {
        s.push_str("notes: none");
    } else {
        s.push_str("notes:");
        for (o, v) in &b.balances {
            let _ = write!(s, "\n  {o}: {v} sat");
        }
    }
    s
}

/// `bnap receipts`.
#[must_use]
pub fn receipts(list: &[ReceiptSummary]) -> String {
    if list.is_empty() {
        return "no receipts".into();
    }
    list.iter()
        .map(|r| {
            format!(
                "{}  {}  {} sat  {}  {}",
                r.id,
                r.scheme.as_deref().unwrap_or("-"),
                r.cost_sat,
                if r.ok { "OK" } else { "FAILED" },
                r.request
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `bnap receipts verify`.
#[must_use]
pub fn verified(results: &[(String, Result<(), String>)]) -> String {
    if results.is_empty() {
        return "no receipts".into();
    }
    results
        .iter()
        .map(|(id, r)| match r {
            Ok(()) => format!("{id}  valid"),
            Err(e) => format!("{id}  INVALID: {e}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `bnap fund`.
#[must_use]
pub fn funded(f: &FundReport) -> String {
    format!(
        "bought {} sat of notes at {} (routing fee {} sat); {} sat held there now",
        f.amount, f.origin, f.fee_sat, f.balance
    )
}

/// `bnap restore`.
#[must_use]
pub fn restored(r: &[RestoreReport]) -> String {
    r.iter()
        .map(|x| {
            format!(
                "{}: restored {} notes worth {} sat ({} spent ones skipped)",
                x.origin, x.notes, x.restored_sat, x.spent
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `bnap resume`.
#[must_use]
pub fn resumed(r: &[ResumeOutcome]) -> String {
    if r.is_empty() {
        return "nothing to resume".into();
    }
    r.iter()
        .map(|o| match &o.result {
            Ok(Some(p)) => format!("{}: {}", o.id, payment(p)),
            Ok(None) => format!("{}: done", o.id),
            Err(e) => format!("{}: {}", o.id, refusal(e)),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The mnemonic, shown once by `bnap init`.
#[must_use]
pub fn mnemonic(words: &str, path: &str) -> String {
    format!(
        "Created a wallet at {path}.\n\nWrite these 12 words down and keep them offline. They are shown once,\nnever stored outside the encrypted wallet, and they restore every note:\n\n    {words}\n\nNext: set a pay source (`bnap paysource nwc <uri>`), review the caps\n(`bnap budget`), and opt in to experimental schemes if you accept them\n(`bnap budget set --allow-experimental true`)."
    )
}
