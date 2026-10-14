//! Notes outside a paid request: buying credit (NUT-23 quote, NUT-04
//! mint), minting a paid quote that a credential did not use, and restoring
//! notes from the seed (NUT-09 restore, NUT-07 state check; bnap:notes 8
//! and 12).

use std::collections::BTreeMap;

use bnap_core::hash::sha256;
use bnap_core::offer::{ClientOfferCheck, Offer};
use bnap_scheme_notes::client::{self as notes, PendingOutput};
use bnap_scheme_notes::wire::Params;
use cashu::nuts::{BlindedMessage, Id, PublicKey, State};
use serde::Serialize;

use crate::error::{Code, Refusal, Result};
use crate::invoice::Invoice;
use crate::issuer::Issuer;
use crate::policy::{self, Caps};
use crate::records::{
    CounterRecord, NoteRecord, NoteState, QuoteRecord, QuoteState, SiteRecord, kind,
};
use crate::transport::HttpRequest;
use crate::wallet::{Wallet, random_id, random32};

/// The manifest route id of the notes swap route (bnap:notes 11), where
/// the wallet learns an origin's issuer.
pub const SWAP_ROUTE: &str = "notes-swap";
/// Counter values per restore batch (bnap:notes 12.2).
pub const RESTORE_BATCH: u64 = 100;
/// Empty batches that end a restore scan.
pub const RESTORE_EMPTY: u32 = 3;

/// What `bnap fund` did.
#[derive(Debug, Clone, Serialize)]
pub struct FundReport {
    /// The origin.
    pub origin: String,
    /// The issuer.
    pub issuer: String,
    /// Sat bought.
    pub amount: u64,
    /// Routing fee paid.
    pub fee_sat: u64,
    /// The quote.
    pub quote: String,
    /// Notes held at the origin now.
    pub balance: u64,
}

/// What `bnap restore` found at one origin.
#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    /// The origin.
    pub origin: String,
    /// The issuer.
    pub issuer: String,
    /// Notes found unspent.
    pub notes: usize,
    /// Their value.
    pub restored_sat: u64,
    /// Notes the issuer reports spent.
    pub spent: usize,
}

fn https_origin(origin: &str) -> Result<String> {
    let u =
        url::Url::parse(origin).map_err(|e| Refusal::bad_input(format!("Not an origin: {e}.")))?;
    if u.scheme() != "https" {
        return Err(Refusal::bad_input("Origins must be https://."));
    }
    Ok(u.origin().ascii_serialization())
}

impl Wallet {
    /// Writes a ledger entry for `cost` inside `tx`, after checking every
    /// cap against the ledger as `tx` sees it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reserve_entry(
        &self,
        tx: &mut crate::store::Tx,
        caps: &Caps,
        origin: &str,
        id: &str,
        cost: u64,
        what: &str,
    ) -> Result<()> {
        let ledger: Vec<policy::LedgerEntry> = tx.list(kind::LEDGER).await?;
        let now = self.now();
        policy::check(caps, &ledger, origin, &self.task, cost, now)?;
        tx.put(
            kind::LEDGER,
            id,
            &policy::LedgerEntry {
                id: id.to_owned(),
                origin: origin.to_owned(),
                task: self.task.clone(),
                at: now,
                reserved: cost,
                actual: None,
                what: what.to_owned(),
            },
        )
        .await
    }

    /// The issuer of `origin`: given, recorded for the site, or read from
    /// the offer of the manifest's `notes-swap` route.
    pub async fn discover_issuer(&self, origin: &str, given: Option<&str>) -> Result<String> {
        if let Some(g) = given {
            Issuer::new(g, origin, &*self.transport)?;
            return Ok(g.to_owned());
        }
        if let Some(s) = self.store.get::<SiteRecord>(kind::SITE, origin).await? {
            return Ok(s.issuer);
        }
        let none = || {
            Refusal::new(
                Code::Issuer,
                format!(
                    "Could not find the notes issuer of {origin}. Pass it with --issuer <url>."
                ),
            )
        };
        let pin = self.ensure_pin(origin, false).await?.ok_or_else(|| {
            Refusal::new(
                Code::Manifest,
                format!("Could not fetch a valid manifest from {origin}/.well-known/bnap."),
            )
        })?;
        let m = pin.manifest().ok_or_else(none)?;
        let route = m
            .manifest()
            .routes
            .iter()
            .find(|r| r.id == SWAP_ROUTE)
            .ok_or_else(none)?;
        let (method, path) = route.match_.split_once(' ').ok_or_else(none)?;
        if path.ends_with('*') {
            return Err(none());
        }
        let resp = self
            .transport
            .send(HttpRequest::new(method, format!("{origin}{path}")))
            .await
            .map_err(Refusal::network)?;
        let ch = crate::pay::Challenges::parse(&resp);
        let now = self.now();
        let scope = bnap_core::http::route_scope(origin, &route.id);
        for b in &ch.offers {
            let Ok(o) = Offer::parse(b) else { continue };
            let action = bnap_core::http::action_scope(
                method,
                &bnap_core::http::target(origin, path),
                &[],
                &[],
            );
            if o.check_client(&ClientOfferCheck {
                now,
                origin,
                pinned_keys: Some(&pin.keys),
                action_scope: action,
                route_scope: Some(scope),
            })
            .is_err()
            {
                continue;
            }
            for e in &o.fields().pay {
                if e.scheme != bnap_scheme_notes::SCHEME_ID {
                    continue;
                }
                if let Some(p) = e.params.as_deref().and_then(|b| Params::parse(b).ok()) {
                    Issuer::new(&p.issuer, origin, &*self.transport)?;
                    return Ok(p.issuer);
                }
            }
        }
        Err(none())
    }

    async fn active_keyset(&self, origin: &str, issuer: &str) -> Result<[u8; 33]> {
        let iss = Issuer::new(issuer, origin, &*self.transport)?;
        let now = self.now();
        let infos = iss.keysets().await?;
        let k = infos
            .iter()
            .filter(|k| {
                k.active
                    && k.unit == cashu::nuts::CurrencyUnit::Sat
                    && k.final_expiry.is_some_and(|f| f > now + 86_400)
            })
            .map(|k| k.id.to_bytes())
            .find_map(|b| <[u8; 33]>::try_from(b).ok())
            .ok_or_else(|| Refusal::new(Code::Issuer, "The issuer has no active sat keyset."))?;
        Ok(k)
    }

    /// Buys `amount` sat of notes at `origin` (NUT-23 quote locked to a
    /// fresh NUT-20 key, paid through the pay source, minted with NUT-04).
    /// The routing fee counts against the caps; the notes count when they
    /// are spent. The balance held at one origin stays under the policy's
    /// limit.
    pub async fn fund(
        &self,
        origin: &str,
        amount: u64,
        issuer: Option<&str>,
    ) -> Result<FundReport> {
        let origin = https_origin(origin)?;
        let cfg = self.config().await?;
        if amount == 0 {
            return Err(Refusal::bad_input("Fund at least 1 sat."));
        }
        let held = self.balances().await?.get(&origin).copied().unwrap_or(0);
        let max = cfg.policy.max_balance_per_origin;
        if held.saturating_add(amount) > max {
            return Err(Refusal::new(
                Code::Policy,
                format!(
                    "Policy: {origin} would hold {} sat of notes, above the {max} sat per origin. Fund at most {} sat, or raise it with `bnap budget set --max-balance`.",
                    held.saturating_add(amount),
                    max.saturating_sub(held)
                ),
            ));
        }
        let pay = self.pay_source(&cfg).ok_or_else(|| {
            Refusal::new(
                Code::NoPaySource,
                "No pay source is configured. A person can set one with `bnap paysource nwc <uri>`.",
            )
        })?;
        let issuer = self.discover_issuer(&origin, issuer).await?;
        let iss = Issuer::new(&issuer, &origin, &*self.transport)?;
        let key = random32();
        let pubkey = notes::quote_pubkey(&key).map_err(|e| Refusal::storage(e.to_string()))?;
        let q = iss.quote(amount, &pubkey).await?;
        let inv = Invoice::decode(&q.request)
            .map_err(|e| Refusal::new(Code::BadInvoice, format!("The quote's invoice: {e}.")))?;
        let now = self.now();
        let key_ok = q.pubkey.is_some_and(|p| p.to_bytes() == pubkey);
        if q.amount.map(u64::from) != Some(amount)
            || inv.amount_sat() != Some(amount)
            || !key_ok
            || inv.expires_at <= now
        {
            return Err(Refusal::new(
                Code::BadInvoice,
                "The quote does not match what was asked for. Nothing was paid.",
            ));
        }
        let max_fee = cfg.policy.fee.max_fee(amount);
        let id = random_id();
        let caps = self.caps(&cfg);
        let mut tx = self.store.tx().await?;
        self.reserve_entry(
            &mut tx,
            &caps,
            &origin,
            &id,
            max_fee,
            &format!("fund {origin} (routing fee)"),
        )
        .await?;
        let mut rec = QuoteRecord {
            id: q.quote.clone(),
            origin: origin.clone(),
            issuer: issuer.clone(),
            key,
            amount,
            invoice: q.request.clone(),
            payment_hash: inv.payment_hash,
            offer: None,
            state: QuoteState::Unpaid,
            fee_sat: 0,
            ledger: Some(id.clone()),
        };
        tx.put(kind::QUOTE, &q.quote, &rec).await?;
        tx.commit().await?;
        let paid = match pay.pay_invoice(&q.request, amount, max_fee).await {
            Ok(p) if sha256(&p.preimage) == inv.payment_hash => p,
            Ok(_) => {
                self.true_up(&id, Some(amount + max_fee)).await?;
                return Err(Refusal::new(
                    Code::PaymentFailed,
                    "The pay source returned a preimage that does not open the invoice.",
                ));
            }
            Err(e) => {
                // The payment may still settle: the fee stays reserved and
                // `resume` mints the quote if it does.
                return Err(e);
            }
        };
        rec.state = QuoteState::Paid;
        rec.fee_sat = paid.fee_sat;
        self.store.put(kind::QUOTE, &q.quote, &rec).await?;
        // The amount counts until the mint returns notes; `mint_quote`
        // takes it off then.
        self.true_up(&id, Some(rec.amount + rec.fee_sat)).await?;
        self.mint_quote(&q.quote).await?;
        let balance = self.balances().await?.get(&origin).copied().unwrap_or(0);
        Ok(FundReport {
            origin,
            issuer,
            amount,
            fee_sat: rec.fee_sat,
            quote: q.quote.clone(),
            balance,
        })
    }

    /// Mints a paid quote into notes (NUT-04). Returns the sat minted;
    /// 0 when the quote is not paid or was used already.
    pub async fn mint_quote(&self, quote: &str) -> Result<u64> {
        let Some(mut q) = self.store.get::<QuoteRecord>(kind::QUOTE, quote).await? else {
            return Ok(0);
        };
        // An unpaid quote may have been paid late (a pay source error is
        // not proof that nothing settled): the issuer decides.
        if !matches!(q.state, QuoteState::Paid | QuoteState::Unpaid) {
            return Ok(0);
        }
        let cfg = self.config().await?;
        let ks_id = self.active_keyset(&q.origin, &q.issuer).await?;
        let ks = self.keyset_keys(&q.origin, &q.issuer, &ks_id).await?;
        let seed = self.seed().await?;
        let mut tx = self.store.tx().await?;
        // NUT-04: outputs that add up to the quote, one per bit.
        let amounts: Vec<u64> = (0..64)
            .map(|b| 1u64 << b)
            .filter(|v| q.amount & v != 0)
            .collect();
        let outputs = self
            .take_outputs(&mut tx, &seed, cfg.slot, &ks_id, &amounts)
            .await?;
        self.record_site(&mut tx, &q.origin, &q.issuer, &ks_id, cfg.slot)
            .await?;
        tx.commit().await?;
        let outs: Vec<_> = outputs.iter().map(|p| p.output).collect();
        let req = notes::mint_request(&q.id, &outs, &q.key)
            .map_err(|e| Refusal::storage(format!("cannot sign the mint request: {e}")))?;
        let resp = Issuer::new(&q.issuer, &q.origin, &*self.transport)?
            .mint(&req)
            .await?;
        let table: notes::KeyTable = [(ks_id, ks.points())].into_iter().collect();
        let got = notes::unblind_mint(&outputs, &resp.signatures, notes::key_lookup(&table))
            .map_err(|e| {
                Refusal::new(
                    Code::BadChange,
                    format!("The issuer's signatures fail their checks: {e}."),
                )
            })?;
        let mut tx = self.store.tx().await?;
        for n in &got {
            let r = NoteRecord::from_note(n, &q.origin, &q.issuer).map_err(Refusal::storage)?;
            tx.put(kind::NOTE, &hex::encode(r.k), &r).await?;
        }
        q.state = QuoteState::Minted;
        tx.put(kind::QUOTE, &q.id, &q).await?;
        // The quote's value is back as notes: the ledger keeps its fee.
        if let Some(l) = &q.ledger
            && let Some(mut e) = tx
                .get::<crate::policy::LedgerEntry>(kind::LEDGER, l)
                .await?
        {
            e.actual = Some(e.counted().saturating_sub(q.amount));
            tx.put(kind::LEDGER, l, &e).await?;
        }
        tx.commit().await?;
        Ok(got.iter().map(|n| n.amount).sum())
    }

    /// The canonical change ladder for `value` on `keyset` (bnap:notes
    /// 6.3), from this slot's next counter on; the counter advance is
    /// written in `tx`.
    pub(crate) async fn take_ladder(
        &self,
        tx: &mut crate::store::Tx,
        seed: &[u8; 64],
        slot: u16,
        keyset: &[u8; 33],
        value: u64,
    ) -> Result<Vec<PendingOutput>> {
        let amounts = bnap_scheme_notes::amount::canonical_ladder(value);
        self.take_outputs(tx, seed, slot, keyset, &amounts).await
    }

    /// Outputs of these amounts on `keyset`, from this slot's next counter
    /// on; the counter advance is written in `tx` before any is sent.
    pub(crate) async fn take_outputs(
        &self,
        tx: &mut crate::store::Tx,
        seed: &[u8; 64],
        slot: u16,
        keyset: &[u8; 33],
        amounts: &[u64],
    ) -> Result<Vec<PendingOutput>> {
        let name = format!("{}/{slot}", hex::encode(keyset));
        let next = tx
            .get::<CounterRecord>(kind::COUNTER, &name)
            .await?
            .map_or(0, |c| c.next);
        let start =
            notes::counter(slot, next).ok_or_else(|| Refusal::storage("counter overflow"))?;
        let (outs, end) = notes::derive_outputs(seed, keyset, amounts, start);
        let base = u64::from(slot) << notes::SLOT_SHIFT;
        tx.put(kind::COUNTER, &name, &CounterRecord { next: end - base })
            .await?;
        Ok(outs)
    }

    /// Records the site, its issuer, keyset and slot (the backup list).
    pub(crate) async fn record_site(
        &self,
        tx: &mut crate::store::Tx,
        origin: &str,
        issuer: &str,
        keyset: &[u8; 33],
        slot: u16,
    ) -> Result<()> {
        let mut s: SiteRecord = tx.get(kind::SITE, origin).await?.unwrap_or_default();
        s.origin = origin.to_owned();
        s.issuer = issuer.to_owned();
        let k = hex::encode(keyset);
        if !s.keysets.contains(&k) {
            s.keysets.push(k);
        }
        if !s.slots.contains(&slot) {
            s.slots.push(slot);
        }
        tx.put(kind::SITE, origin, &s).await
    }

    /// Restores the notes of `origins` from the seed: for every sat keyset
    /// the issuer lists, regenerates outputs in batches of 100 counter
    /// values, asks the issuer to restore them (NUT-09), and stops after
    /// three empty batches past the highest counter recorded; then keeps
    /// the notes NUT-07 reports unspent. Slots scanned: the recorded
    /// ones, this device's, 0 and `extra_slots`. Counters move past everything
    /// scanned, so no restored output is ever sent again.
    #[allow(clippy::too_many_lines)]
    pub async fn restore(
        &self,
        origins: &[String],
        issuer: Option<&str>,
        extra_slots: &[u16],
    ) -> Result<Vec<RestoreReport>> {
        let cfg = self.config().await?;
        let seed = self.seed().await?;
        let mut out = Vec::new();
        for origin in origins {
            let origin = https_origin(origin)?;
            let issuer = self.discover_issuer(&origin, issuer).await?;
            let iss = Issuer::new(&issuer, &origin, &*self.transport)?;
            let now = self.now();
            let site: SiteRecord = self
                .store
                .get(kind::SITE, &origin)
                .await?
                .unwrap_or_default();
            let mut slots: Vec<u16> = site.slots.clone();
            // Slots the backup list names, this device's, slot 0, and every
            // slot the person names (a seed restored without its backup
            // does not know the others).
            for &s in [cfg.slot, 0].iter().chain(extra_slots) {
                if !slots.contains(&s) {
                    slots.push(s);
                }
            }
            let infos = iss.keysets().await?;
            let mut found: BTreeMap<[u8; 32], NoteRecord> = BTreeMap::new();
            for info in infos.iter().filter(|k| {
                k.unit == cashu::nuts::CurrencyUnit::Sat
                    && k.final_expiry.is_some_and(|f| f + 60 >= now)
            }) {
                let Ok(ks_id) = <[u8; 33]>::try_from(info.id.to_bytes()) else {
                    continue;
                };
                let ks = self.keyset_keys(&origin, &issuer, &ks_id).await?;
                let table: notes::KeyTable = [(ks_id, ks.points())].into_iter().collect();
                for &slot in &slots {
                    let name = format!("{}/{slot}", hex::encode(ks_id));
                    let recorded = self
                        .store
                        .get::<CounterRecord>(kind::COUNTER, &name)
                        .await?
                        .map_or(0, |c| c.next);
                    let mut idx = 0u64;
                    let mut empty = 0u32;
                    while empty < RESTORE_EMPTY || idx < recorded {
                        let mut derived = Vec::new();
                        for i in idx..idx + RESTORE_BATCH {
                            if let Some(c) = notes::counter(slot, i)
                                && let Some(d) = notes::derive(&*seed, &ks_id, c)
                            {
                                derived.push(d);
                            }
                        }
                        idx += RESTORE_BATCH;
                        let msgs = derived
                            .iter()
                            .map(|d| {
                                Ok(BlindedMessage {
                                    amount: 0.into(),
                                    keyset_id: Id::from_bytes(&ks_id)
                                        .map_err(|e| Refusal::storage(e.to_string()))?,
                                    blinded_secret: PublicKey::from_slice(&d.blinded)
                                        .map_err(|e| Refusal::storage(e.to_string()))?,
                                    witness: None,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let r = iss.restore(msgs).await?;
                        let mut pending = Vec::new();
                        let mut sigs = Vec::new();
                        for (o, s) in r.outputs.iter().zip(&r.signatures) {
                            let b = o.blinded_secret.to_bytes();
                            if let Some(d) = derived.iter().find(|d| d.blinded == b) {
                                pending.push(PendingOutput {
                                    output: bnap_scheme_notes::Output {
                                        keyset: ks_id,
                                        amount: u64::from(s.amount),
                                        blinded: d.blinded,
                                    },
                                    derived: d.clone(),
                                });
                                sigs.push(s.clone());
                            }
                        }
                        if pending.is_empty() {
                            empty += 1;
                            continue;
                        }
                        empty = 0;
                        let got = notes::unblind_mint(&pending, &sigs, notes::key_lookup(&table))
                            .map_err(|e| {
                            Refusal::new(
                                Code::BadChange,
                                format!("The issuer's restored signatures fail their checks: {e}."),
                            )
                        })?;
                        for n in &got {
                            let r = NoteRecord::from_note(n, &origin, &issuer)
                                .map_err(Refusal::storage)?;
                            found.insert(r.k, r);
                        }
                    }
                    let mut tx = self.store.tx().await?;
                    let cur = tx
                        .get::<CounterRecord>(kind::COUNTER, &name)
                        .await?
                        .map_or(0, |c| c.next);
                    tx.put(kind::COUNTER, &name, &CounterRecord { next: cur.max(idx) })
                        .await?;
                    tx.commit().await?;
                }
            }
            // NUT-07: keep what is unspent.
            let ys: Vec<PublicKey> = found
                .values()
                .filter_map(|n| PublicKey::from_slice(&n.note().y().ok()?).ok())
                .collect();
            let states = if ys.is_empty() {
                Vec::new()
            } else {
                iss.check_state(ys).await?.states
            };
            let mut report = RestoreReport {
                origin: origin.clone(),
                issuer: issuer.clone(),
                notes: 0,
                restored_sat: 0,
                spent: 0,
            };
            let mut tx = self.store.tx().await?;
            for n in found.values() {
                let Ok(y) = n.note().y() else { continue };
                let state = states.iter().find(|s| s.y.to_bytes() == y).map(|s| s.state);
                if state != Some(State::Unspent) {
                    report.spent += 1;
                    continue;
                }
                let name = hex::encode(n.k);
                let have = tx.get::<NoteRecord>(kind::NOTE, &name).await?;
                if have.as_ref().is_some_and(|h| h.state != NoteState::Unspent) {
                    // The wallet knows it spent or locked this note.
                    continue;
                }
                tx.put(kind::NOTE, &name, n).await?;
                report.notes += 1;
                report.restored_sat += n.amount;
            }
            let mut s = site.clone();
            s.origin.clone_from(&origin);
            s.issuer.clone_from(&issuer);
            for k in &infos {
                let h = hex::encode(k.id.to_bytes());
                if !s.keysets.contains(&h) {
                    s.keysets.push(h);
                }
            }
            for sl in slots {
                if !s.slots.contains(&sl) {
                    s.slots.push(sl);
                }
            }
            tx.put(kind::SITE, &origin, &s).await?;
            tx.commit().await?;
            out.push(report);
        }
        Ok(out)
    }
}
