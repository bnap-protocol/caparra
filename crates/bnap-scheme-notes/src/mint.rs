//! NUT-04 minting of a paid fund quote (8.5).
//!
//! ```text
//! rk_mint = H_"bnap:notes/mint"( lp(quote ID) ‖ BigSize(k) ‖ lp(output₁) ‖ … ‖ lp(outputₖ) )
//! ```
//!
//! Draft-00 6.1 requires a scheme that mints credit from a payment to have
//! the gate commit that payment's `RailId` when it mints, in the use store
//! the socket commits to. bnap-core seals every write to that store, so the
//! mint runs through `outcome::process` like a credential: a price-0
//! request whose Context is `rk_mint` and whose one rail payment is the
//! quote's, for an `atomic` value of the quote's amount. That gives the
//! three outcomes 8.5 asks for in one serializable transaction:
//!
//! - the same quote and outputs again (a retry) find their own outcome and
//!   get the same signatures back, from the recorded `scheme_result`;
//! - a quote whose `RailId` a credential or another mint committed is SPENT,
//!   reported as issued;
//! - otherwise the `RailId` is committed and the outputs are signed through
//!   a `CappedSigner` whose change cap is the quote's amount, reserved in
//!   the outcome's change ledger, so a mint can never sign more than its
//!   quote paid for.
//!
//! Where this differs from the pseudo-code of 8.5 (an outcome record and a
//! PENDING state exist; a retry after the record window is SPENT) is noted
//! as ERRATA candidate N6-3.

use std::sync::Arc;

use bnap_core::encoding::{lp, write_bigsize, write_lp};
use bnap_core::hash::{Context, Scope, tagged_hash};
use bnap_core::limits::Limits;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ProcessError, Recorded, Request, SettleError};
use bnap_core::pricing::{PayValue, Refund, backed_value};
use bnap_core::response::Status;
use bnap_core::schnorr::Key;
use bnap_core::store::{Settlement, UseStore};
use bnap_plug::ChangeCap;
use bnap_plug::{CappedSigner, RailRef, Signer, confirm_rail_id};
use cashu::nuts::{BlindSignature as CashuBlindSignature, BlindSignatureDleq, Id, MintRequest};
use cashu::{Amount, PublicKey as CashuPublicKey, SecretKey as CashuSecretKey};

use crate::SCHEME_ID;
use crate::issuer::find_keyset;
use crate::keyset::{KeysetState, UNIT};
use crate::scheme::{BOLT11, NotesScheme};
use crate::wire::{Output, SignatureEntry, encode_scheme_result, parse_scheme_result};

/// The tag of `rk_mint` (2.3), the scheme's one tagged hash.
pub const MINT_TAG: &str = "bnap:notes/mint";

/// How long the mint's internal offer lives: it only bounds the commit.
const MINT_OFFER_LIFETIME: u64 = 300;

/// `rk_mint` of a quote and its outputs (8.5): every output is the output
/// entry of 3.3 built from the request's blinded message, in request order.
#[must_use]
pub fn rk_mint(quote: &str, outputs: &[Output]) -> [u8; 32] {
    let mut m = lp(quote.as_bytes());
    write_bigsize(&mut m, outputs.len() as u64);
    for o in outputs {
        write_lp(&mut m, &o.entry_bytes());
    }
    tagged_hash(MINT_TAG, &m)
}

/// What a mint needs from the gate: the use store the socket commits to,
/// the operator's signer, the gate's limits and clock.
#[derive(Clone)]
pub struct MintEnv<'a> {
    /// The gate's use store.
    pub store: Arc<dyn UseStore>,
    /// The operator's signer.
    pub signer: Arc<dyn Signer>,
    /// The gate's limits.
    pub limits: &'a Limits,
    /// The gate's clock.
    pub now: u64,
}

/// Why a mint did not sign (NUT-04 errors).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// No such quote.
    #[error("unknown quote")]
    UnknownQuote,
    /// Not a BOLT11 `sat` quote with a NUT-20 key (P24).
    #[error("not a BNAP quote")]
    NotBnapQuote,
    /// The NUT-20 signature is missing or does not verify.
    #[error("bad NUT-20 signature")]
    BadSignature,
    /// The outputs are not powers of two on active BNAP keysets adding up
    /// to the quote amount, or repeat a `B'`.
    #[error("bad outputs: {0}")]
    BadOutputs(String),
    /// An output was signed before under another source (NUT-04).
    #[error("an output was signed before")]
    OutputSigned,
    /// The rail does not confirm the quote's payment in full.
    #[error("quote not paid")]
    Unpaid,
    /// The quote's `RailId` was committed by a credential or another mint.
    #[error("quote already issued")]
    Issued,
    /// The same mint is still in flight.
    #[error("mint in flight, retry in {retry_after} s")]
    Pending {
        /// Seconds to wait.
        retry_after: u64,
    },
    /// A store, rail or signer cannot be reached; nothing is answered.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

fn down(e: impl std::fmt::Display) -> MintError {
    MintError::Unavailable(e.to_string())
}

/// The mint request's outputs as output entries; a version-00 keyset ID is
/// refused, BNAP uses full IDs only (4.2).
fn outputs_of(req: &MintRequest<String>) -> Result<Vec<Output>, MintError> {
    req.outputs
        .iter()
        .map(|b| {
            let keyset: [u8; 33] = b
                .keyset_id
                .to_bytes()
                .try_into()
                .map_err(|_| MintError::BadOutputs("not a full keyset ID".into()))?;
            Ok(Output {
                keyset,
                amount: u64::from(b.amount),
                blinded: b.blinded_secret.to_bytes(),
            })
        })
        .collect()
}

fn to_cashu(
    outputs: &[Output],
    entries: &[SignatureEntry],
) -> Result<Vec<CashuBlindSignature>, MintError> {
    entries
        .iter()
        .map(|e| {
            let o = usize::try_from(e.index)
                .ok()
                .and_then(|i| outputs.get(i))
                .ok_or_else(|| down("a recorded signature names no output"))?;
            Ok(CashuBlindSignature {
                amount: Amount::from(o.amount),
                keyset_id: Id::from_bytes(&o.keyset).map_err(down)?,
                c: CashuPublicKey::from_slice(&e.c).map_err(down)?,
                dleq: Some(BlindSignatureDleq {
                    e: CashuSecretKey::from_slice(&e.e).map_err(down)?,
                    s: CashuSecretKey::from_slice(&e.s).map_err(down)?,
                }),
            })
        })
        .collect()
}

impl NotesScheme {
    /// Mints a paid quote (8.5): checks the quote, its NUT-20 signature and
    /// the outputs, confirms the payment through the rail, then commits the
    /// quote's `RailId` and signs the outputs as described in the module
    /// docs. Returns the blind signatures in output order.
    pub async fn mint(
        &self,
        env: &MintEnv<'_>,
        req: &MintRequest<String>,
    ) -> Result<Vec<CashuBlindSignature>, MintError> {
        let q = self
            .issuer()
            .quote(&req.quote)
            .await
            .map_err(down)?
            .ok_or(MintError::UnknownQuote)?;
        let pubkey = q
            .pubkey
            .filter(|_| q.method == BOLT11 && q.unit == UNIT)
            .ok_or(MintError::NotBnapQuote)?;
        let pubkey = CashuPublicKey::from_slice(&pubkey).map_err(|_| MintError::NotBnapQuote)?;
        req.verify_signature(pubkey)
            .map_err(|_| MintError::BadSignature)?;
        let outputs = outputs_of(req)?;
        self.check_mint_outputs(&outputs, q.amount, env.now).await?;
        let rk = rk_mint(&q.id, &outputs);
        let blinded: Vec<_> = outputs.iter().map(|o| o.blinded).collect();
        let earlier = self
            .issuer()
            .outputs_by_blinded(&blinded)
            .await
            .map_err(down)?;
        if earlier.iter().any(|r| r.source != rk) {
            return Err(MintError::OutputSigned);
        }
        let rail = self.rail().ok_or_else(|| down("no funding rail"))?.clone();
        let reference = RailRef {
            kind: bnap_core::ids::rail::LN.into(),
            reference: q.payment_hash.to_vec(),
        };
        let payment = match confirm_rail_id(&*rail, &reference).await {
            Ok(p) => p,
            Err(bnap_plug::RailError::Unavailable(m)) => return Err(MintError::Unavailable(m)),
            Err(_) => return Err(MintError::Unpaid),
        };
        // Rails report in their own unit (the Lightning rails in msat):
        // compare the value in the quote's unit, rounded down.
        let paid = backed_value(UNIT, &[payment.backing()]).map_or(0, |(v, _)| v);
        if paid < q.amount {
            return Err(MintError::Unpaid);
        }
        let _ = self.issuer().mark_quote(&q.id, true, false).await;

        let mut offer = OfferFields::new(
            Scope(rk),
            env.now.saturating_add(MINT_OFFER_LIFETIME),
            Key([0; 32]),
            [0; 16],
        );
        offer.pay = vec![PayEntry::new(SCHEME_ID, 0, UNIT)];
        let rail_ids = [payment.rail_id];
        let admitted = outcome::process(
            &*env.store,
            &Request {
                offer: &offer,
                context: &Context(rk),
                pay_body: &[],
                attest_bodies: &[],
                schemes: &[],
                rail_ids: &rail_ids,
                pay: Some(PayValue {
                    scheme: SCHEME_ID,
                    claimed: q.amount,
                    backing: vec![payment.backing()],
                    refund: Refund::Atomic,
                }),
                attest: &[],
                now: env.now,
            },
            env.limits,
        )
        .await;
        let entries = match admitted {
            Ok(Admitted::New(pending)) => {
                let charge = pending.charge(Status::Ok, 0);
                let entries = self.sign_all(env, charge.cap(), &outputs, rk).await?;
                let s = Settlement::new(&charge, env.now)
                    .with_scheme_result(encode_scheme_result(&entries));
                match outcome::settle(&*env.store, &pending, &s, env.limits).await {
                    Ok(_) => entries,
                    Err(SettleError::AlreadySettled(rec)) => {
                        self.answer(env, &rec, &outputs, rk).await?
                    }
                    Err(e) => return Err(down(e)),
                }
            }
            Ok(Admitted::Replay(rec)) => self.answer(env, &rec, &outputs, rk).await?,
            Err(ProcessError::Spent) => {
                let _ = self.issuer().mark_quote(&q.id, true, true).await;
                return Err(MintError::Issued);
            }
            Err(ProcessError::Pending { retry_after }) => {
                return Err(MintError::Pending { retry_after });
            }
            Err(e) => return Err(down(e)),
        };
        let _ = self.issuer().mark_quote(&q.id, true, true).await;
        to_cashu(&outputs, &entries)
    }

    /// NUT-04's output rules for BNAP keysets (8.5): at least one output,
    /// each a power of two with a key on an active, unrevoked `sat` keyset,
    /// no `B'` twice, adding up to the quote amount.
    async fn check_mint_outputs(
        &self,
        outputs: &[Output],
        amount: u64,
        now: u64,
    ) -> Result<(), MintError> {
        if outputs.is_empty() {
            return Err(MintError::BadOutputs("no outputs".into()));
        }
        let table = self.issuer().keysets().await.map_err(down)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0u64;
        for o in outputs {
            let ok = find_keyset(&table, &o.keyset).is_some_and(|k| {
                k.state == KeysetState::Active
                    && k.unit == UNIT
                    && !k.expired(now)
                    && o.amount.is_power_of_two()
                    && k.key(o.amount).is_some()
            });
            if !ok {
                return Err(MintError::BadOutputs(
                    "an output is not on an active BNAP keyset".into(),
                ));
            }
            if !seen.insert(o.blinded) {
                return Err(MintError::BadOutputs("a blinded point is repeated".into()));
            }
            total = total
                .checked_add(o.amount)
                .ok_or_else(|| MintError::BadOutputs("overflow".into()))?;
        }
        if total != amount {
            return Err(MintError::BadOutputs(format!(
                "outputs add up to {total}, the quote to {amount}"
            )));
        }
        Ok(())
    }

    /// Signs every output under `cap`, through a change budget closed as
    /// soon as signing returns.
    async fn sign_all(
        &self,
        env: &MintEnv<'_>,
        cap: &ChangeCap,
        outputs: &[Output],
        rk: [u8; 32],
    ) -> Result<Vec<SignatureEntry>, MintError> {
        let (capped, guard) = CappedSigner::for_change(env.signer.clone(), env.store.clone(), cap);
        let all: Vec<usize> = (0..outputs.len()).collect();
        let r = self.sign_outputs(&capped, outputs, &all, rk).await;
        guard.close();
        r.map_err(down)
    }

    /// The signatures of a recorded mint: the stored ones, or, for a mint
    /// that timed out before it was settled, the refund signed now under
    /// the cap its commit recorded (the same outputs) and recorded once.
    async fn answer(
        &self,
        env: &MintEnv<'_>,
        rec: &Recorded,
        outputs: &[Output],
        rk: [u8; 32],
    ) -> Result<Vec<SignatureEntry>, MintError> {
        let rec = if rec.needs_refund() {
            let cap = rec.refund_cap().ok_or_else(|| down("no refund cap"))?;
            let entries = self.sign_all(env, &cap, outputs, rk).await?;
            let result = encode_scheme_result(&entries);
            outcome::record_refund(&*env.store, rec, result.as_deref())
                .await
                .map_err(down)?
        } else {
            rec.clone()
        };
        let bytes = rec.record().scheme_result.clone().unwrap_or_default();
        let entries = parse_scheme_result(&bytes).map_err(down)?;
        if entries.len() != outputs.len() {
            return Err(down("the recorded mint signed other outputs"));
        }
        Ok(entries)
    }
}
