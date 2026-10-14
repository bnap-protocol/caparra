//! The server side: [`NotesScheme`], the `bnap:notes` [`CredentialScheme`]
//! (sections 5 to 9), the fund quote of 8.2, and the admission cutoff of
//! 5.4.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bnap_core::credential::SchemePart;
use bnap_core::hash::sha256;
use bnap_core::ids::rail;
use bnap_core::limits::CLOCK_SKEW;
use bnap_core::offer::OfferFields;
use bnap_core::response::Status;
use bnap_core::schnorr::Key;
use bnap_plug::{
    BlindedOutput, CappedSigner, CredentialScheme, Entry, FundingRail, KeysetId, OfferCtx,
    OfferRole, PayId, PayState, Point, RailError, RailRef, SchemeError, SchemeOffer, SettleCtx,
    Verified, VerifyCtx,
};

use crate::amount::{covers, select, select_among, value};
use crate::codes::{
    BAD_AMOUNT, BAD_OUTPUTS, BAD_SIGNATURE, EMPTY, LIMIT, NON_CANONICAL, QUOTE_UNPAID,
    UNKNOWN_KEYSET, reject,
};
use crate::issuer::{
    IssuerError, IssuerStore, QuoteInsert, QuoteRecord, SignedOutput, find_keyset,
};
use crate::keyset::{BlindSigned, KeysetInfo, UNIT, verify_dleq};
use crate::wire::{
    Body, DEFAULT_MAX_COUNT, FundQuote, Output, Params, PointBytes, SignatureEntry, Witness,
    encode_scheme_result, is_point,
};
use crate::{SCHEME_ID, fund::FundRequest};

/// The NUT-23 payment method a body's `fund` redeems (P21).
pub const BOLT11: &str = "bolt11";

/// How a gate runs `bnap:notes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotesConfig {
    /// The issuer's Cashu API base, an absolute `https` URL on the origin
    /// the offers come from (5.1).
    pub issuer_url: String,
    /// `max_inputs` to put in offers; the default 16 when `None`.
    pub max_inputs: Option<u64>,
    /// `max_outputs` to put in offers; the default 16 when `None`.
    pub max_outputs: Option<u64>,
    /// Funding inside the 402 up to this amount (`max_fund`, 8.1); `None`
    /// offers none.
    pub max_fund: Option<u64>,
    /// The smallest top-up a fund quote is made for (8.2); smaller requests
    /// get no quote.
    pub min_fund: u64,
    /// Routes whose `require` sets `link-payment` to `unlinkable`: their
    /// offers carry no `max_fund` and no `fund_quote` (5.4, P36).
    pub unlinkable_routes: BTreeSet<String>,
    /// The gate's `pending_timeout`, for the admission cutoff (5.4).
    pub pending_timeout: u64,
}

impl NotesConfig {
    /// A configuration with the defaults and no funding inside the 402.
    #[must_use]
    pub fn new(issuer_url: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            max_inputs: None,
            max_outputs: None,
            max_fund: None,
            min_fund: 1,
            unlinkable_routes: BTreeSet::new(),
            pending_timeout: bnap_core::limits::DEFAULT_PENDING_TIMEOUT,
        }
    }
}

/// The admission cutoff of a notes entry (5.4, P9): its deadline (the
/// earlier of the offer's `expires` and the entry's `quote_expires`) minus
/// `pending_timeout` minus 60 s. No new notes credential commits after it.
#[must_use]
pub fn admission_cutoff(deadline: u64, pending_timeout: u64) -> u64 {
    deadline
        .saturating_sub(pending_timeout)
        .saturating_sub(CLOCK_SKEW)
}

/// The offer fields to give `outcome::process` for a credential that pays
/// with `bnap:notes`: the same fields, with the notes entry's
/// `quote_expires` lowered to its admission cutoff less the 60 s skew that
/// `process` adds back. `process` looks up `outcome[rk]` first, so a replay
/// is still answered from its outcome, and only a new credential after the
/// cutoff is refused, with STALE, consuming nothing (5.4: the cutoff applies
/// inside the commit, after the replay lookup). The gate keeps checking the
/// offer itself as received (draft-00 4.4).
#[must_use]
pub fn admission_fields(offer: &OfferFields, pending_timeout: u64) -> OfferFields {
    let mut f = offer.clone();
    if let Some(e) = f.pay.iter_mut().find(|e| e.scheme == SCHEME_ID) {
        let deadline = e.effective_quote_expires(offer.expires);
        let cutoff = admission_cutoff(deadline, pending_timeout);
        e.quote_expires = Some(cutoff.saturating_sub(CLOCK_SKEW));
    }
    f
}

/// True when a verified notes credential redeems a fund quote, the one case
/// where it returns a rail reference (6.4). On a route whose `require` sets
/// `link-payment` to `unlinkable`, the gate answers such a credential with
/// POLICY after verification and before commit (8.4, P36).
#[must_use]
pub fn funded(verified: &Verified) -> bool {
    !verified.rail_ids.is_empty()
}

/// The scheme error for a rail that did not confirm a fund quote's payment
/// (6.4, P14): `QUOTE_UNPAID` for a payment that is not there or not final,
/// UNAVAILABLE for a rail that cannot be reached.
#[must_use]
pub fn rail_error(err: &RailError) -> SchemeError {
    match err {
        RailError::Unavailable(m) => SchemeError::Unavailable(m.clone()),
        other => reject(QUOTE_UNPAID, other.to_string()),
    }
}

fn unavailable(e: &IssuerError) -> SchemeError {
    SchemeError::Unavailable(e.to_string())
}

/// The `bnap:notes` scheme (server side).
///
/// It holds the issuer's tables ([`IssuerStore`]) and, for funding, the
/// operator's `ln` [`FundingRail`]. It never holds a key: notes are checked
/// and outputs signed by the operator's signer, through the
/// [`CappedSigner`] the gate hands it.
pub struct NotesScheme {
    config: NotesConfig,
    issuer: Arc<dyn IssuerStore>,
    rail: Option<Arc<dyn FundingRail>>,
}

impl std::fmt::Debug for NotesScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotesScheme")
            .field("config", &self.config)
            .field("rail", &self.rail.as_ref().map(|r| r.kind().to_owned()))
            .finish_non_exhaustive()
    }
}

impl NotesScheme {
    /// The scheme over these tables. `rail` is the operator's `ln` rail:
    /// without it no fund quote is made and none verifies.
    #[must_use]
    pub fn new(
        config: NotesConfig,
        issuer: Arc<dyn IssuerStore>,
        rail: Option<Arc<dyn FundingRail>>,
    ) -> Self {
        Self {
            config,
            issuer,
            rail,
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &NotesConfig {
        &self.config
    }

    /// The issuer's tables.
    #[must_use]
    pub fn issuer(&self) -> &Arc<dyn IssuerStore> {
        &self.issuer
    }

    /// The funding rail, if any.
    #[must_use]
    pub fn rail(&self) -> Option<&Arc<dyn FundingRail>> {
        self.rail.as_ref()
    }

    /// The pay entry's parameters for an offer being built (5.1), with a
    /// fund quote made for this request when `quote` is given.
    ///
    /// Refused ([`SchemeError::Unsupported`], so the gate leaves
    /// `bnap:notes` out of the offer) when the role is not a `sat` pay
    /// entry, when the offer's admission cutoff is less than 60 s after it
    /// is issued (5.4), or when a quote is asked for in a route-scope offer
    /// or on a route that requires unlinkable payment (5.4). UNAVAILABLE
    /// when no keyset the offer may list is active.
    pub async fn offer_params(
        &self,
        cx: &OfferCtx<'_>,
        quote: Option<&FundQuote>,
    ) -> Result<Params, SchemeError> {
        match cx.role {
            OfferRole::Pay { unit, .. } if unit == UNIT => {}
            _ => return Err(SchemeError::Unsupported),
        }
        let cutoff = admission_cutoff(cx.expires, self.config.pending_timeout);
        if cutoff < cx.now.saturating_add(CLOCK_SKEW) {
            return Err(SchemeError::Unsupported);
        }
        let table = self.issuer.keysets().await.map_err(|e| unavailable(&e))?;
        let mut keysets: Vec<_> = table
            .iter()
            .filter(|k| k.offerable(cx.expires))
            .map(KeysetInfo::entry)
            .collect();
        keysets.sort_by_key(|k| k.id);
        if !keysets.iter().any(|k| k.active) {
            return Err(SchemeError::Unavailable("no active BNAP keyset".into()));
        }
        let unlinkable = self.config.unlinkable_routes.contains(cx.route_id);
        let mut params = Params::new(self.config.issuer_url.clone(), keysets);
        params.max_inputs = self.config.max_inputs;
        params.max_outputs = self.config.max_outputs;
        params.max_fund = if unlinkable {
            None
        } else {
            self.config.max_fund
        };
        if let Some(q) = quote {
            if cx.route_scope || unlinkable {
                return Err(SchemeError::Unsupported);
            }
            params.fund_quote = Some(q.clone());
        }
        Ok(params)
    }

    /// The pay entry of an exact-scope offer made for one request that
    /// carried `BNAP-Fund`, with its fund quote (5.3, 8.2). The gate MUST
    /// NOT cache that offer (5.4).
    pub async fn offer_with_quote(
        &self,
        cx: &OfferCtx<'_>,
        quote: &FundQuote,
    ) -> Result<SchemeOffer, SchemeError> {
        let params = self.offer_params(cx, Some(quote)).await?;
        Ok(SchemeOffer {
            params: Some(params.to_bytes()),
        })
    }

    /// Makes the NUT-23 BOLT11 quote of 8.2 for a request that carried
    /// `BNAP-Fund`, locked to its NUT-20 key, for `min(amount, max_fund)`.
    ///
    /// `Ok(None)` when the gate does not fund here: no `max_fund`, a route
    /// that requires unlinkable payment, or an amount below `min_fund`. The
    /// quote ID is the hex of the offer's nonce, so a nonce never gets two
    /// quotes (8.2): asked again, the same quote comes back, and another
    /// key gets none. Rate limits per client address are the gate's (8.2).
    pub async fn create_fund_quote(
        &self,
        req: &FundRequest,
        route_id: &str,
        nonce: &[u8; 16],
        now: u64,
    ) -> Result<Option<FundQuote>, SchemeError> {
        let Some(max) = self.config.max_fund else {
            return Ok(None);
        };
        if self.config.unlinkable_routes.contains(route_id) {
            return Ok(None);
        }
        let amount = req.amount.min(max);
        if amount < self.config.min_fund.max(1) {
            return Ok(None);
        }
        let rail = self
            .rail
            .as_ref()
            .ok_or_else(|| SchemeError::Unavailable("no funding rail".into()))?;
        let id = hex::encode(nonce);
        if let Some(q) = self.issuer.quote(&id).await.map_err(|e| unavailable(&e))? {
            return Ok(fund_quote_of(&q, &req.pubkey));
        }
        let memo = sha256(&[b"bnap:notes quote ", id.as_bytes()].concat());
        let pay = rail
            .request(amount, UNIT, memo)
            .await
            .map_err(|e| SchemeError::Unavailable(e.to_string()))?;
        let payment_hash: [u8; 32] = pay.id.0.as_slice().try_into().map_err(|_| {
            SchemeError::Unavailable("the ln rail's payment ID is not a payment hash".into())
        })?;
        if pay.rail_kind != rail::LN || pay.unit != UNIT || pay.amount != amount {
            return Err(SchemeError::Unavailable(
                "the rail made a request other than the one asked for".into(),
            ));
        }
        let record = QuoteRecord {
            id: id.clone(),
            method: BOLT11.into(),
            unit: UNIT.into(),
            amount,
            request: pay.request,
            payment_hash,
            expiry: pay.expires,
            pubkey: Some(req.pubkey),
            paid: false,
            issued: false,
            created: now,
        };
        match self
            .issuer
            .insert_quote(&record)
            .await
            .map_err(|e| unavailable(&e))?
        {
            QuoteInsert::Inserted => Ok(fund_quote_of(&record, &req.pubkey)),
            QuoteInsert::Exists(q) => Ok(fund_quote_of(&q, &req.pubkey)),
        }
    }

    /// The quote record for a NUT-23 state check (8.6), its `paid` flag
    /// refreshed from the rail. `issued` is a cache of the use store, set
    /// when a credential's settlement or a mint used the quote.
    pub async fn quote_state(&self, id: &str) -> Result<Option<QuoteRecord>, SchemeError> {
        let Some(mut q) = self.issuer.quote(id).await.map_err(|e| unavailable(&e))? else {
            return Ok(None);
        };
        if !q.paid && self.rail_paid(&q).await? {
            self.issuer
                .mark_quote(id, true, false)
                .await
                .map_err(|e| unavailable(&e))?;
            q.paid = true;
        }
        Ok(Some(q))
    }

    /// Step 4 of 6.2: the fund quote exists, is a BOLT11 `sat` quote with a
    /// NUT-20 key, and is paid in full (`QUOTE_UNPAID`). Whether it has
    /// issued is not asked: the `RailId` commit decides that (P10).
    async fn check_fund(
        &self,
        body: &Body,
    ) -> Result<Option<(QuoteRecord, PointBytes)>, SchemeError> {
        let Some(id) = &body.fund else {
            return Ok(None);
        };
        let q = self
            .issuer
            .quote(id)
            .await
            .map_err(|e| unavailable(&e))?
            .ok_or_else(|| reject(QUOTE_UNPAID, "unknown fund quote"))?;
        let pubkey = q
            .pubkey
            .filter(|_| q.method == BOLT11 && q.unit == UNIT)
            .ok_or_else(|| reject(QUOTE_UNPAID, "not a BOLT11 sat quote with a NUT-20 key"))?;
        if !q.paid && !self.rail_paid(&q).await? {
            return Err(reject(QUOTE_UNPAID, "the fund quote is not paid"));
        }
        Ok(Some((q, pubkey)))
    }

    /// Asks the rail whether a quote's invoice is paid.
    async fn rail_paid(&self, q: &QuoteRecord) -> Result<bool, SchemeError> {
        let Some(rail) = &self.rail else {
            return Ok(false);
        };
        match rail.status(&PayId(q.payment_hash.to_vec())).await {
            Ok(PayState::Paid) => Ok(true),
            Ok(_) | Err(RailError::NotConfirmed(_) | RailError::WrongKind { .. }) => Ok(false),
            Err(e) => Err(rail_error(&e)),
        }
    }

    /// NUT-09 restore (12.2): the signature of each output the issuer
    /// signed, found by `B'` under any source, with matching keyset and
    /// amount. Outputs never signed are left out.
    pub async fn restore(
        &self,
        outputs: &[Output],
    ) -> Result<Vec<(Output, BlindSigned)>, SchemeError> {
        let blinded: Vec<PointBytes> = outputs.iter().map(|o| o.blinded).collect();
        let records = self
            .issuer
            .outputs_by_blinded(&blinded)
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(outputs
            .iter()
            .filter_map(|o| {
                records
                    .iter()
                    .find(|r| {
                        r.blinded == o.blinded && r.keyset == o.keyset && r.amount == o.amount
                    })
                    .and_then(|r| r.signature.map(|s| (*o, s)))
            })
            .collect())
    }

    /// Signs the selected outputs of `body` through `signer`, recording
    /// each in the signed-output table under `source` before the signer is
    /// asked and completing the record after (7.4). Every DLEQ proof the
    /// signer returns is checked against the keyset's key before it goes
    /// into a `scheme_result`.
    pub(crate) async fn sign_outputs(
        &self,
        signer: &CappedSigner,
        outputs: &[Output],
        selected: &[usize],
        source: [u8; 32],
    ) -> Result<Vec<SignatureEntry>, SchemeError> {
        let table = self.issuer.keysets().await.map_err(|e| unavailable(&e))?;
        let reserve: Vec<SignedOutput> = selected
            .iter()
            .map(|&i| SignedOutput {
                keyset: outputs[i].keyset,
                amount: outputs[i].amount,
                blinded: outputs[i].blinded,
                source,
                signature: None,
            })
            .collect();
        self.issuer
            .put_outputs(&reserve)
            .await
            .map_err(|e| unavailable(&e))?;
        let mut groups: BTreeMap<[u8; 33], Vec<usize>> = BTreeMap::new();
        for &i in selected {
            groups.entry(outputs[i].keyset).or_default().push(i);
        }
        let mut entries = Vec::new();
        let mut done = Vec::new();
        for (ks, idx) in groups {
            let batch: Vec<BlindedOutput> = idx
                .iter()
                .map(|&i| BlindedOutput {
                    amount: outputs[i].amount,
                    blinded: Point(outputs[i].blinded),
                })
                .collect();
            let sigs = signer
                .blind_sign(&KeysetId(ks.to_vec()), &batch)
                .await
                .map_err(|e| SchemeError::Unavailable(e.to_string()))?;
            let keyset = find_keyset(&table, &ks).ok_or_else(|| {
                SchemeError::Unavailable("an output keyset left the table".into())
            })?;
            for (&i, sig) in idx.iter().zip(&sigs) {
                let blind = BlindSigned {
                    c: sig.signature.0,
                    e: sig.dleq.e,
                    s: sig.dleq.s,
                };
                let a = keyset.key(outputs[i].amount).ok_or_else(|| {
                    SchemeError::Unavailable("no key for an output amount".into())
                })?;
                if !verify_dleq(a, &outputs[i].blinded, &blind) {
                    return Err(SchemeError::Unavailable(
                        "the signer returned a DLEQ proof that does not verify".into(),
                    ));
                }
                entries.push(SignatureEntry {
                    index: i as u64,
                    c: blind.c,
                    e: blind.e,
                    s: blind.s,
                });
                done.push(SignedOutput {
                    signature: Some(blind),
                    ..reserve
                        .iter()
                        .find(|r| r.blinded == outputs[i].blinded)
                        .cloned()
                        .ok_or_else(|| SchemeError::Unavailable("lost a reservation".into()))?
                });
            }
        }
        self.issuer
            .put_outputs(&done)
            .await
            .map_err(|e| unavailable(&e))?;
        entries.sort_by_key(|e| e.index);
        Ok(entries)
    }

    /// The outputs a FAILED settlement signs (7.2, 7.5): the 7.2 selection
    /// for the whole refund, unless outputs of this body were already
    /// signed for its outcome (a late OK settle that lost to the timeout,
    /// or an OK settle the gate replaced with FAILED). The use store counts
    /// those against the outcome's value (ERRATA N3b-16, N3b-29), so the
    /// refund then re-signs them, at no cost, and adds the 7.2 greedy over
    /// the other outputs for what is left. This returns the whole value
    /// when the remaining outputs can form it, and as much of it as they
    /// can otherwise (see the notes, ERRATA candidate N6-1).
    async fn refund_selection(
        &self,
        body: &Body,
        amounts: &[u64],
        target: u64,
        source: &[u8; 32],
    ) -> Result<Vec<usize>, SchemeError> {
        let plain = select(amounts, target)
            .ok_or_else(|| SchemeError::Unavailable("the outputs cannot form the refund".into()))?;
        let records = self
            .issuer
            .outputs_by_source(source)
            .await
            .map_err(|e| unavailable(&e))?;
        let prior: BTreeSet<usize> = body
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                records
                    .iter()
                    .any(|r| r.blinded == o.blinded && r.keyset == o.keyset && r.amount == o.amount)
            })
            .map(|(i, _)| i)
            .collect();
        if prior.iter().all(|i| plain.contains(i)) {
            return Ok(plain);
        }
        let signed: u64 = prior.iter().map(|&i| amounts[i]).sum();
        let (rest, _) = select_among(
            amounts,
            |i| !prior.contains(&i),
            target.saturating_sub(signed),
        );
        let mut all: Vec<usize> = prior.into_iter().chain(rest).collect();
        all.sort_unstable();
        Ok(all)
    }
}

/// The offer's view of a quote record, for the client whose key it is.
fn fund_quote_of(q: &QuoteRecord, pubkey: &PointBytes) -> Option<FundQuote> {
    (q.pubkey.as_ref() == Some(pubkey)).then(|| FundQuote {
        quote: q.id.clone(),
        request: q.request.clone(),
        amount: q.amount,
        expiry: q.expiry,
        pubkey: *pubkey,
        unknown: Vec::new(),
    })
}

/// The live keyset an input or output names, if the offer and the table
/// both allow it (6.2 step 2).
fn live_keyset<'a>(
    table: &'a [KeysetInfo],
    params: &Params,
    id: &[u8; 33],
    output: bool,
    now: u64,
) -> Option<&'a KeysetInfo> {
    let listed = params.keyset(id)?;
    if output && !listed.active {
        return None;
    }
    let live = find_keyset(table, id)?;
    (!live.revoked() && live.unit == UNIT && !live.expired(now)).then_some(live)
}

/// Step 1 of 6.2: the body and witness in canonical form (`NON_CANONICAL`),
/// something to spend (`EMPTY`) and the counts (`LIMIT`). Returns the
/// parameters too, or `UNKNOWN_KEYSET` when the entry has none it can use.
fn check_form(
    part: &SchemePart,
    entry: &bnap_core::offer::PayEntry,
) -> Result<(Body, Witness, Params), SchemeError> {
    let body = Body::parse(&part.body).map_err(|e| reject(NON_CANONICAL, e.0))?;
    let witness = Witness::parse(&part.witness, &body).map_err(|e| reject(NON_CANONICAL, e.0))?;
    if body.inputs.is_empty() && body.fund.is_none() {
        return Err(reject(EMPTY, "neither inputs nor fund"));
    }
    let params = entry.params.as_deref().map(Params::parse).transpose();
    let (max_in, max_out) = match &params {
        Ok(Some(p)) => (p.max_inputs(), p.max_outputs()),
        _ => (DEFAULT_MAX_COUNT, DEFAULT_MAX_COUNT),
    };
    if body.inputs.len() as u64 > max_in || body.outputs.len() as u64 > max_out {
        return Err(reject(
            LIMIT,
            "more inputs or outputs than the offer allows",
        ));
    }
    match params {
        Ok(Some(p)) if entry.unit == UNIT => Ok((body, witness, p)),
        _ => Err(reject(UNKNOWN_KEYSET, "the pay entry lists no sat keysets")),
    }
}

/// Steps 2 and 3 of 6.2: every input keyset listed in the offer, known,
/// unrevoked and inside its final expiry; every output keyset listed as
/// active and unrevoked (`UNKNOWN_KEYSET`); every amount a power of two
/// with a key (`BAD_AMOUNT`). Returns each input's `input_fee_ppk` as the
/// offer states it, which is what the client computed its value with.
fn check_keysets(
    body: &Body,
    params: &Params,
    table: &[KeysetInfo],
    now: u64,
) -> Result<Vec<u64>, SchemeError> {
    let mut fee_ppk = Vec::with_capacity(body.inputs.len());
    let mut amounts = Vec::with_capacity(body.inputs.len() + body.outputs.len());
    for i in &body.inputs {
        let live = live_keyset(table, params, &i.keyset, false, now)
            .ok_or_else(|| reject(UNKNOWN_KEYSET, "an input keyset is not accepted"))?;
        fee_ppk.push(params.keyset(&i.keyset).map_or(0, |k| k.input_fee_ppk));
        amounts.push((live, i.amount));
    }
    for o in &body.outputs {
        let live = live_keyset(table, params, &o.keyset, true, now)
            .ok_or_else(|| reject(UNKNOWN_KEYSET, "an output keyset is not active"))?;
        amounts.push((live, o.amount));
    }
    if !amounts
        .iter()
        .all(|(k, a)| a.is_power_of_two() && k.key(*a).is_some())
    {
        return Err(reject(
            BAD_AMOUNT,
            "an amount is not a power of two with a key",
        ));
    }
    Ok(fee_ppk)
}

/// Step 6 of 6.2: the i-th input signature verifies under the i-th `K`,
/// and `fund_sig` under the x-only form of the quote's key, both over the
/// Digest (`BAD_SIGNATURE`).
fn check_witness(
    body: &Body,
    witness: &Witness,
    fund_key: Option<&PointBytes>,
    digest: &bnap_core::hash::Digest,
) -> Result<(), SchemeError> {
    for (i, sig) in body.inputs.iter().zip(&witness.input_sigs) {
        Key(i.key)
            .verify(&digest.0, sig)
            .map_err(|_| reject(BAD_SIGNATURE, "an input signature does not verify"))?;
    }
    if let (Some(pubkey), Some(sig)) = (fund_key, &witness.fund_sig) {
        let mut x = [0u8; 32];
        x.copy_from_slice(&pubkey[1..]);
        if !is_point(pubkey) || Key(x).verify(&digest.0, sig).is_err() {
            return Err(reject(BAD_SIGNATURE, "the fund signature does not verify"));
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl CredentialScheme for NotesScheme {
    fn id(&self) -> &str {
        SCHEME_ID
    }

    async fn offer(&self, cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        let params = self.offer_params(cx, None).await?;
        Ok(SchemeOffer {
            params: Some(params.to_bytes()),
        })
    }

    /// The checks of 6.2, in order, cheapest first; the first failure ends
    /// verification. Nothing is written anywhere, and no use state is read:
    /// a replay of a committed credential always reaches the socket's
    /// replay path (6.2, "No use state").
    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let Entry::Pay(entry) = cx.entry else {
            return Err(SchemeError::Unsupported);
        };
        // 1. Form.
        let (body, witness, params) = check_form(part, entry)?;
        // 2. Keysets and 3. amounts.
        let table = self.issuer.keysets().await.map_err(|e| unavailable(&e))?;
        let fee_ppk = check_keysets(&body, &params, &table, cx.now)?;
        // 4. Fund.
        let fund = self.check_fund(&body).await?;
        // 5. Value and outputs.
        let f = fund.as_ref().map_or(0, |(q, _)| q.amount);
        let value = value(
            body.inputs
                .iter()
                .map(|i| i.amount)
                .zip(fee_ppk.iter().copied()),
            f,
        )
        .map_err(|e| reject(BAD_AMOUNT, e.to_string()))?;
        let amounts: Vec<u64> = body.outputs.iter().map(|o| o.amount).collect();
        if !covers(&amounts, value) {
            return Err(reject(
                BAD_OUTPUTS,
                "the outputs are not a complete ladder covering the value",
            ));
        }
        // 6. Witness.
        check_witness(&body, &witness, fund.as_ref().map(|(_, k)| k), cx.digest)?;
        // 7. Notes, checked by the signer, which derives each Y itself.
        let mut ys = Vec::with_capacity(body.inputs.len());
        for i in &body.inputs {
            let y = cx
                .signer
                .verify_unblinded(
                    &KeysetId(i.keyset.to_vec()),
                    i.amount,
                    i.secret().as_bytes(),
                    &Point(i.c),
                )
                .await
                .map_err(|e| SchemeError::Unavailable(e.to_string()))?
                .ok_or_else(|| reject(BAD_SIGNATURE, "a note does not verify"))?;
            ys.push(y.0.to_vec());
        }
        let rail_ids = fund
            .map(|(q, _)| RailRef {
                kind: rail::LN.into(),
                reference: q.payment_hash.to_vec(),
            })
            .into_iter()
            .collect();
        Ok(Verified {
            use_ids: ys,
            rail_ids,
            value,
            quota_id: None,
        })
    }

    /// Signs exactly `value - charged` of the client's outputs (7.1, 7.2):
    /// OK signs the change, FAILED (charge 0) the whole value. The amount
    /// is also bounded by the signer's cap, which bnap-core computed from
    /// the admitted value. Returns `None` when nothing is signed (P17).
    async fn settle(
        &self,
        part: &SchemePart,
        verified: &Verified,
        cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        let body = Body::parse(&part.body).map_err(|e| reject(NON_CANONICAL, e.0))?;
        let source = sha256(&part.body);
        let cap = signer.cap().unwrap_or(0);
        let target = verified.value.saturating_sub(cx.charged).min(cap);
        let amounts: Vec<u64> = body.outputs.iter().map(|o| o.amount).collect();
        let selected = match cx.status {
            Status::Ok => select(&amounts, target).ok_or_else(|| {
                SchemeError::Unavailable("the outputs cannot form the change".into())
            })?,
            Status::Failed => {
                self.refund_selection(&body, &amounts, target, &source)
                    .await?
            }
        };
        if let Some(id) = &body.fund {
            // After commit the quote counts as issued, whatever the outcome
            // (8.4). A cache only: the use store is the authority.
            let _ = self.issuer.mark_quote(id, true, true).await;
        }
        if selected.is_empty() {
            return Ok(None);
        }
        let entries = self
            .sign_outputs(signer, &body.outputs, &selected, source)
            .await?;
        Ok(encode_scheme_result(&entries))
    }
}
