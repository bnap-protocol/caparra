//! The bytes of the scheme: body and witness (section 3), the pay entry
//! parameters (section 5) and the `scheme_result` (7.3).
//!
//! Body, witness and `scheme_result` have exactly one encoding (3.5): every
//! reader here refuses a framing error, a non-minimal integer, an unknown
//! record (odd and GREASE included), an empty value, a missing Required
//! record, a value of the wrong length and a point or key that is not on the
//! curve. The gate answers each such refusal with `bnap:notes/NON_CANONICAL`,
//! never with socket MALFORMED (2.1).
//!
//! The parameters are bytes inside a signed offer and follow the even/odd
//! rule of draft-00 section 2 instead (5.1): an unknown odd record is kept
//! and ignored, an unknown even one makes the entry unusable.

use bnap_core::encoding::{read_tu64, tu64};
use bnap_core::schnorr::Signature;
use bnap_core::secp256k1::{PublicKey, XOnlyPublicKey};
use bnap_core::tlv::{Fields, StreamKind, TlvStream, entry_list, parse_entry_list, write_record};

/// A full keyset ID: the byte `01` and a SHA-256 digest (NUT-02 version
/// 01). Bodies, parameters and derivation never use the short ID (4.2).
pub type KeysetIdBytes = [u8; 33];

/// A compressed secp256k1 point: `C`, `B'`, `C'` or `Y`.
pub type PointBytes = [u8; 33];

/// Why bytes are not in the canonical form this module reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct WireError(pub String);

fn err(msg: impl Into<String>) -> WireError {
    WireError(msg.into())
}

/// Body record types (3.1).
pub mod body_types {
    /// Entry list of inputs, sorted by `key`.
    pub const INPUTS: u64 = 0;
    /// Entry list of outputs, in the client's order.
    pub const OUTPUTS: u64 = 2;
    /// The quote ID of a paid fund quote.
    pub const FUND: u64 = 4;
}

/// Input entry record types (3.2).
pub mod input_types {
    /// The full keyset ID.
    pub const KEYSET: u64 = 0;
    /// A power of two, in sat.
    pub const AMOUNT: u64 = 2;
    /// `K`; the secret is `hex(K)`.
    pub const KEY: u64 = 4;
    /// The unblinded signature.
    pub const C: u64 = 6;
}

/// Output entry record types (3.3).
pub mod output_types {
    /// The full ID of a keyset the offer lists as active.
    pub const KEYSET: u64 = 0;
    /// A power of two, in sat.
    pub const AMOUNT: u64 = 2;
    /// `B'`.
    pub const BLINDED: u64 = 4;
}

/// Witness record types (3.4).
pub mod witness_types {
    /// One signature per input, in input order.
    pub const INPUT_SIGS: u64 = 0;
    /// The signature by the fund quote's NUT-20 key.
    pub const FUND_SIG: u64 = 2;
}

/// Pay entry parameter types (5.1).
pub mod param_types {
    /// The issuer's Cashu API base URL.
    pub const ISSUER: u64 = 0;
    /// Entry list of keyset entries, sorted by `id`.
    pub const KEYSETS: u64 = 2;
    /// At most this many inputs; 16 when absent.
    pub const MAX_INPUTS: u64 = 4;
    /// At most this many outputs; 16 when absent.
    pub const MAX_OUTPUTS: u64 = 6;
    /// Funding requests are accepted up to this amount.
    pub const MAX_FUND: u64 = 8;
    /// A fund quote made for this client; exact-scope offers only.
    pub const FUND_QUOTE: u64 = 10;
}

/// Keyset entry record types (5.2).
pub mod keyset_types {
    /// The keyset ID.
    pub const ID: u64 = 0;
    /// The keyset's NUT-02 `input_fee_ppk`; 0 when absent.
    pub const INPUT_FEE_PPK: u64 = 2;
    /// Flag: the keyset signs outputs.
    pub const ACTIVE: u64 = 4;
}

/// Fund quote record types (5.3).
pub mod quote_types {
    /// The quote ID.
    pub const QUOTE: u64 = 0;
    /// The BOLT11 invoice.
    pub const REQUEST: u64 = 2;
    /// The quote amount, in sat.
    pub const AMOUNT: u64 = 4;
    /// Until when the invoice can be paid.
    pub const EXPIRY: u64 = 6;
    /// The client's compressed NUT-20 key.
    pub const PUBKEY: u64 = 8;
}

/// Signature entry record types (7.3).
pub mod sig_types {
    /// The zero-based output index; present even when empty (index 0).
    pub const INDEX: u64 = 0;
    /// `C' = a·B'`.
    pub const C_: u64 = 2;
    /// The NUT-12 DLEQ challenge.
    pub const E: u64 = 4;
    /// The NUT-12 DLEQ response.
    pub const S: u64 = 6;
}

/// Default `max_inputs` and `max_outputs` (3.6, provisional P3).
pub const DEFAULT_MAX_COUNT: u64 = 16;

/// The longest quote ID (3.1, 5.3).
pub const MAX_QUOTE_ID: usize = 64;

/// True for 33 bytes that are a valid compressed secp256k1 point.
#[must_use]
pub fn is_point(p: &[u8]) -> bool {
    p.len() == 33 && matches!(p[0], 0x02 | 0x03) && PublicKey::from_slice(p).is_ok()
}

/// True for 32 bytes that are a valid x-only key: below the field size and
/// the x coordinate of a curve point.
#[must_use]
pub fn is_xonly(k: &[u8]) -> bool {
    k.len() == 32 && XOnlyPublicKey::from_slice(k).is_ok()
}

/// One note spent by a credential (3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Input {
    /// The full keyset ID.
    pub keyset: KeysetIdBytes,
    /// The amount, a power of two, in sat.
    pub amount: u64,
    /// `K`, the note's x-only key.
    pub key: [u8; 32],
    /// `C`, the unblinded signature.
    pub c: PointBytes,
}

impl Input {
    /// The note's secret: `hex(K)`, 64 lowercase characters (4.1).
    #[must_use]
    pub fn secret(&self) -> String {
        hex::encode(self.key)
    }
}

/// One blinded output (3.3), used as change or as a refund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Output {
    /// The full keyset ID.
    pub keyset: KeysetIdBytes,
    /// The amount, a power of two, in sat.
    pub amount: u64,
    /// `B'`.
    pub blinded: PointBytes,
}

impl Output {
    /// The output entry's stream (3.3).
    #[must_use]
    pub fn entry_bytes(&self) -> Vec<u8> {
        let mut s = Vec::new();
        write_record(&mut s, output_types::KEYSET, &self.keyset);
        write_record(&mut s, output_types::AMOUNT, &tu64(self.amount));
        write_record(&mut s, output_types::BLINDED, &self.blinded);
        s
    }
}

/// The body of a notes credential (3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Body {
    /// Inputs, strictly ascending by `key`.
    pub inputs: Vec<Input>,
    /// Outputs, in the client's order.
    pub outputs: Vec<Output>,
    /// The quote ID of a paid fund quote.
    pub fund: Option<String>,
}

/// A parsed stream whose types are all in `allowed`, with no empty value.
fn strict(bytes: &[u8], allowed: &[u64], what: &str) -> Result<TlvStream, WireError> {
    let s =
        TlvStream::parse(bytes, StreamKind::TopLevel).map_err(|e| err(format!("{what}: {e}")))?;
    for (t, v) in s.records() {
        if !allowed.contains(t) {
            return Err(err(format!("{what}: record type {t} is not defined here")));
        }
        if v.is_empty() {
            return Err(err(format!("{what}: record {t} has an empty value")));
        }
    }
    Ok(s)
}

fn required<'a>(s: &'a TlvStream, typ: u64, what: &str) -> Result<&'a [u8], WireError> {
    s.get(typ)
        .ok_or_else(|| err(format!("{what}: Required record {typ} is missing")))
}

fn fixed<const N: usize>(v: &[u8], typ: u64, what: &str) -> Result<[u8; N], WireError> {
    <[u8; N]>::try_from(v).map_err(|_| {
        err(format!(
            "{what}: record {typ} is {} bytes, not {N}",
            v.len()
        ))
    })
}

fn amount(v: &[u8], typ: u64, what: &str) -> Result<u64, WireError> {
    let a = read_tu64(v, typ).map_err(|e| err(format!("{what}: {e}")))?;
    if a == 0 {
        return Err(err(format!("{what}: amount 0")));
    }
    Ok(a)
}

fn point(v: &[u8], typ: u64, what: &str) -> Result<PointBytes, WireError> {
    let p = fixed::<33>(v, typ, what)?;
    if !is_point(&p) {
        return Err(err(format!("{what}: record {typ} is not a point")));
    }
    Ok(p)
}

fn entries(v: &[u8], what: &str) -> Result<Vec<Vec<u8>>, WireError> {
    let items = parse_entry_list(v).map_err(|e| err(format!("{what}: {e}")))?;
    if items.iter().any(|i| i.is_empty()) {
        return Err(err(format!("{what}: an entry is the empty stream")));
    }
    Ok(items.into_iter().map(<[u8]>::to_vec).collect())
}

fn quote_id(v: &[u8], what: &str) -> Result<String, WireError> {
    if v.is_empty() || v.len() > MAX_QUOTE_ID {
        return Err(err(format!("{what}: quote ID of {} bytes", v.len())));
    }
    String::from_utf8(v.to_vec()).map_err(|_| err(format!("{what}: quote ID is not UTF-8")))
}

impl Input {
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use input_types as t;
        let w = "input entry";
        let s = strict(bytes, &[t::KEYSET, t::AMOUNT, t::KEY, t::C], w)?;
        let keyset = fixed::<33>(required(&s, t::KEYSET, w)?, t::KEYSET, w)?;
        let amount = amount(required(&s, t::AMOUNT, w)?, t::AMOUNT, w)?;
        let key = fixed::<32>(required(&s, t::KEY, w)?, t::KEY, w)?;
        if !is_xonly(&key) {
            return Err(err("input entry: key is not a valid x-only key"));
        }
        let c = point(required(&s, t::C, w)?, t::C, w)?;
        Ok(Self {
            keyset,
            amount,
            key,
            c,
        })
    }

    fn entry_bytes(&self) -> Vec<u8> {
        use input_types as t;
        let mut s = Vec::new();
        write_record(&mut s, t::KEYSET, &self.keyset);
        write_record(&mut s, t::AMOUNT, &tu64(self.amount));
        write_record(&mut s, t::KEY, &self.key);
        write_record(&mut s, t::C, &self.c);
        s
    }
}

impl Output {
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use output_types as t;
        let w = "output entry";
        let s = strict(bytes, &[t::KEYSET, t::AMOUNT, t::BLINDED], w)?;
        let keyset = fixed::<33>(required(&s, t::KEYSET, w)?, t::KEYSET, w)?;
        let amount = amount(required(&s, t::AMOUNT, w)?, t::AMOUNT, w)?;
        let blinded = point(required(&s, t::BLINDED, w)?, t::BLINDED, w)?;
        Ok(Self {
            keyset,
            amount,
            blinded,
        })
    }
}

impl Body {
    /// Parses a body in its one canonical form (3.5). Inputs must be strictly
    /// ascending by `key` (so no `K` twice) and no two outputs may share a
    /// `B'`. Whether the body holds anything at all is a separate check
    /// (`EMPTY`), and so are the counts (`LIMIT`).
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use body_types as t;
        let s = strict(bytes, &[t::INPUTS, t::OUTPUTS, t::FUND], "body")?;
        let mut body = Self::default();
        if let Some(v) = s.get(t::INPUTS) {
            for e in entries(v, "inputs")? {
                body.inputs.push(Input::parse(&e)?);
            }
        }
        if let Some(v) = s.get(t::OUTPUTS) {
            for e in entries(v, "outputs")? {
                body.outputs.push(Output::parse(&e)?);
            }
        }
        if let Some(v) = s.get(t::FUND) {
            body.fund = Some(quote_id(v, "fund")?);
        }
        body.check_order()?;
        Ok(body)
    }

    fn check_order(&self) -> Result<(), WireError> {
        if self.inputs.windows(2).any(|w| w[0].key >= w[1].key) {
            return Err(err(
                "inputs are not strictly ascending by key (or a key is repeated)",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !self.outputs.iter().all(|o| seen.insert(o.blinded)) {
            return Err(err("two outputs share one blinded point"));
        }
        Ok(())
    }

    /// Serializes the body. Refuses a body the parser would refuse: inputs
    /// out of order, a repeated `B'`, an amount of 0, a quote ID that is
    /// empty or longer than 64 bytes, or a point or key off the curve.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        use body_types as t;
        let mut out = Vec::new();
        if !self.inputs.is_empty() {
            let list: Vec<Vec<u8>> = self.inputs.iter().map(Input::entry_bytes).collect();
            write_record(&mut out, t::INPUTS, &entry_list(&list));
        }
        if !self.outputs.is_empty() {
            let list: Vec<Vec<u8>> = self.outputs.iter().map(Output::entry_bytes).collect();
            write_record(&mut out, t::OUTPUTS, &entry_list(&list));
        }
        if let Some(f) = &self.fund {
            write_record(&mut out, t::FUND, f.as_bytes());
        }
        let back = Self::parse(&out)?;
        if &back != self {
            return Err(err("the body does not survive its own parser"));
        }
        Ok(out)
    }

    /// `I + F` and the amounts are the caller's business; this is the sum
    /// of the output amounts, saturating.
    #[must_use]
    pub fn outputs_total(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.amount))
    }
}

/// The witness of a notes credential (3.4): signatures over the Digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Witness {
    /// One signature per input, in input order.
    pub input_sigs: Vec<Signature>,
    /// The signature by the fund quote's key, with `fund`.
    pub fund_sig: Option<Signature>,
}

impl Witness {
    /// Parses a witness in its canonical form, matched against `body`:
    /// `input_sigs` exactly when the body has inputs, 64 bytes per input,
    /// and `fund_sig` exactly when it has `fund` (3.5).
    pub fn parse(bytes: &[u8], body: &Body) -> Result<Self, WireError> {
        use witness_types as t;
        let s = strict(bytes, &[t::INPUT_SIGS, t::FUND_SIG], "witness")?;
        let mut w = Self::default();
        match (s.get(t::INPUT_SIGS), body.inputs.is_empty()) {
            (Some(v), false) => {
                if v.len() != 64 * body.inputs.len() {
                    return Err(err(format!(
                        "input_sigs is {} bytes for {} inputs",
                        v.len(),
                        body.inputs.len()
                    )));
                }
                w.input_sigs = v
                    .as_chunks::<64>()
                    .0
                    .iter()
                    .map(|c| Signature(*c))
                    .collect();
            }
            (None, true) => {}
            (Some(_), true) => return Err(err("input_sigs without inputs")),
            (None, false) => return Err(err("inputs without input_sigs")),
        }
        match (s.get(t::FUND_SIG), body.fund.is_some()) {
            (Some(v), true) => {
                w.fund_sig = Some(Signature(fixed::<64>(v, t::FUND_SIG, "witness")?));
            }
            (None, false) => {}
            (Some(_), false) => return Err(err("fund_sig without fund")),
            (None, true) => return Err(err("fund without fund_sig")),
        }
        Ok(w)
    }

    /// Serializes the witness.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use witness_types as t;
        let mut out = Vec::new();
        if !self.input_sigs.is_empty() {
            let sigs: Vec<u8> = self.input_sigs.iter().flat_map(|s| s.0).collect();
            write_record(&mut out, t::INPUT_SIGS, &sigs);
        }
        if let Some(s) = &self.fund_sig {
            write_record(&mut out, t::FUND_SIG, &s.0);
        }
        out
    }
}

/// A keyset entry of the parameters (5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetEntry {
    /// The keyset ID.
    pub id: KeysetIdBytes,
    /// The keyset's NUT-02 `input_fee_ppk`.
    pub input_fee_ppk: u64,
    /// The keyset signs outputs.
    pub active: bool,
    /// Unknown odd records, kept.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

/// The fund quote of an exact-scope offer (5.3): the NUT-23 quote fields a
/// client needs to pay from the 402.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundQuote {
    /// The quote ID, 1 to 64 bytes.
    pub quote: String,
    /// The BOLT11 invoice.
    pub request: String,
    /// The quote amount, in sat.
    pub amount: u64,
    /// Until when the invoice can be paid, Unix seconds.
    pub expiry: u64,
    /// The compressed NUT-20 key the client sent.
    pub pubkey: PointBytes,
    /// Unknown odd records, kept.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

/// The `params` record of a `bnap:notes` pay entry (5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// The issuer's Cashu API base URL, `https`, on the offer's origin.
    pub issuer: String,
    /// Keyset entries, strictly ascending by `id`.
    pub keysets: Vec<KeysetEntry>,
    /// At most this many inputs; [`DEFAULT_MAX_COUNT`] when absent.
    pub max_inputs: Option<u64>,
    /// At most this many outputs; [`DEFAULT_MAX_COUNT`] when absent.
    pub max_outputs: Option<u64>,
    /// Funding requests are accepted up to this amount, in sat.
    pub max_fund: Option<u64>,
    /// A fund quote made for this client.
    pub fund_quote: Option<FundQuote>,
    /// Unknown odd records, kept.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

fn even_odd(e: &bnap_core::MalformedKind, what: &str) -> WireError {
    err(format!("{what}: {e}"))
}

impl KeysetEntry {
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use keyset_types as t;
        let w = "keyset entry";
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(|e| even_odd(&e, w))?;
        let mut f = Fields::new(&s);
        let id = f.required_fixed::<33>(t::ID).map_err(|e| even_odd(&e, w))?;
        let input_fee_ppk = f
            .tu64(t::INPUT_FEE_PPK)
            .map_err(|e| even_odd(&e, w))?
            .unwrap_or(0);
        let active = f.flag(t::ACTIVE).map_err(|e| even_odd(&e, w))?;
        let unknown = f.finish().map_err(|e| even_odd(&e, w))?;
        Ok(Self {
            id,
            input_fee_ppk,
            active,
            unknown,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        use keyset_types as t;
        let mut recs = vec![(t::ID, self.id.to_vec())];
        if self.input_fee_ppk > 0 {
            recs.push((t::INPUT_FEE_PPK, tu64(self.input_fee_ppk)));
        }
        if self.active {
            recs.push((t::ACTIVE, Vec::new()));
        }
        recs.extend(self.unknown.iter().cloned());
        sorted(recs)
    }
}

/// Serializes records in type order; a later duplicate is dropped.
fn sorted(mut recs: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    recs.sort_by_key(|(t, _)| *t);
    recs.dedup_by_key(|(t, _)| *t);
    let mut out = Vec::new();
    for (t, v) in recs {
        write_record(&mut out, t, &v);
    }
    out
}

impl FundQuote {
    /// Parses a fund quote stream (5.3).
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use quote_types as t;
        let w = "fund quote";
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(|e| even_odd(&e, w))?;
        let mut f = Fields::new(&s);
        let quote = quote_id(f.required(t::QUOTE).map_err(|e| even_odd(&e, w))?, w)?;
        let request = f.required_utf8(t::REQUEST).map_err(|e| even_odd(&e, w))?;
        let amount = f.required_tu64(t::AMOUNT).map_err(|e| even_odd(&e, w))?;
        let expiry = f.required_tu64(t::EXPIRY).map_err(|e| even_odd(&e, w))?;
        let pubkey = f
            .required_fixed::<33>(t::PUBKEY)
            .map_err(|e| even_odd(&e, w))?;
        let unknown = f.finish().map_err(|e| even_odd(&e, w))?;
        if !is_point(&pubkey) {
            return Err(err("fund quote: pubkey is not a point"));
        }
        Ok(Self {
            quote,
            request,
            amount,
            expiry,
            pubkey,
            unknown,
        })
    }

    /// Serializes the fund quote stream.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use quote_types as t;
        let mut recs = vec![
            (t::QUOTE, self.quote.as_bytes().to_vec()),
            (t::REQUEST, self.request.as_bytes().to_vec()),
            (t::AMOUNT, tu64(self.amount)),
            (t::EXPIRY, tu64(self.expiry)),
            (t::PUBKEY, self.pubkey.to_vec()),
        ];
        recs.extend(self.unknown.iter().cloned());
        sorted(recs)
    }
}

impl Params {
    /// Parameters with an issuer and keysets only.
    #[must_use]
    pub fn new(issuer: impl Into<String>, keysets: Vec<KeysetEntry>) -> Self {
        Self {
            issuer: issuer.into(),
            keysets,
            max_inputs: None,
            max_outputs: None,
            max_fund: None,
            fund_quote: None,
            unknown: Vec::new(),
        }
    }

    /// Parses the `params` record of a notes pay entry. An unknown even
    /// record, a missing Required record, keysets out of order or without
    /// an active one, or a limit of 0 make the entry unusable (5.1).
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use param_types as t;
        let w = "params";
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(|e| even_odd(&e, w))?;
        let mut f = Fields::new(&s);
        let issuer = f.required_utf8(t::ISSUER).map_err(|e| even_odd(&e, w))?;
        let mut keysets = Vec::new();
        for e in parse_entry_list(f.required(t::KEYSETS).map_err(|e| even_odd(&e, w))?)
            .map_err(|e| even_odd(&e, w))?
        {
            keysets.push(KeysetEntry::parse(e)?);
        }
        let max_inputs = f.tu64(t::MAX_INPUTS).map_err(|e| even_odd(&e, w))?;
        let max_outputs = f.tu64(t::MAX_OUTPUTS).map_err(|e| even_odd(&e, w))?;
        let max_fund = f.tu64(t::MAX_FUND).map_err(|e| even_odd(&e, w))?;
        let fund_quote = f.take(t::FUND_QUOTE).map(FundQuote::parse).transpose()?;
        let unknown = f.finish().map_err(|e| even_odd(&e, w))?;
        if keysets.windows(2).any(|k| k[0].id >= k[1].id) {
            return Err(err("params: keysets are not strictly ascending by id"));
        }
        if !keysets.iter().any(|k| k.active) {
            return Err(err("params: no keyset is active"));
        }
        if max_inputs == Some(0) || max_outputs == Some(0) {
            return Err(err("params: a count limit of 0"));
        }
        Ok(Self {
            issuer,
            keysets,
            max_inputs,
            max_outputs,
            max_fund,
            fund_quote,
            unknown,
        })
    }

    /// Serializes the parameters, keysets sorted by `id`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        use param_types as t;
        let mut ks = self.keysets.clone();
        ks.sort_by_key(|k| k.id);
        let list: Vec<Vec<u8>> = ks.iter().map(KeysetEntry::to_bytes).collect();
        let mut recs = vec![
            (t::ISSUER, self.issuer.as_bytes().to_vec()),
            (t::KEYSETS, entry_list(&list)),
        ];
        if let Some(n) = self.max_inputs {
            recs.push((t::MAX_INPUTS, tu64(n)));
        }
        if let Some(n) = self.max_outputs {
            recs.push((t::MAX_OUTPUTS, tu64(n)));
        }
        if let Some(n) = self.max_fund {
            recs.push((t::MAX_FUND, tu64(n)));
        }
        if let Some(q) = &self.fund_quote {
            recs.push((t::FUND_QUOTE, q.to_bytes()));
        }
        recs.extend(self.unknown.iter().cloned());
        sorted(recs)
    }

    /// `max_inputs`, or the default.
    #[must_use]
    pub fn max_inputs(&self) -> u64 {
        self.max_inputs.unwrap_or(DEFAULT_MAX_COUNT)
    }

    /// `max_outputs`, or the default.
    #[must_use]
    pub fn max_outputs(&self) -> u64 {
        self.max_outputs.unwrap_or(DEFAULT_MAX_COUNT)
    }

    /// The keyset entry for `id`.
    #[must_use]
    pub fn keyset(&self, id: &KeysetIdBytes) -> Option<&KeysetEntry> {
        self.keysets.iter().find(|k| &k.id == id)
    }
}

/// One blind signature in a `scheme_result` (7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureEntry {
    /// The zero-based index of the output in the body.
    pub index: u64,
    /// `C' = a·B'`.
    pub c: PointBytes,
    /// The NUT-12 DLEQ challenge.
    pub e: [u8; 32],
    /// The NUT-12 DLEQ response.
    pub s: [u8; 32],
}

impl SignatureEntry {
    /// The entry's stream: the `index` record is always written, as the
    /// two bytes `00 00` for index 0 (7.3, P32).
    #[must_use]
    pub fn entry_bytes(&self) -> Vec<u8> {
        use sig_types as t;
        let mut s = Vec::with_capacity(106);
        write_record(&mut s, t::INDEX, &tu64(self.index));
        write_record(&mut s, t::C_, &self.c);
        write_record(&mut s, t::E, &self.e);
        write_record(&mut s, t::S, &self.s);
        s
    }

    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        use sig_types as t;
        let w = "signature entry";
        let s =
            TlvStream::parse(bytes, StreamKind::TopLevel).map_err(|e| err(format!("{w}: {e}")))?;
        for (typ, v) in s.records() {
            if ![t::INDEX, t::C_, t::E, t::S].contains(typ) {
                return Err(err(format!("{w}: record type {typ} is not defined here")));
            }
            // Only the index may be empty (index 0).
            if v.is_empty() && *typ != t::INDEX {
                return Err(err(format!("{w}: record {typ} has an empty value")));
            }
        }
        // An entry without `index` is index 0 (draft-00 section 2: absent and
        // empty mean the same), never a reason to reject it alone (7.3).
        let index = match s.get(t::INDEX) {
            Some(v) => read_tu64(v, t::INDEX).map_err(|e| err(format!("{w}: {e}")))?,
            None => 0,
        };
        Ok(Self {
            index,
            c: point(required(&s, t::C_, w)?, t::C_, w)?,
            e: fixed::<32>(required(&s, t::E, w)?, t::E, w)?,
            s: fixed::<32>(required(&s, t::S, w)?, t::S, w)?,
        })
    }
}

/// Serializes a `scheme_result` (7.3): `None` when nothing was signed, so
/// the Response omits record 16 (P17); otherwise the entries in ascending
/// `index` order.
#[must_use]
pub fn encode_scheme_result(entries: &[SignatureEntry]) -> Option<Vec<u8>> {
    if entries.is_empty() {
        return None;
    }
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(|e| e.index);
    let list: Vec<Vec<u8>> = sorted_entries
        .iter()
        .map(SignatureEntry::entry_bytes)
        .collect();
    let mut out = Vec::new();
    write_record(&mut out, 0, &entry_list(&list));
    Some(out)
}

/// Parses a `scheme_result` under the rules of 3.5, with the one exception
/// 7.3 defines: an `index` may be empty or absent, which both mean 0.
/// Indices must be strictly ascending. Empty bytes are no signatures.
pub fn parse_scheme_result(bytes: &[u8]) -> Result<Vec<SignatureEntry>, WireError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let s = strict(bytes, &[0], "scheme_result")?;
    let mut out = Vec::new();
    for e in entries(required(&s, 0, "scheme_result")?, "signatures")? {
        out.push(SignatureEntry::parse(&e)?);
    }
    if out.windows(2).any(|w| w[0].index >= w[1].index) {
        return Err(err("scheme_result: indices are not strictly ascending"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(tag: u8) -> PointBytes {
        // hash_to_curve gives valid points for any input.
        bnap_core::note::hash_to_curve(&[tag]).unwrap()
    }

    fn key(tag: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(&pt(tag)[1..]);
        k
    }

    fn sample() -> Body {
        let mut inputs = vec![
            Input {
                keyset: [1; 33],
                amount: 4,
                key: key(1),
                c: pt(2),
            },
            Input {
                keyset: [1; 33],
                amount: 8,
                key: key(3),
                c: pt(4),
            },
        ];
        inputs.sort_by_key(|i| i.key);
        Body {
            inputs,
            outputs: vec![
                Output {
                    keyset: [1; 33],
                    amount: 1,
                    blinded: pt(5),
                },
                Output {
                    keyset: [1; 33],
                    amount: 2,
                    blinded: pt(6),
                },
            ],
            fund: Some("q1".into()),
        }
    }

    #[test]
    fn body_roundtrips_and_every_byte_matters() {
        let b = sample();
        let bytes = b.to_bytes().unwrap();
        assert_eq!(Body::parse(&bytes).unwrap(), b);
        // No proper prefix reads as the same body: inside a record it is a
        // framing error, at a record boundary a different body.
        for n in 0..bytes.len() {
            assert_ne!(Body::parse(&bytes[..n]).ok(), Some(b.clone()), "prefix {n}");
        }
        // Trailing bytes are refused.
        let mut more = bytes.clone();
        more.push(0);
        assert!(Body::parse(&more).is_err());
    }

    #[test]
    fn an_unknown_record_even_odd_or_grease_is_refused() {
        let bytes = sample().to_bytes().unwrap();
        for typ in [5u64, 6, 7, 3_000_000_001] {
            let mut b = bytes.clone();
            write_record(&mut b, typ, &[1]);
            assert!(Body::parse(&b).is_err(), "type {typ}");
        }
    }

    #[test]
    fn empty_values_and_empty_entries_are_refused() {
        let mut b = Vec::new();
        write_record(&mut b, body_types::INPUTS, &[]);
        assert!(Body::parse(&b).is_err());
        let mut b = Vec::new();
        write_record(&mut b, body_types::OUTPUTS, &[0]);
        assert!(Body::parse(&b).is_err(), "the empty stream as an entry");
    }

    #[test]
    fn order_and_duplicates() {
        let mut b = sample();
        b.inputs.reverse();
        assert!(b.to_bytes().is_err());
        let mut b = sample();
        b.inputs[1].key = b.inputs[0].key;
        assert!(b.to_bytes().is_err());
        let mut b = sample();
        b.outputs[1].blinded = b.outputs[0].blinded;
        assert!(b.to_bytes().is_err());
    }

    #[test]
    fn witness_must_match_the_body() {
        let b = sample();
        let w = Witness {
            input_sigs: vec![Signature([1; 64]), Signature([2; 64])],
            fund_sig: Some(Signature([3; 64])),
        };
        assert_eq!(Witness::parse(&w.to_bytes(), &b).unwrap(), w);
        let short = Witness {
            input_sigs: vec![Signature([1; 64])],
            ..w.clone()
        };
        assert!(Witness::parse(&short.to_bytes(), &b).is_err());
        let no_fund = Witness {
            fund_sig: None,
            ..w.clone()
        };
        assert!(Witness::parse(&no_fund.to_bytes(), &b).is_err());
        let mut nf = b.clone();
        nf.fund = None;
        assert!(Witness::parse(&w.to_bytes(), &nf).is_err());
    }

    #[test]
    fn scheme_result_writes_index_zero_as_an_empty_record() {
        let e = SignatureEntry {
            index: 0,
            c: pt(1),
            e: [2; 32],
            s: [3; 32],
        };
        let bytes = e.entry_bytes();
        assert_eq!(bytes.len(), 105);
        assert_eq!(&bytes[..4], &[0x00, 0x00, 0x02, 0x21]);
        let e5 = SignatureEntry { index: 5, ..e };
        let bytes5 = e5.entry_bytes();
        assert_eq!(bytes5.len(), 106);
        assert_eq!(&bytes5[..5], &[0x00, 0x01, 0x05, 0x02, 0x21]);
        let r = encode_scheme_result(&[e5, e]).unwrap();
        assert_eq!(parse_scheme_result(&r).unwrap(), vec![e, e5]);
        assert_eq!(encode_scheme_result(&[]), None);
        // An entry without the index record reads as index 0.
        let mut no_index = Vec::new();
        write_record(&mut no_index, sig_types::C_, &e.c);
        write_record(&mut no_index, sig_types::E, &e.e);
        write_record(&mut no_index, sig_types::S, &e.s);
        let mut r = Vec::new();
        write_record(&mut r, 0, &entry_list(&[no_index]));
        assert_eq!(parse_scheme_result(&r).unwrap(), vec![e]);
    }

    #[test]
    fn params_follow_the_even_odd_rule() {
        let p = Params {
            max_fund: Some(5000),
            fund_quote: Some(FundQuote {
                quote: "q".into(),
                request: "lnbcrt-test".into(),
                amount: 21,
                expiry: 9,
                pubkey: pt(9),
                unknown: Vec::new(),
            }),
            ..Params::new(
                "https://api.example/cashu",
                vec![KeysetEntry {
                    id: [1; 33],
                    input_fee_ppk: 100,
                    active: true,
                    unknown: Vec::new(),
                }],
            )
        };
        let bytes = p.to_bytes();
        assert_eq!(Params::parse(&bytes).unwrap(), p);
        let mut odd = bytes.clone();
        write_record(&mut odd, 101, b"x");
        assert_eq!(
            Params::parse(&odd).unwrap().unknown,
            vec![(101, b"x".to_vec())]
        );
        let mut even = bytes;
        write_record(&mut even, 100, b"x");
        assert!(Params::parse(&even).is_err());
    }
}
