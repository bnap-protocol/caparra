//! Client-side building blocks for a notes wallet (sections 4, 6.3, 7.3,
//! 8.3 and 12): deriving note keys and outputs from a seed, building the
//! body and the witness for a Digest, choosing notes for a price, checking a
//! fund quote, minting it, and recovering change from a `scheme_result`.
//!
//! Nothing here keeps state or does I/O; the wallet (and its spend policy,
//! section 15) owns both. The curve math is cashu's.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use bnap_core::hash::{Digest, hmac_sha256};
use bnap_core::note::hash_to_curve;
use bnap_core::schnorr::SigningKey;
use bnap_core::secp256k1::{Scalar, SecretKey};
use cashu::nuts::{BlindSignature as CashuBlindSignature, BlindedMessage, Id, MintRequest};
use cashu::{Amount, Bolt11Invoice, PublicKey as CashuPublicKey, SecretKey as CashuSecretKey};

use crate::amount::{canonical_ladder, input_fee, select, value};
use crate::keyset::{BlindSigned, verify_dleq};
use crate::wire::{
    Body, FundQuote, Input, KeysetIdBytes, Output, PointBytes, WireError, Witness,
    parse_scheme_result,
};

/// The NUT-13 KDF prefix for version-01 keysets (12.1).
pub const KDF_PREFIX: &[u8] = b"Cashu_KDF_HMAC_SHA256";
/// NUT-13 derivation type of a blinding factor.
pub const TYPE_BLINDING: u8 = 0x01;
/// Derivation type of a note key (12.1, provisional P27; not yet assigned
/// by NUT-13).
pub const TYPE_NOTE_KEY: u8 = 0x02;
/// Bits of a counter that count within one slot (12.1, P27).
pub const SLOT_SHIFT: u32 = 48;

/// Why a client step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Bytes are not in the scheme's canonical form.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A key, point or scalar is not valid.
    #[error("bad key: {0}")]
    BadKey(String),
    /// A signature in a `scheme_result` names no output, or no key is known
    /// for its keyset and amount.
    #[error("unknown output: {0}")]
    UnknownOutput(String),
    /// A DLEQ proof does not verify: the issuer's evidence of misbehaviour.
    #[error("a DLEQ proof does not verify for output {0}")]
    BadDleq(u64),
    /// A fund quote fails the checks of 8.3.
    #[error("fund quote refused: {0}")]
    BadQuote(String),
}

/// The counter of output `index` in device or agent `slot` (12.1): the top
/// 16 bits name the slot, the low 48 count within it. `None` when `index`
/// does not fit 48 bits.
#[must_use]
pub fn counter(slot: u16, index: u64) -> Option<u64> {
    (index < (1 << SLOT_SHIFT)).then(|| (u64::from(slot) << SLOT_SHIFT) | index)
}

/// `d(type) = HMAC-SHA256(seed, "Cashu_KDF_HMAC_SHA256" ‖ keyset ID ‖
/// counter as 8 bytes big-endian ‖ type)` (12.1, NUT-13 for version-01
/// IDs).
#[must_use]
pub fn kdf(seed: &[u8], keyset: &KeysetIdBytes, counter: u64, typ: u8) -> [u8; 32] {
    let mut msg = Vec::with_capacity(KDF_PREFIX.len() + 33 + 9);
    msg.extend_from_slice(KDF_PREFIX);
    msg.extend_from_slice(keyset);
    msg.extend_from_slice(&counter.to_be_bytes());
    msg.push(typ);
    hmac_sha256(seed, &msg)
}

/// `int(d) mod n` as 32 bytes, or `None` when it is 0 (the wallet skips
/// that counter value, 12.1).
#[must_use]
pub fn scalar_mod_n(d: [u8; 32]) -> Option<[u8; 32]> {
    if let Ok(s) = Scalar::from_be_bytes(d) {
        return (s != Scalar::ZERO).then_some(d);
    }
    // d ≥ n, and d < 2²⁵⁶ < 2n, so d mod n = d − n, done here in base 2⁸.
    let n = Scalar::MAX.to_be_bytes();
    let mut out = [0u8; 32];
    // n = MAX + 1: subtract MAX, then 1.
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut v = i16::from(d[i]) - i16::from(n[i]) - borrow;
        borrow = i16::from(v < 0);
        if v < 0 {
            v += 256;
        }
        out[i] = u8::try_from(v).unwrap_or(0);
    }
    let mut borrow = 1u8;
    for b in out.iter_mut().rev() {
        let (v, under) = b.overflowing_sub(borrow);
        *b = v;
        borrow = u8::from(under);
        if borrow == 0 {
            break;
        }
    }
    (out != [0; 32]).then_some(out)
}

/// One output and note derived from a seed (4.1, 12.1).
#[derive(Clone, PartialEq, Eq)]
pub struct Derived {
    /// The keyset the derivation used.
    pub keyset: KeysetIdBytes,
    /// The counter value.
    pub counter: u64,
    /// `k_n`, the note key (type `0x02`).
    pub note_key: [u8; 32],
    /// `K`, its x-only public key.
    pub key: [u8; 32],
    /// `hex(K)`.
    pub secret: String,
    /// `Y = hash_to_curve(secret)`.
    pub y: PointBytes,
    /// `r`, the blinding factor (type `0x01`).
    pub r: [u8; 32],
    /// `B' = Y + r·G`.
    pub blinded: PointBytes,
}

impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Derived")
            .field("counter", &self.counter)
            .field("key", &hex::encode(self.key))
            .field("blinded", &hex::encode(self.blinded))
            .finish_non_exhaustive()
    }
}

/// Derives the note key, secret, `Y`, blinding factor and `B'` for one
/// counter value of one keyset (4.1, 12.1). `None` when `k_n` or `r` is 0:
/// the wallet skips that counter value.
#[must_use]
pub fn derive(seed: &[u8], keyset: &KeysetIdBytes, counter: u64) -> Option<Derived> {
    let note_key = scalar_mod_n(kdf(seed, keyset, counter, TYPE_NOTE_KEY))?;
    let r = scalar_mod_n(kdf(seed, keyset, counter, TYPE_BLINDING))?;
    let key = SigningKey::from_secret_bytes(&note_key)
        .ok()?
        .public_key()
        .0;
    let secret = hex::encode(key);
    let y = hash_to_curve(secret.as_bytes())?;
    let rk = CashuSecretKey::from_slice(&r).ok()?;
    let (b, _) = cashu::dhke::blind_message(secret.as_bytes(), Some(rk)).ok()?;
    Some(Derived {
        keyset: *keyset,
        counter,
        note_key,
        key,
        secret,
        y,
        r,
        blinded: b.to_bytes(),
    })
}

/// An output the wallet sent, with what it needs to unblind the signature
/// on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOutput {
    /// The output as the body carries it.
    pub output: Output,
    /// Its derivation.
    pub derived: Derived,
}

/// Outputs of these amounts on `keyset`, from counter `start` on, skipping
/// counter values that derive a zero key. Returns them and the next unused
/// counter. A wallet MUST NOT reuse a counter once its `B'` was sent (12.1).
#[must_use]
pub fn derive_outputs(
    seed: &[u8],
    keyset: &KeysetIdBytes,
    amounts: &[u64],
    start: u64,
) -> (Vec<PendingOutput>, u64) {
    let mut out = Vec::with_capacity(amounts.len());
    let mut c = start;
    for &amount in amounts {
        let d = loop {
            let d = derive(seed, keyset, c);
            c += 1;
            if let Some(d) = d {
                break d;
            }
        };
        out.push(PendingOutput {
            output: Output {
                keyset: *keyset,
                amount,
                blinded: d.blinded,
            },
            derived: d,
        });
    }
    (out, c)
}

/// The canonical ladder of outputs for `value` (6.3, P13).
#[must_use]
pub fn ladder_outputs(
    seed: &[u8],
    keyset: &KeysetIdBytes,
    value: u64,
    start: u64,
) -> (Vec<PendingOutput>, u64) {
    derive_outputs(seed, keyset, &canonical_ladder(value), start)
}

/// A note the wallet holds: a Cashu proof whose secret is `hex(K)`, and the
/// key `k_n` that spends it (4.1).
#[derive(Clone, PartialEq, Eq)]
pub struct Note {
    /// Its keyset.
    pub keyset: KeysetIdBytes,
    /// Its amount.
    pub amount: u64,
    /// `k_n`.
    pub note_key: [u8; 32],
    /// `C`.
    pub c: PointBytes,
}

impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Note")
            .field("keyset", &hex::encode(self.keyset))
            .field("amount", &self.amount)
            .field("c", &hex::encode(self.c))
            .finish_non_exhaustive()
    }
}

impl Note {
    /// `K`.
    pub fn key(&self) -> Result<[u8; 32], ClientError> {
        Ok(SigningKey::from_secret_bytes(&self.note_key)
            .map_err(|e| ClientError::BadKey(e.to_string()))?
            .public_key()
            .0)
    }

    /// The input entry that spends it.
    pub fn input(&self) -> Result<Input, ClientError> {
        Ok(Input {
            keyset: self.keyset,
            amount: self.amount,
            key: self.key()?,
            c: self.c,
        })
    }

    /// `Y`, its single-use ID.
    pub fn y(&self) -> Result<PointBytes, ClientError> {
        hash_to_curve(hex::encode(self.key()?).as_bytes())
            .ok_or_else(|| ClientError::BadKey("no point for the secret".into()))
    }
}

/// The body that spends `notes` (sorted by `K`, as 3.2 requires), with
/// `outputs` in the given order and an optional fund quote ID. Returns the
/// body and the notes in body order, for [`sign_witness`].
pub fn build_body(
    notes: &[Note],
    outputs: &[Output],
    fund: Option<&str>,
) -> Result<(Body, Vec<Note>), ClientError> {
    let mut ordered: Vec<(Input, Note)> = notes
        .iter()
        .map(|n| Ok((n.input()?, n.clone())))
        .collect::<Result<_, ClientError>>()?;
    ordered.sort_by_key(|(i, _)| i.key);
    let body = Body {
        inputs: ordered.iter().map(|(i, _)| *i).collect(),
        outputs: outputs.to_vec(),
        fund: fund.map(str::to_owned),
    };
    body.to_bytes()?;
    Ok((body, ordered.into_iter().map(|(_, n)| n).collect()))
}

/// The witness of 3.4 for `body` over `digest`: each input's `K` signs the
/// Digest (`notes` in body order, as [`build_body`] returns them), and the
/// fund quote's NUT-20 key signs it too when the body has `fund`. `aux` is
/// the BIP-340 auxiliary randomness.
pub fn sign_witness(
    body: &Body,
    notes: &[Note],
    fund_key: Option<&[u8; 32]>,
    digest: &Digest,
    aux: &[u8; 32],
) -> Result<Witness, ClientError> {
    if notes.len() != body.inputs.len() {
        return Err(ClientError::BadKey("one note per input".into()));
    }
    let mut w = Witness::default();
    for (n, i) in notes.iter().zip(&body.inputs) {
        let sk = SigningKey::from_secret_bytes(&n.note_key)
            .map_err(|e| ClientError::BadKey(e.to_string()))?;
        if sk.public_key().0 != i.key {
            return Err(ClientError::BadKey("notes are not in body order".into()));
        }
        w.input_sigs.push(sk.sign(&digest.0, aux));
    }
    if body.fund.is_some() {
        let k = fund_key.ok_or_else(|| ClientError::BadKey("no fund quote key".into()))?;
        let sk =
            SigningKey::from_secret_bytes(k).map_err(|e| ClientError::BadKey(e.to_string()))?;
        w.fund_sig = Some(sk.sign(&digest.0, aux));
    }
    Ok(w)
}

/// The compressed NUT-20 public key of a quote key, for `BNAP-Fund`.
pub fn quote_pubkey(quote_key: &[u8; 32]) -> Result<PointBytes, ClientError> {
    let sk = SecretKey::from_slice(quote_key).map_err(|e| ClientError::BadKey(e.to_string()))?;
    Ok(sk
        .public_key(&bnap_core::secp256k1::Secp256k1::signing_only())
        .serialize())
}

/// Notes chosen to pay a price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Indices into the wallet's notes, ascending.
    pub notes: Vec<usize>,
    /// Their value after input fees (6.3).
    pub value: u64,
}

/// Chooses notes worth at least `price` after input fees (6.3), at most
/// `max_inputs` of them, on keysets `fee_ppk` knows (the offer's keysets;
/// `None` for a keyset the offer does not list). Prefers the single
/// smallest note that pays, then adds notes largest first; `None` when the
/// notes cannot pay.
#[must_use]
pub fn select_notes(
    notes: &[Note],
    fee_ppk: impl Fn(&KeysetIdBytes) -> Option<u64>,
    price: u64,
    max_inputs: usize,
) -> Option<Selection> {
    let usable: Vec<(usize, u64)> = notes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| fee_ppk(&n.keyset).map(|f| (i, f)))
        .collect();
    let worth =
        |sel: &[(usize, u64)]| value(sel.iter().map(|&(i, f)| (notes[i].amount, f)), 0).ok();
    let mut by_amount = usable.clone();
    by_amount.sort_by_key(|&(i, _)| (notes[i].amount, i));
    if let Some(one) = by_amount
        .iter()
        .find(|&&n| worth(&[n]).is_some_and(|v| v >= price))
    {
        return Some(Selection {
            notes: vec![one.0],
            value: worth(&[*one])?,
        });
    }
    let mut chosen = Vec::new();
    for &n in by_amount.iter().rev() {
        if chosen.len() >= max_inputs {
            break;
        }
        chosen.push(n);
        if let Some(v) = worth(&chosen).filter(|v| *v >= price) {
            let mut idx: Vec<usize> = chosen.iter().map(|&(i, _)| i).collect();
            idx.sort_unstable();
            return Some(Selection {
                notes: idx,
                value: v,
            });
        }
    }
    None
}

/// The fee the offer's keysets put on these inputs (6.3).
#[must_use]
pub fn fee_of(inputs: &[Input], fee_ppk: impl Fn(&KeysetIdBytes) -> Option<u64>) -> Option<u64> {
    input_fee(
        inputs
            .iter()
            .map(|i| fee_ppk(&i.keyset))
            .collect::<Option<Vec<u64>>>()?,
    )
}

/// The change a client recovered from a Response (7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// The notes, one per signed output, in output order.
    pub notes: Vec<Note>,
    /// The signed output indices, ascending.
    pub indices: Vec<usize>,
    /// The signed indices are exactly the selection of 7.2 for `value -
    /// charged`. When false the operator is at fault and the signed
    /// Response is the evidence; the notes are still the client's.
    pub matches_rule: bool,
}

/// Checks and unblinds the change in a `scheme_result` (7.3): every index
/// names one of `outputs`, every DLEQ proof verifies against the keyset key
/// `A` for that output's amount (`key(keyset, amount)`, from the issuer's
/// NUT-01 keys the wallet checked), and only then is `C = C' - r·A`
/// computed. `value` is the value the client computed for its own body and
/// `charged` the Response's; a FAILED Response charges 0.
pub fn recover_change(
    outputs: &[PendingOutput],
    key: impl Fn(&KeysetIdBytes, u64) -> Option<PointBytes>,
    value: u64,
    charged: u64,
    scheme_result: Option<&[u8]>,
) -> Result<Recovered, ClientError> {
    let entries = parse_scheme_result(scheme_result.unwrap_or_default())?;
    let mut notes = Vec::with_capacity(entries.len());
    let mut indices = Vec::with_capacity(entries.len());
    for e in &entries {
        let idx = usize::try_from(e.index)
            .ok()
            .filter(|&i| i < outputs.len())
            .ok_or_else(|| ClientError::UnknownOutput(format!("index {}", e.index)))?;
        let p = &outputs[idx];
        let a = key(&p.output.keyset, p.output.amount)
            .ok_or_else(|| ClientError::UnknownOutput(format!("no key for output {idx}")))?;
        let signed = BlindSigned {
            c: e.c,
            e: e.e,
            s: e.s,
        };
        if !verify_dleq(&a, &p.output.blinded, &signed) {
            return Err(ClientError::BadDleq(e.index));
        }
        notes.push(Note {
            keyset: p.output.keyset,
            amount: p.output.amount,
            note_key: p.derived.note_key,
            c: unblind(&e.c, &p.derived.r, &a)?,
        });
        indices.push(idx);
    }
    let amounts: Vec<u64> = outputs.iter().map(|p| p.output.amount).collect();
    let matches_rule = select(&amounts, value.saturating_sub(charged)) == Some(indices.clone());
    Ok(Recovered {
        notes,
        indices,
        matches_rule,
    })
}

/// `C = C' - r·A` (NUT-00), cashu's unblinding.
pub fn unblind(c_: &PointBytes, r: &[u8; 32], a: &PointBytes) -> Result<PointBytes, ClientError> {
    let c_ = CashuPublicKey::from_slice(c_).map_err(|e| ClientError::BadKey(e.to_string()))?;
    let r = CashuSecretKey::from_slice(r).map_err(|e| ClientError::BadKey(e.to_string()))?;
    let a = CashuPublicKey::from_slice(a).map_err(|e| ClientError::BadKey(e.to_string()))?;
    Ok(cashu::dhke::unblind_message(&c_, &r, &a)
        .map_err(|e| ClientError::BadKey(e.to_string()))?
        .to_bytes())
}

/// The checks of 8.3 before paying a fund quote: the key is the one the
/// client sent, the amount is at most what it asked for and equals the
/// BOLT11 invoice's amount, and neither the quote nor the invoice has
/// expired at `now`. The offer's own checks (draft-00 4.4) come first and
/// are the caller's.
pub fn check_fund_quote(
    quote: &FundQuote,
    pubkey: &PointBytes,
    asked: u64,
    now: u64,
) -> Result<(), ClientError> {
    if &quote.pubkey != pubkey {
        return Err(ClientError::BadQuote(
            "the quote is locked to another key".into(),
        ));
    }
    if quote.amount > asked {
        return Err(ClientError::BadQuote("more than was asked for".into()));
    }
    if quote.expiry <= now {
        return Err(ClientError::BadQuote("the quote has expired".into()));
    }
    let invoice = Bolt11Invoice::from_str(&quote.request)
        .map_err(|e| ClientError::BadQuote(format!("not a BOLT11 invoice: {e}")))?;
    if invoice.amount_milli_satoshis() != quote.amount.checked_mul(1000) {
        return Err(ClientError::BadQuote(
            "the invoice is for another amount".into(),
        ));
    }
    if invoice.would_expire(Duration::from_secs(now)) {
        return Err(ClientError::BadQuote("the invoice has expired".into()));
    }
    Ok(())
}

/// The payment hash of a fund quote's invoice, for the wallet's records.
pub fn invoice_payment_hash(quote: &FundQuote) -> Result<[u8; 32], ClientError> {
    let invoice = Bolt11Invoice::from_str(&quote.request)
        .map_err(|e| ClientError::BadQuote(format!("not a BOLT11 invoice: {e}")))?;
    let h: &[u8] = invoice.payment_hash().as_ref();
    h.try_into()
        .map_err(|_| ClientError::BadQuote("bad payment hash".into()))
}

/// A NUT-04 mint request for a paid quote (8.5), signed with the quote's
/// NUT-20 key.
pub fn mint_request(
    quote: &str,
    outputs: &[Output],
    quote_key: &[u8; 32],
) -> Result<MintRequest<String>, ClientError> {
    let msgs = outputs
        .iter()
        .map(|o| {
            Ok(BlindedMessage {
                amount: Amount::from(o.amount),
                keyset_id: Id::from_bytes(&o.keyset)
                    .map_err(|e| ClientError::BadKey(e.to_string()))?,
                blinded_secret: CashuPublicKey::from_slice(&o.blinded)
                    .map_err(|e| ClientError::BadKey(e.to_string()))?,
                witness: None,
            })
        })
        .collect::<Result<Vec<_>, ClientError>>()?;
    let mut req = MintRequest {
        quote: quote.to_owned(),
        outputs: msgs,
        signature: None,
    };
    let sk =
        CashuSecretKey::from_slice(quote_key).map_err(|e| ClientError::BadKey(e.to_string()))?;
    req.sign(&sk)
        .map_err(|e| ClientError::BadKey(e.to_string()))?;
    Ok(req)
}

/// The notes a NUT-04 mint response pays for `outputs` (in request order),
/// each DLEQ proof checked first.
pub fn unblind_mint(
    outputs: &[PendingOutput],
    sigs: &[CashuBlindSignature],
    key: impl Fn(&KeysetIdBytes, u64) -> Option<PointBytes>,
) -> Result<Vec<Note>, ClientError> {
    if sigs.len() != outputs.len() {
        return Err(ClientError::UnknownOutput(
            "one signature per output".into(),
        ));
    }
    let mut notes = Vec::with_capacity(sigs.len());
    for (i, (p, s)) in outputs.iter().zip(sigs).enumerate() {
        let a = key(&p.output.keyset, p.output.amount)
            .ok_or_else(|| ClientError::UnknownOutput(format!("no key for output {i}")))?;
        let dleq = s.dleq.as_ref().ok_or(ClientError::BadDleq(i as u64))?;
        let signed = BlindSigned {
            c: s.c.to_bytes(),
            e: dleq.e.to_secret_bytes(),
            s: dleq.s.to_secret_bytes(),
        };
        if u64::from(s.amount) != p.output.amount || !verify_dleq(&a, &p.output.blinded, &signed) {
            return Err(ClientError::BadDleq(i as u64));
        }
        notes.push(Note {
            keyset: p.output.keyset,
            amount: p.output.amount,
            note_key: p.derived.note_key,
            c: unblind(&signed.c, &p.derived.r, &a)?,
        });
    }
    Ok(notes)
}

/// Public keys by keyset and amount, for [`recover_change`] and
/// [`unblind_mint`].
pub type KeyTable = BTreeMap<KeysetIdBytes, BTreeMap<u64, PointBytes>>;

/// A lookup over a [`KeyTable`].
pub fn key_lookup(table: &KeyTable) -> impl Fn(&KeysetIdBytes, u64) -> Option<PointBytes> + '_ {
    move |ks, amount| table.get(ks).and_then(|m| m.get(&amount)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_name_a_slot() {
        assert_eq!(counter(0, 5), Some(5));
        assert_eq!(counter(1, 0), Some(1 << 48));
        assert_eq!(counter(2, (1 << 48) - 1), Some((3 << 48) - 1));
        assert_eq!(counter(0, 1 << 48), None);
    }

    #[test]
    fn scalars_reduce_mod_n() {
        let n = {
            let mut m = Scalar::MAX.to_be_bytes();
            // MAX + 1 = n.
            for b in m.iter_mut().rev() {
                let (v, c) = b.overflowing_add(1);
                *b = v;
                if !c {
                    break;
                }
            }
            m
        };
        assert_eq!(scalar_mod_n(n), None, "n mod n is 0");
        let mut n1 = n;
        n1[31] += 1;
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(scalar_mod_n(n1), Some(one));
        assert_eq!(scalar_mod_n([0; 32]), None);
        assert_eq!(scalar_mod_n(one), Some(one));
        let mut max = [0xff; 32];
        let reduced = scalar_mod_n(max).unwrap();
        // 2²⁵⁶ − 1 − n.
        assert!(Scalar::from_be_bytes(reduced).is_ok());
        max[0] = 0x7f;
        assert_eq!(scalar_mod_n(max), Some(max));
    }

    #[test]
    fn derivation_is_deterministic_and_blinds_y() {
        let seed = [7u8; 64];
        let ks = [1u8; 33];
        let d = derive(&seed, &ks, 0).unwrap();
        assert_eq!(derive(&seed, &ks, 0).unwrap(), d);
        assert_ne!(derive(&seed, &ks, 1).unwrap().key, d.key);
        assert_eq!(d.secret, hex::encode(d.key));
        assert_eq!(Some(d.y), hash_to_curve(d.secret.as_bytes()));
        assert_ne!(d.blinded, d.y);
        // The note key matches cashu's NUT-13 type 0x01 derivation for r.
        let r = cashu::SecretKey::from_seed(
            &seed,
            Id::from_bytes(&{
                let mut k = [0u8; 33];
                k[0] = 1;
                k
            })
            .unwrap(),
            3,
        )
        .unwrap();
        let mut k01 = [0u8; 33];
        k01[0] = 1;
        assert_eq!(derive(&seed, &k01, 3).unwrap().r, r.to_secret_bytes());
    }
}
