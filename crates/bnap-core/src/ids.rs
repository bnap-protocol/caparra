//! Socket identifiers (draft-00 section 6.1): `UseId`, `RailId`, `ReplayKey`, and
//! the rate and quota counter keys of 6.2.
//!
//! A scheme's `verify` returns local IDs; the gate turns each into a socket
//! ID itself with [`use_id`], so no scheme can name an ID in another scheme's
//! space. Canonical payment bytes come from the operator-trusted rail plug,
//! never from the scheme.

use crate::encoding::{len_u64, tu64, write_bigsize, write_lp};
use crate::hash::{Context, CounterKey, RailId, ReplayKey, TaggedHasher, UseId, sha256, tags};

/// `UseId = H_"bnap/use"(lp(scheme ID) ‖ local ID)`.
#[must_use]
pub fn use_id(scheme: &str, local_id: &[u8]) -> UseId {
    let mut h = TaggedHasher::new(tags::USE);
    let mut l = Vec::new();
    write_lp(&mut l, scheme.as_bytes());
    h.update(&l);
    h.update(local_id);
    UseId(h.finish())
}

/// `RailId = H_"bnap/rail"(lp(rail kind) ‖ canonical payment bytes)`.
#[must_use]
pub fn rail_id(kind: &str, canonical: &[u8]) -> RailId {
    let mut h = TaggedHasher::new(tags::RAIL);
    let mut l = Vec::new();
    write_lp(&mut l, kind.as_bytes());
    h.update(&l);
    h.update(canonical);
    RailId(h.finish())
}

/// `ReplayKey = H_"bnap/replay"(Context ‖ H(pay body, or empty) ‖ H(attest
/// body₁) ‖ … ‖ H(attest bodyₙ) ‖ BigSize(m) ‖ id₁ ‖ … ‖ idₘ)`, with the ids
/// (every `UseId` and `RailId` of every scheme in the request, whatever its use
/// model) sorted bytewise.
///
/// The ids are sorted but not deduplicated, as in the reference encoder.
#[must_use]
pub fn replay_key(
    ctx: &Context,
    pay_body: &[u8],
    attest_bodies: &[&[u8]],
    ids: &[[u8; 32]],
) -> ReplayKey {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let mut h = TaggedHasher::new(tags::REPLAY);
    h.update(&ctx.0);
    h.update(&sha256(pay_body));
    for b in attest_bodies {
        h.update(&sha256(b));
    }
    let mut m = Vec::new();
    write_bigsize(&mut m, len_u64(sorted.len()));
    h.update(&m);
    for id in &sorted {
        h.update(id);
    }
    ReplayKey(h.finish())
}

fn counter_key(tag: &str, id: &UseId, limit: u64, epoch: u64, now: u64) -> Option<CounterKey> {
    let window = now.checked_div(epoch)?;
    let mut h = TaggedHasher::new(tag);
    h.update(&id.0);
    h.update(&tu64(limit));
    h.update(&tu64(epoch));
    h.update(&tu64(window));
    Some(CounterKey(h.finish()))
}

/// The `rate(k, epoch)` counter key of 6.2:
/// `H_"bnap/rate"(UseId ‖ tu64(k) ‖ tu64(epoch) ‖ tu64(⌊now / epoch⌋))`.
/// `None` when `epoch` is 0.
#[must_use]
pub fn rate_key(id: &UseId, k: u64, epoch: u64, now: u64) -> Option<CounterKey> {
    counter_key(tags::RATE, id, k, epoch, now)
}

/// The quota counter key of 6.2:
/// `H_"bnap/quota"(UseId ‖ tu64(value) ‖ tu64(epoch) ‖ tu64(⌊now / epoch⌋))`.
/// `None` when `epoch` is 0.
#[must_use]
pub fn quota_key(id: &UseId, value: u64, epoch: u64, now: u64) -> Option<CounterKey> {
    counter_key(tags::QUOTA, id, value, epoch, now)
}

/// The initial rail kinds of 6.1 and their canonical payment bytes.
pub mod rail {
    use crate::encoding::write_lp;

    /// Lightning.
    pub const LN: &str = "ln";
    /// Bitcoin on chain.
    pub const ONCHAIN: &str = "onchain";
    /// EVM token transfer.
    pub const EVM: &str = "evm";
    /// Card processor.
    pub const CARD: &str = "card";

    /// `ln`: the 32-byte payment hash.
    #[must_use]
    pub fn ln(payment_hash: &[u8; 32]) -> Vec<u8> {
        payment_hash.to_vec()
    }

    /// `onchain`: txid, 32 bytes ‖ output index as 4 bytes big-endian.
    #[must_use]
    pub fn onchain(txid: &[u8; 32], vout: u32) -> Vec<u8> {
        let mut v = txid.to_vec();
        v.extend_from_slice(&vout.to_be_bytes());
        v
    }

    /// `evm`: lp(CAIP-2 chain ID) ‖ token contract, 20 bytes ‖ payer, 20
    /// bytes ‖ authorization nonce, 32 bytes.
    #[must_use]
    pub fn evm(chain_id: &str, token: &[u8; 20], payer: &[u8; 20], nonce: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::new();
        write_lp(&mut v, chain_id.as_bytes());
        v.extend_from_slice(token);
        v.extend_from_slice(payer);
        v.extend_from_slice(nonce);
        v
    }

    /// `card`: lp(processor name) ‖ lp(processor's payment ID).
    #[must_use]
    pub fn card(processor: &str, payment_id: &str) -> Vec<u8> {
        let mut v = Vec::new();
        write_lp(&mut v, processor.as_bytes());
        write_lp(&mut v, payment_id.as_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_key_sorts_ids() {
        let ctx = Context([1; 32]);
        let a = [[3u8; 32], [2u8; 32]];
        let b = [[2u8; 32], [3u8; 32]];
        assert_eq!(
            replay_key(&ctx, b"x", &[], &a),
            replay_key(&ctx, b"x", &[], &b)
        );
    }

    #[test]
    fn counter_keys_need_an_epoch() {
        let id = use_id("s", b"l");
        assert!(rate_key(&id, 5, 0, 100).is_none());
        assert_eq!(rate_key(&id, 5, 60, 119), rate_key(&id, 5, 60, 60));
        assert_ne!(rate_key(&id, 5, 60, 120), rate_key(&id, 5, 60, 60));
        assert_ne!(rate_key(&id, 5, 60, 60), quota_key(&id, 5, 60, 60));
    }

    #[test]
    fn rail_bytes() {
        assert_eq!(rail::onchain(&[0; 32], 1).len(), 36);
        assert_eq!(
            rail::evm("eip155:8453", &[1; 20], &[2; 20], &[3; 32]).len(),
            12 + 72
        );
        assert_eq!(rail::card("p", "id"), b"\x01p\x02id");
    }
}
