//! In-memory fake settlement rail for tests and local development.
//!
//! [`FakeRail`] is a deterministic Lightning [`FundingRail`] (kind `ln`).
//! It makes invoices whose preimages derive from a seed and a counter, so a
//! test sees the same payment hashes on every run, and it lets the test play
//! the payer: [`FakeRail::pay`] settles an invoice and hands out its
//! preimage, [`FakeRail::pay_amount`] settles it for another amount, and
//! [`FakeRail::set_state`] moves it to any [`PayState`].
//!
//! Like every rail, it reports the payment's canonical bytes (the 32-byte
//! payment hash, draft-00 6.1), its state and the amount received, so
//! `bnap_plug::confirm_rail_id` computes the `RailId` and admission counts
//! what the rail says was paid, never what a scheme claims.
//!
//! A [`PayId`] of this rail, like that of every `ln` rail in this
//! repository, is the 32-byte payment hash.
//!
//! Not for production: nothing here moves money.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use bnap_core::hash::{TaggedHasher, sha256};
use bnap_core::ids::rail;
use bnap_plug::{Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailRef};

/// How long an invoice lives unless [`FakeRail::with_ttl`] says otherwise:
/// five minutes, the lifetime of an exact-scope offer. Like every rail's
/// invoices, the fake's must not outlive the offer that carries them; the
/// Lightning schemes refuse to offer one that does.
pub const DEFAULT_TTL: u64 = 300;

/// The tag the preimages derive under.
const PREIMAGE_TAG: &str = "bnap-rail-fake/preimage";

/// One invoice the fake rail made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeInvoice {
    /// The payment hash, `SHA-256(preimage)`.
    pub payment_hash: [u8; 32],
    /// The preimage. A payer learns it only by paying ([`FakeRail::pay`]).
    pub preimage: [u8; 32],
    /// The amount asked for, in `unit`.
    pub amount: u64,
    /// `sat` or `msat`.
    pub unit: String,
    /// The 32 bytes the invoice commits to (its description hash).
    pub memo: [u8; 32],
    /// Unix seconds.
    pub expires: u64,
    /// The invoice's state.
    pub state: PayState,
    /// What was received, in `unit`; 0 until paid.
    pub received: u64,
    /// The invoice string a payer reads.
    pub invoice: String,
}

#[derive(Debug, Default)]
struct State {
    next: u64,
    invoices: BTreeMap<[u8; 32], FakeInvoice>,
}

/// A deterministic in-memory Lightning rail.
#[derive(Debug)]
pub struct FakeRail {
    seed: [u8; 32],
    state: Mutex<State>,
    now: AtomicU64,
    ttl: u64,
    unavailable: AtomicBool,
}

impl FakeRail {
    /// A rail whose preimages derive from `seed`. Its clock starts at 0;
    /// set it with [`FakeRail::set_now`].
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            state: Mutex::new(State::default()),
            now: AtomicU64::new(0),
            ttl: DEFAULT_TTL,
            unavailable: AtomicBool::new(false),
        }
    }

    /// The same rail with invoices that live `ttl` seconds.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the rail's clock, which dates new invoices.
    pub fn set_now(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    /// Makes every call fail with [`RailError::Unavailable`], or stops it.
    pub fn set_unavailable(&self, down: bool) {
        self.unavailable.store(down, Ordering::SeqCst);
    }

    /// The preimage the `n`th invoice (from 0) of a rail with `seed` gets.
    #[must_use]
    pub fn preimage_for(seed: &[u8; 32], n: u64) -> [u8; 32] {
        let mut h = TaggedHasher::new(PREIMAGE_TAG);
        h.update(seed);
        h.update(&n.to_be_bytes());
        h.finish()
    }

    /// Pays the invoice in full and returns its preimage, as a payer's
    /// wallet would learn it.
    pub fn pay(&self, payment_hash: &[u8; 32]) -> Option<[u8; 32]> {
        let mut st = self.lock();
        let inv = st.invoices.get_mut(payment_hash)?;
        inv.state = PayState::Paid;
        inv.received = inv.amount;
        Some(inv.preimage)
    }

    /// Settles the invoice as paid with `received` (in the invoice's unit),
    /// more or less than it asked, and returns its preimage.
    pub fn pay_amount(&self, payment_hash: &[u8; 32], received: u64) -> Option<[u8; 32]> {
        let mut st = self.lock();
        let inv = st.invoices.get_mut(payment_hash)?;
        inv.state = PayState::Paid;
        inv.received = received;
        Some(inv.preimage)
    }

    /// Moves the invoice to `state`. Returns false for an unknown invoice.
    pub fn set_state(&self, payment_hash: &[u8; 32], state: PayState) -> bool {
        let mut st = self.lock();
        match st.invoices.get_mut(payment_hash) {
            Some(inv) => {
                inv.state = state;
                true
            }
            None => false,
        }
    }

    /// The invoice with this payment hash.
    #[must_use]
    pub fn invoice(&self, payment_hash: &[u8; 32]) -> Option<FakeInvoice> {
        self.lock().invoices.get(payment_hash).cloned()
    }

    /// How many invoices the rail has made.
    #[must_use]
    pub fn invoice_count(&self) -> usize {
        self.lock().invoices.len()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn up(&self) -> Result<(), RailError> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(RailError::Unavailable("the fake rail is down".into()))
        } else {
            Ok(())
        }
    }
}

/// Reads a reference as a 32-byte payment hash.
fn payment_hash(bytes: &[u8]) -> Result<[u8; 32], RailError> {
    bytes
        .try_into()
        .map_err(|_| RailError::NotConfirmed("not a 32-byte payment hash".into()))
}

#[async_trait::async_trait]
impl FundingRail for FakeRail {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        self.up()?;
        if unit != "sat" && unit != "msat" {
            return Err(RailError::Unavailable(format!(
                "a Lightning rail takes sat or msat, not {unit}"
            )));
        }
        let now = self.now.load(Ordering::SeqCst);
        let mut st = self.lock();
        let preimage = Self::preimage_for(&self.seed, st.next);
        st.next += 1;
        let hash = sha256(&preimage);
        let invoice = format!("lnfake{amount}{unit}1{}", hex::encode(hash));
        let expires = now.saturating_add(self.ttl);
        st.invoices.insert(
            hash,
            FakeInvoice {
                payment_hash: hash,
                preimage,
                amount,
                unit: unit.to_owned(),
                memo,
                expires,
                state: PayState::Pending,
                received: 0,
                invoice: invoice.clone(),
            },
        );
        Ok(PayRequest {
            id: PayId(hash.to_vec()),
            rail_kind: rail::LN.to_owned(),
            request: invoice,
            amount,
            unit: unit.to_owned(),
            expires,
        })
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        self.up()?;
        let hash = payment_hash(&id.0)?;
        self.lock()
            .invoices
            .get(&hash)
            .map(|i| i.state)
            .ok_or_else(|| RailError::NotConfirmed("unknown invoice".into()))
    }

    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError> {
        self.up()?;
        if reference.kind != rail::LN {
            return Err(RailError::WrongKind {
                want: rail::LN.to_owned(),
                got: reference.kind.clone(),
            });
        }
        let hash = payment_hash(&reference.reference)?;
        let st = self.lock();
        let inv = st
            .invoices
            .get(&hash)
            .ok_or_else(|| RailError::NotConfirmed("no invoice with this payment hash".into()))?;
        Ok(Confirmed {
            canonical: rail::ln(&inv.payment_hash),
            state: inv.state,
            amount: inv.received,
            unit: inv.unit.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bnap_core::ErrorCode;
    use bnap_core::ids::rail_id;
    use bnap_core::test_support::block_on;
    use bnap_plug::{RailPayment, confirm_rail_id};

    use super::*;

    fn ln(hash: &[u8; 32]) -> RailRef {
        RailRef {
            kind: rail::LN.into(),
            reference: hash.to_vec(),
        }
    }

    fn hash_of(r: &PayRequest) -> [u8; 32] {
        r.id.0.as_slice().try_into().unwrap()
    }

    #[test]
    fn invoices_are_deterministic() {
        let a = FakeRail::new([1; 32]);
        let b = FakeRail::new([1; 32]);
        let ra = block_on(a.request(21, "sat", [9; 32])).unwrap();
        let rb = block_on(b.request(21, "sat", [9; 32])).unwrap();
        assert_eq!(ra, rb);
        let hash = hash_of(&ra);
        assert_eq!(hash, sha256(&FakeRail::preimage_for(&[1; 32], 0)));
        // A second invoice gets the next preimage.
        let second = block_on(a.request(21, "sat", [9; 32])).unwrap();
        assert_ne!(hash_of(&second), hash);
        assert_eq!(a.invoice_count(), 2);
        // Another seed, other invoices.
        let c = FakeRail::new([2; 32]);
        assert_ne!(
            hash_of(&block_on(c.request(21, "sat", [9; 32])).unwrap()),
            hash
        );
    }

    #[test]
    fn an_invoice_moves_from_pending_to_paid() {
        let rail = FakeRail::new([1; 32]).with_ttl(60);
        rail.set_now(1_000);
        let r = block_on(rail.request(21, "sat", [7; 32])).unwrap();
        assert_eq!(r.expires, 1_060);
        assert_eq!(r.rail_kind, "ln");
        assert_eq!((r.amount, r.unit.as_str()), (21, "sat"));
        let hash = hash_of(&r);
        assert_eq!(rail.invoice(&hash).unwrap().memo, [7; 32]);
        assert_eq!(block_on(rail.status(&r.id)).unwrap(), PayState::Pending);
        let c = block_on(rail.confirm(&ln(&hash))).unwrap();
        assert_eq!((c.state, c.amount), (PayState::Pending, 0));

        let preimage = rail.pay(&hash).unwrap();
        assert_eq!(sha256(&preimage), hash);
        assert_eq!(block_on(rail.status(&r.id)).unwrap(), PayState::Paid);
        let c = block_on(rail.confirm(&ln(&hash))).unwrap();
        assert_eq!(c.canonical, hash.to_vec());
        assert_eq!(
            (c.state, c.amount, c.unit.as_str()),
            (PayState::Paid, 21, "sat")
        );
    }

    #[test]
    fn default_invoices_end_with_a_five_minute_offer() {
        // An invoice must not outlive the exact-scope offer that carries it
        // (bnap-scheme-l402, bnap-scheme-mpp refuse to offer one), and those
        // offers live minutes (draft-00 section 10).
        let rail = FakeRail::new([1; 32]);
        rail.set_now(1_000);
        let r = block_on(rail.request(21, "sat", [7; 32])).unwrap();
        assert_eq!(r.expires, 1_300);
    }

    #[test]
    fn the_rail_reports_what_was_received_not_what_was_asked() {
        let rail = FakeRail::new([1; 32]);
        let r = block_on(rail.request(21_000, "msat", [0; 32])).unwrap();
        let hash = hash_of(&r);
        rail.pay_amount(&hash, 20_999).unwrap();
        let p = block_on(confirm_rail_id(&rail, &ln(&hash))).unwrap();
        assert_eq!(
            p,
            RailPayment {
                rail_id: rail_id(rail::LN, &hash),
                amount: 20_999,
                unit: "msat".into(),
            }
        );
    }

    #[test]
    fn only_a_paid_invoice_confirms() {
        let rail = FakeRail::new([1; 32]);
        let hash = hash_of(&block_on(rail.request(21, "sat", [0; 32])).unwrap());
        for state in [PayState::Pending, PayState::Expired, PayState::Failed] {
            assert!(rail.set_state(&hash, state));
            let err = block_on(confirm_rail_id(&rail, &ln(&hash))).unwrap_err();
            assert_eq!(err.code(), ErrorCode::BadCredential, "{state:?}");
        }
        // An unknown payment, a short reference and another rail kind.
        let err = block_on(confirm_rail_id(&rail, &ln(&[3; 32]))).unwrap_err();
        assert!(matches!(err, RailError::NotConfirmed(_)));
        let short = RailRef {
            kind: "ln".into(),
            reference: vec![1; 31],
        };
        assert!(matches!(
            block_on(rail.confirm(&short)),
            Err(RailError::NotConfirmed(_))
        ));
        let onchain = RailRef {
            kind: "onchain".into(),
            reference: hash.to_vec(),
        };
        assert!(matches!(
            block_on(rail.confirm(&onchain)),
            Err(RailError::WrongKind { .. })
        ));
        assert!(!rail.set_state(&[3; 32], PayState::Paid));
        assert_eq!(rail.pay(&[3; 32]), None);
    }

    #[test]
    fn a_down_rail_fails_closed_and_units_are_checked() {
        let rail = FakeRail::new([1; 32]);
        let hash = hash_of(&block_on(rail.request(1, "sat", [0; 32])).unwrap());
        rail.pay(&hash).unwrap();
        rail.set_unavailable(true);
        let err = block_on(confirm_rail_id(&rail, &ln(&hash))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(block_on(rail.request(1, "sat", [0; 32])).is_err());
        assert!(block_on(rail.status(&PayId(hash.to_vec()))).is_err());
        rail.set_unavailable(false);
        assert!(block_on(confirm_rail_id(&rail, &ln(&hash))).is_ok());
        assert!(matches!(
            block_on(rail.request(1, "USD", [0; 32])),
            Err(RailError::Unavailable(_))
        ));
    }
}
