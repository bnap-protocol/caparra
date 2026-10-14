//! One invoice per offer, shared by every Lightning scheme of the offer.
//!
//! An offer that lists L402 and `payment:lightning/charge` carries a native
//! challenge for each. Both embed the same invoice when the gate gives both
//! schemes one [`OfferInvoices`] over its Lightning rail: the first
//! `request` for an offer's `OfferID` (the memo, which becomes the invoice's
//! description hash) mints the invoice, and every later request for the same
//! offer, amount and unit gets the same one. That keeps the provisional rule
//! of at most one invoice per offer nonce (DECISIONS row 24) and lets one
//! payment answer either challenge, while the shared `ln` `RailId` still
//! admits it once (draft-00 6.1).
//!
//! The cache is bounded ([`OfferInvoices::with_capacity`]); the oldest
//! offers are forgotten first. Concurrent requests for one offer wait for
//! the first and share its invoice.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use bnap_plug::{Confirmed, FundingRail, PayId, PayRequest, PayState, RailError, RailRef};
use tokio::sync::OnceCell;

/// How many offers [`OfferInvoices::new`] remembers.
pub const DEFAULT_CAPACITY: usize = 4096;

type Key = ([u8; 32], u64, String);

#[derive(Default)]
struct Cache {
    cells: HashMap<Key, Arc<OnceCell<PayRequest>>>,
    order: VecDeque<Key>,
}

/// A [`FundingRail`] that makes at most one payment request per memo,
/// amount and unit, and passes everything else to the rail it wraps.
pub struct OfferInvoices {
    inner: Arc<dyn FundingRail>,
    capacity: usize,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for OfferInvoices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfferInvoices")
            .field("kind", &self.inner.kind())
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl OfferInvoices {
    /// Wraps `inner`, remembering [`DEFAULT_CAPACITY`] offers.
    #[must_use]
    pub fn new(inner: Arc<dyn FundingRail>) -> Self {
        Self::with_capacity(inner, DEFAULT_CAPACITY)
    }

    /// Wraps `inner`, remembering `capacity` offers (at least 1).
    #[must_use]
    pub fn with_capacity(inner: Arc<dyn FundingRail>, capacity: usize) -> Self {
        Self {
            inner,
            capacity: capacity.max(1),
            cache: Mutex::new(Cache::default()),
        }
    }

    fn cell(&self, key: Key) -> Arc<OnceCell<PayRequest>> {
        let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cell) = c.cells.get(&key) {
            return cell.clone();
        }
        while c.order.len() >= self.capacity {
            if let Some(old) = c.order.pop_front() {
                c.cells.remove(&old);
            }
        }
        let cell = Arc::new(OnceCell::new());
        c.cells.insert(key.clone(), cell.clone());
        c.order.push_back(key);
        cell
    }
}

#[async_trait::async_trait]
impl FundingRail for OfferInvoices {
    fn kind(&self) -> &str {
        self.inner.kind()
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        let cell = self.cell((memo, amount, unit.to_owned()));
        cell.get_or_try_init(|| self.inner.request(amount, unit, memo))
            .await
            .cloned()
    }

    async fn status(&self, id: &PayId) -> Result<PayState, RailError> {
        self.inner.status(id).await
    }

    async fn confirm(&self, reference: &RailRef) -> Result<Confirmed, RailError> {
        self.inner.confirm(reference).await
    }
}

#[cfg(test)]
mod tests {
    use bnap_core::test_support::block_on;
    use bnap_rail_fake::FakeRail;

    use super::*;

    #[test]
    fn one_offer_gets_one_invoice() {
        let fake = Arc::new(FakeRail::new([1; 32]));
        let rail = OfferInvoices::new(fake.clone());
        assert_eq!(rail.kind(), "ln");
        let a = block_on(rail.request(21, "sat", [5; 32])).unwrap();
        let b = block_on(rail.request(21, "sat", [5; 32])).unwrap();
        assert_eq!(a, b);
        assert_eq!(fake.invoice_count(), 1);
        // Another offer, amount or unit is another invoice.
        let others = [
            block_on(rail.request(21, "sat", [6; 32])).unwrap(),
            block_on(rail.request(22, "sat", [5; 32])).unwrap(),
            block_on(rail.request(21_000, "msat", [5; 32])).unwrap(),
        ];
        assert_eq!(fake.invoice_count(), 4);
        assert!(others.iter().all(|o| *o != a));
        // Status and confirmation pass through.
        let hash: [u8; 32] = a.id.0.clone().try_into().unwrap();
        fake.pay(&hash).unwrap();
        assert_eq!(block_on(rail.status(&a.id)).unwrap(), PayState::Paid);
        let reference = RailRef {
            kind: "ln".into(),
            reference: hash.to_vec(),
        };
        assert_eq!(block_on(rail.confirm(&reference)).unwrap().amount, 21);
    }

    #[test]
    fn concurrent_requests_for_one_offer_share_one_invoice() {
        let fake = Arc::new(FakeRail::new([1; 32]));
        let rail = Arc::new(OfferInvoices::new(fake.clone()));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (rail, barrier) = (rail.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    block_on(rail.request(21, "sat", [5; 32])).unwrap()
                })
            })
            .collect();
        let got: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(got.iter().all(|r| *r == got[0]));
        assert_eq!(fake.invoice_count(), 1);
    }

    #[test]
    fn a_failed_request_is_retried_and_the_cache_is_bounded() {
        let fake = Arc::new(FakeRail::new([1; 32]));
        let rail = OfferInvoices::with_capacity(fake.clone(), 2);
        fake.set_unavailable(true);
        assert!(block_on(rail.request(21, "sat", [5; 32])).is_err());
        fake.set_unavailable(false);
        let first = block_on(rail.request(21, "sat", [5; 32])).unwrap();
        block_on(rail.request(21, "sat", [6; 32])).unwrap();
        block_on(rail.request(21, "sat", [7; 32])).unwrap();
        // The oldest offer was forgotten, so it is minted again.
        let again = block_on(rail.request(21, "sat", [5; 32])).unwrap();
        assert_ne!(first, again);
        assert_eq!(fake.invoice_count(), 4);
    }
}
