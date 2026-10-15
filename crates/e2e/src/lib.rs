//! End-to-end tests across the BNAP plugs.
//!
//! This crate holds a small gate ([`Gate`]) that runs the socket's flow
//! with real scheme and rail plugs: it issues exact-scope offers with each
//! class O scheme's native artifact, runs the offer checks of draft-00 4.4,
//! verifies a credential with its scheme, confirms every payment with the
//! Lightning rail, and hands the rest to `bnap_core::outcome::process`,
//! then settles and signs the receipt from the recorded outcome. It takes a
//! BNAP Credential ([`Gate::handle`]) or a native credential through the
//! synthetic envelope of draft-00 5.4 ([`Gate::handle_native`]).
//!
//! The use store is bnap-core's in-memory `MemoryStore` and the signer a
//! test signer with fixed keys: this is a test harness, not the gate (that
//! is `caparra-gate`).
//!
//! `tests/lightning.rs` runs one Lightning payment through L402 and
//! `payment:lightning/charge` against the fake rail. With the `regtest`
//! feature, `tests/regtest.rs` runs the LND rail against the network of
//! `devenv/regtest`, and `tests/gate.rs` runs the real binaries end to end:
//! `caparra-gate run` (LND rail, SQLite store, process signer),
//! `bnap-signer --store`, and the `bnap` CLI behind a TLS front.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use bnap_core::credential::{SchemePart, native_context, native_digest};
use bnap_core::hash::{Context, Digest, OfferId, Scope, sha256};
use bnap_core::limits::Limits;
use bnap_core::offer::{GateOfferCheck, NativeEntry, OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, ReceiptInput, Recorded, Request};
use bnap_core::pricing::{ChangeCap, PayValue, Refund};
use bnap_core::response::{Response, Status};
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::{CoreMessage, UnsignedOffer};
use bnap_core::store::{Settlement, UseModel, UseStore};
use bnap_core::test_support::MemoryStore;
use bnap_core::{BindingClass, Credential, ErrorCode, ErrorObject, Offer, SettleError};
use bnap_plug::{
    BlindSignature, BlindedOutput, CappedSigner, ChangeLimit, CredentialScheme, Entry, FundingRail,
    KeysetId, NativeCtx, OfferCtx, OfferRole, Point, RailPayment, SettleCtx, Signer, SignerError,
    Verified, VerifyCtx, confirm_rail_id,
};

/// How long the offers this gate issues live, in seconds. The rail's
/// invoices must not live longer (beyond the 60 s skew): the Lightning
/// schemes refuse to offer such an invoice, so [`Gate::issue`] fails
/// UNAVAILABLE.
pub const OFFER_LIFETIME: u64 = 300;

/// What the registry says about a scheme, as the gate reads it: binding
/// class, use model and refund property. Only the two Lightning schemes.
#[must_use]
pub fn registered(scheme: &str) -> Option<(BindingClass, UseModel, Refund)> {
    match scheme {
        bnap_scheme_l402::SCHEME_ID | bnap_scheme_mpp::SCHEME_ID => {
            Some((BindingClass::O, UseModel::Single, Refund::None))
        }
        _ => None,
    }
}

/// Why the gate did not answer with a receipt: the draft-00 code and, for
/// a scheme rejection, the scheme's namespaced code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The socket error code.
    pub code: ErrorCode,
    /// The scheme's code, such as `httpauth:L402/OFFER_MISMATCH`.
    pub scheme_code: Option<String>,
}

impl Refused {
    fn code(code: ErrorCode) -> Self {
        Self {
            code,
            scheme_code: None,
        }
    }
}

impl From<ErrorObject> for Refused {
    fn from(e: ErrorObject) -> Self {
        Self {
            code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unavailable),
            scheme_code: e.scheme_code,
        }
    }
}

impl From<&bnap_core::Error> for Refused {
    fn from(e: &bnap_core::Error) -> Self {
        Self::code(e.code())
    }
}

/// A signer with one offer key and one receipt key. It checks no notes and
/// signs no change: the Lightning schemes need neither.
#[derive(Debug)]
pub struct GateSigner {
    offer: SigningKey,
    receipt: SigningKey,
}

impl GateSigner {
    /// Keys derived from fixed test strings.
    ///
    /// # Panics
    ///
    /// Never: the derived secrets are valid keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(&sha256(b"e2e offer key")).expect("valid key"),
            receipt: SigningKey::from_secret_bytes(&sha256(b"e2e receipt key")).expect("valid key"),
        }
    }

    /// The offer key.
    #[must_use]
    pub fn offer_key(&self) -> Key {
        self.offer.public_key()
    }

    /// The receipt key.
    #[must_use]
    pub fn receipt_key(&self) -> Key {
        self.receipt.public_key()
    }
}

impl Default for GateSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Signer for GateSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let key = if *msg.key() == self.offer.public_key() {
            &self.offer
        } else if *msg.key() == self.receipt.public_key() {
            &self.receipt
        } else {
            return Err(SignerError::Refused("key not held".into()));
        };
        msg.sign_with(key, &[0; 32])
            .map_err(|e| SignerError::Refused(e.to_string()))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        _unit: &str,
        _amount: u64,
        _secret: &[u8],
        _c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        Ok(None)
    }

    async fn blind_sign(
        &self,
        _keyset: &KeysetId,
        _outputs: &[BlindedOutput],
        _limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        Err(SignerError::Refused("this gate signs no change".into()))
    }
}

/// A test gate over the in-memory store, one Lightning rail and the scheme
/// plugs it is given.
pub struct Gate {
    store: Arc<MemoryStore>,
    signer: Arc<GateSigner>,
    rail: Arc<dyn FundingRail>,
    schemes: Vec<Arc<dyn CredentialScheme>>,
    offers: Mutex<HashMap<OfferId, Offer>>,
    mac_key: [u8; 32],
    limits: Limits,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("rail", &self.rail.kind())
            .field(
                "schemes",
                &self.schemes.iter().map(|s| s.id()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// Everything one pay part needs on its way through the socket.
struct Pay<'a> {
    offer: &'a Offer,
    scheme: &'a dyn CredentialScheme,
    part: &'a SchemePart,
    context: Context,
    digest: Digest,
    now: u64,
}

impl Gate {
    /// A gate that confirms payments with `rail` and accepts `schemes`.
    #[must_use]
    pub fn new(rail: Arc<dyn FundingRail>, schemes: Vec<Arc<dyn CredentialScheme>>) -> Self {
        Self {
            store: Arc::new(MemoryStore::new()),
            signer: Arc::new(GateSigner::new()),
            rail,
            schemes,
            offers: Mutex::new(HashMap::new()),
            mac_key: [0x6b; 32],
            limits: Limits::default(),
        }
    }

    /// The use store.
    #[must_use]
    pub fn store(&self) -> &MemoryStore {
        &self.store
    }

    /// The receipt key a client checks the ack under.
    #[must_use]
    pub fn receipt_key(&self) -> Key {
        self.signer.receipt_key()
    }

    fn scheme(&self, id: &str) -> Option<&Arc<dyn CredentialScheme>> {
        self.schemes.iter().find(|s| s.id() == id)
    }

    fn cached(&self, id: &OfferId) -> Option<Offer> {
        self.offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn check(&self, now: u64, scope: Scope) -> GateOfferCheck<'_> {
        GateOfferCheck {
            now,
            max_offer: self.limits.max_offer,
            mac_keys: std::slice::from_ref(&self.mac_key),
            offer_keys: &[],
            action_scope: scope,
            route_scope: None,
        }
    }

    /// Issues an exact-scope offer for `scope` with one pay entry per
    /// `(scheme, sat)` and each scheme's native artifact (4.2), and caches
    /// it by `OfferID` (5.1).
    pub async fn issue(
        &self,
        scope: Scope,
        pay: &[(&str, u64)],
        nonce: [u8; 16],
        now: u64,
    ) -> Result<Offer, Refused> {
        let expires = now + OFFER_LIFETIME;
        let mut f = OfferFields::new(scope, expires, self.signer.offer_key(), nonce);
        for (id, amount) in pay {
            let scheme = self
                .scheme(id)
                .ok_or(Refused::code(ErrorCode::NotOffered))?;
            let params = scheme
                .offer(&OfferCtx {
                    now,
                    route_id: "e2e",
                    scope: &scope,
                    route_scope: false,
                    metered: false,
                    expires,
                    role: OfferRole::Pay {
                        amount: *amount,
                        unit: "sat",
                    },
                })
                .await
                .map_err(|e| Refused::from(e.to_error_object()))?;
            let mut entry = PayEntry::new(*id, *amount, "sat");
            entry.params = params.params;
            f.pay.push(entry);
        }
        let offer_id = f.offer_id().map_err(|e| Refused::from(&e))?;
        for (i, entry) in f.pay.clone().iter().enumerate() {
            let scheme = self
                .scheme(&entry.scheme)
                .ok_or(Refused::code(ErrorCode::NotOffered))?;
            let natives = scheme
                .natives(&NativeCtx {
                    now,
                    offer_id: &offer_id,
                    entry,
                    pay_index: i,
                    expires,
                })
                .await
                .map_err(|e| Refused::from(e.to_error_object()))?;
            for n in natives {
                f.native.push(NativeEntry::new(i as u64, n.kind, n.data));
            }
        }
        let unsigned = UnsignedOffer::new(&f, Some(&self.mac_key))
            .map_err(|_| Refused::code(ErrorCode::Unavailable))?;
        let sig = self
            .signer
            .schnorr(unsigned.message())
            .await
            .map_err(|_| Refused::code(ErrorCode::Unavailable))?;
        let offer = unsigned
            .finish(&sig)
            .map_err(|_| Refused::code(ErrorCode::Unavailable))?;
        self.offers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(offer.offer_id(), offer.clone());
        Ok(offer)
    }

    /// Handles a request carrying a BNAP Credential for the action `scope`.
    pub async fn handle(
        &self,
        cred: &Credential,
        scope: Scope,
        now: u64,
    ) -> Result<Response, Refused> {
        let offer = self
            .check(now, scope)
            .check_credential(cred, |id| self.cached(id))
            .map_err(|e| Refused::from(&e))?;
        cred.check_binding_classes(|s| registered(s).map(|r| r.0))
            .map_err(|e| Refused::from(&e))?;
        let part = cred
            .pay
            .as_ref()
            .ok_or(Refused::code(ErrorCode::Malformed))?;
        let scheme = self
            .scheme(&part.scheme)
            .ok_or(Refused::code(ErrorCode::NotOffered))?;
        let context = cred.context(&offer.offer_id(), &scope);
        let digest = cred.digest(&context);
        self.pay(&Pay {
            offer: &offer,
            scheme: &**scheme,
            part,
            context,
            digest,
            now,
        })
        .await
    }

    /// Handles a request carrying only a native credential of `scheme_id`
    /// (draft-00 5.4): the adapter recovers the `OfferID`, the gate takes
    /// the offer from its cache, checks it, and builds the synthetic
    /// envelope over the native bytes.
    pub async fn handle_native(
        &self,
        scheme_id: &str,
        native: &[u8],
        scope: Scope,
        now: u64,
    ) -> Result<Response, Refused> {
        let scheme = self
            .scheme(scheme_id)
            .ok_or(Refused::code(ErrorCode::NotOffered))?;
        let recovered = scheme
            .recover_native(native, now)
            .await
            .map_err(|e| Refused::from(e.to_error_object()))?;
        let offer = self
            .cached(&recovered.offer_id)
            .ok_or(Refused::code(ErrorCode::BadOffer))?;
        self.check(now, scope)
            .check_native(&offer, scheme_id)
            .map_err(|e| Refused::from(&e))?;
        let context = native_context(&offer.offer_id(), &scope, scheme_id);
        let digest = native_digest(&context, native);
        self.pay(&Pay {
            offer: &offer,
            scheme: &**scheme,
            part: &recovered.part,
            context,
            digest,
            now,
        })
        .await
    }

    /// Verify, confirm, `process`, settle and sign, in the socket's order.
    async fn pay(&self, p: &Pay<'_>) -> Result<Response, Refused> {
        let id = p.scheme.id();
        let (model, refund) = registered(id)
            .map(|r| (r.1, r.2))
            .ok_or(Refused::code(ErrorCode::NotOffered))?;
        let (_, entry) = p
            .offer
            .fields()
            .pay_entry(id)
            .ok_or(Refused::code(ErrorCode::NotOffered))?;
        let view = CappedSigner::verify_only(self.signer.clone(), &entry.unit);
        let verified = p
            .scheme
            .verify(
                p.part,
                &VerifyCtx {
                    now: p.now,
                    offer: p.offer,
                    entry: Entry::Pay(entry),
                    action_scope: &p.offer.fields().scope,
                    context: &p.context,
                    digest: &p.digest,
                    signer: &view,
                },
            )
            .await
            .map_err(|e| Refused::from(e.to_error_object()))?;
        // The rail confirms every payment the scheme named: the RailId comes
        // from its bytes, the value from what it saw paid.
        let mut payments: Vec<RailPayment> = Vec::new();
        for r in &verified.rail_ids {
            let paid = confirm_rail_id(&*self.rail, r)
                .await
                .map_err(|e| Refused::code(e.code()))?;
            payments.push(paid);
        }
        let rail_ids: Vec<_> = payments.iter().map(|p| p.rail_id).collect();
        let mut backing: Vec<_> = payments.iter().map(RailPayment::backing).collect();
        backing.extend(view.notes());
        let schemes = [verified.uses(id, model)];
        let store: &dyn UseStore = &*self.store;
        let admitted = outcome::process(
            store,
            &Request {
                offer: p.offer.fields(),
                context: &p.context,
                pay_body: &p.part.body,
                attest_bodies: &[],
                schemes: &schemes,
                rail_ids: &rail_ids,
                pay: Some(PayValue {
                    scheme: id,
                    claimed: verified.value,
                    backing,
                    refund,
                }),
                attest: &[],
                now: p.now,
            },
            &self.limits,
        )
        .await
        .map_err(|e| Refused::from(e.to_error_object()))?;
        let recorded = match admitted {
            Admitted::Replay(r) if r.needs_refund() => self.refund(p, &verified, &r).await?,
            Admitted::Replay(r) => r,
            Admitted::New(pending) => {
                // The action runs here; it succeeds.
                let charge = pending.charge(Status::Ok, 0);
                let result = self
                    .settle_scheme(p, &verified, charge.cap(), charge.charged())
                    .await?;
                let s = Settlement::new(&charge, p.now).with_scheme_result(result);
                match outcome::settle(store, &pending, &s, &self.limits).await {
                    Ok(r) => r,
                    Err(SettleError::AlreadySettled(r)) if r.needs_refund() => {
                        self.refund(p, &verified, &r).await?
                    }
                    Err(SettleError::AlreadySettled(r)) => *r,
                    Err(_) => return Err(Refused::code(ErrorCode::Unavailable)),
                }
            }
        };
        let unsigned = recorded
            .unsigned_receipt(&ReceiptInput {
                offer_id: p.offer.offer_id(),
                digest: p.digest,
                unit: Some(entry.unit.clone()),
                metered: false,
                receipt_key: self.signer.receipt_key(),
            })
            .ok_or(Refused::code(ErrorCode::Unavailable))?
            .map_err(|_| Refused::code(ErrorCode::Unavailable))?;
        let ack = self
            .signer
            .schnorr(unsigned.message())
            .await
            .map_err(|_| Refused::code(ErrorCode::Unavailable))?;
        unsigned
            .finish(&ack)
            .map_err(|_| Refused::code(ErrorCode::Unavailable))
    }

    /// The scheme's settle inside one change budget, closed when it returns.
    async fn settle_scheme(
        &self,
        p: &Pay<'_>,
        verified: &Verified,
        cap: &ChangeCap,
        charged: u64,
    ) -> Result<Option<Vec<u8>>, Refused> {
        let (_, entry) = p
            .offer
            .fields()
            .pay_entry(p.scheme.id())
            .ok_or(Refused::code(ErrorCode::NotOffered))?;
        let (capped, guard) =
            CappedSigner::for_change(self.signer.clone(), self.store.clone(), cap);
        let result = p
            .scheme
            .settle(
                p.part,
                verified,
                &SettleCtx {
                    now: p.now,
                    status: cap.status(),
                    charged,
                    entry,
                    context: &p.context,
                    digest: &p.digest,
                },
                &capped,
            )
            .await;
        guard.close();
        result.map_err(|e| Refused::from(e.to_error_object()))
    }

    /// A timed-out outcome's refund: settle FAILED under the recorded cap,
    /// then record it once.
    async fn refund(
        &self,
        p: &Pay<'_>,
        verified: &Verified,
        r: &Recorded,
    ) -> Result<Recorded, Refused> {
        let cap = r
            .refund_cap()
            .ok_or(Refused::code(ErrorCode::Unavailable))?;
        let result = self.settle_scheme(p, verified, &cap, 0).await?;
        outcome::record_refund(&*self.store, r, result.as_deref())
            .await
            .map_err(|_| Refused::code(ErrorCode::Unavailable))
    }
}
