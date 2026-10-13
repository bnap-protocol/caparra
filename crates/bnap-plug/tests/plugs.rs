//! The plug traits driven end to end through `dyn` objects: mock schemes, a
//! fake Lightning rail, a key-holding test signer and the in-memory store.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use bnap_core::credential::{Credential, OfferRef, SchemePart};
use bnap_core::hash::{Scope, sha256};
use bnap_core::ids::{rail, rail_id};
use bnap_core::limits::Limits;
use bnap_core::manifest::KeyUse;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::outcome::{self, Admitted, CommitError, ReceiptInput};
use bnap_core::pricing::{AdmitInput, PayValue};
use bnap_core::response::{Response, Status};
use bnap_core::schnorr::{Key, Signature, SigningKey};
use bnap_core::sign::{UnsignedOffer, UnsignedResponse};
use bnap_core::store::{CommitPlan, PlanInput, Settlement, UseModel};
use bnap_core::test_support::{MemoryStore, block_on};
use bnap_core::{ErrorCode, Offer};
use bnap_plug::{
    Action, BlindSignature, BlindedOutput, Budget, CappedSigner, Carrier, Challenge, Confirmed,
    CoreMessage, CredentialScheme, Decision, Dleq, Entry, FundingRail, KeysetId, OfferCtx, PayId,
    PayRequest, PayState, Point, RailError, RailRef, RawCredential, SchemeError, SchemeOffer,
    SettleCtx, Signer, SignerError, UseStore, Verified, VerifyCtx, confirm_rail_id,
};

const NOW: u64 = 1_791_700_000;
const AUX0: [u8; 32] = [0; 32];

// ---------------------------------------------------------------- signer

/// A signer that holds keys by use and records every blind-sign call.
struct TestSigner {
    offer: SigningKey,
    receipt: SigningKey,
    blind_calls: Mutex<Vec<u64>>,
    short_answer: bool,
}

impl TestSigner {
    fn new() -> Self {
        Self {
            offer: SigningKey::from_secret_bytes(&sha256(b"test offer key")).unwrap(),
            receipt: SigningKey::from_secret_bytes(&sha256(b"test receipt key")).unwrap(),
            blind_calls: Mutex::new(Vec::new()),
            short_answer: false,
        }
    }

    fn calls(&self) -> Vec<u64> {
        self.blind_calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let key = match msg.purpose().key_use() {
            KeyUse::Offer => &self.offer,
            KeyUse::Receipt => &self.receipt,
            KeyUse::Other(_) => return Err(SignerError::Refused("no such use".into())),
        };
        msg.sign_with(key, &AUX0)
            .map_err(|_| SignerError::Refused("key not held for this use".into()))
    }

    async fn verify_unblinded(
        &self,
        _keyset: &KeysetId,
        _amount: u64,
        y: &Point,
        c: &Point,
    ) -> Result<bool, SignerError> {
        // Stand-in for C == k·Y.
        Ok(y == c)
    }

    async fn blind_sign(
        &self,
        _keyset: &KeysetId,
        outputs: &[BlindedOutput],
        cap: u64,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        self.blind_calls.lock().unwrap().push(cap);
        let sum: u64 = outputs.iter().map(|o| o.amount).sum();
        if sum > cap {
            return Err(SignerError::OverCap { sum, cap });
        }
        let n = if self.short_answer {
            outputs.len().saturating_sub(1)
        } else {
            outputs.len()
        };
        Ok(outputs[..n]
            .iter()
            .map(|o| BlindSignature {
                amount: o.amount,
                signature: o.blinded,
                dleq: Dleq {
                    e: [0; 32],
                    s: [0; 32],
                },
            })
            .collect())
    }
}

fn outputs(amounts: &[u64]) -> Vec<BlindedOutput> {
    amounts
        .iter()
        .map(|a| BlindedOutput {
            amount: *a,
            blinded: Point([2; 33]),
        })
        .collect()
}

fn ks() -> KeysetId {
    KeysetId(vec![0, 1, 2, 3, 4, 5, 6, 7])
}

/// A change cap the way the gate gets one: from bnap-core's settlement.
fn cap_of(value: u64, price: u64) -> bnap_plug::ChangeCap {
    let mut o = OfferFields::new(Scope([1; 32]), NOW + 300, Key([9; 32]), [0; 16]);
    o.pay.push(PayEntry::new("bnap:notes", price, "sat"));
    let adm = bnap_core::pricing::admit(
        &AdmitInput {
            offer: &o,
            pay: Some(PayValue {
                scheme: "bnap:notes",
                value,
            }),
            attest: &[],
            now: NOW,
        },
        |_| 0,
    )
    .unwrap();
    adm.settle(Status::Ok, 0).cap
}

#[test]
fn the_capped_signer_refuses_outputs_above_the_cap() {
    let inner = Arc::new(TestSigner::new());
    let capped = CappedSigner::for_change(inner.clone(), cap_of(150, 50));
    assert_eq!(capped.cap(), Some(100));
    // 64 + 32 + 4 = 100: signed, and the cap goes to the signer too.
    let sigs = block_on(capped.blind_sign(&ks(), &outputs(&[64, 32, 4]))).unwrap();
    assert_eq!(sigs.len(), 3);
    assert_eq!(inner.calls(), vec![100]);
    // 64 + 32 + 8 = 104: refused before the signer is called.
    let err = block_on(capped.blind_sign(&ks(), &outputs(&[64, 32, 8]))).unwrap_err();
    assert_eq!(err, SignerError::OverCap { sum: 104, cap: 100 });
    assert_eq!(err.code(), ErrorCode::Unavailable);
    // An amount sum that overflows u64 is above any cap.
    let err = block_on(capped.blind_sign(&ks(), &outputs(&[u64::MAX, 1]))).unwrap_err();
    assert_eq!(
        err,
        SignerError::OverCap {
            sum: u64::MAX,
            cap: 100
        }
    );
    assert_eq!(inner.calls(), vec![100]);
}

#[test]
fn the_verify_only_view_signs_nothing() {
    let inner = Arc::new(TestSigner::new());
    let view = CappedSigner::verify_only(inner.clone());
    assert_eq!(view.cap(), None);
    assert!(block_on(view.verify_unblinded(&ks(), 8, &Point([3; 33]), &Point([3; 33]))).unwrap());
    assert!(matches!(
        block_on(view.blind_sign(&ks(), &[])),
        Err(SignerError::Refused(_))
    ));
    assert_eq!(inner.calls(), Vec::<u64>::new());
}

#[test]
fn a_signer_answer_that_does_not_match_the_outputs_is_refused() {
    let mut s = TestSigner::new();
    s.short_answer = true;
    let capped = CappedSigner::for_change(Arc::new(s), cap_of(100, 0));
    assert!(matches!(
        block_on(capped.blind_sign(&ks(), &outputs(&[1, 2]))),
        Err(SignerError::Refused(_))
    ));
}

#[test]
fn the_signer_signs_core_messages_with_the_key_for_their_use() {
    let signer: Arc<dyn Signer> = Arc::new(TestSigner::new());
    let t = TestSigner::new();
    let mut f = OfferFields::new(Scope([1; 32]), NOW + 300, t.offer.public_key(), [0; 16]);
    f.pay.push(PayEntry::new("httpauth:L402", 21, "sat"));
    let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
    let sig = block_on(signer.schnorr(unsigned.message())).unwrap();
    unsigned.finish(&sig).unwrap().verify_signature().unwrap();
    // An offer that names the receipt key: the signer holds that key only
    // for receipts, so it refuses.
    let mut wrong = f.clone();
    wrong.offer_key = t.receipt.public_key();
    let unsigned = UnsignedOffer::new(&wrong, Some(&[7; 32])).unwrap();
    assert!(matches!(
        block_on(signer.schnorr(unsigned.message())),
        Err(SignerError::Refused(_))
    ));
}

// ------------------------------------------------------- schemes and rail

/// A class O scheme whose local ID is its payment hash, like L402, or a
/// challenge ID, like MPP; both refer to the Lightning payment.
struct LnScheme {
    id: &'static str,
    local: fn(&[u8; 32]) -> Vec<u8>,
}

#[async_trait::async_trait]
impl CredentialScheme for LnScheme {
    fn id(&self) -> &str {
        self.id
    }

    async fn offer(&self, _cx: &OfferCtx<'_>) -> Result<SchemeOffer, SchemeError> {
        Ok(SchemeOffer::default())
    }

    async fn verify(&self, part: &SchemePart, cx: &VerifyCtx<'_>) -> Result<Verified, SchemeError> {
        let Entry::Pay(entry) = cx.entry else {
            return Err(SchemeError::rejected(self.id, "NOT_PAY", "attest entry"));
        };
        let hash: [u8; 32] = part
            .body
            .as_slice()
            .try_into()
            .map_err(|_| SchemeError::rejected(self.id, "BAD_BODY", "not 32 bytes"))?;
        Ok(Verified {
            use_ids: vec![(self.local)(&hash)],
            rail_ids: vec![RailRef {
                kind: rail::LN.into(),
                reference: hash.to_vec(),
            }],
            value: entry.amount,
            quota_id: None,
        })
    }

    async fn settle(
        &self,
        _part: &SchemePart,
        _verified: &Verified,
        cx: &SettleCtx<'_>,
        signer: &CappedSigner,
    ) -> Result<Option<Vec<u8>>, SchemeError> {
        // A class O scheme returns no change; it may not sign anything.
        assert_eq!(signer.cap(), Some(0));
        Ok(Some(format!("settled {}", cx.charged).into_bytes()))
    }
}

/// A Lightning rail that knows which payment hashes were paid.
struct FakeLn {
    paid: BTreeSet<[u8; 32]>,
}

#[async_trait::async_trait]
impl FundingRail for FakeLn {
    fn kind(&self) -> &str {
        rail::LN
    }

    async fn request(
        &self,
        amount: u64,
        unit: &str,
        memo: [u8; 32],
    ) -> Result<PayRequest, RailError> {
        Ok(PayRequest {
            id: PayId(memo.to_vec()),
            rail_kind: rail::LN.into(),
            request: "lnbc-test".into(),
            amount,
            unit: unit.into(),
            expires: NOW + 600,
        })
    }

    async fn status(&self, _id: &PayId) -> Result<PayState, RailError> {
        Ok(PayState::Paid)
    }

    async fn confirm(&self, r: &RailRef) -> Result<Confirmed, RailError> {
        let hash: [u8; 32] = r
            .reference
            .as_slice()
            .try_into()
            .map_err(|_| RailError::NotConfirmed("not a payment hash".into()))?;
        if !self.paid.contains(&hash) {
            return Err(RailError::NotConfirmed("unpaid".into()));
        }
        Ok(Confirmed {
            canonical: rail::ln(&hash),
            amount: 21,
            unit: "sat".into(),
        })
    }
}

fn l402() -> Arc<dyn CredentialScheme> {
    Arc::new(LnScheme {
        id: "httpauth:L402",
        local: |h| h.to_vec(),
    })
}

fn mpp() -> Arc<dyn CredentialScheme> {
    Arc::new(LnScheme {
        id: "payment:lightning/charge",
        local: |h| sha256(&[&b"mpp id "[..], h].concat()).to_vec(),
    })
}

#[test]
fn the_rail_supplies_the_rail_id() {
    let hash = sha256(b"preimage");
    let ln = FakeLn {
        paid: BTreeSet::from([hash]),
    };
    let r = RailRef {
        kind: "ln".into(),
        reference: hash.to_vec(),
    };
    assert_eq!(
        block_on(confirm_rail_id(&ln, &r)).unwrap(),
        rail_id(rail::LN, &hash)
    );
    // A scheme cannot point an ln payment at another rail kind's space.
    let lie = RailRef {
        kind: "onchain".into(),
        reference: hash.to_vec(),
    };
    let err = block_on(confirm_rail_id(&ln, &lie)).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BadCredential);
    let unpaid = RailRef {
        kind: "ln".into(),
        reference: sha256(b"other").to_vec(),
    };
    assert!(matches!(
        block_on(confirm_rail_id(&ln, &unpaid)),
        Err(RailError::NotConfirmed(_))
    ));
}

// ------------------------------------------------------------------ gate

struct Gate {
    store: MemoryStore,
    signer: Arc<TestSigner>,
    rail: FakeLn,
    offer: Offer,
    scope: Scope,
    limits: Limits,
}

impl Gate {
    fn new(paid: [u8; 32]) -> Self {
        let signer = Arc::new(TestSigner::new());
        let scope = Scope(sha256(b"POST /v1/thing"));
        let mut f = OfferFields::new(scope, NOW + 300, signer.offer.public_key(), [5; 16]);
        f.pay = vec![
            PayEntry::new("httpauth:L402", 21, "sat"),
            PayEntry::new("payment:lightning/charge", 21, "sat"),
        ];
        let unsigned = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
        let sig = block_on(signer.schnorr(unsigned.message())).unwrap();
        let offer = unsigned.finish(&sig).unwrap();
        Self {
            store: MemoryStore::new(),
            signer,
            rail: FakeLn {
                paid: BTreeSet::from([paid]),
            },
            offer,
            scope,
            limits: Limits::default(),
        }
    }

    /// Verify, confirm rails, price, commit, run, settle and sign the
    /// receipt, all through `dyn` plugs.
    fn handle(
        &self,
        scheme: &dyn CredentialScheme,
        cred: &Credential,
        now: u64,
    ) -> Result<Response, ErrorCode> {
        let offer_id = self.offer.offer_id();
        let ctx = cred.context(&offer_id, &self.scope);
        let digest = cred.digest(&ctx);
        let part = cred.pay.as_ref().unwrap();
        let (_, entry) = self.offer.fields().pay_entry(scheme.id()).unwrap();
        let view = CappedSigner::verify_only(self.signer.clone());
        let verified = block_on(scheme.verify(
            part,
            &VerifyCtx {
                now,
                offer: &self.offer,
                entry: Entry::Pay(entry),
                action_scope: &self.scope,
                context: &ctx,
                digest: &digest,
                signer: &view,
            },
        ))
        .map_err(|e| e.code())?;
        let rail_ids = verified
            .rail_ids
            .iter()
            .map(|r| block_on(confirm_rail_id(&self.rail, r)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.code())?;
        let store: &dyn UseStore = &self.store;
        let admission = block_on(outcome::admit(
            store,
            &AdmitInput {
                offer: self.offer.fields(),
                pay: Some(PayValue {
                    scheme: scheme.id(),
                    value: verified.value,
                }),
                attest: &[],
                now,
            },
        ))
        .map_err(|e| e.code())?;
        let plan = CommitPlan::build(&PlanInput {
            context: &ctx,
            pay_body: &part.body,
            attest_bodies: &[],
            schemes: &[verified.uses(scheme.id(), UseModel::Single)],
            rail_ids: &rail_ids,
            quota: admission.decision.quota.as_ref(),
            offer_expires: self.offer.fields().expires,
            now,
            replay_window: self.limits.replay_window,
        })
        .map_err(|e| e.code())?;
        let receipt_input = ReceiptInput {
            offer_id,
            digest,
            unit: Some(entry.unit.clone()),
            metered: false,
            receipt_key: self.signer.receipt.public_key(),
        };
        let fields = match block_on(outcome::commit(store, &plan, &self.limits)) {
            Err(e) => return Err(e.code()),
            Ok(Admitted::Replay(r)) => r.receipt(&receipt_input).unwrap(),
            Ok(Admitted::New) => {
                // The action runs here.
                let charge = admission.settle(Status::Ok, 0);
                let capped = CappedSigner::for_change(self.signer.clone(), charge.cap);
                let result = block_on(scheme.settle(
                    part,
                    &verified,
                    &SettleCtx {
                        now,
                        status: charge.status,
                        charged: charge.charged,
                        entry,
                        context: &ctx,
                        digest: &digest,
                    },
                    &capped,
                ))
                .map_err(|e| e.code())?;
                let s = Settlement::new(&charge, now).with_scheme_result(result);
                let rec = block_on(outcome::settle(store, plan.replay_key(), &s)).unwrap();
                outcome::receipt(&rec, &receipt_input, false).unwrap()
            }
        };
        let unsigned = UnsignedResponse::new(&fields).unwrap();
        let signer: &dyn Signer = &*self.signer;
        let ack = block_on(signer.schnorr(unsigned.message())).unwrap();
        Ok(unsigned.finish(&ack).unwrap())
    }
}

fn credential(scheme: &str, hash: [u8; 32], gate: &Gate) -> Credential {
    let mut c = Credential::new(OfferRef::Id(gate.offer.offer_id()));
    c.pay = Some(SchemePart::new(scheme, hash.to_vec()));
    c
}

#[test]
fn one_lightning_payment_under_two_schemes_admits_one_action() {
    let hash = sha256(b"preimage");
    let gate = Gate::new(hash);
    let (l402, mpp) = (l402(), mpp());
    let first = credential(l402.id(), hash, &gate);
    let receipt = gate.handle(&*l402, &first, NOW).unwrap();
    assert_eq!(receipt.fields().status, Status::Ok);
    assert_eq!(receipt.fields().charged, 21);
    assert_eq!(
        receipt.fields().scheme_result.as_deref(),
        Some(&b"settled 21"[..])
    );
    receipt.verify_ack().unwrap();

    // The same payment presented through MPP: its own use ID is new, but
    // the RailId is the same, so it is SPENT.
    let second = credential(mpp.id(), hash, &gate);
    assert_eq!(gate.handle(&*mpp, &second, NOW + 1), Err(ErrorCode::Spent));

    // The L402 credential again: a replay, signed afresh with replayed.
    let again = gate.handle(&*l402, &first, NOW + 2).unwrap();
    assert!(again.fields().replayed);
    assert_eq!(again.fields().settled_at, NOW);
    assert_eq!(again.fields().charged, 21);
    again.verify_ack().unwrap();
}

#[test]
fn an_unpaid_payment_never_reaches_commit() {
    let gate = Gate::new(sha256(b"paid"));
    let l402 = l402();
    let cred = credential(l402.id(), sha256(b"not paid"), &gate);
    assert_eq!(
        gate.handle(&*l402, &cred, NOW),
        Err(ErrorCode::BadCredential)
    );
    gate.store.inspect(|t| assert_eq!(t.outcomes_len(), 0));
}

#[test]
fn a_store_outage_fails_closed() {
    let hash = sha256(b"preimage");
    let gate = Gate::new(hash);
    gate.store.set_unavailable(true);
    let l402 = l402();
    let cred = credential(l402.id(), hash, &gate);
    // admit reads no counter here (no quota), so the commit is where it
    // fails, closed.
    assert_eq!(gate.handle(&*l402, &cred, NOW), Err(ErrorCode::Unavailable));
    let err = CommitError::Store(bnap_plug::StoreError("down".into()));
    assert_eq!(err.code(), ErrorCode::Unavailable);
}

// ------------------------------------------------- carrier, judge, wallet

/// A carrier over plain strings: request "METHOD path [credential hex]".
struct LineCarrier;

impl Carrier for LineCarrier {
    type Request = String;
    type Response = Vec<String>;

    fn name(&self) -> &'static str {
        "line"
    }

    fn action_scope(&self, req: &String) -> Result<Scope, bnap_core::Error> {
        let line = req.rsplit_once(' ').map_or(req.as_str(), |(head, _)| head);
        Ok(Scope(sha256(line.as_bytes())))
    }

    fn route_scope(&self, route_id: &str) -> Scope {
        Scope(sha256(route_id.as_bytes()))
    }

    fn extract(&self, req: &String) -> Result<Option<RawCredential>, bnap_core::Error> {
        let parts: Vec<&str> = req.split(' ').collect();
        Ok(parts
            .get(2)
            .and_then(|h| hex::decode(h).ok())
            .map(RawCredential::Bnap))
    }

    fn offer(&self, c: &Challenge<'_>, out: &mut Vec<String>) {
        out.extend(c.offers.iter().map(|o| hex::encode(o.bytes())));
        out.extend(c.natives.iter().map(|n| n.value.clone()));
    }

    fn receipt(&self, r: &Response, out: &mut Vec<String>) {
        out.push(hex::encode(r.bytes()));
    }

    fn error(&self, e: &bnap_core::ErrorObject, out: &mut Vec<String>) {
        out.push(format!("error {}", e.code));
    }
}

#[test]
fn carriers_judges_and_budgets() {
    let carrier: &dyn Carrier<Request = String, Response = Vec<String>> = &LineCarrier;
    assert_eq!(carrier.name(), "line");
    let req = "POST /x 0001".to_owned();
    assert_eq!(
        carrier.extract(&req).unwrap(),
        Some(RawCredential::Bnap(vec![0, 1]))
    );
    let gate = Gate::new([0; 32]);
    let mut out = Vec::new();
    carrier.offer(
        &Challenge {
            offers: std::slice::from_ref(&gate.offer),
            natives: &[],
            error: None,
        },
        &mut out,
    );
    assert_eq!(out.len(), 1);

    assert_eq!(Decision::Admit.error(), None);
    let q = Decision::Queue { retry_after: 7 }.error().unwrap();
    assert_eq!(
        (q.socket_code(), q.retry_after),
        (Some(ErrorCode::RateLimited), Some(7))
    );
    let r = Decision::Refuse {
        detail: "abuse".into(),
    }
    .error()
    .unwrap();
    assert_eq!(r.socket_code(), Some(ErrorCode::Policy));

    let req = PayRequest {
        id: PayId(vec![1]),
        rail_kind: "ln".into(),
        request: "lnbc-test".into(),
        amount: 21,
        unit: "sat".into(),
        expires: NOW,
    };
    let budget = |max, unit: &str| Budget {
        max,
        unit: unit.into(),
    };
    assert!(bnap_plug::pay::within_budget(&req, &budget(21, "sat")));
    assert!(!bnap_plug::pay::within_budget(&req, &budget(20, "sat")));
    assert!(!bnap_plug::pay::within_budget(&req, &budget(21, "msat")));

    let action = Action {
        route_id: "chat".into(),
        carrier: "line".into(),
        scope: Scope([0; 32]),
        route_scope: true,
        metered: true,
        meter: Some("tokens".into()),
    };
    assert_eq!(action.meter.as_deref(), Some("tokens"));
}

#[test]
fn scheme_errors_carry_a_namespaced_code() {
    let e = SchemeError::rejected("bnap:notes", "BAD_SIGNATURE", "input 2");
    assert_eq!(e.code(), ErrorCode::BadCredential);
    let obj = e.to_error_object();
    assert_eq!(obj.scheme_code.as_deref(), Some("bnap:notes/BAD_SIGNATURE"));
    assert_eq!(obj.detail, None, "the detail stays in the logs");
    assert_eq!(
        SchemeError::Unavailable("facilitator".into()).code(),
        ErrorCode::Unavailable
    );
    // The default native path is unsupported.
    let s = l402();
    assert_eq!(
        block_on(s.recover_native(b"token", NOW)),
        Err(SchemeError::Unsupported)
    );
}
