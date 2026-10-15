//! A signer process that can reach the use store signs change only for
//! outputs the store reserved for the outcome: the server runs in this test
//! process, on a temporary socket, over a `MemoryStore`.

use std::sync::Arc;

use bnap_core::response::Status;
use bnap_core::test_support::MemoryStore;
use bnap_plug::{CappedSigner, ChangeLimit, Signer, SignerError, UseStore};
use bnap_signer_file::FileSigner;
use bnap_signer_file::testkit::{self, KEY_FILE};
use bnap_signer_process::{ProcessSigner, ServeOptions, Server, SignerSocket};

struct InProcess {
    _dir: tempfile::TempDir,
    signer: Arc<dyn Signer>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for InProcess {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn serve(store: Option<Arc<dyn UseStore>>) -> InProcess {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.sock");
    let socket = SignerSocket::bind(&path).unwrap();
    let server = Arc::new(Server::new(
        Arc::new(FileSigner::from_toml(KEY_FILE).unwrap()),
        ServeOptions {
            store,
            ..ServeOptions::default()
        },
    ));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(server.serve(socket, async {
        let _ = stopped.await;
    }));
    InProcess {
        _dir: dir,
        signer: Arc::new(ProcessSigner::new(path)),
        stop: Some(stop),
    }
}

fn limit_of(cap: &bnap_plug::ChangeCap) -> ChangeLimit {
    ChangeLimit {
        replay_key: *cap.replay_key(),
        status: cap.status(),
        unit: cap.unit().to_owned(),
        cap: cap.get(),
        keep_until: cap.keep_until(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_outputs_the_store_reserved_are_signed() {
    let store: Arc<dyn UseStore> = Arc::new(MemoryStore::new());
    let p = serve(Some(store.clone()));
    let fx = testkit::fixture();
    let pending = testkit::commit(&*store, 64, 21);
    let charge = pending.charge(Status::Ok, 0);
    let limit = limit_of(charge.cap());

    // Straight to the signer, past the gate's reservation: refused.
    let stray = testkit::outputs(&[32, 8]);
    let plain: Vec<_> = stray.iter().map(|o| o.output).collect();
    assert!(matches!(
        p.signer.blind_sign(&fx.active.id, &plain, &limit).await,
        Err(SignerError::Refused(m)) if m.contains("not reserved")
    ));

    // Through the gate's capped signer, which reserves first: signed.
    let (capped, guard) = CappedSigner::for_change(p.signer.clone(), store.clone(), charge.cap());
    let outs = testkit::outputs(&[32, 8, 2, 1]);
    let plain: Vec<_> = outs.iter().map(|o| o.output).collect();
    let sigs = capped.blind_sign(&fx.active.id, &plain).await.unwrap();
    for (o, s) in outs.iter().zip(&sigs) {
        let _ = testkit::check_and_unblind(&fx.active, o, s);
    }
    guard.close();

    // Reserved outputs may be signed again (the same notes); one new output
    // among them is refused.
    p.signer
        .blind_sign(&fx.active.id, &plain, &limit)
        .await
        .unwrap();
    let mut mixed = plain.clone();
    mixed.push(testkit::output(1).output);
    assert!(matches!(
        p.signer.blind_sign(&fx.active.id, &mixed, &limit).await,
        Err(SignerError::Refused(_))
    ));

    // Outputs reserved for this outcome, named under another one.
    let other = testkit::commit(&*store, 64, 21);
    let other_limit = limit_of(other.charge(Status::Ok, 0).cap());
    assert!(matches!(
        p.signer
            .blind_sign(&fx.active.id, &plain, &other_limit)
            .await,
        Err(SignerError::Refused(_))
    ));
    // An outcome the store does not know.
    let mut unknown = limit.clone();
    unknown.replay_key = testkit::fresh_replay_key();
    assert!(matches!(
        p.signer.blind_sign(&fx.active.id, &plain, &unknown).await,
        Err(SignerError::Refused(m)) if m.contains("no record")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_store_signs_nothing() {
    let store = Arc::new(MemoryStore::new());
    let dyn_store: Arc<dyn UseStore> = store.clone();
    let p = serve(Some(dyn_store.clone()));
    let fx = testkit::fixture();
    let pending = testkit::commit(&*dyn_store, 64, 21);
    let limit = limit_of(pending.charge(Status::Ok, 0).cap());
    store.set_unavailable(true);
    assert!(matches!(
        p.signer
            .blind_sign(&fx.active.id, &[testkit::output(1).output], &limit)
            .await,
        Err(SignerError::Unavailable(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_store_the_suite_passes_in_process_too() {
    let p = serve(None);
    testkit::run(p.signer.clone()).await;
}

/// A settled outcome and the unsigned receipt the gate would ask for.
async fn settled(store: &dyn UseStore) -> bnap_core::sign::UnsignedResponse {
    use bnap_core::outcome::{self, ReceiptInput};
    let fx = testkit::fixture();
    let pending = testkit::commit(store, 64, 21);
    let charge = pending.charge(Status::Ok, 0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let s = bnap_core::store::Settlement::new(&charge, now);
    let recorded = outcome::settle(store, &pending, &s, &bnap_core::Limits::default())
        .await
        .unwrap();
    recorded
        .unsigned_receipt(&ReceiptInput {
            offer_id: bnap_core::OfferId([3; 32]),
            digest: bnap_core::Digest([4; 32]),
            unit: Some("sat".into()),
            metered: false,
            receipt_key: fx.receipt_key,
        })
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_store_an_ack_needs_its_settled_outcome() {
    use bnap_signer_process::wire::{Reply, Request, WirePurpose};
    let store: Arc<dyn UseStore> = Arc::new(MemoryStore::new());
    let p = serve(Some(store.clone()));
    // Through the gate's path: the message names its outcome; signed.
    let u = settled(&*store).await;
    assert!(
        u.message().replay_key().is_some(),
        "an ack names its outcome"
    );
    let sig = p.signer.schnorr(u.message()).await.unwrap();
    let receipt = u.finish(&sig).unwrap();
    receipt.verify_ack().unwrap();

    // Straight to the server, as a process that reaches the socket only.
    let server = Server::new(
        Arc::new(FileSigner::from_toml(KEY_FILE).unwrap()),
        ServeOptions {
            store: Some(store.clone()),
            ..ServeOptions::default()
        },
    );
    let fx = testkit::fixture();
    let u = settled(&*store).await;
    let own = u.message().replay_key().unwrap().0;
    let signed = u.message().signed_bytes().to_vec();
    let ask = |rk: Option<[u8; 32]>, signed: Vec<u8>| Request::Schnorr {
        purpose: WirePurpose::Ack,
        key: fx.receipt_key.0,
        signed,
        replay_key: rk,
    };
    let refused = |r: &Reply| matches!(r, Reply::Error { .. });
    assert!(!refused(
        &server.handle(ask(Some(own), signed.clone())).await
    ));
    // No outcome named.
    assert!(refused(&server.handle(ask(None, signed.clone())).await));
    // An outcome the store does not know.
    assert!(refused(
        &server.handle(ask(Some([7; 32]), signed.clone())).await
    ));
    // A Response that says more than the record: charge changed.
    let mut s =
        bnap_core::tlv::TlvStream::parse(&signed, bnap_core::tlv::StreamKind::TopLevel).unwrap();
    let records: Vec<_> = s
        .records()
        .iter()
        .map(|(t, v)| {
            if *t == 6 {
                (*t, vec![99])
            } else {
                (*t, v.clone())
            }
        })
        .collect();
    s = bnap_core::tlv::TlvStream::from_records(records).unwrap();
    assert!(refused(&server.handle(ask(Some(own), s.to_bytes())).await));
    // Another unit.
    let s2 =
        bnap_core::tlv::TlvStream::parse(&signed, bnap_core::tlv::StreamKind::TopLevel).unwrap();
    let records: Vec<_> = s2
        .records()
        .iter()
        .map(|(t, v)| {
            if *t == 8 {
                (*t, b"msat".to_vec())
            } else {
                (*t, v.clone())
            }
        })
        .collect();
    let s2 = bnap_core::tlv::TlvStream::from_records(records).unwrap();
    assert!(refused(&server.handle(ask(Some(own), s2.to_bytes())).await));
    // A pending outcome.
    let pending = testkit::commit(&*store, 64, 21);
    assert!(refused(
        &server
            .handle(ask(Some(pending.replay_key().0), signed.clone()))
            .await
    ));
    // Offers are not outcome-bound.
    let offer = Request::Schnorr {
        purpose: WirePurpose::OfferSig,
        key: fx.offer_key.0,
        signed: vec![1, 2, 3],
        replay_key: None,
    };
    assert!(
        matches!(server.handle(offer).await, Reply::Error { message, .. } if !message.contains("ack"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keep_until_is_bounded() {
    use bnap_signer_process::wire::{Request, WireLimit, WireOutput, WireStatus};
    let signer = Arc::new(FileSigner::from_toml(KEY_FILE).unwrap());
    let server = Server::new(
        signer.clone(),
        ServeOptions {
            max_keep: std::time::Duration::from_secs(100),
            ..ServeOptions::default()
        },
    );
    let fx = testkit::fixture();
    let o = testkit::output(4).output;
    let r = server
        .handle(Request::BlindSign {
            keyset: fx.active.id.0.clone(),
            outputs: vec![WireOutput {
                amount: o.amount,
                blinded: o.blinded.0,
            }],
            limit: WireLimit {
                replay_key: [5; 32],
                status: WireStatus::Ok,
                unit: "sat".into(),
                cap: 10,
                keep_until: u64::MAX,
            },
        })
        .await;
    assert!(
        matches!(r, bnap_signer_process::wire::Reply::BlindSignatures { .. }),
        "{r:?}"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(signer.ledger().forget_expired(now + 50), 0);
    assert_eq!(
        signer.ledger().forget_expired(now + 100 + 61 + 5),
        1,
        "dropped despite u64::MAX"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_signer_serves_the_public_halves_of_its_keysets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.sock");
    let socket = SignerSocket::bind(&path).unwrap();
    let file = FileSigner::from_toml(KEY_FILE).unwrap();
    let want: Vec<_> = file
        .keysets()
        .iter()
        .map(|k| {
            (
                k.public_keys(),
                k.input_fee_ppk(),
                k.final_expiry(),
                k.active(),
            )
        })
        .collect();
    let server = Arc::new(Server::new(Arc::new(file), ServeOptions::default()));
    tokio::spawn(server.serve(socket, std::future::pending()));
    let got = ProcessSigner::new(path).keysets().await.unwrap();
    assert_ne!(got.len(), 0);
    let got: Vec<_> = got
        .into_iter()
        .map(|k| {
            (
                k.keys.into_iter().map(|k| (k.amount, k.public)).collect(),
                k.input_fee_ppk,
                k.final_expiry,
                k.active,
            )
        })
        .collect();
    assert_eq!(got, want);
}
