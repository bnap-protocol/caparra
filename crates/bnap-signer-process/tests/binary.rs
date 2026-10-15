//! The `bnap-signer` binary on a temporary socket: the shared Signer
//! behaviour suite through `ProcessSigner`, and what the process refuses on
//! the wire, at start-up and in its logs.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bnap_core::hash::{Digest, OfferId, Scope, tagged_hash};
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::response::{ResponseFields, Status};
use bnap_core::sign::{Purpose, UnsignedOffer};
use bnap_core::test_support::unsigned_response;
use bnap_plug::Signer;
use bnap_signer_file::testkit::{self, KEY_FILE};
use bnap_signer_process::ProcessSigner;
use bnap_signer_process::wire::{
    ErrorKind, MAX_FRAME, Reply, Request, WirePurpose, decode_reply, encode_request,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The secrets in [`KEY_FILE`], which must never leave the process.
const SECRETS: [&str; 3] = [
    "bda3aea2a2aae7f8373847fa9ea2937fa8befc1da0d83a3071da3c458f13a6b6",
    "03cd229c5c5926c3fba5ce72f70d3ac6d632506b9a461c12201b4e8849d9b494",
    "4a7627233f8531b73f6cd8d2b708fede917ebf29f7a518537cc7e0ac5a77c998",
];

/// A running `bnap-signer`, killed on drop.
struct Running {
    child: Child,
    dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Running {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("stderr.log")).unwrap_or_default()
    }

    fn signer(&self) -> Arc<dyn Signer> {
        Arc::new(ProcessSigner::new(&self.socket))
    }

    /// SIGTERM, then the exit status.
    fn terminate(mut self) -> (std::process::ExitStatus, String, PathBuf) {
        let pid = self.child.id().to_string();
        Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        let status = wait(&mut self.child, Duration::from_secs(10)).expect("stops on SIGTERM");
        (status, self.log(), self.socket.clone())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Writes the key file with `mode` and spawns the binary with `args`.
fn spawn(mode: u32, args: &[&str], env: &[(&str, &str)]) -> (Child, tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let keys = dir.path().join("keys.toml");
    std::fs::write(&keys, KEY_FILE).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(mode)).unwrap();
    let socket = dir.path().join("s.sock");
    let log = std::fs::File::create(dir.path().join("stderr.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_bnap-signer"))
        .arg("--keys")
        .arg(&keys)
        .arg("--socket")
        .arg(&socket)
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    (child, dir, socket)
}

fn start_with(args: &[&str], env: &[(&str, &str)]) -> Running {
    let (child, dir, socket) = spawn(0o600, args, env);
    let mut running = Running { child, dir, socket };
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if std::os::unix::net::UnixStream::connect(&running.socket).is_ok() {
            return running;
        }
        if let Some(status) = running.child.try_wait().unwrap() {
            panic!("bnap-signer exited with {status}: {}", running.log());
        }
        assert!(
            Instant::now() < until,
            "bnap-signer did not start: {}",
            running.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start() -> Running {
    start_with(&[], &[])
}

fn assert_no_secret(text: &str) {
    for s in SECRETS {
        assert!(!text.contains(s), "a secret leaked");
        assert!(!text.contains(&s.to_uppercase()), "a secret leaked");
    }
}

// ------------------------------------------------- the shared suite

#[tokio::test(flavor = "multi_thread")]
async fn signs_offers_and_acks_with_the_key_for_their_use() {
    let p = start();
    testkit::signs_offers_and_acks_with_the_key_for_their_use(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_foreign_messages() {
    let p = start();
    testkit::refuses_foreign_messages(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blind_signatures_verify_with_the_cashu_crate() {
    let p = start();
    testkit::blind_signatures_verify_with_the_cashu_crate(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn notes_are_checked_against_their_secret() {
    let p = start();
    testkit::notes_are_checked_against_their_secret(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_outputs_over_the_cap() {
    let p = start();
    testkit::refuses_outputs_over_the_cap(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_zero_amounts_and_empty_batches() {
    let p = start();
    testkit::refuses_zero_amounts_and_empty_batches(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_outputs_it_must_not_sign() {
    let p = start();
    testkit::refuses_outputs_it_must_not_sign(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn change_goes_through_the_store_ledger() {
    let p = start();
    testkit::change_goes_through_the_store_ledger(p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_suite_runs_and_no_secret_reaches_the_logs() {
    let p = start_with(&[], &[("RUST_LOG", "trace")]);
    testkit::run(p.signer()).await;
    let (status, log, socket) = p.terminate();
    assert!(status.success(), "{status}: {log}");
    assert!(log.contains("op=\"blind_sign\""), "requests are logged");
    assert!(log.contains("holding keyset"), "keysets are logged");
    assert_no_secret(&log);
    assert!(!socket.exists(), "the socket is removed on SIGTERM");
}

// ------------------------------------------------------ start-up

#[test]
fn the_socket_is_private() {
    let p = start();
    let mode = std::fs::metadata(&p.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_key_file_with_bad_permissions_is_refused() {
    for mode in [0o644, 0o640, 0o604] {
        let (mut child, dir, socket) = spawn(mode, &[], &[]);
        let status = wait(&mut child, Duration::from_secs(20)).expect("exits");
        assert_eq!(status.code(), Some(2), "mode {mode:o}");
        let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
        assert!(log.contains("chmod 600"), "{log}");
        assert_no_secret(&log);
        assert!(!socket.exists(), "no socket without keys");
    }
}

#[test]
fn a_socket_that_is_served_is_not_taken_over() {
    let p = start();
    let mut second = Command::new(env!("CARGO_BIN_EXE_bnap-signer"))
        .arg("--keys")
        .arg(p.dir.path().join("keys.toml"))
        .arg("--socket")
        .arg(&p.socket)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = wait(&mut second, Duration::from_secs(20)).expect("exits");
    assert_eq!(status.code(), Some(2));
    let mut log = String::new();
    std::io::Read::read_to_string(&mut second.stderr.take().unwrap(), &mut log).unwrap();
    assert!(log.contains("another process is serving"), "{log}");
}

// --------------------------------------------------------- the wire

async fn send(stream: &mut UnixStream, body: &[u8]) {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(body).await.unwrap();
}

/// The next reply on `stream`, or `None` when the server closed it.
async fn recv(stream: &mut UnixStream) -> Option<Reply> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    stream.read_exact(&mut body).await.ok()?;
    Some(decode_reply(&body).unwrap())
}

async fn ask(stream: &mut UnixStream, req: Request) -> Option<Reply> {
    send(stream, &encode_request(req)).await;
    recv(stream).await
}

fn refused(reply: Option<Reply>) -> bool {
    reply.is_some_and(|r| {
        matches!(
            r,
            Reply::Error {
                kind: ErrorKind::Refused,
                ..
            }
        )
    })
}

async fn closed(stream: &mut UnixStream) -> bool {
    let mut b = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut b)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn only_objects_bnap_core_builds_are_signed() {
    let running = start();
    let fx = testkit::fixture();
    let mut fields = OfferFields::new(Scope([1; 32]), 1_999_999_999, fx.offer_key, [0; 16]);
    fields.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    let offer = UnsignedOffer::new(&fields, Some(&[7; 32])).unwrap();
    let signed = offer.message().signed_bytes().to_vec();
    let schnorr = |purpose, key: bnap_core::Key, signed: Vec<u8>| Request::Schnorr {
        purpose,
        key: key.0,
        signed,
        replay_key: None,
    };
    let mut conn = UnixStream::connect(&running.socket).await.unwrap();
    // The digest itself, or any 32 bytes, under the offer key.
    let digest = tagged_hash(Purpose::OfferSig.tag(), &signed).to_vec();
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::OfferSig, fx.offer_key, digest)
        )
        .await
    ));
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::OfferSig, fx.offer_key, vec![0; 32])
        )
        .await
    ));
    // The offer as an ack, and under the receipt key the signer holds.
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::Ack, fx.offer_key, signed.clone())
        )
        .await
    ));
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::Ack, fx.receipt_key, signed.clone())
        )
        .await
    ));
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::OfferSig, fx.receipt_key, signed.clone())
        )
        .await
    ));
    // An offer that names another key, asked of the offer key.
    let stranger = bnap_core::SigningKey::from_secret_bytes(&bnap_core::hash::sha256(b"stranger"))
        .unwrap()
        .public_key();
    let mut foreign = fields.clone();
    foreign.offer_key = stranger;
    let foreign = UnsignedOffer::new(&foreign, Some(&[7; 32])).unwrap();
    assert!(refused(
        ask(
            &mut conn,
            schnorr(
                WirePurpose::OfferSig,
                fx.offer_key,
                foreign.message().signed_bytes().to_vec()
            )
        )
        .await
    ));
    // A Response that names the offer key.
    let response = ResponseFields {
        status: Status::Ok,
        replayed: false,
        charged: 1,
        unit: Some("sat".into()),
        offer_id: OfferId([1; 32]),
        digest: Digest([2; 32]),
        metered_units: None,
        scheme_result: None,
        receipt_key: fx.offer_key,
        settled_at: 1,
        unknown: Vec::new(),
    };
    let resp_bytes = unsigned_response(&response)
        .unwrap()
        .message()
        .signed_bytes()
        .to_vec();
    assert!(refused(
        ask(
            &mut conn,
            schnorr(WirePurpose::Ack, fx.offer_key, resp_bytes)
        )
        .await
    ));
    // The connection still serves the real thing.
    let Some(Reply::Signature { sig }) = ask(
        &mut conn,
        schnorr(WirePurpose::OfferSig, fx.offer_key, signed),
    )
    .await
    else {
        panic!("the offer is signed");
    };
    offer
        .finish(&bnap_core::Signature(sig))
        .unwrap()
        .verify_signature()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_frames_close_the_connection_and_the_server_carries_on() {
    let p = start();
    for body in [
        &b"not json"[..],
        br#"{"v":2,"req":{"verify_unblinded":{"keyset":"","unit":"sat","amount":1,"secret":"","c":"00"}}}"#,
        br#"{"v":1,"req":{"sign_digest":{"digest":"00"}}}"#,
    ] {
        let mut c = UnixStream::connect(&p.socket).await.unwrap();
        send(&mut c, body).await;
        assert!(refused(recv(&mut c).await));
        assert!(closed(&mut c).await, "closed after a malformed request");
    }
    // A length above the limit: refused before the body is read.
    let mut c = UnixStream::connect(&p.socket).await.unwrap();
    c.write_all(&u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes())
        .await
        .unwrap();
    assert!(refused(recv(&mut c).await));
    assert!(closed(&mut c).await);
    // The server still answers.
    testkit::signs_offers_and_acks_with_the_key_for_their_use(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_and_slow_connections_time_out() {
    let p = start_with(&["--idle-timeout-ms", "200", "--io-timeout-ms", "200"], &[]);
    let mut idle = UnixStream::connect(&p.socket).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(closed(&mut idle).await, "an idle connection is closed");
    let mut slow = UnixStream::connect(&p.socket).await.unwrap();
    slow.write_all(&[0, 0, 0, 100, b'{']).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        closed(&mut slow).await,
        "a frame that never ends is cut off"
    );
    testkit::signs_offers_and_acks_with_the_key_for_their_use(&p.signer()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signer_that_is_gone_or_silent_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let gone = ProcessSigner::new(dir.path().join("none.sock"));
    let fx = testkit::fixture();
    let one = [testkit::output(1).output];
    let lim = testkit::limit(Status::Ok, 1);
    assert!(matches!(
        gone.blind_sign(&fx.active.id, &one, &lim).await,
        Err(bnap_plug::SignerError::Unavailable(_))
    ));
    // A socket that accepts and never answers.
    let path = dir.path().join("silent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let silent = ProcessSigner::new(&path).with_timeout(Duration::from_millis(200));
    let started = Instant::now();
    assert!(matches!(
        silent.blind_sign(&fx.active.id, &one, &lim).await,
        Err(bnap_plug::SignerError::Unavailable(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(3));
    hold.abort();
    assert_eq!(silent.socket(), Path::new(&path));
}

fn is_refused<T>(r: Result<T, bnap_plug::SignerError>) -> bool {
    r.is_err_and(|e| matches!(e, bnap_plug::SignerError::Refused(_)))
}

/// A fake signer process that answers every request with `reply`.
fn fake(dir: &Path, name: &str, reply: Reply) -> (ProcessSigner, tokio::task::JoinHandle<()>) {
    let path = dir.join(name);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
                let _ = s.read_exact(&mut body).await;
                let out = bnap_signer_process::wire::encode_reply(reply);
                send(&mut s, &out).await;
            });
        }
    });
    (ProcessSigner::new(path), task)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_checks_what_the_process_answers() {
    let dir = tempfile::tempdir().unwrap();
    let fx = testkit::fixture();

    // A signature that does not verify over the message.
    let mut f = OfferFields::new(Scope([1; 32]), 1_999_999_999, fx.offer_key, [0; 16]);
    f.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    let offer = UnsignedOffer::new(&f, Some(&[7; 32])).unwrap();
    let (bad_sig, t1) = fake(dir.path(), "a.sock", Reply::Signature { sig: [1; 64] });
    assert!(is_refused(bad_sig.schnorr(offer.message()).await));

    // A Y that is not hash_to_curve(secret).
    let other_y = bnap_core::note::hash_to_curve(b"another secret").unwrap();
    let (bad_y, t2) = fake(dir.path(), "b.sock", Reply::Unblinded { y: Some(other_y) });
    let c = bnap_plug::Point([2; 33]);
    assert!(is_refused(
        bad_y
            .verify_unblinded(&fx.active.id, "sat", 1, b"a secret", &c)
            .await
    ));

    // Blind signatures that do not match the outputs, and a reply of the
    // wrong kind.
    let one = [testkit::output(1).output];
    let lim = testkit::limit(Status::Ok, 8);
    let (short, t3) = fake(
        dir.path(),
        "c.sock",
        Reply::BlindSignatures { sigs: vec![] },
    );
    assert!(is_refused(
        short.blind_sign(&fx.active.id, &one, &lim).await
    ));
    let wrong_amount = bnap_signer_process::wire::WireSignature {
        amount: 2,
        c: [2; 33],
        e: [0; 32],
        s: [0; 32],
    };
    let (wrong, t4) = fake(
        dir.path(),
        "d.sock",
        Reply::BlindSignatures {
            sigs: vec![wrong_amount],
        },
    );
    assert!(is_refused(
        wrong.blind_sign(&fx.active.id, &one, &lim).await
    ));
    let (kind, t5) = fake(dir.path(), "e.sock", Reply::Unblinded { y: None });
    assert!(is_refused(kind.blind_sign(&fx.active.id, &one, &lim).await));
    assert!(is_refused(kind.schnorr(offer.message()).await));
    for t in [t1, t2, t3, t4, t5] {
        t.abort();
    }
}

// ------------------------------------------- who serves the socket

/// A directory under a private temporary one, with `mode`.
fn dir_with_mode(base: &Path, name: &str, mode: u32) -> PathBuf {
    let d = base.join(name);
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    assert_eq!(
        std::fs::metadata(&d).unwrap().permissions().mode() & 0o7777,
        mode,
        "the platform keeps mode {mode:o}"
    );
    d
}

#[test]
fn bind_refuses_a_directory_others_can_write_sticky_or_not() {
    let base = tempfile::tempdir().unwrap();
    for (i, mode) in [0o1777, 0o1770, 0o1730, 0o777, 0o770, 0o720, 0o702]
        .into_iter()
        .enumerate()
    {
        let d = dir_with_mode(base.path(), &format!("bad{i}"), mode);
        let path = d.join("s.sock");
        match bnap_signer_process::SignerSocket::bind(&path) {
            Err(bnap_signer_process::BindError::UnsafeDirectory { dir, mode: m }) => {
                assert_eq!(dir, d);
                assert_eq!(m, mode);
            }
            other => panic!("mode {mode:o}: {other:?}"),
        }
        assert!(!path.exists(), "nothing is created in mode {mode:o}");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (i, mode) in [0o700, 0o750, 0o755, 0o711, 0o1755].into_iter().enumerate() {
        let d = dir_with_mode(base.path(), &format!("good{i}"), mode);
        let socket = bnap_signer_process::SignerSocket::bind(d.join("s.sock"))
            .unwrap_or_else(|e| panic!("mode {mode:o}: {e}"));
        assert!(socket.path().exists());
    }
}

/// A fake signer process, running as this test's user, that answers
/// `verify_unblinded` for `secret` the way a real one would for a good
/// note, whatever `C` is: the impostor of a socket path someone else could
/// take over. It counts the requests it is sent.
struct Impostor {
    client: ProcessSigner,
    asked: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Impostor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn impostor(dir: &Path, secret: &[u8]) -> Impostor {
    let y = bnap_core::note::hash_to_curve(secret).unwrap();
    let out = bnap_signer_process::wire::encode_reply(Reply::Unblinded { y: Some(y) });
    let path = dir.join("impostor.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut len = [0u8; 4];
            if s.read_exact(&mut len).await.is_err() {
                continue;
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let mut body = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
            let _ = s.read_exact(&mut body).await;
            send(&mut s, &out).await;
        }
    });
    Impostor {
        client: ProcessSigner::new(path),
        asked,
        task,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_talks_only_to_a_process_running_as_the_signer_uid() {
    let dir = tempfile::tempdir().unwrap();
    let own = std::fs::metadata(dir.path()).unwrap().uid();
    let fx = testkit::fixture();
    let any_c = bnap_plug::Point([2; 33]);
    let fake = impostor(dir.path(), b"a secret");
    // The listener runs as this user: the default signer uid, or this uid
    // named, accepts it.
    for client in [
        fake.client.clone(),
        fake.client.clone().with_signer_uid(own),
    ] {
        let got = client
            .verify_unblinded(&fx.active.id, "sat", 1, b"a secret", &any_c)
            .await;
        assert!(matches!(got, Ok(Some(_))), "{got:?}");
    }
    assert_eq!(fake.asked.load(Ordering::SeqCst), 2);
    // Expecting the signer under another uid, the same listener is refused
    // before the note's secret is sent to it.
    let other = fake.client.clone().with_signer_uid(own.wrapping_add(1));
    let got = other
        .verify_unblinded(&fx.active.id, "sat", 1, b"a secret", &any_c)
        .await;
    assert!(
        matches!(got, Err(bnap_plug::SignerError::Unavailable(ref m)) if m.contains("uid")),
        "{got:?}"
    );
    let one = [testkit::output(1).output];
    let lim = testkit::limit(Status::Ok, 1);
    assert!(matches!(
        other.blind_sign(&fx.active.id, &one, &lim).await,
        Err(bnap_plug::SignerError::Unavailable(_))
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fake.asked.load(Ordering::SeqCst), 2, "nothing was sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_refuses_a_socket_in_a_directory_others_can_write() {
    let base = tempfile::tempdir().unwrap();
    let fx = testkit::fixture();
    let any_c = bnap_plug::Point([2; 33]);
    for (i, mode) in [0o1777, 0o777, 0o770, 0o1730].into_iter().enumerate() {
        let d = dir_with_mode(base.path(), &format!("d{i}"), mode);
        let fake = impostor(&d, b"a secret");
        let got = fake
            .client
            .verify_unblinded(&fx.active.id, "sat", 1, b"a secret", &any_c)
            .await;
        assert!(
            matches!(got, Err(bnap_plug::SignerError::Unavailable(_))),
            "mode {mode:o}: {got:?}"
        );
        assert_eq!(fake.asked.load(Ordering::SeqCst), 0, "mode {mode:o}");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

// ------------------------------------- a gate under another user

/// The groups this test's user is in (`id -G`).
fn groups() -> Vec<u32> {
    let out = Command::new("id").arg("-G").output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .map(|g| g.parse().unwrap())
        .collect()
}

/// A group this user is in that a new file in `dir` does not get by
/// default, when there is one: then the socket's group shows that the
/// signer set it.
fn another_group(dir: &Path) -> u32 {
    let probe = dir.join("probe");
    std::fs::write(&probe, b"").unwrap();
    let default = std::fs::metadata(&probe).unwrap().gid();
    std::fs::remove_file(&probe).unwrap();
    groups()
        .into_iter()
        .find(|g| *g != default)
        .unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_for_a_gate_user_is_0660_with_the_named_group() {
    let probe = tempfile::tempdir().unwrap();
    let gid = another_group(probe.path());
    let gate = std::fs::metadata(probe.path())
        .unwrap()
        .uid()
        .wrapping_add(1);
    let p = start_with(
        &[
            "--socket-group",
            &gid.to_string(),
            "--allow-uid",
            &gate.to_string(),
        ],
        &[],
    );
    let meta = std::fs::metadata(&p.socket).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o660);
    assert_eq!(meta.gid(), gid, "the socket's group is the one named");
    // The signer's own user is still served.
    testkit::signs_offers_and_acks_with_the_key_for_their_use(&p.signer()).await;
}

#[test]
fn allowed_users_and_the_socket_group_come_together() {
    let gid = groups()[0].to_string();
    for (args, needs) in [
        (&["--allow-uid", "4242"][..], "--socket-group"),
        (&["--socket-group", &gid][..], "--allow-uid"),
    ] {
        let (mut child, dir, socket) = spawn(0o600, args, &[]);
        let status = wait(&mut child, Duration::from_secs(20)).expect("exits");
        assert_eq!(status.code(), Some(2), "{args:?}");
        let log = std::fs::read_to_string(dir.path().join("stderr.log")).unwrap();
        assert!(log.contains(needs), "{args:?}: {log}");
        assert!(!socket.exists(), "{args:?}: no socket");
    }
}

#[test]
fn bind_with_a_group_gives_the_socket_that_group_and_mode_0660() {
    use bnap_signer_process::{SignerSocket, SocketAccess};
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    let own = std::fs::metadata(dir.path()).unwrap().uid();
    let gid = another_group(dir.path());
    let gate = own.wrapping_add(1);
    let access = SocketAccess::Group {
        gid,
        uids: vec![gate],
    };
    let socket = SignerSocket::bind_with(dir.path().join("g.sock"), access.clone()).unwrap();
    let meta = std::fs::metadata(socket.path()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o660);
    assert_eq!(meta.gid(), gid);
    assert_eq!(socket.access(), &access);
    assert!(socket.admits(own) && socket.admits(gate));
    assert!(!socket.admits(own.wrapping_add(2)));

    let private = SignerSocket::bind(dir.path().join("o.sock")).unwrap();
    let meta = std::fs::metadata(private.path()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert!(private.admits(own));
    assert!(
        !private.admits(gate),
        "an owner-only socket admits no one else"
    );
}

#[test]
fn a_group_socket_needs_users_and_a_group_the_signer_is_in() {
    use bnap_signer_process::{BindError, SignerSocket, SocketAccess};
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("s.sock");
    let gid = groups()[0];
    let none = SocketAccess::Group {
        gid,
        uids: Vec::new(),
    };
    assert!(matches!(
        SignerSocket::bind_with(&path, none),
        Err(BindError::NoAllowedUsers)
    ));
    assert!(!path.exists());
    // Root may give a file any group; everyone else only their own.
    let own = std::fs::metadata(dir.path()).unwrap().uid();
    if own != 0 {
        let mine = groups();
        let foreign = (40_000..u32::MAX).find(|g| !mine.contains(g)).unwrap();
        let access = SocketAccess::Group {
            gid: foreign,
            uids: vec![own.wrapping_add(1)],
        };
        match SignerSocket::bind_with(&path, access) {
            Err(BindError::Group { gid, .. }) => assert_eq!(gid, foreign),
            other => panic!("{other:?}"),
        }
        assert!(!path.exists(), "the socket is removed");
    }
}
