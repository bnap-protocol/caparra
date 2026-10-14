//! The signer process's side: a [`FileSigner`] served on a Unix socket.

use std::future::Future;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bnap_core::schnorr::Key;
use bnap_core::store::ChangeOutput;
use bnap_plug::{BlindedOutput, ChangeLimit, KeysetId, Point, Signer, SignerError, UseStore};
use bnap_signer_file::FileSigner;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::wire::{
    FrameError, Reply, Request, WireSignature, decode_request, encode_reply, read_frame,
    write_frame,
};

/// How the server treats its connections.
#[derive(Clone)]
pub struct ServeOptions {
    /// The most time to read the rest of a frame once it began, or to
    /// write one.
    pub io_timeout: Duration,
    /// The most time a connection may wait between requests.
    pub idle_timeout: Duration,
    /// The most connections served at once; more wait in the backlog.
    pub max_connections: usize,
    /// Users, besides the one the server runs as, whose processes may
    /// connect. The socket is mode `0600` as well.
    pub allowed_uids: Vec<u32>,
    /// The gate's use store, when the signer process can reach it: then a
    /// blind signature is made only for outputs the store reserved in the
    /// outcome's record ([`UseStore::reserve_change`]), on top of the
    /// signer's own ledger.
    pub store: Option<Arc<dyn UseStore>>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_connections: 64,
            allowed_uids: Vec::new(),
            store: None,
        }
    }
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("io_timeout", &self.io_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_connections", &self.max_connections)
            .field("allowed_uids", &self.allowed_uids)
            .field("store", &self.store.is_some())
            .finish()
    }
}

/// Why the socket could not be bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// The socket's directory can be written by others and is not sticky,
    /// so someone else could replace the socket.
    #[error(
        "{dir} can be written by the group or others (mode {mode:o}); put the socket in a private directory"
    )]
    UnsafeDirectory {
        /// The directory.
        dir: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Something other than a socket is at the path.
    #[error("{0} exists and is not a socket")]
    Exists(PathBuf),
    /// Another process serves the socket.
    #[error("another process is serving {0}")]
    InUse(PathBuf),
    /// The file system refused.
    #[error("{path}: {source}")]
    Io {
        /// The path.
        path: PathBuf,
        /// What happened.
        source: std::io::Error,
    },
}

/// A bound, private signer socket. The socket file is removed on drop.
#[derive(Debug)]
pub struct SignerSocket {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
    owner: u32,
}

impl SignerSocket {
    /// Binds `path`, mode `0600`. Refuses a directory others could write
    /// (unless it is sticky, as `/tmp` is), a path that holds anything but
    /// a socket, and a socket another process still serves; a stale socket
    /// is replaced.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, BindError> {
        let path = path.as_ref().to_owned();
        let io = |source| BindError::Io {
            path: path.clone(),
            source,
        };
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_owned(),
            _ => PathBuf::from("."),
        };
        let mode = std::fs::metadata(&dir).map_err(io)?.permissions().mode() & 0o7777;
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(BindError::UnsafeDirectory { dir, mode });
        }
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_socket() => {
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    return Err(BindError::InUse(path));
                }
                std::fs::remove_file(&path).map_err(io)?;
            }
            Ok(_) => return Err(BindError::Exists(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        let listener = std::os::unix::net::UnixListener::bind(&path).map_err(io)?;
        // From here on, drop removes the file.
        let mut socket = Self {
            listener,
            path: path.clone(),
            owner: 0,
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        socket.owner = std::fs::symlink_metadata(&path).map_err(io)?.uid();
        socket.listener.set_nonblocking(true).map_err(io)?;
        Ok(socket)
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SignerSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Checks that every output was reserved for the outcome `limit` names in
/// the use store's change ledger. A store that cannot be reached signs
/// nothing.
pub async fn check_reserved(
    store: &dyn UseStore,
    keyset: &KeysetId,
    outputs: &[BlindedOutput],
    limit: &ChangeLimit,
) -> Result<(), SignerError> {
    let record = store
        .outcome(&limit.replay_key)
        .await
        .map_err(|e| SignerError::Unavailable(format!("use store: {e}")))?
        .ok_or_else(|| SignerError::Refused("the outcome has no record in the use store".into()))?;
    if record.unit != limit.unit {
        return Err(SignerError::Refused(
            "the settlement's unit is not the outcome's".into(),
        ));
    }
    let all_reserved = outputs.iter().all(|o| {
        record.change_outputs.contains(&ChangeOutput {
            keyset: keyset.0.clone(),
            amount: o.amount,
            blinded: o.blinded.0,
        })
    });
    if !all_reserved {
        return Err(SignerError::Refused(
            "an output the use store has not reserved for this outcome".into(),
        ));
    }
    Ok(())
}

/// A [`FileSigner`] served on a [`SignerSocket`].
#[derive(Debug)]
pub struct Server {
    signer: Arc<FileSigner>,
    options: ServeOptions,
}

impl Server {
    /// A server for `signer`.
    #[must_use]
    pub fn new(signer: Arc<FileSigner>, options: ServeOptions) -> Self {
        Self { signer, options }
    }

    /// Serves connections on `socket` until `shutdown` completes. A
    /// connection from a user other than the server's own (or one in
    /// [`ServeOptions::allowed_uids`]) is closed at once.
    pub async fn serve(
        self: Arc<Self>,
        socket: SignerSocket,
        shutdown: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        let listener = UnixListener::from_std(socket.listener.try_clone()?)?;
        let permits = Arc::new(Semaphore::new(self.options.max_connections.max(1)));
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                () = &mut shutdown => break,
                p = permits.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };
            let stream = tokio::select! {
                () = &mut shutdown => break,
                r = listener.accept() => match r {
                    Ok((s, _)) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            match stream.peer_cred() {
                Ok(c)
                    if c.uid() == socket.owner || self.options.allowed_uids.contains(&c.uid()) => {}
                Ok(c) => {
                    tracing::warn!(
                        uid = c.uid(),
                        "connection from a user that may not sign: closed"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "no peer credentials: closed");
                    continue;
                }
            }
            let this = self.clone();
            tokio::spawn(async move {
                this.connection(stream).await;
                drop(permit);
            });
        }
        drop(socket);
        Ok(())
    }

    /// Serves requests on one connection until it closes, idles, or sends
    /// something that is not a request frame.
    async fn connection(&self, mut stream: UnixStream) {
        let io = self.options.io_timeout;
        loop {
            let body = match read_frame(&mut stream, self.options.idle_timeout, io).await {
                Ok(b) => b,
                Err(FrameError::TooLarge(n)) => {
                    tracing::debug!(len = n, "frame too large: closed");
                    let reply = Reply::refused(format!("frame of {n} bytes is above the limit"));
                    let _ = write_frame(&mut stream, &encode_reply(reply), io).await;
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "connection ends");
                    return;
                }
            };
            let reply = match decode_request(&body) {
                Ok(req) => {
                    let op = req.name();
                    let reply = self.handle(req).await;
                    let result = match &reply {
                        Reply::Error { kind, .. } => format!("{kind:?}"),
                        _ => "ok".into(),
                    };
                    tracing::debug!(op, result, "request");
                    reply
                }
                Err(e) => {
                    tracing::debug!(error = %e, "malformed request: closed");
                    let reply = Reply::refused(format!("malformed request: {e}"));
                    let _ = write_frame(&mut stream, &encode_reply(reply), io).await;
                    return;
                }
            };
            if write_frame(&mut stream, &encode_reply(reply), io)
                .await
                .is_err()
            {
                return;
            }
        }
    }

    /// Answers one request.
    pub async fn handle(&self, req: Request) -> Reply {
        match req {
            Request::Schnorr {
                purpose,
                key,
                signed,
            } => match self.signer.sign_object(purpose.into(), &Key(key), &signed) {
                Ok(sig) => Reply::Signature { sig: sig.0 },
                Err(e) => (&e).into(),
            },
            Request::VerifyUnblinded {
                keyset,
                unit,
                amount,
                secret,
                c,
            } => match self
                .signer
                .verify_unblinded(&KeysetId(keyset), &unit, amount, &secret, &Point(c))
                .await
            {
                Ok(y) => Reply::Unblinded { y: y.map(|p| p.0) },
                Err(e) => (&e).into(),
            },
            Request::BlindSign {
                keyset,
                outputs,
                limit,
            } => {
                let keyset = KeysetId(keyset);
                let outputs: Vec<BlindedOutput> = outputs
                    .iter()
                    .map(|o| BlindedOutput {
                        amount: o.amount,
                        blinded: Point(o.blinded),
                    })
                    .collect();
                let limit = ChangeLimit {
                    replay_key: bnap_core::hash::ReplayKey(limit.replay_key),
                    status: limit.status.into(),
                    unit: limit.unit,
                    cap: limit.cap,
                    keep_until: limit.keep_until,
                };
                if let Some(store) = &self.options.store
                    && let Err(e) = check_reserved(&**store, &keyset, &outputs, &limit).await
                {
                    return (&e).into();
                }
                match self.signer.blind_sign(&keyset, &outputs, &limit).await {
                    Ok(sigs) => Reply::BlindSignatures {
                        sigs: sigs
                            .iter()
                            .map(|s| WireSignature {
                                amount: s.amount,
                                c: s.signature.0,
                                e: s.dleq.e,
                                s: s.dleq.s,
                            })
                            .collect(),
                    },
                    Err(e) => (&e).into(),
                }
            }
        }
    }
}
