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

use crate::trust::{DirInfo, parent_dir, peer_allowed};
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
    /// The gate's use store, when the signer process can reach it: then a
    /// blind signature is made only for outputs the store reserved in the
    /// outcome's record ([`UseStore::reserve_change`]), on top of the
    /// signer's own ledger; and an ack is made only for a Response that
    /// matches its settled outcome record ([`check_ack`]).
    pub store: Option<Arc<dyn UseStore>>,
    /// The longest a change ledger entry is kept after now, whatever
    /// `keep_until` a request names: a client cannot make the signer's
    /// in-memory ledger keep entries forever. The use store's reservation
    /// stays the bound across restarts.
    pub max_keep: Duration,
}

/// The default [`ServeOptions::max_keep`]: 31 days, past the longest
/// manifest lifetime and route-offer lifetime with a replay window of days.
pub const DEFAULT_MAX_KEEP: Duration = Duration::from_hours(31 * 24);

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            max_connections: 64,
            store: None,
            max_keep: DEFAULT_MAX_KEEP,
        }
    }
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("io_timeout", &self.io_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_connections", &self.max_connections)
            .field("store", &self.store.is_some())
            .field("max_keep", &self.max_keep)
            .finish()
    }
}

/// Why the socket could not be bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// The group or others can write the socket's directory, so someone
    /// else could serve the path while the signer is down. A sticky
    /// directory such as `/tmp` is refused as well.
    #[error(
        "{dir} can be written by the group or others (mode {mode:o}); put the socket in a private directory"
    )]
    UnsafeDirectory {
        /// The directory.
        dir: PathBuf,
        /// Its permission bits, sticky bit included.
        mode: u32,
    },
    /// Another user (not root) owns the socket's directory, and could
    /// replace the socket.
    #[error("{dir} belongs to uid {owner}; put the socket in a directory of your own")]
    ForeignDirectory {
        /// The directory.
        dir: PathBuf,
        /// Its owner.
        owner: u32,
    },
    /// [`SocketAccess::Group`] names no user to admit: the group could
    /// reach the socket, and the server would close every connection.
    #[error("a group socket needs at least one allowed user ID")]
    NoAllowedUsers,
    /// The socket could not be given its group, typically because the
    /// signer's user is not a member of it. The socket is removed.
    #[error("cannot give {path} the group {gid} (the signer's user must be a member): {source}")]
    Group {
        /// The socket's path.
        path: PathBuf,
        /// The group asked for.
        gid: u32,
        /// What happened.
        source: std::io::Error,
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

/// Who can reach the signer socket, and who is then served.
///
/// A process needs write permission on a socket file to connect to it (on
/// Linux, macOS and the BSDs), so the file mode decides which users can
/// reach the signer at all. Every accepted connection is then checked on
/// its peer credentials: the signer's own user and the listed users are
/// served, anyone else is closed at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SocketAccess {
    /// Mode `0600`: only the signer's own user (and root) can connect. A
    /// gate under the same user can read the key file and trace the signer
    /// process, so this keeps the keys from a compromised gate only as far
    /// as the operating system separates processes of one user: not at
    /// all. Use it for tests and single-user setups.
    #[default]
    Owner,
    /// Mode `0660` with group `gid`: the members of `gid` can connect, and
    /// of them only the users in `uids` are served. The signer's user must
    /// be a member of `gid` to give the socket that group. This is the
    /// deployment that keeps the keys from the gate: the signer runs as a
    /// user of its own, the key file is that user's (mode `0600`), and the
    /// gate runs as a user in `uids`.
    Group {
        /// The socket file's group.
        gid: u32,
        /// The users, besides the signer's own, that are served. Not empty.
        uids: Vec<u32>,
    },
}

impl SocketAccess {
    /// The socket file's permission bits.
    #[must_use]
    pub fn mode(&self) -> u32 {
        match self {
            Self::Owner => 0o600,
            Self::Group { .. } => 0o660,
        }
    }

    /// The users, besides the signer's own, that are served.
    #[must_use]
    pub fn allowed_uids(&self) -> &[u32] {
        match self {
            Self::Owner => &[],
            Self::Group { uids, .. } => uids,
        }
    }
}

/// A bound signer socket. The socket file is removed on drop.
#[derive(Debug)]
pub struct SignerSocket {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
    owner: u32,
    access: SocketAccess,
}

impl SignerSocket {
    /// Binds `path` for the signer's own user only ([`SocketAccess::Owner`],
    /// mode `0600`); see [`SignerSocket::bind_with`].
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, BindError> {
        Self::bind_with(path, SocketAccess::Owner)
    }

    /// Binds `path` with the mode and group `access` asks for. Refuses a
    /// directory the group or others can write (sticky or not: `/tmp` is
    /// refused) or that another user than root or the signer's own owns, a
    /// path that holds anything but a socket, a socket another process
    /// still serves, and a [`SocketAccess::Group`] without users; a stale
    /// socket is replaced. The socket is made `0600` right after it is
    /// bound, and only then given its group and mode `0660`, so it is
    /// never open to a group other than the one named. (Between the bind
    /// and the first chmod it has the mode the umask leaves; the peer
    /// check covers that moment.)
    pub fn bind_with(path: impl AsRef<Path>, access: SocketAccess) -> Result<Self, BindError> {
        let path = path.as_ref().to_owned();
        if let SocketAccess::Group { uids, .. } = &access
            && uids.is_empty()
        {
            return Err(BindError::NoAllowedUsers);
        }
        let io = |source| BindError::Io {
            path: path.clone(),
            source,
        };
        let dir = parent_dir(&path);
        let info = DirInfo::of(&dir).map_err(io)?;
        if info.writable_by_others() {
            return Err(BindError::UnsafeDirectory {
                dir,
                mode: info.mode,
            });
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
            access: SocketAccess::Owner,
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        socket.owner = std::fs::symlink_metadata(&path).map_err(io)?.uid();
        // The socket's owner is the user this process runs as.
        if !info.owned_by(&[socket.owner]) {
            return Err(BindError::ForeignDirectory {
                dir,
                owner: info.owner,
            });
        }
        if let SocketAccess::Group { gid, .. } = &access {
            let gid = *gid;
            std::os::unix::fs::chown(&path, None, Some(gid)).map_err(|source| {
                BindError::Group {
                    path: path.clone(),
                    gid,
                    source,
                }
            })?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(access.mode()))
                .map_err(io)?;
        }
        socket.access = access;
        socket.listener.set_nonblocking(true).map_err(io)?;
        Ok(socket)
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Who can reach the socket, and who is served.
    #[must_use]
    pub fn access(&self) -> &SocketAccess {
        &self.access
    }

    /// Whether a connection whose peer runs as `uid` is served: the
    /// signer's own user (the socket file's owner) or one of
    /// [`SocketAccess::allowed_uids`].
    #[must_use]
    pub fn admits(&self, uid: u32) -> bool {
        peer_allowed(uid, self.owner, self.access.allowed_uids())
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

/// Checks an ack against the use store: the Response's outcome (`rk`)
/// must have a settled record, and the Response must state that record's
/// status, charge, unit, metered units, scheme result and settlement time.
/// So a process that reaches the socket but not the store cannot mint a
/// receipt for an outcome that never settled, or one that misstates its
/// settlement. It cannot check the Response's `digest` or `offer_id`, which
/// the record does not hold.
pub async fn check_ack(
    store: &dyn UseStore,
    rk: Option<[u8; 32]>,
    signed: &[u8],
) -> Result<(), SignerError> {
    use bnap_core::response::types as t;
    use bnap_core::store::OutcomeStatus;
    let refuse = |m: &str| SignerError::Refused(format!("ack: {m}"));
    let rk = rk.ok_or_else(|| refuse("no outcome named"))?;
    let record = store
        .outcome(&bnap_core::hash::ReplayKey(rk))
        .await
        .map_err(|e| SignerError::Unavailable(format!("use store: {e}")))?
        .ok_or_else(|| refuse("the outcome has no record in the use store"))?;
    let stream = bnap_core::tlv::TlvStream::parse(signed, bnap_core::tlv::StreamKind::TopLevel)
        .map_err(|_| refuse("not a Response"))?;
    let tu64 = |typ: u64| -> Result<Option<u64>, SignerError> {
        stream
            .get(typ)
            .map(|v| bnap_core::encoding::read_tu64(v, typ))
            .transpose()
            .map_err(|_| refuse("not a Response"))
    };
    let status = match record.status {
        OutcomeStatus::Pending => return Err(refuse("the outcome is not settled")),
        OutcomeStatus::Ok => 0,
        OutcomeStatus::Failed => 1,
    };
    if record.needs_refund() {
        return Err(refuse("the outcome's refund is not recorded"));
    }
    let same = tu64(t::STATUS)? == Some(status)
        && tu64(t::CHARGED)?.unwrap_or(0) == record.charged.unwrap_or(0)
        && tu64(t::METERED_UNITS)? == record.metered_units
        && tu64(t::SETTLED_AT)? == record.settled_at
        && stream
            .get(t::UNIT)
            .is_none_or(|u| u == record.unit.as_bytes())
        && stream.get(t::SCHEME_RESULT).filter(|r| !r.is_empty())
            == record.scheme_result.as_deref().filter(|r| !r.is_empty());
    if !same {
        return Err(refuse("the Response does not state the recorded outcome"));
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
    /// connection from a user the socket does not admit
    /// ([`SignerSocket::admits`]) is closed at once.
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
                Ok(c) if socket.admits(c.uid()) => {}
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
                replay_key,
            } => {
                if let Some(store) = &self.options.store
                    && purpose == crate::wire::WirePurpose::Ack
                    && let Err(e) = check_ack(&**store, replay_key, &signed).await
                {
                    return (&e).into();
                }
                match self.signer.sign_object(purpose.into(), &Key(key), &signed) {
                    Ok(sig) => Reply::Signature { sig: sig.0 },
                    Err(e) => (&e).into(),
                }
            }
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
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let limit = ChangeLimit {
                    replay_key: bnap_core::hash::ReplayKey(limit.replay_key),
                    status: limit.status.into(),
                    unit: limit.unit,
                    cap: limit.cap,
                    keep_until: limit
                        .keep_until
                        .min(now.saturating_add(self.options.max_keep.as_secs())),
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

#[cfg(test)]
mod tests {
    use bnap_signer_file::testkit::KEY_FILE;

    use super::*;
    use crate::wire::{decode_reply, encode_request};

    /// Serves on a socket in a fresh directory whose owner, as far as the
    /// server knows, is `owner`, admitting `allowed` as well, and sends one
    /// request from this test (which runs as the socket file's real owner).
    /// The reply, or `None` when the server closed the connection unread.
    async fn ask_as_owner(owner: impl Fn(u32) -> u32, allowed: Vec<u32>) -> Option<Reply> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let mut socket = SignerSocket::bind(&path).unwrap();
        socket.owner = owner(socket.owner);
        if !allowed.is_empty() {
            // The file mode is left alone: this test runs as the file's
            // owner and can reach it anyway.
            socket.access = SocketAccess::Group {
                gid: 0,
                uids: allowed,
            };
        }
        let server = Arc::new(Server::new(
            Arc::new(FileSigner::from_toml(KEY_FILE).unwrap()),
            ServeOptions::default(),
        ));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(server.serve(socket, async {
            let _ = stopped.await;
        }));
        let mut conn = UnixStream::connect(&path).await.unwrap();
        let req = Request::VerifyUnblinded {
            keyset: vec![1; 33],
            unit: "sat".into(),
            amount: 1,
            secret: b"a secret".to_vec(),
            c: [2; 33],
        };
        let io = Duration::from_secs(5);
        // The server may close the connection before or after the request
        // arrives; either way no reply comes back.
        let _ = write_frame(&mut conn, &encode_request(req), io).await;
        let reply = read_frame(&mut conn, io, io)
            .await
            .ok()
            .map(|b| decode_reply(&b).unwrap());
        let _ = stop.send(());
        task.await.unwrap().unwrap();
        reply
    }

    fn own_uid() -> u32 {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::metadata(file.path()).unwrap().uid()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_owner_is_served() {
        let reply = ask_as_owner(|own| own, Vec::new()).await;
        assert!(
            matches!(reply, Some(Reply::Unblinded { y: None })),
            "{reply:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_user_who_is_neither_the_owner_nor_allowed_is_not_served() {
        let me = own_uid();
        // The socket "belongs" to another user, so this test's process is
        // a stranger to the server.
        let other = |own: u32| own.wrapping_add(1);
        assert_eq!(ask_as_owner(other, Vec::new()).await, None);
        assert_eq!(
            ask_as_owner(other, vec![me.wrapping_add(2), me.wrapping_add(3)]).await,
            None
        );
        // Named in the allowed users, the same process is served.
        let reply = ask_as_owner(other, vec![me.wrapping_add(2), me]).await;
        assert!(
            matches!(reply, Some(Reply::Unblinded { y: None })),
            "{reply:?}"
        );
    }
}
