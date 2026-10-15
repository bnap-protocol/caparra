//! The gate's side: [`ProcessSigner`], a [`Signer`] that asks the signer
//! process over its Unix socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bnap_core::note::hash_to_curve;
use bnap_core::schnorr::Signature;
use bnap_core::sign::CoreMessage;
use bnap_plug::{
    BlindSignature, BlindedOutput, ChangeLimit, Dleq, KeysetId, Point, Signer, SignerError,
};
use tokio::net::UnixStream;

use crate::trust::{DirInfo, parent_dir};
use crate::wire::{
    FrameError, Reply, Request, WireLimit, WireOutput, decode_reply, encode_request, read_frame,
    write_frame,
};

/// How long a call may take, connection included, unless set otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`Signer`] whose keys live in a separate process: the `bnap-signer`
/// binary of this crate, listening on a Unix socket.
///
/// Every call opens a connection, sends one request and reads one reply,
/// within [`ProcessSigner::with_timeout`]. A signer process that cannot be
/// reached, or does not answer in time, is [`SignerError::Unavailable`];
/// the gate fails closed (draft-00 section 12).
///
/// Before it sends anything, the client checks who it is talking to: the
/// socket's directory must be one that neither the group nor others can
/// write, owned by root, this process's user or the signer's, and the
/// process at the other end of the connection must run as the signer's
/// user ([`ProcessSigner::with_signer_uid`]; by default the user this
/// process runs as). Otherwise any local user could serve the path while
/// the signer is down and answer for it. Either failure is
/// [`SignerError::Unavailable`].
///
/// The client checks what it gets back as well: a signature must verify
/// under the message's key over its digest, a checked note's `Y` must be
/// `hash_to_curve(secret)`, and blind signatures must match the outputs one
/// to one by amount. Change goes through
/// [`bnap_plug::CappedSigner::for_change`] as for any signer: the gate
/// reserves every output in the use store before this client is called.
#[derive(Debug, Clone)]
pub struct ProcessSigner {
    socket: PathBuf,
    timeout: Duration,
    signer_uid: Option<u32>,
}

impl ProcessSigner {
    /// A client for the signer process listening on `socket`.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
            signer_uid: None,
        }
    }

    /// Sets the user ID the signer process must run as. Without it, the
    /// signer must run as the same user as this process. A connection to a
    /// process running as anyone else is closed before a request is sent.
    ///
    /// A signer under another user is the deployment that keeps its keys
    /// from this process. That signer must let this process's user in: a
    /// socket bound with [`crate::SocketAccess::Group`] naming a group this
    /// user is in and this user's ID (`bnap-signer --socket-group GID
    /// --allow-uid UID`); with the default `0600` socket every call is
    /// [`SignerError::Unavailable`].
    #[must_use]
    pub fn with_signer_uid(mut self, uid: u32) -> Self {
        self.signer_uid = Some(uid);
        self
    }

    /// Sets the most time one call may take.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The socket's path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Connects to the socket, once its directory is one only trusted
    /// users can change, and checks that the process serving it runs as
    /// the signer's user.
    async fn connect(&self) -> Result<UnixStream, SignerError> {
        let own = own_uid()?;
        let signer = self.signer_uid.unwrap_or(own);
        let info = DirInfo::of(&parent_dir(&self.socket)).map_err(|e| {
            SignerError::Unavailable(format!(
                "cannot read the signer socket's directory: {}",
                e.kind()
            ))
        })?;
        if info.writable_by_others() {
            return Err(SignerError::Unavailable(format!(
                "the signer socket's directory can be written by the group or others (mode {:o})",
                info.mode
            )));
        }
        if !info.owned_by(&[own, signer]) {
            return Err(SignerError::Unavailable(format!(
                "the signer socket's directory belongs to uid {}, who could replace the socket",
                info.owner
            )));
        }
        let stream = UnixStream::connect(&self.socket).await.map_err(|e| {
            SignerError::Unavailable(format!("cannot reach the signer process: {}", e.kind()))
        })?;
        check_peer(&stream, signer)?;
        Ok(stream)
    }

    /// One request, one reply. An error reply comes back as its
    /// [`SignerError`].
    async fn call(&self, req: Request) -> Result<Reply, SignerError> {
        let exchange = async {
            let mut stream = self.connect().await?;
            let lost = |e: FrameError| SignerError::Unavailable(format!("signer process: {e}"));
            write_frame(&mut stream, &encode_request(req), self.timeout)
                .await
                .map_err(lost)?;
            let body = read_frame(&mut stream, self.timeout, self.timeout)
                .await
                .map_err(lost)?;
            decode_reply(&body)
                .map_err(|e| SignerError::Refused(format!("signer process: bad reply: {e}")))
        };
        let reply = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| {
                SignerError::Unavailable("the signer process did not answer in time".into())
            })??;
        match reply.to_error() {
            Some(e) => Err(e),
            None => Ok(reply),
        }
    }
}

/// The user ID this process runs as (its effective one), read without
/// `unsafe` as the peer of a socket pair it opens with itself.
fn own_uid() -> Result<u32, SignerError> {
    let (a, _b) = UnixStream::pair().map_err(|e| {
        SignerError::Unavailable(format!("cannot learn this process's user: {}", e.kind()))
    })?;
    a.peer_cred().map(|c| c.uid()).map_err(|e| {
        SignerError::Unavailable(format!("cannot learn this process's user: {}", e.kind()))
    })
}

/// Refuses a connection whose peer does not run as `signer`.
fn check_peer(stream: &UnixStream, signer: u32) -> Result<(), SignerError> {
    let uid = stream
        .peer_cred()
        .map_err(|e| {
            SignerError::Unavailable(format!(
                "no credentials for the process serving the signer socket: {}",
                e.kind()
            ))
        })?
        .uid();
    if uid != signer {
        return Err(SignerError::Unavailable(format!(
            "the signer socket is served by uid {uid}, not by the signer's uid {signer}"
        )));
    }
    Ok(())
}

fn unexpected() -> SignerError {
    SignerError::Refused("signer process: a reply of the wrong kind".into())
}

#[async_trait::async_trait]
impl Signer for ProcessSigner {
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError> {
        let reply = self
            .call(Request::Schnorr {
                purpose: msg.purpose().into(),
                key: msg.key().0,
                signed: msg.signed_bytes().to_vec(),
                replay_key: msg.replay_key().map(|rk| rk.0),
            })
            .await?;
        let Reply::Signature { sig } = reply else {
            return Err(unexpected());
        };
        let sig = Signature(sig);
        msg.verify(&sig).map_err(|_| {
            SignerError::Refused("signer process: a signature that does not verify".into())
        })?;
        Ok(sig)
    }

    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        unit: &str,
        amount: u64,
        secret: &[u8],
        c: &Point,
    ) -> Result<Option<Point>, SignerError> {
        let reply = self
            .call(Request::VerifyUnblinded {
                keyset: keyset.0.clone(),
                unit: unit.to_owned(),
                amount,
                secret: secret.to_vec(),
                c: c.0,
            })
            .await?;
        let Reply::Unblinded { y } = reply else {
            return Err(unexpected());
        };
        match y {
            None => Ok(None),
            Some(y) if Some(y) == hash_to_curve(secret) => Ok(Some(Point(y))),
            Some(_) => Err(SignerError::Refused(
                "signer process: checked a point that is not hash_to_curve(secret)".into(),
            )),
        }
    }

    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        limit: &ChangeLimit,
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let reply = self
            .call(Request::BlindSign {
                keyset: keyset.0.clone(),
                outputs: outputs
                    .iter()
                    .map(|o| WireOutput {
                        amount: o.amount,
                        blinded: o.blinded.0,
                    })
                    .collect(),
                limit: WireLimit {
                    replay_key: limit.replay_key.0,
                    status: limit.status.into(),
                    unit: limit.unit.clone(),
                    cap: limit.cap,
                    keep_until: limit.keep_until,
                },
            })
            .await?;
        let Reply::BlindSignatures { sigs } = reply else {
            return Err(unexpected());
        };
        let matches = sigs.len() == outputs.len()
            && sigs.iter().zip(outputs).all(|(s, o)| s.amount == o.amount);
        if !matches {
            return Err(SignerError::Refused(
                "signer process: the signatures do not match the outputs".into(),
            ));
        }
        Ok(sigs
            .into_iter()
            .map(|s| BlindSignature {
                amount: s.amount,
                signature: Point(s.c),
                dleq: Dleq { e: s.e, s: s.s },
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[tokio::test]
    async fn own_uid_is_the_owner_of_a_file_this_process_creates() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owner = std::fs::metadata(file.path()).unwrap().uid();
        assert_eq!(own_uid().unwrap(), owner);
    }

    #[tokio::test]
    async fn a_peer_under_another_uid_is_refused() {
        let own = own_uid().unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        check_peer(&a, own).unwrap();
        assert!(matches!(
            check_peer(&a, own.wrapping_add(1)),
            Err(SignerError::Unavailable(_))
        ));
    }
}
