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
}

impl ProcessSigner {
    /// A client for the signer process listening on `socket`.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
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

    /// One request, one reply. An error reply comes back as its
    /// [`SignerError`].
    async fn call(&self, req: Request) -> Result<Reply, SignerError> {
        let exchange = async {
            let mut stream = UnixStream::connect(&self.socket).await.map_err(|e| {
                SignerError::Unavailable(format!("cannot reach the signer process: {}", e.kind()))
            })?;
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
