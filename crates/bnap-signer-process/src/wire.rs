//! The wire protocol between [`crate::ProcessSigner`] and the signer
//! process.
//!
//! One request, one reply, each in one frame: a 4-byte big-endian length,
//! then that many bytes of JSON. A frame is at most [`MAX_FRAME`] bytes;
//! every byte string is lower-case hex; unknown fields are refused.
//!
//! ```text
//! request  {"v":1,"req":{"schnorr":{"purpose":"offer_sig","key":"..","signed":".."}}}
//!          {"v":1,"req":{"schnorr":{"purpose":"ack","key":"..","signed":"..","replay_key":".."}}}
//!          {"v":1,"req":{"verify_unblinded":{"keyset":"..","unit":"sat","amount":8,"secret":"..","c":".."}}}
//!          {"v":1,"req":{"blind_sign":{"keyset":"..","outputs":[{"amount":8,"blinded":".."}],
//!                                      "limit":{"replay_key":"..","status":"ok","unit":"sat","cap":43,"keep_until":..}}}}
//! reply    {"v":1,"reply":{"signature":{"sig":".."}}}
//!          {"v":1,"reply":{"unblinded":{"y":".." or null}}}
//!          {"v":1,"reply":{"blind_signatures":{"sigs":[{"amount":8,"c":"..","e":"..","s":".."}]}}}
//!          {"v":1,"reply":{"error":{"kind":"over_cap"|"refused"|"unavailable","message":"..","sum":..,"cap":..}}}
//! ```
//!
//! A `schnorr` request carries the object's bytes
//! ([`bnap_core::CoreMessage::signed_bytes`]), never a digest: the signer
//! process recomputes the message from them with bnap-core
//! ([`bnap_signer_file::object::recompute`]) before it signs. Nothing in any
//! request or reply is secret, and no key ever crosses the socket.

use std::time::Duration;

use bnap_core::response::Status;
use bnap_core::sign::Purpose;
use bnap_plug::SignerError;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol version every frame carries.
pub const VERSION: u32 = 1;

/// The largest frame either side reads or writes, in bytes: room for the
/// hex of the largest object the signer parses
/// ([`bnap_signer_file::object::MAX_OBJECT`]) and of
/// [`bnap_signer_file::MAX_OUTPUTS_PER_CALL`] outputs.
pub const MAX_FRAME: usize = 256 * 1024;

/// Hex for fixed-size byte arrays.
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = <&str as Deserialize>::deserialize(d)?;
        let mut b = [0u8; N];
        hex::decode_to_slice(s, &mut b).map_err(D::Error::custom)?;
        Ok(b)
    }
}

/// Hex for an optional 33-byte point.
mod hex_point_opt {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(b: &Option<[u8; 33]>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 33]>, D::Error> {
        let Some(s) = <Option<&str> as Deserialize>::deserialize(d)? else {
            return Ok(None);
        };
        let mut b = [0u8; 33];
        hex::decode_to_slice(s, &mut b).map_err(D::Error::custom)?;
        Ok(Some(b))
    }
}

/// Hex for an optional 32-byte value.
mod hex_key_opt {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(b: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let Some(s) = <Option<&str> as Deserialize>::deserialize(d)? else {
            return Ok(None);
        };
        let mut b = [0u8; 32];
        hex::decode_to_slice(s, &mut b).map_err(D::Error::custom)?;
        Ok(Some(b))
    }
}

/// Hex for byte strings.
mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <&str as Deserialize>::deserialize(d)?;
        hex::decode(s).map_err(D::Error::custom)
    }
}

/// [`Purpose`] on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePurpose {
    /// `offer_sig` (draft-00 4.2).
    OfferSig,
    /// `ack` (draft-00 8.1).
    Ack,
}

impl From<Purpose> for WirePurpose {
    fn from(p: Purpose) -> Self {
        match p {
            Purpose::OfferSig => Self::OfferSig,
            Purpose::Ack => Self::Ack,
        }
    }
}

impl From<WirePurpose> for Purpose {
    fn from(p: WirePurpose) -> Self {
        match p {
            WirePurpose::OfferSig => Self::OfferSig,
            WirePurpose::Ack => Self::Ack,
        }
    }
}

/// [`Status`] on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireStatus {
    /// OK: change.
    Ok,
    /// FAILED: a refund.
    Failed,
}

impl From<Status> for WireStatus {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => Self::Ok,
            Status::Failed => Self::Failed,
        }
    }
}

impl From<WireStatus> for Status {
    fn from(s: WireStatus) -> Self {
        match s {
            WireStatus::Ok => Self::Ok,
            WireStatus::Failed => Self::Failed,
        }
    }
}

/// One blinded output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireOutput {
    /// Its amount.
    pub amount: u64,
    /// `B'`.
    #[serde(with = "hex_array")]
    pub blinded: [u8; 33],
}

/// [`bnap_plug::ChangeLimit`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireLimit {
    /// The outcome.
    #[serde(with = "hex_array")]
    pub replay_key: [u8; 32],
    /// OK or FAILED.
    pub status: WireStatus,
    /// The pay entry's unit.
    pub unit: String,
    /// The settlement's cap.
    pub cap: u64,
    /// The earliest purge of the outcome's record.
    pub keep_until: u64,
}

/// One blind signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSignature {
    /// The output's amount.
    pub amount: u64,
    /// `C'`.
    #[serde(with = "hex_array")]
    pub c: [u8; 33],
    /// The DLEQ challenge.
    #[serde(with = "hex_array")]
    pub e: [u8; 32],
    /// The DLEQ response.
    #[serde(with = "hex_array")]
    pub s: [u8; 32],
}

/// What the client asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Sign the message of an object, recomputed from its bytes.
    Schnorr {
        /// What for.
        purpose: WirePurpose,
        /// The key the object names.
        #[serde(with = "hex_array")]
        key: [u8; 32],
        /// [`bnap_core::CoreMessage::signed_bytes`].
        #[serde(with = "hex_vec")]
        signed: Vec<u8>,
        /// For an ack, [`bnap_core::CoreMessage::replay_key`]: the outcome
        /// the Response answers. A signer that reads the use store
        /// (`bnap-signer --store`) refuses an ack without it. Absent from
        /// the frame when `None`, so older signers keep reading offers.
        #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_key_opt")]
        replay_key: Option<[u8; 32]>,
    },
    /// Check an unblinded note.
    VerifyUnblinded {
        /// The keyset ID.
        #[serde(with = "hex_vec")]
        keyset: Vec<u8>,
        /// The pay entry's unit.
        unit: String,
        /// The note's amount.
        amount: u64,
        /// The note's secret.
        #[serde(with = "hex_vec")]
        secret: Vec<u8>,
        /// The note's `C`.
        #[serde(with = "hex_array")]
        c: [u8; 33],
    },
    /// Sign blinded outputs for a settlement.
    BlindSign {
        /// The keyset ID.
        #[serde(with = "hex_vec")]
        keyset: Vec<u8>,
        /// The outputs.
        outputs: Vec<WireOutput>,
        /// The settlement.
        limit: WireLimit,
    },
}

impl Request {
    /// A short name for logs; never the contents.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Schnorr { .. } => "schnorr",
            Self::VerifyUnblinded { .. } => "verify_unblinded",
            Self::BlindSign { .. } => "blind_sign",
        }
    }
}

/// Why the signer process did not do what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// [`SignerError::OverCap`].
    OverCap,
    /// [`SignerError::Refused`].
    Refused,
    /// [`SignerError::Unavailable`].
    Unavailable,
}

/// What the signer process answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    /// A BIP-340 signature.
    Signature {
        /// The signature.
        #[serde(with = "hex_array")]
        sig: [u8; 64],
    },
    /// The `Y` the signer checked, or none.
    Unblinded {
        /// `Y`, when the note was accepted.
        #[serde(with = "hex_point_opt")]
        y: Option<[u8; 33]>,
    },
    /// One signature per output, in order.
    BlindSignatures {
        /// The signatures.
        sigs: Vec<WireSignature>,
    },
    /// A refusal.
    Error {
        /// Which kind.
        kind: ErrorKind,
        /// Why, for people (never a secret).
        message: String,
        /// For `over_cap`: the total the outputs would reach.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sum: Option<u64>,
        /// For `over_cap`: the cap.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cap: Option<u64>,
    },
}

impl From<&SignerError> for Reply {
    fn from(e: &SignerError) -> Self {
        let (kind, message, sum, cap) = match e {
            SignerError::OverCap { sum, cap } => {
                (ErrorKind::OverCap, e.to_string(), Some(*sum), Some(*cap))
            }
            SignerError::Refused(m) => (ErrorKind::Refused, m.clone(), None, None),
            SignerError::Unavailable(m) => (ErrorKind::Unavailable, m.clone(), None, None),
            other => (ErrorKind::Refused, other.to_string(), None, None),
        };
        Self::Error {
            kind,
            message,
            sum,
            cap,
        }
    }
}

impl Reply {
    /// The [`SignerError`] an error reply stands for; `None` for any other.
    #[must_use]
    pub fn to_error(&self) -> Option<SignerError> {
        let Self::Error {
            kind,
            message,
            sum,
            cap,
        } = self
        else {
            return None;
        };
        Some(match kind {
            ErrorKind::OverCap => SignerError::OverCap {
                sum: sum.unwrap_or(u64::MAX),
                cap: cap.unwrap_or(0),
            },
            ErrorKind::Refused => SignerError::Refused(format!("signer process: {message}")),
            ErrorKind::Unavailable => {
                SignerError::Unavailable(format!("signer process: {message}"))
            }
        })
    }

    /// A refusal with this message.
    #[must_use]
    pub fn refused(message: impl Into<String>) -> Self {
        Self::Error {
            kind: ErrorKind::Refused,
            message: message.into(),
            sum: None,
            cap: None,
        }
    }
}

/// A request frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrame {
    /// [`VERSION`].
    pub v: u32,
    /// The request.
    pub req: Request,
}

/// A reply frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyFrame {
    /// [`VERSION`].
    pub v: u32,
    /// The reply.
    pub reply: Reply,
}

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The peer closed the connection before a frame began.
    #[error("connection closed")]
    Closed,
    /// No complete frame in time.
    #[error("timed out")]
    Timeout,
    /// A length above [`MAX_FRAME`].
    #[error("frame of {0} bytes is above the limit of {MAX_FRAME}")]
    TooLarge(usize),
    /// Not the JSON of a frame.
    #[error("malformed frame: {0}")]
    Malformed(String),
    /// A frame of another protocol version.
    #[error("protocol version {0} is not {VERSION}")]
    Version(u32),
    /// The socket failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads one frame's bytes. `first` bounds the wait for the frame to
/// begin (an idle connection), `rest` the time to read the rest of it once
/// it began.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    first: Duration,
    rest: Duration,
) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    match tokio::time::timeout(first, r.read_exact(&mut len[..1])).await {
        Err(_) => return Err(FrameError::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(FrameError::Closed);
        }
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(_)) => {}
    }
    let body = async {
        r.read_exact(&mut len[1..]).await?;
        let n = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
        if n > MAX_FRAME {
            return Err(FrameError::TooLarge(n));
        }
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    };
    tokio::time::timeout(rest, body)
        .await
        .map_err(|_| FrameError::Timeout)?
}

/// Writes one frame, within `within`.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
    within: Duration,
) -> Result<(), FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(body.len()))?;
    let write = async {
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(body).await?;
        w.flush().await?;
        Ok::<_, std::io::Error>(())
    };
    tokio::time::timeout(within, write)
        .await
        .map_err(|_| FrameError::Timeout)??;
    Ok(())
}

/// Parses a request frame and checks its version.
pub fn decode_request(body: &[u8]) -> Result<Request, FrameError> {
    let f: RequestFrame =
        serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if f.v != VERSION {
        return Err(FrameError::Version(f.v));
    }
    Ok(f.req)
}

/// Parses a reply frame and checks its version.
pub fn decode_reply(body: &[u8]) -> Result<Reply, FrameError> {
    let f: ReplyFrame =
        serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if f.v != VERSION {
        return Err(FrameError::Version(f.v));
    }
    Ok(f.reply)
}

/// The JSON of a request frame.
#[must_use]
pub fn encode_request(req: Request) -> Vec<u8> {
    serde_json::to_vec(&RequestFrame { v: VERSION, req }).unwrap_or_default()
}

/// The JSON of a reply frame.
#[must_use]
pub fn encode_reply(reply: Reply) -> Vec<u8> {
    serde_json::to_vec(&ReplyFrame { v: VERSION, reply }).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_refuse_strangers() {
        let req = Request::BlindSign {
            keyset: vec![1; 33],
            outputs: vec![WireOutput {
                amount: 8,
                blinded: [2; 33],
            }],
            limit: WireLimit {
                replay_key: [3; 32],
                status: WireStatus::Failed,
                unit: "sat".into(),
                cap: 43,
                keep_until: 9,
            },
        };
        assert_eq!(decode_request(&encode_request(req.clone())).unwrap(), req);
        let reply = Reply::Unblinded { y: None };
        assert_eq!(decode_reply(&encode_reply(reply.clone())).unwrap(), reply);
        let reply = Reply::Unblinded { y: Some([2; 33]) };
        assert_eq!(decode_reply(&encode_reply(reply.clone())).unwrap(), reply);
        // Another version, an unknown field, a short array, an unknown
        // purpose, and a field named twice.
        let bad = [
            r#"{"v":2,"req":{"schnorr":{"purpose":"ack","key":"00","signed":""}}}"#,
            r#"{"v":1,"req":{"schnorr":{"purpose":"ack","key":"00","signed":""}},"x":1}"#,
            r#"{"v":1,"req":{"schnorr":{"purpose":"ack","key":"00","signed":""}}}"#,
            r#"{"v":1,"req":{"schnorr":{"purpose":"sighash","key":"00","signed":""}}}"#,
            r#"{"v":1,"v":1,"req":{"verify_unblinded":{}}}"#,
        ];
        for b in bad {
            assert!(decode_request(b.as_bytes()).is_err(), "{b}");
        }
    }

    #[test]
    fn frames_above_the_limit_are_refused_on_both_sides() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut a, mut b) = tokio::io::duplex(64);
            let big = vec![0u8; MAX_FRAME + 1];
            assert!(matches!(
                write_frame(&mut a, &big, Duration::from_secs(1)).await,
                Err(FrameError::TooLarge(_))
            ));
            a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
            assert!(matches!(
                read_frame(&mut b, Duration::from_secs(1), Duration::from_secs(1)).await,
                Err(FrameError::TooLarge(_))
            ));
            // A frame that starts and never ends times out.
            a.write_all(&[0, 0, 0, 9, 1]).await.unwrap();
            assert!(matches!(
                read_frame(&mut b, Duration::from_secs(1), Duration::from_millis(50)).await,
                Err(FrameError::Timeout)
            ));
            drop(a);
            let (_a, mut b) = tokio::io::duplex(64);
            assert!(matches!(
                read_frame(&mut b, Duration::from_millis(50), Duration::from_secs(1)).await,
                Err(FrameError::Timeout)
            ));
        });
    }
}
