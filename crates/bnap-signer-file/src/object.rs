//! Recomputing a signer message from the object it signs.
//!
//! The online signer "signs only messages the socket built" (overview,
//! signer). In process, bnap-core seals that guarantee into
//! [`bnap_core::sign::CoreMessage`]; across a process boundary nothing
//! sealed survives, so the signer recomputes the message itself:
//! [`recompute`] parses the bytes a [`CoreMessage`](bnap_core::CoreMessage)
//! hashes ([`CoreMessage::signed_bytes`](bnap_core::CoreMessage::signed_bytes))
//! with bnap-core's own parser, as the object the purpose names, checks that
//! the object names the key it is to be signed with, and returns the tagged
//! hash computed from those bytes.
//!
//! - **Offer signature** (draft-00 4.2): the bytes are `S`, every record of
//!   the offer outside the signature range, natives included. A placeholder
//!   `offer_sig` is added and the result must pass [`Offer::parse`], every
//!   record rule of 4.1 and 4.3 included; its `offer_key` must be the key.
//!   The message is `H_"bnap/offer-sig"(S)`.
//! - **Ack** (draft-00 8.1): the bytes are every record of the Response
//!   outside 240 to 1000. A placeholder `ack` is added and the result must
//!   pass [`Response::parse`]; its `receipt_key` must be the key. The
//!   message is `H_"bnap/ack"(bytes)`.
//!
//! The bytes must be a canonical TLV stream with no record in the signature
//! range, so they are exactly the signed part of the object that results.
//! Anything else (raw 32 bytes, a Bitcoin sighash, a note challenge, an
//! offer that names another key) is refused before any key is touched.
//!
//! What this cannot prove: that an ack answers an outcome the use store
//! recorded. In process only `Recorded::unsigned_receipt` makes an ack
//! message; a remote signer sees a well-formed Response under its receipt
//! key and nothing more (N4-3 in `notes/n4.md`).

use bnap_core::hash::tagged_hash;
use bnap_core::offer::{Offer, types as offer_types};
use bnap_core::response::{Response, types as response_types};
use bnap_core::schnorr::Key;
use bnap_core::sign::Purpose;
use bnap_core::tlv::{StreamKind, TlvStream, is_signature_type};

/// The largest object the signer parses, in bytes: far above the default
/// offer (4,096) and Response (8,192) limits, so a manifest that raised
/// them still signs, and small enough to bound the work per request.
pub const MAX_OBJECT: usize = 65_536;

/// The bytes of a 64-byte record of type 240: type, length, value.
const SIG_RECORD: usize = 66;

/// Why bytes are not a message bnap-core builds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ObjectError {
    /// Longer than [`MAX_OBJECT`].
    #[error("object of {0} bytes is above the signer's limit")]
    TooLarge(usize),
    /// Not a canonical top-level TLV stream.
    #[error("not a canonical TLV stream")]
    Framing,
    /// A record in the signature range, which no signed part holds.
    #[error("a record of type {0} in the signature range")]
    SignatureRange(u64),
    /// The object breaks a record rule of draft-00.
    #[error("not a valid {object}: {reason}")]
    Invalid {
        /// `offer` or `response`.
        object: &'static str,
        /// bnap-core's reason.
        reason: String,
    },
    /// The object names another key than the one requested.
    #[error("the object names another key")]
    OtherKey,
}

/// The message to sign for `purpose` under `key`, recomputed from `signed`
/// (see the module docs), or why `signed` is not one.
pub fn recompute(purpose: Purpose, key: &Key, signed: &[u8]) -> Result<[u8; 32], ObjectError> {
    if signed.len() > MAX_OBJECT {
        return Err(ObjectError::TooLarge(signed.len()));
    }
    let stream =
        TlvStream::parse(signed, StreamKind::TopLevel).map_err(|_| ObjectError::Framing)?;
    if stream.to_bytes() != signed {
        return Err(ObjectError::Framing);
    }
    if let Some((t, _)) = stream.records().iter().find(|(t, _)| is_signature_type(*t)) {
        return Err(ObjectError::SignatureRange(*t));
    }
    let mut whole = stream;
    let digest = match purpose {
        Purpose::OfferSig => {
            whole
                .insert(offer_types::OFFER_SIG, [0u8; 64])
                .map_err(|_| ObjectError::Framing)?;
            let offer = Offer::parse_with_limit(&whole.to_bytes(), MAX_OBJECT + SIG_RECORD)
                .map_err(|e| ObjectError::Invalid {
                    object: "offer",
                    reason: e.to_string(),
                })?;
            if offer.fields().offer_key != *key {
                return Err(ObjectError::OtherKey);
            }
            if offer.signed_bytes() != signed {
                return Err(ObjectError::Framing);
            }
            offer.sig_message()
        }
        Purpose::Ack => {
            whole
                .insert(response_types::ACK, [0u8; 64])
                .map_err(|_| ObjectError::Framing)?;
            let response = Response::parse_with_limit(&whole.to_bytes(), MAX_OBJECT + SIG_RECORD)
                .map_err(|e| ObjectError::Invalid {
                object: "response",
                reason: e.to_string(),
            })?;
            if response.fields().receipt_key != *key {
                return Err(ObjectError::OtherKey);
            }
            response.ack_message()
        }
    };
    // The object's own message is the tagged hash of exactly these bytes.
    if digest != tagged_hash(purpose.tag(), signed) {
        return Err(ObjectError::Framing);
    }
    Ok(digest)
}
