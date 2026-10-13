//! Messages for the online signer, built only by bnap-core.
//!
//! The overview's signer "signs only messages the socket built". A
//! [`CoreMessage`] is that message: a 32-byte tagged hash of a socket object
//! this crate serialized and validated, together with the key that must
//! sign it and its purpose. It has no public constructor, so neither a plug
//! nor a gate can hand the signer arbitrary bytes, such as a Bitcoin
//! sighash or a note key challenge, and every signature it makes is domain
//! separated by a socket tag:
//!
//! ```compile_fail,E0451
//! use bnap_core::sign::CoreMessage;
//! // Private fields: no code outside bnap-core can build one.
//! let m = CoreMessage { purpose: todo!(), key: todo!(), digest: [0u8; 32] };
//! ```
//!
//! The two ways to get one are [`UnsignedOffer`] (4.2) and
//! [`UnsignedResponse`] (8.1). Each serializes its object, keeps the bytes,
//! and after the signer answers, [`UnsignedOffer::finish`] or
//! [`UnsignedResponse::finish`] checks the signature under the object's own
//! key before it assembles and re-parses the object, so a faulty signer
//! cannot produce a bad offer or receipt.
//!
//! The signer itself is a plug (`bnap_plug::Signer`); schemes never reach
//! it, only a `CappedSigner` that cannot sign any [`CoreMessage`].

use crate::error::Error;
use crate::hash::{hmac_sha256, tagged_hash, tags};
use crate::limits::{MAX_OFFER, MAX_RESPONSE};
use crate::manifest::KeyUse;
use crate::offer::{Offer, OfferFields, types as offer_types};
use crate::response::{Response, ResponseFields, types as response_types};
use crate::schnorr::{Key, SchnorrError, Signature, SigningKey};
use crate::tlv::TlvStream;

/// What a [`CoreMessage`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// `offer_sig`: `H_"bnap/offer-sig"(S)` (4.2), signed by an offer key.
    OfferSig,
    /// `ack`: `H_"bnap/ack"(every record outside 240–1000)` (8.1), signed by
    /// a receipt key.
    Ack,
}

impl Purpose {
    /// The manifest key use that may sign this purpose. A signer MUST refuse
    /// a message whose key is not held for this use.
    #[must_use]
    pub fn key_use(self) -> KeyUse {
        match self {
            Self::OfferSig => KeyUse::Offer,
            Self::Ack => KeyUse::Receipt,
        }
    }

    /// The hash tag of the message.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::OfferSig => tags::OFFER_SIG,
            Self::Ack => tags::ACK,
        }
    }
}

/// A message bnap-core built for the online signer. See the module docs.
#[derive(Debug, PartialEq, Eq)]
pub struct CoreMessage {
    purpose: Purpose,
    key: Key,
    digest: [u8; 32],
}

impl CoreMessage {
    fn new(purpose: Purpose, key: Key, signed: &[u8]) -> Self {
        Self {
            purpose,
            key,
            digest: tagged_hash(purpose.tag(), signed),
        }
    }

    /// What the message is for.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The key that must sign it: the object's `offer_key` or `receipt_key`.
    #[must_use]
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// The 32 bytes BIP-340 signs.
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Signs with a local key, for signers that hold one. Refuses a key
    /// other than [`CoreMessage::key`].
    pub fn sign_with(&self, key: &SigningKey, aux: &[u8; 32]) -> Result<Signature, SignError> {
        if key.public_key() != self.key {
            return Err(SignError::WrongKey);
        }
        Ok(key.sign(&self.digest, aux))
    }

    /// Verifies a signature over the message under [`CoreMessage::key`].
    pub fn verify(&self, sig: &Signature) -> Result<(), SchnorrError> {
        self.key.verify(&self.digest, sig)
    }
}

/// Why signing through [`UnsignedOffer`] or [`UnsignedResponse`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The object breaks a record rule or a size limit.
    #[error(transparent)]
    Object(#[from] Error),
    /// The signature does not verify under the object's key.
    #[error("signature does not verify under the object's key")]
    BadSignature,
    /// A local signing key other than the object's key.
    #[error("signing key is not the object's key")]
    WrongKey,
}

/// An offer serialized for signing (4.2 step 4), waiting for `offer_sig`.
#[derive(Debug)]
pub struct UnsignedOffer {
    stream: TlvStream,
    mac: Option<[u8; 32]>,
    message: CoreMessage,
}

impl UnsignedOffer {
    /// Serializes `fields` with natives and computes `S`, the message and
    /// the MAC. `mac_key` is the current `K_mac`; `None` only for an offer
    /// published in advance, which then needs `issued_at`.
    pub fn new(fields: &OfferFields, mac_key: Option<&[u8; 32]>) -> Result<Self, SignError> {
        if mac_key.is_none() && fields.issued_at.is_none() {
            return Err(Error::rule(
                crate::error::Object::Offer,
                "an offer without mac needs issued_at",
            )
            .into());
        }
        let stream = fields.to_stream(true)?;
        let signed = stream.to_bytes();
        let mac = mac_key.map(|k| hmac_sha256(k, &signed));
        let message = CoreMessage::new(Purpose::OfferSig, fields.offer_key, &signed);
        Ok(Self {
            stream,
            mac,
            message,
        })
    }

    /// The message the offer key signs.
    #[must_use]
    pub fn message(&self) -> &CoreMessage {
        &self.message
    }

    /// Adds `offer_sig` and the MAC and parses the offer, with the default
    /// 4,096-byte limit.
    pub fn finish(self, sig: &Signature) -> Result<Offer, SignError> {
        self.finish_with_limit(sig, MAX_OFFER)
    }

    /// [`UnsignedOffer::finish`] with a size limit raised by the manifest.
    pub fn finish_with_limit(mut self, sig: &Signature, max: usize) -> Result<Offer, SignError> {
        self.message
            .verify(sig)
            .map_err(|_| SignError::BadSignature)?;
        let m = Error::malformed(crate::error::Object::Offer);
        self.stream
            .insert(offer_types::OFFER_SIG, sig.0)
            .map_err(&m)?;
        if let Some(mac) = self.mac {
            self.stream.insert(offer_types::MAC, mac).map_err(&m)?;
        }
        Ok(Offer::parse_with_limit(&self.stream.to_bytes(), max)?)
    }
}

/// A Response serialized for signing (8.1), waiting for its `ack`.
#[derive(Debug)]
pub struct UnsignedResponse {
    stream: TlvStream,
    message: CoreMessage,
}

impl UnsignedResponse {
    /// Serializes `fields` and computes the ack message.
    pub fn new(fields: &ResponseFields) -> Result<Self, SignError> {
        let stream = fields.to_stream()?;
        let message = CoreMessage::new(Purpose::Ack, fields.receipt_key, &stream.to_bytes());
        Ok(Self { stream, message })
    }

    /// The message the receipt key signs.
    #[must_use]
    pub fn message(&self) -> &CoreMessage {
        &self.message
    }

    /// Adds the `ack` and parses the Response, with the default 8,192-byte
    /// limit.
    pub fn finish(self, sig: &Signature) -> Result<Response, SignError> {
        self.finish_with_limit(sig, MAX_RESPONSE)
    }

    /// [`UnsignedResponse::finish`] with a size limit raised by the manifest.
    pub fn finish_with_limit(mut self, sig: &Signature, max: usize) -> Result<Response, SignError> {
        self.message
            .verify(sig)
            .map_err(|_| SignError::BadSignature)?;
        self.stream
            .insert(response_types::ACK, sig.0)
            .map_err(Error::malformed(crate::error::Object::Response))?;
        Ok(Response::parse_with_limit(&self.stream.to_bytes(), max)?)
    }
}
