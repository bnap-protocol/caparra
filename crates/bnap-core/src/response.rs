//! The Response and its receipt (draft-00 section 8.1).
//!
//! The `ack` (type 240) is a signature by `receipt_key` over
//! `H_"bnap/ack"(every record outside 240..=1000)`, unknown odd records
//! included.

use crate::encoding::tu64;
use crate::error::{Error, MalformedKind, Object, VERSION};
use crate::hash::{Digest, OfferId, tagged_hash, tags};
use crate::limits::{CLOCK_SKEW, MAX_RESPONSE};
use crate::manifest::{KeyUse, ManifestKey};
use crate::schnorr::{Key, Signature, SigningKey};
use crate::tlv::{Fields, StreamKind, TlvStream, is_signature_type};

/// Record types of the Response (8.1).
pub mod types {
    /// `version`, tu64.
    pub const VERSION: u64 = 0;
    /// `status`, tu64: 0 OK, 1 FAILED.
    pub const STATUS: u64 = 2;
    /// `replayed`, flag.
    pub const REPLAYED: u64 = 4;
    /// `charged`, tu64.
    pub const CHARGED: u64 = 6;
    /// `unit`, UTF-8.
    pub const UNIT: u64 = 8;
    /// `offer_id`, 32 bytes.
    pub const OFFER_ID: u64 = 10;
    /// `digest`, 32 bytes.
    pub const DIGEST: u64 = 12;
    /// `metered_units`, tu64.
    pub const METERED_UNITS: u64 = 14;
    /// `scheme_result`, bytes.
    pub const SCHEME_RESULT: u64 = 16;
    /// `receipt_key`, key.
    pub const RECEIPT_KEY: u64 = 18;
    /// `settled_at`, tu64.
    pub const SETTLED_AT: u64 = 20;
    /// `ack`, signature.
    pub const ACK: u64 = 240;
}

/// The outcome a Response reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// 0: the action ran and settled OK.
    Ok,
    /// 1: the action failed.
    Failed,
}

impl Status {
    /// The tu64 code.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
        }
    }
}

/// Everything in a Response except `ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseFields {
    /// OK or FAILED.
    pub status: Status,
    /// Set on replays.
    pub replayed: bool,
    /// The charge in `unit`; 0 when nothing was charged.
    pub charged: u64,
    /// The chosen entry's unit; required when the credential has `pay`.
    pub unit: Option<String>,
    /// The `OfferID` of the offer the credential used.
    pub offer_id: OfferId,
    /// The Digest of the request this Response answers.
    pub digest: Digest,
    /// The meter's count; required in metered offers.
    pub metered_units: Option<u64>,
    /// Bytes defined by the scheme, such as change signatures.
    pub scheme_result: Option<Vec<u8>>,
    /// The key that signs the ack.
    pub receipt_key: Key,
    /// Settlement time, Unix seconds.
    pub settled_at: u64,
    /// Unknown odd records outside the signature range; the ack covers them.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl ResponseFields {
    pub(crate) fn to_stream(&self) -> Result<TlvStream, Error> {
        use types as t;
        let m = Error::malformed(Object::Response);
        let mut s = TlvStream::new();
        s.insert(t::VERSION, tu64(VERSION)).map_err(&m)?;
        s.insert(t::STATUS, tu64(self.status.code())).map_err(&m)?;
        if self.replayed {
            s.insert(t::REPLAYED, Vec::<u8>::new()).map_err(&m)?;
        }
        s.insert(t::CHARGED, tu64(self.charged)).map_err(&m)?;
        if let Some(u) = &self.unit {
            s.insert(t::UNIT, u.as_bytes()).map_err(&m)?;
        }
        s.insert(t::OFFER_ID, self.offer_id.0).map_err(&m)?;
        s.insert(t::DIGEST, self.digest.0).map_err(&m)?;
        if let Some(n) = self.metered_units {
            s.insert(t::METERED_UNITS, tu64(n)).map_err(&m)?;
        }
        if let Some(r) = &self.scheme_result {
            s.insert(t::SCHEME_RESULT, r.clone()).map_err(&m)?;
        }
        s.insert(t::RECEIPT_KEY, self.receipt_key.0).map_err(&m)?;
        s.insert(t::SETTLED_AT, tu64(self.settled_at)).map_err(&m)?;
        for (typ, v) in &self.unknown {
            if typ % 2 == 0 {
                return Err(m(MalformedKind::UnknownEvenType(*typ)));
            }
            if is_signature_type(*typ) {
                return Err(Error::rule(
                    Object::Response,
                    "extra records may not use the signature range",
                ));
            }
            s.insert(*typ, v.clone()).map_err(&m)?;
        }
        Ok(s)
    }

    /// Signs the Response with the receipt key and returns it parsed, with
    /// the default 8,192-byte limit. `key` must be the key in `receipt_key`.
    pub fn sign(&self, key: &SigningKey, aux: &[u8; 32]) -> Result<Response, Error> {
        self.sign_with_limit(key, aux, MAX_RESPONSE)
    }

    /// [`ResponseFields::sign`] with a size limit raised by the manifest.
    pub fn sign_with_limit(
        &self,
        key: &SigningKey,
        aux: &[u8; 32],
        max: usize,
    ) -> Result<Response, Error> {
        if key.public_key() != self.receipt_key {
            return Err(Error::rule(
                Object::Response,
                "receipt_key is not the signing key",
            ));
        }
        let mut s = self.to_stream()?;
        let ack = key.sign(&tagged_hash(tags::ACK, &s.to_bytes()), aux);
        s.insert(types::ACK, ack.0)
            .map_err(Error::malformed(Object::Response))?;
        Response::parse_with_limit(&s.to_bytes(), max)
    }
}

/// A parsed, immutable Response. It keeps the bytes as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    bytes: Vec<u8>,
    fields: ResponseFields,
    ack: Signature,
    signed: Vec<u8>,
}

/// Why a receipt failed a client check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The ack does not verify under `receipt_key`.
    #[error("ack does not verify")]
    Ack,
    /// `receipt_key` is not in the pin for use `receipt`, or its `not_after`
    /// is before `settled_at`.
    #[error("receipt key not pinned for use receipt at settled_at")]
    NotPinned,
    /// A fresh (not replayed) receipt whose `settled_at` is more than 60 s
    /// from the client's clock.
    #[error("settled_at more than 60 s from the client clock")]
    Clock,
    /// The Response answers another offer or another Digest.
    #[error("receipt answers another request")]
    WrongRequest,
}

impl Response {
    /// Parses a Response with the default 8,192-byte limit.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_with_limit(bytes, MAX_RESPONSE)
    }

    /// Parses a Response: size, framing, version and the records of 8.1.
    pub fn parse_with_limit(bytes: &[u8], max: usize) -> Result<Self, Error> {
        use types as t;
        if bytes.len() > max {
            return Err(Error::TooLarge {
                object: Object::Response,
                len: bytes.len(),
                max,
            });
        }
        let m = Error::malformed(Object::Response);
        let stream = TlvStream::parse(bytes, StreamKind::TopLevel).map_err(&m)?;
        let mut f = Fields::new(&stream);
        let version = f.required_tu64(t::VERSION).map_err(&m)?;
        if version != VERSION {
            return Err(Error::Version {
                object: Object::Response,
                version,
            });
        }
        let status = match f.required_tu64(t::STATUS).map_err(&m)? {
            0 => Status::Ok,
            1 => Status::Failed,
            _ => return Err(Error::rule(Object::Response, "status outside 0 to 1")),
        };
        let replayed = f.flag(t::REPLAYED).map_err(&m)?;
        let charged = f.required_tu64(t::CHARGED).map_err(&m)?;
        let unit = f.utf8(t::UNIT).map_err(&m)?;
        let offer_id = OfferId(f.required_fixed::<32>(t::OFFER_ID).map_err(&m)?);
        let digest = Digest(f.required_fixed::<32>(t::DIGEST).map_err(&m)?);
        let metered_units = f.tu64(t::METERED_UNITS).map_err(&m)?;
        let scheme_result = f.take(t::SCHEME_RESULT).map(<[u8]>::to_vec);
        let receipt_key = Key(f.required_fixed::<32>(t::RECEIPT_KEY).map_err(&m)?);
        let settled_at = f.required_tu64(t::SETTLED_AT).map_err(&m)?;
        let ack = Signature(f.required_fixed::<64>(t::ACK).map_err(&m)?);
        let unknown = f
            .finish()
            .map_err(&m)?
            .into_iter()
            .filter(|(t, _)| !is_signature_type(*t))
            .collect();
        let fields = ResponseFields {
            status,
            replayed,
            charged,
            unit,
            offer_id,
            digest,
            metered_units,
            scheme_result,
            receipt_key,
            settled_at,
            unknown,
        };
        Ok(Self {
            bytes: bytes.to_vec(),
            fields,
            ack,
            signed: stream.signed_bytes(&[]),
        })
    }

    /// The bytes as received.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The records outside the signature range.
    #[must_use]
    pub fn fields(&self) -> &ResponseFields {
        &self.fields
    }

    /// The ack.
    #[must_use]
    pub fn ack(&self) -> Signature {
        self.ack
    }

    /// The message the ack signs: `H_"bnap/ack"(every record outside
    /// 240..=1000)`.
    #[must_use]
    pub fn ack_message(&self) -> [u8; 32] {
        tagged_hash(tags::ACK, &self.signed)
    }

    /// Verifies the ack under the Response's own `receipt_key`.
    pub fn verify_ack(&self) -> Result<(), ReceiptError> {
        self.fields
            .receipt_key
            .verify(&self.ack_message(), &self.ack)
            .map_err(|_| ReceiptError::Ack)
    }

    /// True when the Response answers the request with this `OfferID` and
    /// Digest.
    #[must_use]
    pub fn answers(&self, offer_id: &OfferId, digest: &Digest) -> bool {
        &self.fields.offer_id == offer_id && &self.fields.digest == digest
    }

    /// The presence rules of 8.1 that depend on the request: `unit` is
    /// required when the credential has `pay`, and `metered_units` in
    /// metered offers.
    pub fn check_required(&self, metered: bool, has_pay: bool) -> Result<(), Error> {
        if has_pay && self.fields.unit.is_none() {
            return Err(Error::rule(
                Object::Response,
                "unit is required when the credential has pay",
            ));
        }
        if metered && self.fields.metered_units.is_none() {
            return Err(Error::rule(
                Object::Response,
                "metered_units is required in metered offers",
            ));
        }
        Ok(())
    }

    /// The client's receipt rules of 9.3: the ack verifies; `receipt_key`
    /// is listed in the pin with use `receipt` and `not_after >= settled_at`;
    /// without `replayed`, `settled_at` is within 60 s of the client's clock
    /// on arrival; and the Response answers `offer_id` and `digest`.
    pub fn check_client(
        &self,
        pinned_keys: &[ManifestKey],
        now: u64,
        offer_id: &OfferId,
        digest: &Digest,
    ) -> Result<(), ReceiptError> {
        self.verify_ack()?;
        let f = &self.fields;
        let listed = pinned_keys.iter().any(|k| {
            k.kid == f.receipt_key && k.key_use == KeyUse::Receipt && k.not_after >= f.settled_at
        });
        if !listed {
            return Err(ReceiptError::NotPinned);
        }
        if !f.replayed && f.settled_at.abs_diff(now) > CLOCK_SKEW {
            return Err(ReceiptError::Clock);
        }
        if !self.answers(offer_id, digest) {
            return Err(ReceiptError::WrongRequest);
        }
        Ok(())
    }
}
