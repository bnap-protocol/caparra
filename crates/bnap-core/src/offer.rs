//! The Offer (draft-00 section 4): records, `OfferID`, `offer_sig`, MAC, the
//! builder, the parser and the section 4.4 checks.
//!
//! Build an offer by filling [`OfferFields`], computing its
//! [`OfferFields::offer_id`] when native artifacts must embed it, adding the
//! natives, then calling [`OfferFields::sign`]. Parse a received offer with
//! [`Offer::parse`]; the parser enforces every structural rule of 4.1 and
//! keeps the received bytes, so the `OfferID`, `S` and the MAC are computed
//! over exactly what was sent, unknown odd records included.

use crate::class::BindingClass;
use crate::encoding::tu64;
use crate::error::{BadOffer, Error, MalformedKind, Object, Stale, VERSION};
use crate::hash::{OfferId, Scope, hmac_sha256, hmac_sha256_verify, tagged_hash, tags};
use crate::limits::{MAX_OFFER, expired, in_future};
use crate::manifest::{KeyUse, ManifestKey};
use crate::schnorr::{Key, Signature, SigningKey};
use crate::tlv::{Fields, StreamKind, TlvStream, entry_list, is_signature_type, parse_entry_list};

/// Record types of the Offer (4.1).
pub mod types {
    /// `version`, tu64.
    pub const VERSION: u64 = 0;
    /// `scope`, 32 bytes.
    pub const SCOPE: u64 = 2;
    /// `route_scope`, flag.
    pub const ROUTE_SCOPE: u64 = 4;
    /// `headers`, UTF-8.
    pub const HEADERS: u64 = 6;
    /// `metered`, flag.
    pub const METERED: u64 = 8;
    /// `expires`, tu64.
    pub const EXPIRES: u64 = 10;
    /// `info`, UTF-8 URI.
    pub const INFO: u64 = 12;
    /// `offer_key`, 32 bytes.
    pub const OFFER_KEY: u64 = 14;
    /// `nonce`, 16 bytes.
    pub const NONCE: u64 = 16;
    /// `pay`, entry list.
    pub const PAY: u64 = 18;
    /// `attest`, entry list.
    pub const ATTEST: u64 = 20;
    /// `issued_at`, tu64.
    pub const ISSUED_AT: u64 = 24;
    /// `native`, entry list.
    pub const NATIVE: u64 = 26;
    /// `offer_sig`, signature.
    pub const OFFER_SIG: u64 = 240;
    /// `mac`, 32 bytes.
    pub const MAC: u64 = 242;
}

/// Record types of a pay entry (4.1).
pub mod pay_types {
    /// `scheme`, UTF-8.
    pub const SCHEME: u64 = 0;
    /// `amount`, tu64.
    pub const AMOUNT: u64 = 2;
    /// `unit`, UTF-8.
    pub const UNIT: u64 = 4;
    /// `quote_expires`, tu64.
    pub const QUOTE_EXPIRES: u64 = 6;
    /// `params`, bytes.
    pub const PARAMS: u64 = 8;
    /// `rate`, tu64.
    pub const RATE: u64 = 10;
}

/// Record types of an attest entry (4.1).
pub mod attest_types {
    /// `scheme`, UTF-8.
    pub const SCHEME: u64 = 0;
    /// `effect`, tu64.
    pub const EFFECT: u64 = 2;
    /// `value`, tu64.
    pub const VALUE: u64 = 4;
    /// `epoch`, tu64.
    pub const EPOCH: u64 = 6;
    /// `params`, bytes.
    pub const PARAMS: u64 = 8;
}

/// Record types of a native entry (4.1).
pub mod native_types {
    /// `pay_index`, tu64.
    pub const PAY_INDEX: u64 = 0;
    /// `kind`, UTF-8.
    pub const KIND: u64 = 2;
    /// `data`, bytes.
    pub const DATA: u64 = 4;
}

/// Maximum discount value in basis points.
pub const MAX_DISCOUNT_BP: u64 = 10_000;

/// What an attestation does to the price (4.1, section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// 0: the attestation is required.
    Required,
    /// 1: a verified attestation makes the price zero.
    Waive,
    /// 2: a verified attestation takes `value` basis points off.
    Discount,
    /// 3: a verified attestation admits up to `value` actions per `epoch`.
    Quota,
}

impl Effect {
    /// The tu64 code: 0 required, 1 waive, 2 discount, 3 quota.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            Self::Required => 0,
            Self::Waive => 1,
            Self::Discount => 2,
            Self::Quota => 3,
        }
    }

    /// Decodes the tu64 code.
    #[must_use]
    pub fn from_code(c: u64) -> Option<Self> {
        match c {
            0 => Some(Self::Required),
            1 => Some(Self::Waive),
            2 => Some(Self::Discount),
            3 => Some(Self::Quota),
            _ => None,
        }
    }
}

/// A pay entry: one value scheme the offer accepts (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayEntry {
    /// Scheme ID, unique within `pay`.
    pub scheme: String,
    /// Amount in the unit's base denomination; the ceiling in a metered offer.
    pub amount: u64,
    /// `sat`, `msat`, an ISO 4217 code or a CAIP-19 asset ID.
    pub unit: String,
    /// Quote expiry; defaults to the offer's `expires` and MUST NOT exceed it.
    pub quote_expires: Option<u64>,
    /// Bytes defined by the scheme's registry entry.
    pub params: Option<Vec<u8>>,
    /// Price per 1,000 meter units in `unit`; required in metered offers.
    pub rate: Option<u64>,
    /// Unknown odd records, kept so the signature still covers them.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl PayEntry {
    /// A pay entry with only the required records.
    #[must_use]
    pub fn new(scheme: impl Into<String>, amount: u64, unit: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            amount,
            unit: unit.into(),
            quote_expires: None,
            params: None,
            rate: None,
            unknown: Vec::new(),
        }
    }

    /// The quote expiry in force: `quote_expires`, or the offer's `expires`.
    #[must_use]
    pub fn effective_quote_expires(&self, offer_expires: u64) -> u64 {
        self.quote_expires.unwrap_or(offer_expires)
    }

    /// Serializes the entry as a nested stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use pay_types as t;
        let m = Error::malformed(Object::PayEntry);
        let mut s = TlvStream::new();
        s.insert(t::SCHEME, self.scheme.as_bytes()).map_err(&m)?;
        s.insert(t::AMOUNT, tu64(self.amount)).map_err(&m)?;
        s.insert(t::UNIT, self.unit.as_bytes()).map_err(&m)?;
        if let Some(q) = self.quote_expires {
            s.insert(t::QUOTE_EXPIRES, tu64(q)).map_err(&m)?;
        }
        if let Some(p) = &self.params {
            s.insert(t::PARAMS, p.clone()).map_err(&m)?;
        }
        if let Some(r) = self.rate {
            s.insert(t::RATE, tu64(r)).map_err(&m)?;
        }
        insert_unknown(&mut s, &self.unknown, Object::PayEntry, StreamKind::Nested)?;
        Ok(s.to_bytes())
    }

    /// Parses a nested pay-entry stream.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use pay_types as t;
        let m = Error::malformed(Object::PayEntry);
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(&m)?;
        let mut f = Fields::new(&s);
        let scheme = f.required_utf8(t::SCHEME).map_err(&m)?;
        let amount = f.required_tu64(t::AMOUNT).map_err(&m)?;
        let unit = f.required_utf8(t::UNIT).map_err(&m)?;
        let quote_expires = f.tu64(t::QUOTE_EXPIRES).map_err(&m)?;
        let params = f.take(t::PARAMS).map(<[u8]>::to_vec);
        let rate = f.tu64(t::RATE).map_err(&m)?;
        let unknown = f.finish().map_err(&m)?;
        Ok(Self {
            scheme,
            amount,
            unit,
            quote_expires,
            params,
            rate,
            unknown,
        })
    }
}

/// An attest entry: one attestation scheme the offer accepts (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestEntry {
    /// Scheme ID, unique within `attest`.
    pub scheme: String,
    /// What a verified attestation does.
    pub effect: Effect,
    /// Basis points for a discount (1 to 10,000); actions per epoch for a
    /// quota (at least 1).
    pub value: Option<u64>,
    /// Quota epoch in seconds, at least 1.
    pub epoch: Option<u64>,
    /// Bytes defined by the scheme's registry entry.
    pub params: Option<Vec<u8>>,
    /// Unknown odd records, kept so the signature still covers them.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl AttestEntry {
    /// An attest entry with only scheme and effect.
    #[must_use]
    pub fn new(scheme: impl Into<String>, effect: Effect) -> Self {
        Self {
            scheme: scheme.into(),
            effect,
            value: None,
            epoch: None,
            params: None,
            unknown: Vec::new(),
        }
    }

    /// A discount of `bp` basis points.
    #[must_use]
    pub fn discount(scheme: impl Into<String>, bp: u64) -> Self {
        Self {
            value: Some(bp),
            ..Self::new(scheme, Effect::Discount)
        }
    }

    /// A quota of `value` actions per `epoch` seconds.
    #[must_use]
    pub fn quota(scheme: impl Into<String>, value: u64, epoch: u64) -> Self {
        Self {
            value: Some(value),
            epoch: Some(epoch),
            ..Self::new(scheme, Effect::Quota)
        }
    }

    /// Serializes the entry as a nested stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use attest_types as t;
        let m = Error::malformed(Object::AttestEntry);
        let mut s = TlvStream::new();
        s.insert(t::SCHEME, self.scheme.as_bytes()).map_err(&m)?;
        s.insert(t::EFFECT, tu64(self.effect.code())).map_err(&m)?;
        if let Some(v) = self.value {
            s.insert(t::VALUE, tu64(v)).map_err(&m)?;
        }
        if let Some(e) = self.epoch {
            s.insert(t::EPOCH, tu64(e)).map_err(&m)?;
        }
        if let Some(p) = &self.params {
            s.insert(t::PARAMS, p.clone()).map_err(&m)?;
        }
        insert_unknown(
            &mut s,
            &self.unknown,
            Object::AttestEntry,
            StreamKind::Nested,
        )?;
        Ok(s.to_bytes())
    }

    /// Parses a nested attest-entry stream, including the effect, value and
    /// epoch ranges.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use attest_types as t;
        let m = Error::malformed(Object::AttestEntry);
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(&m)?;
        let mut f = Fields::new(&s);
        let scheme = f.required_utf8(t::SCHEME).map_err(&m)?;
        let code = f.required_tu64(t::EFFECT).map_err(&m)?;
        let effect = Effect::from_code(code)
            .ok_or_else(|| Error::rule(Object::AttestEntry, "effect outside 0 to 3"))?;
        let value = f.tu64(t::VALUE).map_err(&m)?;
        let epoch = f.tu64(t::EPOCH).map_err(&m)?;
        let params = f.take(t::PARAMS).map(<[u8]>::to_vec);
        let unknown = f.finish().map_err(&m)?;
        let e = Self {
            scheme,
            effect,
            value,
            epoch,
            params,
            unknown,
        };
        e.check_ranges()?;
        Ok(e)
    }

    fn check_ranges(&self) -> Result<(), Error> {
        let bad = |r| Err(Error::rule(Object::AttestEntry, r));
        match self.effect {
            Effect::Discount => match self.value {
                Some(1..=MAX_DISCOUNT_BP) => Ok(()),
                _ => bad("discount value must be 1 to 10,000 basis points"),
            },
            Effect::Quota => {
                if self.value.is_none_or(|v| v < 1) {
                    return bad("quota value must be at least 1");
                }
                if self.epoch.is_none_or(|e| e < 1) {
                    return bad("quota epoch must be at least 1");
                }
                Ok(())
            }
            Effect::Required | Effect::Waive => Ok(()),
        }
    }
}

/// A native entry: an artifact the server made for one pay entry (4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEntry {
    /// Zero-based index into `pay`; that entry's scheme MUST be class O.
    pub pay_index: u64,
    /// Label from the scheme's registry entry, such as `bolt11`.
    pub kind: String,
    /// The artifact's bytes.
    pub data: Vec<u8>,
    /// Unknown odd records, kept so the signature still covers them.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl NativeEntry {
    /// A native entry.
    #[must_use]
    pub fn new(pay_index: u64, kind: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            pay_index,
            kind: kind.into(),
            data: data.into(),
            unknown: Vec::new(),
        }
    }

    /// Serializes the entry as a nested stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use native_types as t;
        let m = Error::malformed(Object::NativeEntry);
        let mut s = TlvStream::new();
        s.insert(t::PAY_INDEX, tu64(self.pay_index)).map_err(&m)?;
        s.insert(t::KIND, self.kind.as_bytes()).map_err(&m)?;
        s.insert(t::DATA, self.data.clone()).map_err(&m)?;
        insert_unknown(
            &mut s,
            &self.unknown,
            Object::NativeEntry,
            StreamKind::Nested,
        )?;
        Ok(s.to_bytes())
    }

    /// Parses a nested native-entry stream.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use native_types as t;
        let m = Error::malformed(Object::NativeEntry);
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(&m)?;
        let mut f = Fields::new(&s);
        let pay_index = f.required_tu64(t::PAY_INDEX).map_err(&m)?;
        let kind = f.required_utf8(t::KIND).map_err(&m)?;
        let data = f.required(t::DATA).map_err(&m)?.to_vec();
        let unknown = f.finish().map_err(&m)?;
        Ok(Self {
            pay_index,
            kind,
            data,
            unknown,
        })
    }
}

/// Adds caller-supplied unknown records to a stream being built. They must
/// be odd (the even/odd rule) and outside the signature range, which no
/// signature covers. In a nested stream they must also be in a nested range.
fn insert_unknown(
    s: &mut TlvStream,
    unknown: &[(u64, Vec<u8>)],
    object: Object,
    kind: StreamKind,
) -> Result<(), Error> {
    for (t, v) in unknown {
        if t % 2 == 0 {
            return Err(Error::Malformed {
                object,
                kind: MalformedKind::UnknownEvenType(*t),
            });
        }
        if is_signature_type(*t) {
            return Err(Error::rule(
                object,
                "extra records may not use the signature range",
            ));
        }
        if kind == StreamKind::Nested && !crate::tlv::nested_type_allowed(*t) {
            return Err(Error::Malformed {
                object,
                kind: MalformedKind::TypeNotAllowed(*t),
            });
        }
        s.insert(*t, v.clone()).map_err(Error::malformed(object))?;
    }
    Ok(())
}

/// Everything in an offer except its signature records: the builder's input
/// and the parser's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferFields {
    /// Action scope or route scope (4.3).
    pub scope: Scope,
    /// `scope` names a route, not one action.
    pub route_scope: bool,
    /// Lower-case field names the carrier hashes into the action scope, in
    /// the route's order. Empty means the record is absent.
    pub headers: Vec<String>,
    /// The charge is set at settlement, up to the entry's amount.
    pub metered: bool,
    /// Expiry, Unix seconds.
    pub expires: u64,
    /// URI of the manifest, on the same origin.
    pub info: Option<String>,
    /// The key that signs this offer.
    pub offer_key: Key,
    /// 16 random bytes.
    pub nonce: [u8; 16],
    /// Pay entries in preference order.
    pub pay: Vec<PayEntry>,
    /// Attest entries.
    pub attest: Vec<AttestEntry>,
    /// Issue time; required when `mac` is absent.
    pub issued_at: Option<u64>,
    /// Native entries; exact-scope offers only.
    pub native: Vec<NativeEntry>,
    /// Unknown odd records outside the signature range, GREASE included.
    /// They are part of `S₀` and `S`.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl OfferFields {
    /// An offer with only the required scalar records set.
    #[must_use]
    pub fn new(scope: Scope, expires: u64, offer_key: Key, nonce: [u8; 16]) -> Self {
        Self {
            scope,
            route_scope: false,
            headers: Vec::new(),
            metered: false,
            expires,
            info: None,
            offer_key,
            nonce,
            pay: Vec::new(),
            attest: Vec::new(),
            issued_at: None,
            native: Vec::new(),
            unknown: Vec::new(),
        }
    }

    fn to_stream(&self, with_native: bool) -> Result<TlvStream, Error> {
        use types as t;
        self.validate()?;
        let m = Error::malformed(Object::Offer);
        let mut s = TlvStream::new();
        s.insert(t::VERSION, tu64(VERSION)).map_err(&m)?;
        s.insert(t::SCOPE, self.scope.0).map_err(&m)?;
        if self.route_scope {
            s.insert(t::ROUTE_SCOPE, Vec::<u8>::new()).map_err(&m)?;
        }
        if !self.headers.is_empty() {
            s.insert(t::HEADERS, self.headers.join(",").into_bytes())
                .map_err(&m)?;
        }
        if self.metered {
            s.insert(t::METERED, Vec::<u8>::new()).map_err(&m)?;
        }
        s.insert(t::EXPIRES, tu64(self.expires)).map_err(&m)?;
        if let Some(i) = &self.info {
            s.insert(t::INFO, i.as_bytes()).map_err(&m)?;
        }
        s.insert(t::OFFER_KEY, self.offer_key.0).map_err(&m)?;
        s.insert(t::NONCE, self.nonce).map_err(&m)?;
        if !self.pay.is_empty() {
            let items = self
                .pay
                .iter()
                .map(PayEntry::to_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            s.insert(t::PAY, entry_list(&items)).map_err(&m)?;
        }
        if !self.attest.is_empty() {
            let items = self
                .attest
                .iter()
                .map(AttestEntry::to_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            s.insert(t::ATTEST, entry_list(&items)).map_err(&m)?;
        }
        if let Some(i) = self.issued_at {
            s.insert(t::ISSUED_AT, tu64(i)).map_err(&m)?;
        }
        if with_native && !self.native.is_empty() {
            let items = self
                .native
                .iter()
                .map(NativeEntry::to_bytes)
                .collect::<Result<Vec<_>, _>>()?;
            s.insert(t::NATIVE, entry_list(&items)).map_err(&m)?;
        }
        insert_unknown(&mut s, &self.unknown, Object::Offer, StreamKind::TopLevel)?;
        Ok(s)
    }

    /// The `OfferID` these fields give: `H_"bnap/offer"(S₀)`, over every record
    /// except the signature range and `native` (4.2 steps 1 and 2).
    ///
    /// Native artifacts that must embed the `OfferID` are made after this call
    /// and added to [`OfferFields::native`]; the `OfferID` does not change.
    pub fn offer_id(&self) -> Result<OfferId, Error> {
        Ok(OfferId(tagged_hash(
            tags::OFFER,
            &self.to_stream(false)?.to_bytes(),
        )))
    }

    /// Signs the offer (4.2 step 4) and returns it parsed, with the default
    /// 4,096-byte limit.
    ///
    /// `key` must be the key named in `offer_key`. `mac_key` is the gate's
    /// current `K_mac`; pass `None` only for an offer published in advance,
    /// which then needs `issued_at`. `aux` is the BIP-340 auxiliary
    /// randomness.
    pub fn sign(
        &self,
        key: &SigningKey,
        mac_key: Option<&[u8; 32]>,
        aux: &[u8; 32],
    ) -> Result<Offer, Error> {
        self.sign_with_limit(key, mac_key, aux, MAX_OFFER)
    }

    /// [`OfferFields::sign`] with a size limit raised by the manifest.
    pub fn sign_with_limit(
        &self,
        key: &SigningKey,
        mac_key: Option<&[u8; 32]>,
        aux: &[u8; 32],
        max: usize,
    ) -> Result<Offer, Error> {
        if key.public_key() != self.offer_key {
            return Err(Error::rule(
                Object::Offer,
                "offer_key is not the signing key",
            ));
        }
        if mac_key.is_none() && self.issued_at.is_none() {
            return Err(Error::rule(
                Object::Offer,
                "an offer without mac needs issued_at",
            ));
        }
        let mut s = self.to_stream(true)?;
        let signed = s.to_bytes();
        let sig = key.sign(&tagged_hash(tags::OFFER_SIG, &signed), aux);
        let m = Error::malformed(Object::Offer);
        s.insert(types::OFFER_SIG, sig.0).map_err(&m)?;
        if let Some(k) = mac_key {
            s.insert(types::MAC, hmac_sha256(k, &signed)).map_err(&m)?;
        }
        Offer::parse_with_limit(&s.to_bytes(), max)
    }

    /// The pay entry for `scheme`, with its index.
    #[must_use]
    pub fn pay_entry(&self, scheme: &str) -> Option<(usize, &PayEntry)> {
        self.pay
            .iter()
            .enumerate()
            .find(|(_, e)| e.scheme == scheme)
    }

    /// The attest entry for `scheme`.
    #[must_use]
    pub fn attest_entry(&self, scheme: &str) -> Option<&AttestEntry> {
        self.attest.iter().find(|e| e.scheme == scheme)
    }

    /// The structural rules of 4.1 and 4.3 that span records.
    fn validate(&self) -> Result<(), Error> {
        let bad = |r| Err(Error::rule(Object::Offer, r));
        for h in &self.headers {
            check_header_name(h).map_err(Error::malformed(Object::Offer))?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.pay {
            if e.scheme.is_empty() {
                return bad("empty scheme ID in pay");
            }
            if !seen.insert(e.scheme.as_str()) {
                return Err(Error::Malformed {
                    object: Object::Offer,
                    kind: MalformedKind::DuplicateScheme(e.scheme.clone()),
                });
            }
            if e.unit.is_empty() {
                return bad("empty unit in pay");
            }
            if e.quote_expires.is_some_and(|q| q > self.expires) {
                return bad("quote_expires exceeds expires");
            }
            if self.metered && e.rate.is_none() {
                return bad("metered offer with a pay entry that has no rate");
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.attest {
            if e.scheme.is_empty() {
                return bad("empty scheme ID in attest");
            }
            if !seen.insert(e.scheme.as_str()) {
                return Err(Error::Malformed {
                    object: Object::Offer,
                    kind: MalformedKind::DuplicateScheme(e.scheme.clone()),
                });
            }
            e.check_ranges()?;
        }
        if self.pay.is_empty() && !self.attest.iter().any(|e| e.effect == Effect::Waive) {
            return bad("pay is required unless attest holds a waive");
        }
        if self.route_scope && !self.native.is_empty() {
            return bad("a route-scope offer carries no native record");
        }
        for n in &self.native {
            if usize::try_from(n.pay_index)
                .ok()
                .is_none_or(|i| i >= self.pay.len())
            {
                return bad("native pay_index outside pay");
            }
        }
        Ok(())
    }
}

/// Parses the `headers` record: comma-separated lower-case field names.
fn parse_headers(s: &str) -> Result<Vec<String>, MalformedKind> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|h| check_header_name(h).map(|()| h.to_owned()))
        .collect()
}

/// A field name is a non-empty RFC 9110 token without upper-case letters.
fn check_header_name(h: &str) -> Result<(), MalformedKind> {
    let tchar =
        |b: u8| b.is_ascii_digit() || b.is_ascii_lowercase() || b"!#$%&'*+-.^_`|~".contains(&b);
    if h.is_empty() || !h.bytes().all(tchar) {
        return Err(MalformedKind::Rule(
            "headers must be comma-separated lower-case field names",
        ));
    }
    Ok(())
}

/// A parsed, immutable offer. It keeps the bytes as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    bytes: Vec<u8>,
    fields: OfferFields,
    sig: Signature,
    mac: Option<[u8; 32]>,
    id: OfferId,
    signed: Vec<u8>,
    signature_unknown: Vec<(u64, Vec<u8>)>,
}

impl Offer {
    /// Parses an offer with the default 4,096-byte limit.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_with_limit(bytes, MAX_OFFER)
    }

    /// Parses an offer (4.4 gate steps 1 and 2): size, framing, version, and
    /// every structural rule of 4.1 and 4.3.
    pub fn parse_with_limit(bytes: &[u8], max: usize) -> Result<Self, Error> {
        use types as t;
        if bytes.len() > max {
            return Err(Error::TooLarge {
                object: Object::Offer,
                len: bytes.len(),
                max,
            });
        }
        let m = Error::malformed(Object::Offer);
        let stream = TlvStream::parse(bytes, StreamKind::TopLevel).map_err(&m)?;
        let mut f = Fields::new(&stream);
        let version = f.required_tu64(t::VERSION).map_err(&m)?;
        if version != VERSION {
            return Err(Error::Version {
                object: Object::Offer,
                version,
            });
        }
        let scope = Scope(f.required_fixed::<32>(t::SCOPE).map_err(&m)?);
        let route_scope = f.flag(t::ROUTE_SCOPE).map_err(&m)?;
        let headers = match f.utf8(t::HEADERS).map_err(&m)? {
            Some(h) => parse_headers(&h).map_err(&m)?,
            None => Vec::new(),
        };
        let metered = f.flag(t::METERED).map_err(&m)?;
        let expires = f.required_tu64(t::EXPIRES).map_err(&m)?;
        let info = f.utf8(t::INFO).map_err(&m)?;
        let offer_key = Key(f.required_fixed::<32>(t::OFFER_KEY).map_err(&m)?);
        let nonce = f.required_fixed::<16>(t::NONCE).map_err(&m)?;
        let pay = parse_list(f.take(t::PAY), PayEntry::parse)?;
        let attest = parse_list(f.take(t::ATTEST), AttestEntry::parse)?;
        let issued_at = f.tu64(t::ISSUED_AT).map_err(&m)?;
        let native = parse_list(f.take(t::NATIVE), NativeEntry::parse)?;
        let offer_sig = Signature(f.required_fixed::<64>(t::OFFER_SIG).map_err(&m)?);
        let mac = f.fixed::<32>(t::MAC).map_err(&m)?;
        let (signature_unknown, unknown): (Vec<_>, Vec<_>) = f
            .finish()
            .map_err(&m)?
            .into_iter()
            .partition(|(t, _)| is_signature_type(*t));
        let fields = OfferFields {
            scope,
            route_scope,
            headers,
            metered,
            expires,
            info,
            offer_key,
            nonce,
            pay,
            attest,
            issued_at,
            native,
            unknown,
        };
        fields.validate()?;
        let signed = stream.signed_bytes(&[]);
        let offer_id = OfferId(tagged_hash(tags::OFFER, &stream.signed_bytes(&[t::NATIVE])));
        Ok(Self {
            bytes: bytes.to_vec(),
            fields,
            sig: offer_sig,
            mac,
            id: offer_id,
            signed,
            signature_unknown,
        })
    }

    /// The offer bytes as received.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The parsed records outside the signature range.
    #[must_use]
    pub fn fields(&self) -> &OfferFields {
        &self.fields
    }

    /// The `OfferID`.
    #[must_use]
    pub fn offer_id(&self) -> OfferId {
        self.id
    }

    /// `offer_sig`.
    #[must_use]
    pub fn offer_sig(&self) -> Signature {
        self.sig
    }

    /// `mac`, absent in offers published in advance.
    #[must_use]
    pub fn mac(&self) -> Option<[u8; 32]> {
        self.mac
    }

    /// `S`: every record outside the signature range, as received.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }

    /// The message `offer_sig` signs: `H_"bnap/offer-sig"(S)`.
    #[must_use]
    pub fn sig_message(&self) -> [u8; 32] {
        tagged_hash(tags::OFFER_SIG, &self.signed)
    }

    /// Unknown odd records in the signature range. No signature covers them.
    #[must_use]
    pub fn signature_unknown(&self) -> &[(u64, Vec<u8>)] {
        &self.signature_unknown
    }

    /// Checks `offer_sig` under the offer's own `offer_key`.
    ///
    /// This proves only that the named key signed; whether that key may sign
    /// offers for the origin is [`Offer::check_client`] or
    /// [`Offer::check_authenticity`].
    pub fn verify_signature(&self) -> Result<(), Error> {
        self.fields
            .offer_key
            .verify(&self.sig_message(), &self.sig)
            .map_err(|_| Error::BadOffer(BadOffer::Signature))
    }

    /// Checks the MAC in constant time under each of the gate's current and
    /// retained `K_mac`.
    pub fn verify_mac(&self, mac_keys: &[[u8; 32]]) -> Result<(), Error> {
        let Some(tag) = self.mac else {
            return Err(Error::BadOffer(BadOffer::Mac));
        };
        if mac_keys
            .iter()
            .any(|k| hmac_sha256_verify(k, &self.signed, &tag))
        {
            Ok(())
        } else {
            Err(Error::BadOffer(BadOffer::Mac))
        }
    }

    /// Gate step 3, authenticity (`BAD_OFFER`).
    ///
    /// An offer with `mac` passes only if the MAC verifies under a current
    /// or retained `K_mac`. An offer without `mac` must carry `issued_at`,
    /// name an `offer_key` in `held_offer_keys` (keys this gate holds for
    /// use `offer` and lists in its current manifest), and its `offer_sig`
    /// must verify. The gate never trusts a key because the offer names it.
    pub fn check_authenticity(
        &self,
        mac_keys: &[[u8; 32]],
        held_offer_keys: &[Key],
    ) -> Result<(), Error> {
        if self.mac.is_some() {
            return self.verify_mac(mac_keys);
        }
        if self.fields.issued_at.is_none() {
            return Err(Error::BadOffer(BadOffer::MissingIssuedAt));
        }
        if !held_offer_keys.contains(&self.fields.offer_key) {
            return Err(Error::BadOffer(BadOffer::UnknownKey));
        }
        self.verify_signature()
    }

    /// Gate step 4, expiry (STALE): `expires`, the chosen pay entry's
    /// `quote_expires`, and `issued_at` not in the future, each with 60 s of
    /// skew. `chosen_pay` is the credential's pay scheme; a scheme the offer
    /// does not list is left to [`Offer::check_offered`].
    pub fn check_expiry(&self, now: u64, chosen_pay: Option<&str>) -> Result<(), Error> {
        let f = &self.fields;
        if expired(f.expires, now) {
            return Err(Error::Stale(Stale::Expired));
        }
        if let Some((_, e)) = chosen_pay.and_then(|s| f.pay_entry(s))
            && expired(e.effective_quote_expires(f.expires), now)
        {
            return Err(Error::Stale(Stale::QuoteExpired));
        }
        if f.issued_at.is_some_and(|t| in_future(t, now)) {
            return Err(Error::Stale(Stale::IssuedInFuture));
        }
        Ok(())
    }

    /// Gate step 5, scope (`WRONG_SCOPE`).
    ///
    /// An exact-scope offer must name `action_scope`, the carrier's scope of
    /// this request. A route-scope offer must name `route_scope`, the scope
    /// of the route this request matched; `None` means no route matched.
    pub fn check_scope(
        &self,
        action_scope: &Scope,
        route_scope: Option<&Scope>,
    ) -> Result<(), Error> {
        let ok = if self.fields.route_scope {
            route_scope == Some(&self.fields.scope)
        } else {
            &self.fields.scope == action_scope
        };
        if ok { Ok(()) } else { Err(Error::WrongScope) }
    }

    /// Gate step 6, offered schemes (`NOT_OFFERED`): the pay scheme must be in
    /// `pay` and every attestation scheme in `attest`.
    pub fn check_offered<'s>(
        &self,
        pay: Option<&str>,
        attest: impl IntoIterator<Item = &'s str>,
    ) -> Result<(), Error> {
        if let Some(p) = pay
            && self.fields.pay_entry(p).is_none()
        {
            return Err(Error::NotOffered(p.to_owned()));
        }
        for a in attest {
            if self.fields.attest_entry(a).is_none() {
                return Err(Error::NotOffered(a.to_owned()));
            }
        }
        Ok(())
    }

    /// The binding-class rules, which need the registry: only class S or A in
    /// a route-scope offer (4.3); a native entry's pay scheme is class O
    /// (4.1); only class S, A or O may waive, discount or carry a quota
    /// (section 7); a class None value scheme only at price 0 (DECISIONS
    /// row 25). A scheme `class_of` does not know counts as class None.
    ///
    /// A gate MUST NOT build an offer that fails this; a client MAY run it
    /// on offers it receives.
    pub fn check_binding_classes(
        &self,
        class_of: impl Fn(&str) -> Option<BindingClass>,
    ) -> Result<(), Error> {
        check_classes(&self.fields, class_of)
    }

    /// The client checks of 4.4 that need no spend policy: version (already
    /// enforced by the parser), expiry, `offer_key` pinned for use `offer`,
    /// `offer_sig`, `info` on the origin, and scope.
    pub fn check_client(&self, cx: &ClientOfferCheck<'_>) -> Result<(), Error> {
        let f = &self.fields;
        if expired(f.expires, cx.now) {
            return Err(Error::Stale(Stale::Expired));
        }
        if f.issued_at.is_some_and(|t| in_future(t, cx.now)) {
            return Err(Error::Stale(Stale::IssuedInFuture));
        }
        if let Some(keys) = cx.pinned_keys {
            let listed = keys.iter().any(|k| {
                k.kid == f.offer_key && k.key_use == KeyUse::Offer && !expired(k.not_after, cx.now)
            });
            if !listed {
                return Err(Error::BadOffer(BadOffer::NotPinned));
            }
        }
        self.verify_signature()?;
        if let Some(info) = &f.info
            && !same_origin(info, cx.origin)
        {
            return Err(Error::BadOffer(BadOffer::InfoOrigin));
        }
        self.check_scope(&cx.action_scope, cx.route_scope.as_ref())
    }
}

/// Inputs to [`Offer::check_client`].
#[derive(Debug, Clone, Copy)]
pub struct ClientOfferCheck<'a> {
    /// The client's clock.
    pub now: u64,
    /// The origin the offer came from, serialized as in RFC 6454.
    pub origin: &'a str,
    /// The online keys of the pinned manifest. `None` means no pin: the
    /// client is trusting on first use.
    pub pinned_keys: Option<&'a [ManifestKey]>,
    /// The action scope of the request the client is about to send.
    pub action_scope: Scope,
    /// The route scope the client expects, if it knows the manifest route.
    pub route_scope: Option<Scope>,
}

/// True when `uri` is on `origin`: it starts with the origin and the next
/// character, if any, ends the authority.
#[must_use]
pub fn same_origin(uri: &str, origin: &str) -> bool {
    uri.strip_prefix(origin)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
}

fn parse_list<T>(v: Option<&[u8]>, parse: fn(&[u8]) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    let Some(v) = v else { return Ok(Vec::new()) };
    parse_entry_list(v)
        .map_err(Error::malformed(Object::Offer))?
        .into_iter()
        .map(parse)
        .collect()
}

fn check_classes(
    f: &OfferFields,
    class_of: impl Fn(&str) -> Option<BindingClass>,
) -> Result<(), Error> {
    let class = |s: &str| class_of(s).unwrap_or(BindingClass::None);
    let viol = |scheme: &str, rule| {
        Err(Error::Malformed {
            object: Object::Offer,
            kind: MalformedKind::ClassViolation {
                scheme: scheme.to_owned(),
                rule,
            },
        })
    };
    for e in &f.pay {
        let c = class(&e.scheme);
        if f.route_scope && !c.route_scope_allowed() {
            return viol(
                &e.scheme,
                "only class S or A may appear in a route-scope offer",
            );
        }
        if c == BindingClass::None && e.amount > 0 {
            return viol(
                &e.scheme,
                "a class None value scheme is admissible only at price 0",
            );
        }
    }
    for e in &f.attest {
        let c = class(&e.scheme);
        if f.route_scope && !c.route_scope_allowed() {
            return viol(
                &e.scheme,
                "only class S or A may appear in a route-scope offer",
            );
        }
        if e.effect != Effect::Required && !c.may_affect_price() {
            return viol(
                &e.scheme,
                "only class S, A or O may waive, discount or carry a quota",
            );
        }
    }
    for n in &f.native {
        let Some(e) = usize::try_from(n.pay_index).ok().and_then(|i| f.pay.get(i)) else {
            return Err(Error::rule(Object::Offer, "native pay_index outside pay"));
        };
        if class(&e.scheme) != BindingClass::O {
            return viol(&e.scheme, "a native entry's pay scheme must be class O");
        }
    }
    Ok(())
}

impl OfferFields {
    /// [`Offer::check_binding_classes`] on unsigned fields, for a gate to run
    /// before it signs.
    pub fn check_binding_classes(
        &self,
        class_of: impl Fn(&str) -> Option<BindingClass>,
    ) -> Result<(), Error> {
        check_classes(self, class_of)
    }
}

/// What a gate needs to run the offer checks of 4.4.
#[derive(Debug, Clone, Copy)]
pub struct GateOfferCheck<'a> {
    /// The gate's clock.
    pub now: u64,
    /// The offer size limit (4,096 unless the manifest raises it).
    pub max_offer: usize,
    /// Current and retained `K_mac`.
    pub mac_keys: &'a [[u8; 32]],
    /// Keys this gate holds for use `offer` and lists in its current
    /// manifest, for offers published in advance.
    pub offer_keys: &'a [Key],
    /// The carrier's action scope of this request.
    pub action_scope: Scope,
    /// The route scope of the manifest route this request matched.
    pub route_scope: Option<Scope>,
}

impl GateOfferCheck<'_> {
    /// Runs 4.4 gate steps 1 to 5 on received offer bytes, in order: size,
    /// parse and version, authenticity, expiry, scope.
    pub fn check_bytes(&self, bytes: &[u8], chosen_pay: Option<&str>) -> Result<Offer, Error> {
        let offer = Offer::parse_with_limit(bytes, self.max_offer)?;
        self.check(&offer, chosen_pay)?;
        Ok(offer)
    }

    /// Runs 4.4 gate steps 3 to 5 on an already parsed offer, such as one
    /// found in the gate's cache by `OfferID`.
    pub fn check(&self, offer: &Offer, chosen_pay: Option<&str>) -> Result<(), Error> {
        if offer.bytes.len() > self.max_offer {
            return Err(Error::TooLarge {
                object: Object::Offer,
                len: offer.bytes.len(),
                max: self.max_offer,
            });
        }
        offer.check_authenticity(self.mac_keys, self.offer_keys)?;
        offer.check_expiry(self.now, chosen_pay)?;
        offer.check_scope(&self.action_scope, self.route_scope.as_ref())
    }
}
