//! The Credential envelope (draft-00 section 5): records, body and witness,
//! offer by reference, the Context and Digest (5.2), the TLS binding check
//! (5.3) and the native envelope (5.4).

use crate::class::BindingClass;
use crate::encoding::{len_u64, tu64, write_bigsize, write_lp};
use crate::error::{BadOffer, Error, MalformedKind, Object, VERSION};
use crate::hash::{Context, Digest, OfferId, ReplayKey, Scope, TaggedHasher, sha256, tags};
use crate::limits::MAX_CREDENTIAL;
use crate::offer::{GateOfferCheck, Offer};
use crate::tlv::{Fields, StreamKind, TlvStream, entry_list, parse_entry_list};

/// Record types of the Credential (5.1).
pub mod types {
    /// `version`, tu64.
    pub const VERSION: u64 = 0;
    /// `offer`, the Offer byte for byte as received.
    pub const OFFER: u64 = 2;
    /// `pay`, nested stream.
    pub const PAY: u64 = 4;
    /// `attest`, entry list of nested streams.
    pub const ATTEST: u64 = 6;
    /// `binding`, 32 bytes.
    pub const BINDING: u64 = 8;
    /// `ext`, nested TLV stream.
    pub const EXT: u64 = 10;
    /// `offer_id`, 32 bytes.
    pub const OFFER_ID: u64 = 12;
}

/// Record types of a `pay` or `attest` part (5.1).
pub mod part_types {
    /// `scheme`, UTF-8.
    pub const SCHEME: u64 = 0;
    /// `body`: everything the scheme needs except signatures over the Digest.
    pub const BODY: u64 = 2;
    /// `witness`: the signatures over the Digest (class S only).
    pub const WITNESS: u64 = 4;
}

/// How a credential names its offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferRef {
    /// The Offer, byte for byte as received.
    Inline(Vec<u8>),
    /// The OfferID of an offer the gate issued and still caches.
    Id(OfferId),
}

/// The `pay` part or one `attest` part of a credential: a scheme ID, its
/// body and its witness.
///
/// An absent body or witness and an empty one mean the same (draft-00
/// section 2); the encoder omits empty ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemePart {
    /// The scheme ID.
    pub scheme: String,
    /// The body. The Digest covers it.
    pub body: Vec<u8>,
    /// The witness: signatures over the Digest. Only class S schemes have one.
    pub witness: Vec<u8>,
}

impl SchemePart {
    /// A part with a body and no witness.
    #[must_use]
    pub fn new(scheme: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self { scheme: scheme.into(), body: body.into(), witness: Vec::new() }
    }

    /// Serializes the part as a nested stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.scheme.is_empty() {
            return Err(Error::rule(Object::CredentialPart, "empty scheme ID"));
        }
        let m = Error::malformed(Object::CredentialPart);
        let mut s = TlvStream::new();
        s.push(part_types::SCHEME, self.scheme.as_bytes()).map_err(&m)?;
        if !self.body.is_empty() {
            s.push(part_types::BODY, self.body.clone()).map_err(&m)?;
        }
        if !self.witness.is_empty() {
            s.push(part_types::WITNESS, self.witness.clone()).map_err(&m)?;
        }
        Ok(s.to_bytes())
    }

    /// Parses a nested part stream. Unknown odd records are ignored and
    /// dropped: they MUST NOT affect processing.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let m = Error::malformed(Object::CredentialPart);
        let s = TlvStream::parse(bytes, StreamKind::Nested).map_err(&m)?;
        let mut f = Fields::new(&s);
        let scheme = f.required_utf8(part_types::SCHEME).map_err(&m)?;
        if scheme.is_empty() {
            return Err(Error::rule(Object::CredentialPart, "empty scheme ID"));
        }
        let body = f.take(part_types::BODY).unwrap_or_default().to_vec();
        let witness = f.take(part_types::WITNESS).unwrap_or_default().to_vec();
        f.finish().map_err(&m)?;
        Ok(Self { scheme, body, witness })
    }
}

/// Parse options for a credential.
#[derive(Debug, Clone, Copy)]
pub struct CredentialParse<'a> {
    /// Size limit in bytes (16,384 unless the manifest raises it).
    pub max_credential: usize,
    /// Even `ext` types this receiver understands. Any other even `ext` type
    /// is MALFORMED under the even/odd rule.
    pub known_ext_types: &'a [u64],
}

impl Default for CredentialParse<'_> {
    fn default() -> Self {
        Self { max_credential: MAX_CREDENTIAL, known_ext_types: &[] }
    }
}

/// A Credential (5.1).
///
/// Build one by filling the fields and calling [`Credential::to_bytes`],
/// which enforces the same rules as the parser. The Context and Digest are
/// computed by the gate itself ([`Credential::context`],
/// [`Credential::digest`]); a scheme plug receives them read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The offer, inline or by OfferID.
    pub offer: OfferRef,
    /// The value part, at most one.
    pub pay: Option<SchemePart>,
    /// Attestation parts, sorted by scheme ID bytewise, each scheme once.
    pub attest: Vec<SchemePart>,
    /// The RFC 9266 `tls-exporter` value of the client's connection; only if
    /// a chosen scheme is class S.
    pub binding: Option<[u8; 32]>,
    /// The extensions stream. Empty means absent.
    pub ext: TlvStream,
    /// Unknown odd top-level records. They are outside every hash and MUST
    /// NOT affect processing; senders use them for GREASE.
    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl Credential {
    /// A credential naming `offer`, with no parts yet.
    #[must_use]
    pub fn new(offer: OfferRef) -> Self {
        Self { offer, pay: None, attest: Vec::new(), binding: None, ext: TlvStream::new(), unknown: Vec::new() }
    }

    /// Sorts the attestation parts by scheme ID, bytewise.
    pub fn sort_attest(&mut self) {
        self.attest.sort_by(|a, b| a.scheme.as_bytes().cmp(b.scheme.as_bytes()));
    }

    /// The pay scheme ID, if the credential has `pay`.
    #[must_use]
    pub fn pay_scheme(&self) -> Option<&str> {
        self.pay.as_ref().map(|p| p.scheme.as_str())
    }

    /// The attestation scheme IDs, in credential order.
    pub fn attest_schemes(&self) -> impl Iterator<Item = &str> {
        self.attest.iter().map(|p| p.scheme.as_str())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.pay.is_none() && self.attest.is_empty() {
            return Err(Error::rule(Object::Credential, "a credential holds pay, attest, or both"));
        }
        for w in self.attest.windows(2) {
            match w[0].scheme.as_bytes().cmp(w[1].scheme.as_bytes()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(Error::Malformed {
                        object: Object::Credential,
                        kind: MalformedKind::DuplicateScheme(w[0].scheme.clone()),
                    });
                }
                std::cmp::Ordering::Greater => {
                    return Err(Error::rule(Object::Credential, "attest list out of order"));
                }
            }
        }
        Ok(())
    }

    /// Serializes the credential.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        use types as t;
        self.validate()?;
        let m = Error::malformed(Object::Credential);
        let mut s = TlvStream::new();
        s.insert(t::VERSION, tu64(VERSION)).map_err(&m)?;
        match &self.offer {
            OfferRef::Inline(b) => s.insert(t::OFFER, b.clone()).map_err(&m)?,
            OfferRef::Id(id) => s.insert(t::OFFER_ID, id.0).map_err(&m)?,
        }
        if let Some(p) = &self.pay {
            s.insert(t::PAY, p.to_bytes()?).map_err(&m)?;
        }
        if !self.attest.is_empty() {
            let items = self.attest.iter().map(SchemePart::to_bytes).collect::<Result<Vec<_>, _>>()?;
            s.insert(t::ATTEST, entry_list(&items)).map_err(&m)?;
        }
        if let Some(b) = self.binding {
            s.insert(t::BINDING, b).map_err(&m)?;
        }
        if !self.ext.is_empty() {
            for (typ, _) in self.ext.records() {
                if !crate::tlv::nested_type_allowed(*typ) {
                    return Err(Error::Malformed { object: Object::Ext, kind: MalformedKind::TypeNotAllowed(*typ) });
                }
            }
            s.insert(t::EXT, self.ext.to_bytes()).map_err(&m)?;
        }
        for (typ, v) in &self.unknown {
            if typ % 2 == 0 {
                return Err(m(MalformedKind::UnknownEvenType(*typ)));
            }
            s.insert(*typ, v.clone()).map_err(&m)?;
        }
        Ok(s.to_bytes())
    }

    /// Parses a credential with the default limits and no known `ext` types.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_with(bytes, &CredentialParse::default())
    }

    /// Parses a credential: size, framing, version and the structural rules
    /// of 5.1. The inline offer, if any, is not parsed here: the gate runs
    /// the checks of 4.4 on it ([`GateOfferCheck::check_credential`]).
    pub fn parse_with(bytes: &[u8], opts: &CredentialParse<'_>) -> Result<Self, Error> {
        use types as t;
        if bytes.len() > opts.max_credential {
            return Err(Error::TooLarge { object: Object::Credential, len: bytes.len(), max: opts.max_credential });
        }
        let m = Error::malformed(Object::Credential);
        let stream = TlvStream::parse(bytes, StreamKind::TopLevel).map_err(&m)?;
        let mut f = Fields::new(&stream);
        let version = f.required_tu64(t::VERSION).map_err(&m)?;
        if version != VERSION {
            return Err(Error::Version { object: Object::Credential, version });
        }
        let inline = f.take(t::OFFER);
        let pay = f.take(t::PAY).map(SchemePart::parse).transpose()?;
        let attest = match f.take(t::ATTEST) {
            Some(v) => parse_entry_list(v)
                .map_err(&m)?
                .into_iter()
                .map(SchemePart::parse)
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        let binding = match f.take(t::BINDING) {
            None | Some([]) => None,
            Some(v) => Some(crate::tlv::fixed::<32>(v, t::BINDING).map_err(&m)?),
        };
        let ext = match f.take(t::EXT) {
            Some(v) => parse_ext(v, opts.known_ext_types)?,
            None => TlvStream::new(),
        };
        let offer_id = f.fixed::<32>(t::OFFER_ID).map_err(&m)?;
        // A credential defines no signature records; odd ones in that range
        // are ignored like any other unknown odd record.
        let unknown = f.finish().map_err(&m)?;
        let offer = match (inline, offer_id) {
            (Some(b), None) => OfferRef::Inline(b.to_vec()),
            (None, Some(id)) => OfferRef::Id(OfferId(id)),
            _ => return Err(Error::rule(Object::Credential, "exactly one of offer and offer_id")),
        };
        let c = Self { offer, pay, attest, binding, ext, unknown };
        c.validate()?;
        Ok(c)
    }

    /// The Context of 5.2 for this credential sent with a request whose
    /// carrier scope is `action_scope`, against the offer `offer_id`.
    #[must_use]
    pub fn context(&self, offer_id: &OfferId, action_scope: &Scope) -> Context {
        let attest: Vec<&str> = self.attest_schemes().collect();
        context(offer_id, action_scope, self.pay_scheme(), &attest, &self.ext.to_bytes())
    }

    /// The Digest of 5.2 under `ctx`.
    #[must_use]
    pub fn digest(&self, ctx: &Context) -> Digest {
        let bodies: Vec<&[u8]> = self.attest.iter().map(|p| p.body.as_slice()).collect();
        digest(ctx, self.binding.as_ref(), self.pay_body(), &bodies)
    }

    /// The ReplayKey of 6.1 under `ctx`, over every UseId and RailId of
    /// every scheme in the request.
    #[must_use]
    pub fn replay_key(&self, ctx: &Context, ids: &[[u8; 32]]) -> ReplayKey {
        let bodies: Vec<&[u8]> = self.attest.iter().map(|p| p.body.as_slice()).collect();
        crate::ids::replay_key(ctx, self.pay_body(), &bodies, ids)
    }

    fn pay_body(&self) -> &[u8] {
        self.pay.as_ref().map_or(&[][..], |p| p.body.as_slice())
    }

    /// The binding-class rule of 5.1: a `binding` when no chosen scheme is
    /// class S is MALFORMED. A scheme `class_of` does not know is not class S.
    pub fn check_binding_classes(&self, class_of: impl Fn(&str) -> Option<BindingClass>) -> Result<(), Error> {
        if self.binding.is_some()
            && !self.pay_scheme().into_iter().chain(self.attest_schemes()).any(|s| class_of(s) == Some(BindingClass::S))
        {
            return Err(Error::rule(Object::Credential, "binding without a class S scheme"));
        }
        Ok(())
    }

    /// The gate's binding check of 5.3. `exporter` is the RFC 9266
    /// `tls-exporter` value of the connection the request arrived on, or
    /// `None` when the gate cannot see the client's TLS session. A binding
    /// that does not match, or that cannot be checked, is BINDING.
    pub fn check_tls_binding(&self, exporter: Option<&[u8; 32]>) -> Result<(), Error> {
        match (self.binding.as_ref(), exporter) {
            (None, _) => Ok(()),
            (Some(b), Some(x)) if b == x => Ok(()),
            _ => Err(Error::Binding),
        }
    }
}

fn parse_ext(v: &[u8], known: &[u64]) -> Result<TlvStream, Error> {
    let m = Error::malformed(Object::Ext);
    let s = TlvStream::parse(v, StreamKind::Nested).map_err(&m)?;
    let mut f = Fields::new(&s);
    for k in known {
        f.take(*k);
    }
    f.finish().map_err(&m)?;
    Ok(s)
}

/// `Context = H_"bnap/ctx"(OfferID ‖ action_scope ‖ lp(pay scheme ID, or
/// empty) ‖ BigSize(n) ‖ lp(attest scheme ID₁) ‖ … ‖ H(ext value, or empty))`
/// (5.2). `attest_schemes` must be in the credential's order, which is
/// sorted; `ext` is the `ext` record's value, empty when absent.
#[must_use]
pub fn context(
    offer_id: &OfferId,
    action_scope: &Scope,
    pay_scheme: Option<&str>,
    attest_schemes: &[&str],
    ext: &[u8],
) -> Context {
    let mut buf = Vec::new();
    buf.extend_from_slice(&offer_id.0);
    buf.extend_from_slice(&action_scope.0);
    write_lp(&mut buf, pay_scheme.unwrap_or("").as_bytes());
    write_bigsize(&mut buf, len_u64(attest_schemes.len()));
    for a in attest_schemes {
        write_lp(&mut buf, a.as_bytes());
    }
    buf.extend_from_slice(&sha256(ext));
    let mut h = TaggedHasher::new(tags::CTX);
    h.update(&buf);
    Context(h.finish())
}

/// `Digest = H_"bnap/cred"(Context ‖ lp(binding, or empty) ‖ H(pay body, or
/// empty) ‖ H(attest body₁) ‖ … ‖ H(attest bodyₙ))` (5.2). `pay_body` is
/// empty when the credential has no pay.
#[must_use]
pub fn digest(ctx: &Context, binding: Option<&[u8; 32]>, pay_body: &[u8], attest_bodies: &[&[u8]]) -> Digest {
    let mut h = TaggedHasher::new(tags::CRED);
    h.update(&ctx.0);
    let mut lpb = Vec::with_capacity(33);
    write_lp(&mut lpb, binding.map_or(&[][..], |b| b.as_slice()));
    h.update(&lpb);
    h.update(&sha256(pay_body));
    for b in attest_bodies {
        h.update(&sha256(b));
    }
    Digest(h.finish())
}

/// Native `Context = H_"bnap/ctx-native"(OfferID ‖ action_scope ‖ lp(scheme
/// ID))` (5.4).
#[must_use]
pub fn native_context(offer_id: &OfferId, action_scope: &Scope, scheme: &str) -> Context {
    let mut h = TaggedHasher::new(tags::CTX_NATIVE);
    h.update(&offer_id.0);
    h.update(&action_scope.0);
    let mut l = Vec::new();
    write_lp(&mut l, scheme.as_bytes());
    h.update(&l);
    Context(h.finish())
}

/// Native `Digest = H_"bnap/cred-native"(Context ‖ H(native credential
/// bytes))` (5.4). The scheme's registry entry defines the bytes, such as
/// the L402 `macaroon:preimage` token.
#[must_use]
pub fn native_digest(ctx: &Context, native_bytes: &[u8]) -> Digest {
    let mut h = TaggedHasher::new(tags::CRED_NATIVE);
    h.update(&ctx.0);
    h.update(&sha256(native_bytes));
    Digest(h.finish())
}

impl GateOfferCheck<'_> {
    /// Resolves the credential's offer and runs the offer checks of 4.4 on
    /// it, steps 1 to 6 in order.
    ///
    /// An inline offer is parsed with `max_offer`. An offer named by OfferID
    /// comes from `cache`, the gate's cache of offers it issued; an unknown
    /// OfferID is BAD_OFFER, and the gate answers with a fresh offer.
    pub fn check_credential(
        &self,
        cred: &Credential,
        cache: impl FnOnce(&OfferId) -> Option<Offer>,
    ) -> Result<Offer, Error> {
        let offer = match &cred.offer {
            OfferRef::Inline(b) => Offer::parse_with_limit(b, self.max_offer)?,
            OfferRef::Id(id) => cache(id)
                .filter(|o| o.offer_id() == *id)
                .ok_or(Error::BadOffer(BadOffer::UnknownOfferId))?,
        };
        self.check(&offer, cred.pay_scheme())?;
        offer.check_offered(cred.pay_scheme(), cred.attest_schemes())?;
        Ok(offer)
    }

    /// Runs the offer checks of 4.4 for a native credential (5.4): the
    /// adapter has recovered the OfferID and the offer; `scheme` is the
    /// native scheme, which must be offered.
    pub fn check_native(&self, offer: &Offer, scheme: &str) -> Result<(), Error> {
        self.check(offer, Some(scheme))?;
        offer.check_offered(Some(scheme), [])
    }
}
