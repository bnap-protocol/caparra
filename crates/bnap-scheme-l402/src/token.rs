//! The L402 token (`macaroon:preimage`) and the macaroons this scheme mints.
//!
//! A macaroon's identifier is bLIP-26's: `version` (2 bytes, 0) ‖
//! `payment_hash` (32 bytes) ‖ `user_id` (32 bytes), 66 bytes in all. It
//! carries exactly two first-party caveats, in this order:
//!
//! - `bnap_offer=<OfferID, 64 lower-case hex digits>`, which embeds the
//!   offer (draft-00 4.2 step 3);
//! - `bnap_expires=<the offer's expires, decimal Unix seconds>`.
//!
//! Its root key is `HMAC-SHA256(secret, identifier)` under a secret only
//! this scheme uses, so the gate authenticates a macaroon without state
//! (draft-00 5.4). The `user_id` is derived from the `OfferID` and the
//! payment hash, so it identifies no client.
//!
//! **Canonical bodies (draft-00 5.1).** A token is accepted only in the
//! exact form this scheme writes: the V2 binary macaroon in standard
//! base64 with padding, no location, exactly the two caveats above, a
//! single `:`, then 64 lower-case hex digits. Anything else, including a
//! macaroon a holder attenuated with more caveats, is refused, so no other
//! byte string verifies as the same credential.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use bnap_core::hash::{OfferId, TaggedHasher, hmac_sha256};
use libmacaroon::{Caveat, Format, Macaroon, MacaroonKey, Verifier};

/// The identifier version this scheme writes and reads.
pub const IDENTIFIER_VERSION: u16 = 0;
/// The identifier's length: version, payment hash, user ID.
pub const IDENTIFIER_LEN: usize = 2 + 32 + 32;
/// The caveat that embeds the `OfferID`.
pub const OFFER_CAVEAT: &str = "bnap_offer";
/// The caveat that carries the offer's expiry.
pub const EXPIRES_CAVEAT: &str = "bnap_expires";

const USER_ID_TAG: &str = "bnap-scheme-l402/user";

/// Why a token or macaroon was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// Not `macaroon:preimage` in the canonical form.
    #[error("malformed L402 token: {0}")]
    Malformed(&'static str),
    /// The macaroon is not one this scheme minted under a key it holds.
    #[error("macaroon not authentic: {0}")]
    NotAuthentic(&'static str),
}

/// A macaroon identifier (bLIP-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identifier {
    /// Always [`IDENTIFIER_VERSION`].
    pub version: u16,
    /// The invoice's payment hash.
    pub payment_hash: [u8; 32],
    /// 32 bytes; this scheme derives it ([`Identifier::new`]).
    pub user_id: [u8; 32],
}

impl Identifier {
    /// The identifier for a payment under an offer: version 0, the payment
    /// hash, and `user_id = H_"bnap-scheme-l402/user"(OfferID ‖
    /// payment_hash)`.
    #[must_use]
    pub fn new(offer_id: &OfferId, payment_hash: &[u8; 32]) -> Self {
        let mut h = TaggedHasher::new(USER_ID_TAG);
        h.update(&offer_id.0);
        h.update(payment_hash);
        Self {
            version: IDENTIFIER_VERSION,
            payment_hash: *payment_hash,
            user_id: h.finish(),
        }
    }

    /// The 66 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; IDENTIFIER_LEN] {
        let mut b = [0; IDENTIFIER_LEN];
        b[..2].copy_from_slice(&self.version.to_be_bytes());
        b[2..34].copy_from_slice(&self.payment_hash);
        b[34..].copy_from_slice(&self.user_id);
        b
    }

    /// Reads 66 bytes of version 0.
    pub fn parse(b: &[u8]) -> Result<Self, TokenError> {
        let b: &[u8; IDENTIFIER_LEN] = b
            .try_into()
            .map_err(|_| TokenError::Malformed("identifier is not 66 bytes"))?;
        let version = u16::from_be_bytes([b[0], b[1]]);
        if version != IDENTIFIER_VERSION {
            return Err(TokenError::Malformed("identifier version is not 0"));
        }
        let mut payment_hash = [0; 32];
        payment_hash.copy_from_slice(&b[2..34]);
        let mut user_id = [0; 32];
        user_id.copy_from_slice(&b[34..]);
        Ok(Self {
            version,
            payment_hash,
            user_id,
        })
    }
}

/// An L402 token: `<macaroon in standard base64>:<preimage in hex>`, the
/// native credential bytes and the BNAP credential body of this scheme.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    macaroon: String,
    preimage: [u8; 32],
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The preimage is a bearer secret until the outcome is committed.
        f.debug_struct("Token")
            .field("macaroon", &self.macaroon)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.macaroon, hex::encode(self.preimage))
    }
}

impl Token {
    /// A token from a macaroon as a challenge carries it (standard base64)
    /// and the preimage the payer learned. Checked as [`Token::parse`]
    /// checks it.
    pub fn new(macaroon: &str, preimage: [u8; 32]) -> Result<Self, TokenError> {
        Self::parse(format!("{macaroon}:{}", hex::encode(preimage)).as_bytes())
    }

    /// Reads a token in the canonical form (module docs).
    pub fn parse(bytes: &[u8]) -> Result<Self, TokenError> {
        let s = std::str::from_utf8(bytes).map_err(|_| TokenError::Malformed("not UTF-8"))?;
        let (mac, pre) = s
            .split_once(':')
            .ok_or(TokenError::Malformed("no ':' separator"))?;
        if pre.len() != 64 || !pre.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(TokenError::Malformed(
                "preimage is not 64 lower-case hex digits",
            ));
        }
        let mut preimage = [0; 32];
        hex::decode_to_slice(pre, &mut preimage)
            .map_err(|_| TokenError::Malformed("preimage is not hex"))?;
        let bin = STANDARD
            .decode(mac)
            .map_err(|_| TokenError::Malformed("macaroon is not canonical standard base64"))?;
        if STANDARD.encode(&bin) != mac {
            return Err(TokenError::Malformed("macaroon is not canonical base64"));
        }
        // The V2 binary form only, written back byte for byte.
        if bin.first() != Some(&2) {
            return Err(TokenError::Malformed("macaroon is not V2 binary"));
        }
        let m = Macaroon::deserialize_binary(&bin)
            .map_err(|_| TokenError::Malformed("macaroon does not parse"))?;
        if v2_bytes(&m)? != bin {
            return Err(TokenError::Malformed(
                "macaroon is not in canonical V2 form",
            ));
        }
        Ok(Self {
            macaroon: mac.to_owned(),
            preimage,
        })
    }

    /// The macaroon, standard base64.
    #[must_use]
    pub fn macaroon(&self) -> &str {
        &self.macaroon
    }

    /// The preimage.
    #[must_use]
    pub fn preimage(&self) -> &[u8; 32] {
        &self.preimage
    }
}

/// The V2 binary bytes of a macaroon.
fn v2_bytes(m: &Macaroon) -> Result<Vec<u8>, TokenError> {
    let url = m
        .serialize(Format::V2)
        .map_err(|_| TokenError::Malformed("macaroon does not serialize"))?;
    URL_SAFE
        .decode(url)
        .map_err(|_| TokenError::Malformed("macaroon does not serialize"))
}

/// The keys macaroons are minted and checked under: the current secret,
/// and retired ones still accepted until every offer minted under them has
/// expired (as `K_mac`, draft-00 4.2).
#[derive(Clone)]
pub struct MacaroonKeys {
    current: [u8; 32],
    retired: Vec<[u8; 32]>,
}

impl std::fmt::Debug for MacaroonKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacaroonKeys")
            .field("retired", &self.retired.len())
            .finish_non_exhaustive()
    }
}

/// What an authentic macaroon says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minted {
    /// The offer it was minted for.
    pub offer_id: OfferId,
    /// That offer's `expires`.
    pub expires: u64,
    /// The identifier, with the payment hash.
    pub identifier: Identifier,
}

impl MacaroonKeys {
    /// Keys with one current secret. The secret MUST be used for nothing
    /// else.
    #[must_use]
    pub fn new(current: [u8; 32]) -> Self {
        Self {
            current,
            retired: Vec::new(),
        }
    }

    /// Adds retired secrets, still accepted when checking.
    #[must_use]
    pub fn with_retired(mut self, retired: impl IntoIterator<Item = [u8; 32]>) -> Self {
        self.retired.extend(retired);
        self
    }

    fn root(secret: &[u8; 32], identifier: &[u8]) -> MacaroonKey {
        MacaroonKey::from(hmac_sha256(secret, identifier))
    }

    /// Mints the macaroon for `payment_hash` under the offer, in standard
    /// base64 as a challenge carries it.
    pub fn mint(
        &self,
        offer_id: &OfferId,
        payment_hash: &[u8; 32],
        expires: u64,
    ) -> Result<String, TokenError> {
        let id = Identifier::new(offer_id, payment_hash).to_bytes();
        let fail = |_| TokenError::Malformed("macaroon could not be minted");
        let mut m = Macaroon::create(None, &Self::root(&self.current, &id), id).map_err(fail)?;
        m.add_first_party_caveat(offer_caveat(offer_id))
            .map_err(fail)?
            .add_first_party_caveat(expires_caveat(expires))
            .map_err(fail)?;
        Ok(STANDARD.encode(v2_bytes(&m)?))
    }

    /// Checks a token's macaroon: its form (no location, the identifier,
    /// exactly the two caveats) and its signature under one of the keys.
    pub fn open(&self, token: &Token) -> Result<Minted, TokenError> {
        let bin = STANDARD
            .decode(&token.macaroon)
            .map_err(|_| TokenError::Malformed("macaroon is not base64"))?;
        let m = Macaroon::deserialize_binary(&bin)
            .map_err(|_| TokenError::Malformed("macaroon does not parse"))?;
        if m.location().is_some() {
            return Err(TokenError::NotAuthentic("macaroon has a location"));
        }
        let identifier = Identifier::parse(m.identifier())?;
        let [Caveat::FirstParty(offer), Caveat::FirstParty(expiry)] = m.caveats() else {
            return Err(TokenError::NotAuthentic(
                "macaroon does not carry exactly the two bnap caveats",
            ));
        };
        let offer_id = parse_offer_caveat(offer.predicate())
            .ok_or(TokenError::NotAuthentic("first caveat is not bnap_offer"))?;
        let expires = parse_expires_caveat(expiry.predicate()).ok_or(TokenError::NotAuthentic(
            "second caveat is not bnap_expires",
        ))?;
        let mut verifier = Verifier::default();
        verifier.satisfy_exact(offer.predicate());
        verifier.satisfy_exact(expiry.predicate());
        let authentic = std::iter::once(&self.current)
            .chain(&self.retired)
            .any(|k| {
                verifier
                    .verify(&m, &Self::root(k, m.identifier()), &[])
                    .is_ok()
            });
        if !authentic {
            return Err(TokenError::NotAuthentic("signature does not verify"));
        }
        Ok(Minted {
            offer_id,
            expires,
            identifier,
        })
    }
}

fn offer_caveat(offer_id: &OfferId) -> String {
    format!("{OFFER_CAVEAT}={}", hex::encode(offer_id.0))
}

fn expires_caveat(expires: u64) -> String {
    format!("{EXPIRES_CAVEAT}={expires}")
}

fn parse_offer_caveat(p: &[u8]) -> Option<OfferId> {
    let v = p.strip_prefix(format!("{OFFER_CAVEAT}=").as_bytes())?;
    if v.len() != 64 || !v.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut id = [0; 32];
    hex::decode_to_slice(v, &mut id).ok()?;
    Some(OfferId(id))
}

fn parse_expires_caveat(p: &[u8]) -> Option<u64> {
    let v = std::str::from_utf8(p.strip_prefix(format!("{EXPIRES_CAVEAT}=").as_bytes())?).ok()?;
    let n: u64 = v.parse().ok()?;
    // Canonical decimal: no sign, no leading zeros.
    (n.to_string() == v).then_some(n)
}

#[cfg(test)]
mod tests {
    use bnap_core::hash::sha256;

    use super::*;

    const OFFER: OfferId = OfferId([7; 32]);

    fn keys() -> MacaroonKeys {
        MacaroonKeys::new([1; 32])
    }

    fn token() -> (Token, [u8; 32]) {
        let preimage = [9; 32];
        let hash = sha256(&preimage);
        let mac = keys().mint(&OFFER, &hash, 1_800_000_000).unwrap();
        (Token::new(&mac, preimage).unwrap(), hash)
    }

    #[test]
    fn a_minted_macaroon_opens_with_its_offer_and_payment_hash() {
        let (t, hash) = token();
        let m = keys().open(&t).unwrap();
        assert_eq!(m.offer_id, OFFER);
        assert_eq!(m.expires, 1_800_000_000);
        assert_eq!(m.identifier, Identifier::new(&OFFER, &hash));
        assert_eq!(m.identifier.payment_hash, hash);
        // The token round-trips byte for byte.
        let s = t.to_string();
        assert_eq!(Token::parse(s.as_bytes()).unwrap(), t);
        assert!(s.ends_with(&hex::encode([9; 32])));
        // Debug never shows the preimage.
        assert!(!format!("{t:?}").contains(&hex::encode([9; 32])));
    }

    #[test]
    fn retired_keys_still_open_and_foreign_keys_do_not() {
        let (t, _) = token();
        let rotated = MacaroonKeys::new([2; 32]).with_retired([[1; 32]]);
        assert!(rotated.open(&t).is_ok());
        let other = MacaroonKeys::new([2; 32]);
        assert_eq!(
            other.open(&t),
            Err(TokenError::NotAuthentic("signature does not verify"))
        );
    }

    #[test]
    fn identifiers_are_66_bytes_of_version_0() {
        let id = Identifier::new(&OFFER, &[3; 32]);
        let b = id.to_bytes();
        assert_eq!(&b[..2], &[0, 0]);
        assert_eq!(&b[2..34], &[3; 32]);
        assert_eq!(Identifier::parse(&b).unwrap(), id);
        // The user ID depends on the offer and the payment, nothing else.
        assert_ne!(
            Identifier::new(&OfferId([8; 32]), &[3; 32]).user_id,
            id.user_id
        );
        let mut v1 = b;
        v1[1] = 1;
        assert!(Identifier::parse(&v1).is_err());
        assert!(Identifier::parse(&b[..65]).is_err());
    }

    /// A macaroon built by hand under the scheme's root key.
    fn hand_made(location: Option<&str>, id: &[u8], caveats: &[&str], key: &[u8; 32]) -> String {
        let mut m = Macaroon::create(location, &MacaroonKeys::root(key, id), id).unwrap();
        for c in caveats {
            m.add_first_party_caveat(c).unwrap();
        }
        STANDARD.encode(v2_bytes(&m).unwrap())
    }

    #[test]
    fn only_the_two_bnap_caveats_in_order_are_accepted() {
        let id = Identifier::new(&OFFER, &sha256(&[9; 32])).to_bytes();
        let offer = offer_caveat(&OFFER);
        let exp = expires_caveat(5);
        let k = [1; 32];
        let open = |mac: String| keys().open(&Token::new(&mac, [9; 32]).unwrap());
        assert!(open(hand_made(None, &id, &[&offer, &exp], &k)).is_ok());
        for caveats in [
            vec![&*exp, &*offer],
            vec![&*offer],
            vec![&*offer, &*exp, "services=x:0"],
            vec![&*offer, "bnap_expires=05"],
            vec![&*offer, "bnap_expires=+5"],
            vec!["bnap_offer=07", &*exp],
            vec![&*offer.to_uppercase(), &*exp],
        ] {
            assert!(
                matches!(
                    open(hand_made(None, &id, &caveats, &k)),
                    Err(TokenError::NotAuthentic(_))
                ),
                "{caveats:?}"
            );
        }
        // A location, or another identifier version.
        assert!(open(hand_made(Some("x"), &id, &[&offer, &exp], &k)).is_err());
        let mut v1 = id;
        v1[1] = 1;
        assert!(open(hand_made(None, &v1, &[&offer, &exp], &k)).is_err());
    }

    #[test]
    fn non_canonical_tokens_are_refused() {
        let (t, _) = token();
        let s = t.to_string();
        let (mac, pre) = s.split_once(':').unwrap();
        let url = mac.replace('+', "-").replace('/', "_");
        let mut bad = vec![
            format!("{mac}:{}", "AB".repeat(32)),
            format!("{}:{pre}", mac.trim_end_matches('=')),
            format!("{mac}:{pre}:{pre}"),
            format!("{mac}:{}", &pre[..62]),
            format!("{mac} :{pre}"),
            format!("{mac}:{pre} "),
            format!("{mac},{mac}:{pre}"),
            format!("{mac}{pre}"),
            String::new(),
        ];
        if url != mac {
            bad.push(format!("{url}:{pre}"));
        }
        for b in bad {
            assert!(
                matches!(Token::parse(b.as_bytes()), Err(TokenError::Malformed(_))),
                "{b}"
            );
        }
        assert!(Token::parse(&[0xff, b':']).is_err());
    }

    #[test]
    fn a_v1_or_json_macaroon_is_refused() {
        let id = Identifier::new(&OFFER, &[3; 32]).to_bytes();
        let mut m = Macaroon::create(None, &MacaroonKeys::root(&[1; 32], &id), id).unwrap();
        m.add_first_party_caveat(offer_caveat(&OFFER)).unwrap();
        let v1 = URL_SAFE.decode(m.serialize(Format::V1).unwrap()).unwrap();
        let v1 = format!("{}:{}", STANDARD.encode(v1), hex::encode([9; 32]));
        assert!(Token::parse(v1.as_bytes()).is_err());
        let json = m.serialize(Format::V2JSON).unwrap();
        let json = format!("{}:{}", STANDARD.encode(json), hex::encode([9; 32]));
        assert!(Token::parse(json.as_bytes()).is_err());
    }
}
