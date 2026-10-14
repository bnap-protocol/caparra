//! SHA-256, BIP-340 tagged hashes and the socket's tags (draft-00 section 2).
//!
//! `H_tag(x) = H(H(tag) ‖ H(tag) ‖ x)`, with `tag` as UTF-8. Every hash the
//! socket defines is tagged, and no two uses share a tag.

use hmac::{KeyInit, Mac};
use sha2::{Digest as _, Sha256};

/// The socket's hash tags, one per use.
pub mod tags {
    /// `OfferID` (4.2).
    pub const OFFER: &str = "bnap/offer";
    /// The message `offer_sig` signs (4.2).
    pub const OFFER_SIG: &str = "bnap/offer-sig";
    /// Context (5.2).
    pub const CTX: &str = "bnap/ctx";
    /// Digest (5.2).
    pub const CRED: &str = "bnap/cred";
    /// Native Context (5.4).
    pub const CTX_NATIVE: &str = "bnap/ctx-native";
    /// Native Digest (5.4).
    pub const CRED_NATIVE: &str = "bnap/cred-native";
    /// `UseId` (6.1).
    pub const USE: &str = "bnap/use";
    /// `RailId` (6.1).
    pub const RAIL: &str = "bnap/rail";
    /// `ReplayKey` (6.1).
    pub const REPLAY: &str = "bnap/replay";
    /// Rate counter key (6.2).
    pub const RATE: &str = "bnap/rate";
    /// Quota counter key (6.2).
    pub const QUOTA: &str = "bnap/quota";
    /// The message the Response ack signs (8.1).
    pub const ACK: &str = "bnap/ack";
    /// The message the manifest root signs (9.1).
    pub const MANIFEST: &str = "bnap/manifest";
    /// HTTP action scope (10.1).
    pub const SCOPE_HTTP: &str = "bnap/scope/http";
    /// HTTP route scope (10.1).
    pub const ROUTE_HTTP: &str = "bnap/route/http";
}

/// `H(x)`: SHA-256 of `x`.
#[must_use]
pub fn sha256(x: &[u8]) -> [u8; 32] {
    Sha256::digest(x).into()
}

/// `H_tag(x)`: the BIP-340 tagged hash of `x` under `tag`.
#[must_use]
pub fn tagged_hash(tag: &str, x: &[u8]) -> [u8; 32] {
    let mut h = TaggedHasher::new(tag);
    h.update(x);
    h.finish()
}

/// Incremental `H_tag(…)`, so callers can hash a concatenation without
/// building it.
#[derive(Clone)]
pub struct TaggedHasher(Sha256);

impl TaggedHasher {
    /// Starts `H_tag`: feeds `H(tag) ‖ H(tag)`.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        let t = sha256(tag.as_bytes());
        let mut h = Sha256::new();
        h.update(t);
        h.update(t);
        Self(h)
    }

    /// Feeds more bytes.
    pub fn update(&mut self, x: &[u8]) {
        self.0.update(x);
    }

    /// Finishes the hash.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl std::fmt::Debug for TaggedHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaggedHasher")
    }
}

type HmacSha256 = hmac::Hmac<Sha256>;

/// HMAC-SHA256 of `msg` under `key`.
///
/// # Panics
///
/// Never: HMAC accepts keys of every length.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of every length"));
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Checks an HMAC-SHA256 tag in constant time.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8; 32]) -> bool {
    let Ok(mut m) = <HmacSha256 as KeyInit>::new_from_slice(key) else {
        return false;
    };
    m.update(msg);
    m.verify_slice(tag).is_ok()
}

macro_rules! hash32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// The 32 bytes.
            #[must_use]
            pub fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Borrows the 32 bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lower-case hex.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parses 64 hex characters.
            pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
                let mut b = [0u8; 32];
                hex::decode_to_slice(s, &mut b)?;
                Ok(Self(b))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(b: [u8; 32]) -> Self {
                Self(b)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
    };
}

hash32!(
    /// An `OfferID`: `H_"bnap/offer"(S₀)` (draft-00 4.2).
    OfferId
);
hash32!(
    /// A carrier scope: an action scope or a route scope (4.3, 10.1).
    Scope
);
hash32!(
    /// A Context (5.2), or a native Context (5.4).
    Context
);
hash32!(
    /// A Digest (5.2), or a native Digest (5.4).
    Digest
);
hash32!(
    /// A socket use ID: `H_"bnap/use"(lp(scheme ID) ‖ local ID)` (6.1).
    UseId
);
hash32!(
    /// A rail ID: `H_"bnap/rail"(lp(rail kind) ‖ canonical payment bytes)` (6.1).
    RailId
);
hash32!(
    /// A `ReplayKey` (6.1).
    ReplayKey
);
hash32!(
    /// A rate or quota counter key (6.2).
    CounterKey
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        let mut bad = tag;
        bad[31] ^= 1;
        assert!(!hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing?",
            &bad
        ));
    }

    #[test]
    fn incremental_equals_one_shot() {
        let mut h = TaggedHasher::new("t");
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(h.finish(), tagged_hash("t", b"abc"));
    }
}
