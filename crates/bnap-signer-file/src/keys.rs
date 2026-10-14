//! Online BIP-340 keys: the offer and receipt keys of draft-00 9.1.

use std::fmt;

use bnap_core::manifest::KeyUse;
use bnap_core::schnorr::{Key, Signature};
use bnap_core::secp256k1::{Keypair, Message, Secp256k1, SignOnly};

/// One online key the signer holds, for exactly one manifest use.
///
/// The secret stays inside: no accessor returns it, `Debug` prints only the
/// public key and the use, and the key pair is erased on drop.
pub struct HeldKey {
    pair: Keypair,
    public: Key,
    key_use: KeyUse,
    not_after: Option<u64>,
}

/// Why a key could not be held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// Zero, or not below the group order.
    #[error("not a valid secp256k1 secret key")]
    InvalidSecret,
    /// Only `offer` and `receipt` keys sign anything.
    #[error("a key for use {0:?} signs nothing; use \"offer\" or \"receipt\"")]
    Use(String),
}

impl HeldKey {
    /// Holds `secret` for `key_use` (`offer` or `receipt`), until
    /// `not_after` (Unix seconds) when given.
    pub fn new(
        key_use: KeyUse,
        secret: &[u8; 32],
        not_after: Option<u64>,
    ) -> Result<Self, KeyError> {
        if let KeyUse::Other(u) = &key_use {
            return Err(KeyError::Use(u.clone()));
        }
        let secp = Secp256k1::signing_only();
        let pair =
            Keypair::from_seckey_slice(&secp, secret).map_err(|_| KeyError::InvalidSecret)?;
        let public = Key(pair.x_only_public_key().0.serialize());
        Ok(Self {
            pair,
            public,
            key_use,
            not_after,
        })
    }

    /// The x-only public key, as the manifest lists it (`kid`).
    #[must_use]
    pub fn public_key(&self) -> Key {
        self.public
    }

    /// The manifest use this key is held for.
    #[must_use]
    pub fn key_use(&self) -> &KeyUse {
        &self.key_use
    }

    /// The last second the signer signs with it, if limited.
    #[must_use]
    pub fn not_after(&self) -> Option<u64> {
        self.not_after
    }

    /// BIP-340 over a digest the caller computed with bnap-core. Private to
    /// the crate: the only callers recompute the digest from the object
    /// first ([`crate::FileSigner::sign_object`]).
    pub(crate) fn sign_digest(
        &self,
        secp: &Secp256k1<SignOnly>,
        digest: &[u8; 32],
        aux: &[u8; 32],
    ) -> Signature {
        let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(*digest), &self.pair, aux);
        Signature(sig.serialize())
    }
}

impl Drop for HeldKey {
    fn drop(&mut self) {
        self.pair.non_secure_erase();
    }
}

impl fmt::Debug for HeldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldKey")
            .field("public", &self.public)
            .field("use", &self.key_use.as_str())
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}
