//! BIP-340 Schnorr keys and signatures over the secp256k1 that the `bitcoin`
//! crate re-exports.
//!
//! Every message the socket signs is a 32-byte tagged hash, so signing and
//! verification take `[u8; 32]`.

use std::fmt;
use std::sync::OnceLock;

use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1, XOnlyPublicKey, schnorr};

fn secp() -> &'static Secp256k1<All> {
    static CTX: OnceLock<Secp256k1<All>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::new)
}

/// Why a signature check or key load failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SchnorrError {
    /// The 32 bytes are not the x coordinate of a curve point.
    #[error("not a valid x-only public key")]
    InvalidKey,
    /// The secret key is zero or not below the curve order.
    #[error("not a valid secret key")]
    InvalidSecretKey,
    /// The signature does not verify.
    #[error("signature does not verify")]
    BadSignature,
}

/// A BIP-340 x-only public key, 32 bytes (the "Key" of draft-00 section 2).
///
/// The bytes are kept as received; whether they name a curve point is
/// checked when a signature is verified.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub [u8; 32]);

impl Key {
    /// The 32 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
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

    /// True when the bytes are a valid x-only public key.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        XOnlyPublicKey::from_slice(&self.0).is_ok()
    }

    /// Verifies a BIP-340 signature over a 32-byte message.
    pub fn verify(&self, msg: &[u8; 32], sig: &Signature) -> Result<(), SchnorrError> {
        let pk = XOnlyPublicKey::from_slice(&self.0).map_err(|_| SchnorrError::InvalidKey)?;
        let sig = schnorr::Signature::from_slice(&sig.0).map_err(|_| SchnorrError::BadSignature)?;
        secp()
            .verify_schnorr(&sig, &Message::from_digest(*msg), &pk)
            .map_err(|_| SchnorrError::BadSignature)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", hex::encode(self.0))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Key {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl serde::Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A BIP-340 Schnorr signature, 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// The 64 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    /// Lower-case hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses 128 hex characters.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut b = [0u8; 64];
        hex::decode_to_slice(s, &mut b)?;
        Ok(Self(b))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

impl From<[u8; 64]> for Signature {
    fn from(b: [u8; 64]) -> Self {
        Self(b)
    }
}

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A BIP-340 signing key.
///
/// The secret never leaves this type except through
/// [`SigningKey::secret_bytes`]; its `Debug` output is redacted.
#[derive(Clone)]
pub struct SigningKey(Keypair);

impl SigningKey {
    /// Loads a 32-byte secret key.
    pub fn from_secret_bytes(sk: &[u8; 32]) -> Result<Self, SchnorrError> {
        Keypair::from_seckey_slice(secp(), sk)
            .map(Self)
            .map_err(|_| SchnorrError::InvalidSecretKey)
    }

    /// The x-only public key.
    #[must_use]
    pub fn public_key(&self) -> Key {
        Key(self.0.x_only_public_key().0.serialize())
    }

    /// The 32-byte secret key.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.secret_bytes()
    }

    /// Signs a 32-byte message with auxiliary randomness `aux`.
    ///
    /// Signers SHOULD use fresh randomness (draft-00 section 2); the test
    /// vectors use 32 zero bytes. This crate has no RNG, so the caller
    /// supplies `aux`.
    #[must_use]
    pub fn sign(&self, msg: &[u8; 32], aux: &[u8; 32]) -> Signature {
        let sig = secp().sign_schnorr_with_aux_rand(&Message::from_digest(*msg), &self.0, aux);
        Signature(sig.serialize())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey(public {})", self.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let k = SigningKey::from_secret_bytes(&[7u8; 32]).unwrap();
        let msg = [9u8; 32];
        let sig = k.sign(&msg, &[0u8; 32]);
        assert_eq!(k.public_key().verify(&msg, &sig), Ok(()));
        let mut other = msg;
        other[0] ^= 1;
        assert_eq!(
            k.public_key().verify(&other, &sig),
            Err(SchnorrError::BadSignature)
        );
        assert!(SigningKey::from_secret_bytes(&[0u8; 32]).is_err());
        assert!(SigningKey::from_secret_bytes(&[0xff; 32]).is_err());
    }
}
