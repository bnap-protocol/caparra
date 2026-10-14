//! The client side: making a `DPoP` proof that carries the Context, and the
//! attest body around it.
//!
//! A client computes the Context of the credential it is about to send
//! (draft-00 5.2: the `OfferID`, the request's action scope, its chosen value
//! and attestation schemes, its extensions), signs a proof whose
//! `bnap_ctx` claim is that Context in lowercase hex, and puts the proof,
//! with its access token if it has one, in the `httpauth:DPoP` attest body.
//! ES256 signatures are always written with a low `s`, the only form the
//! scheme accepts.

use bnap_core::hash::{Context, sha256};
use serde_json::{Map, Value};

use crate::body::DpopBody;
use crate::jose::{Alg, PublicJwk, Thumbprint, b64u};
use crate::proof::{BNAP_CTX_CLAIM, DPOP_TYP};

/// A `DPoP` signing key.
#[derive(Clone)]
pub enum ProofKey {
    /// A P-256 key, signing ES256.
    Es256(p256::ecdsa::SigningKey),
    /// An Ed25519 key, signing `EdDSA`.
    EdDsa(ed25519_dalek::SigningKey),
}

impl std::fmt::Debug for ProofKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProofKey({:?}, {:?})", self.alg(), self.thumbprint())
    }
}

impl ProofKey {
    /// A P-256 key from its 32-byte secret scalar; `None` for zero or a
    /// value not below the group order.
    #[must_use]
    pub fn es256(secret: &[u8; 32]) -> Option<Self> {
        p256::ecdsa::SigningKey::from_slice(secret)
            .ok()
            .map(Self::Es256)
    }

    /// An Ed25519 key from its 32-byte secret.
    #[must_use]
    pub fn ed25519(secret: &[u8; 32]) -> Self {
        Self::EdDsa(ed25519_dalek::SigningKey::from_bytes(secret))
    }

    /// The algorithm the key signs with.
    #[must_use]
    pub fn alg(&self) -> Alg {
        match self {
            Self::Es256(_) => Alg::Es256,
            Self::EdDsa(_) => Alg::EdDsa,
        }
    }

    /// The public key as a JWK.
    ///
    /// # Panics
    ///
    /// Never: an uncompressed P-256 point always has both coordinates.
    #[must_use]
    pub fn public_jwk(&self) -> PublicJwk {
        match self {
            Self::Es256(k) => {
                let p = k.verifying_key().to_sec1_point(false);
                let (Some(x), Some(y)) = (p.x(), p.y()) else {
                    unreachable!("an uncompressed point has both coordinates")
                };
                PublicJwk::P256 {
                    x: x.as_slice().try_into().unwrap_or([0; 32]),
                    y: y.as_slice().try_into().unwrap_or([0; 32]),
                }
            }
            Self::EdDsa(k) => PublicJwk::Ed25519 {
                x: k.verifying_key().to_bytes(),
            },
        }
    }

    /// The key's JWK SHA-256 thumbprint: its `jkt` and the scheme's local
    /// ID.
    #[must_use]
    pub fn thumbprint(&self) -> Thumbprint {
        self.public_jwk().thumbprint()
    }

    /// Signs `signing_input` as JWS: `R ‖ S` with a low `s` for ES256.
    #[must_use]
    pub fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(signing_input);
                sig.normalize_s().to_bytes().to_vec()
            }
            Self::EdDsa(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(signing_input).to_bytes().to_vec()
            }
        }
    }
}

/// The claims of one proof.
#[derive(Debug, Clone, Copy)]
pub struct ProofClaims<'a> {
    /// The Context of the credential the proof goes in.
    pub context: &'a Context,
    /// `htm`: the request's method.
    pub htm: &'a str,
    /// `htu`: the request's URI without query and fragment.
    pub htu: &'a str,
    /// `iat`: now, in Unix seconds.
    pub iat: u64,
    /// `jti`: unique per proof. Two proofs for byte-identical requests
    /// differ only here, so each is its own credential and its own action.
    pub jti: &'a str,
    /// The access token the proof is presented with, if any: `ath` is its
    /// hash.
    pub access_token: Option<&'a str>,
}

/// The JWS header of a proof made with `key`.
#[must_use]
pub fn header(key: &ProofKey) -> Value {
    let mut h = Map::new();
    h.insert("typ".into(), DPOP_TYP.into());
    h.insert("alg".into(), key.alg().as_str().into());
    h.insert("jwk".into(), key.public_jwk().to_value());
    Value::Object(h)
}

/// The JWT claims of a proof.
#[must_use]
pub fn claims(c: &ProofClaims<'_>) -> Value {
    let mut p = Map::new();
    p.insert("jti".into(), c.jti.into());
    p.insert("htm".into(), c.htm.into());
    p.insert("htu".into(), c.htu.into());
    p.insert("iat".into(), c.iat.into());
    p.insert(BNAP_CTX_CLAIM.into(), hex::encode(c.context.0).into());
    if let Some(t) = c.access_token {
        p.insert("ath".into(), b64u(&sha256(t.as_bytes())).into());
    }
    Value::Object(p)
}

/// Signs the exact header and payload bytes given, as a compact JWS. The
/// building block of [`sign_proof`]; tests use it to make malformed proofs.
#[must_use]
pub fn sign_raw(key: &ProofKey, header: &[u8], payload: &[u8]) -> String {
    let input = format!("{}.{}", b64u(header), b64u(payload));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64u(&sig))
}

/// A `DPoP` proof for `c`, signed with `key`.
#[must_use]
pub fn sign_proof(key: &ProofKey, c: &ProofClaims<'_>) -> String {
    sign_raw(
        key,
        header(key).to_string().as_bytes(),
        claims(c).to_string().as_bytes(),
    )
}

/// The `httpauth:DPoP` attest body for a proof and its token.
#[must_use]
pub fn body(proof: &str, access_token: Option<&str>) -> Vec<u8> {
    DpopBody {
        proof: proof.to_owned(),
        access_token: access_token.map(str::to_owned),
    }
    .to_bytes()
}
