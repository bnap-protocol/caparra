//! The JOSE pieces a `DPoP` proof needs, in pure Rust: compact JWS (RFC
//! 7515), public JWKs (RFC 7517, RFC 8037), JWK SHA-256 thumbprints (RFC
//! 7638), ES256 through `p256` and `EdDSA` through `ed25519-dalek`. Nothing
//! here links OpenSSL.
//!
//! Every decoder is strict, because a `DPoP` body MUST be canonical (draft-00
//! 5.1, "Canonical bodies"): base64url without padding and with zero
//! trailing bits, JSON read as I-JSON (a member named twice at any depth is
//! refused, [`bnap_core::manifest::parse_strict`]), ES256 signatures with a
//! low `s` only (the high-`s` twin of a valid ECDSA signature also verifies,
//! so accepting both would let anyone on the path re-encode a proof), and
//! `EdDSA` through `verify_strict`.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::hash::sha256;
use serde_json::{Map, Value};

/// A JWK SHA-256 thumbprint (RFC 7638): the identity of a `DPoP` key, the
/// `cnf.jkt` of a token bound to it, and the scheme's local ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Thumbprint(pub [u8; 32]);

impl Thumbprint {
    /// The base64url form, as `jkt` carries it.
    #[must_use]
    pub fn to_b64u(&self) -> String {
        b64u(&self.0)
    }

    /// Reads the base64url form; `None` unless it is canonical and 32
    /// bytes long.
    #[must_use]
    pub fn from_b64u(s: &str) -> Option<Self> {
        b64u_decode(s.as_bytes()).ok()?.try_into().ok().map(Self)
    }
}

impl fmt::Debug for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thumbprint({})", self.to_b64u())
    }
}

/// Why a JOSE object was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoseError {
    /// Not compact serialization, or base64url that is not canonical.
    #[error("bad encoding: {0}")]
    Encoding(&'static str),
    /// JSON that is not an object, or names a member twice.
    #[error("bad JSON: {0}")]
    Json(String),
    /// A JWK that is not a supported public key.
    #[error("bad key: {0}")]
    Key(&'static str),
    /// The JWK carries private key material.
    #[error("the key carries private key material")]
    PrivateKey,
    /// An `alg` other than `ES256`, `EdDSA` or `Ed25519`.
    #[error("unsupported alg")]
    UnsupportedAlg,
    /// The `alg` does not fit the key type.
    #[error("alg does not fit the key")]
    AlgMismatch,
    /// An ES256 signature with a high `s`: valid, but not the canonical
    /// encoding.
    #[error("non-canonical signature")]
    NonCanonicalSignature,
    /// The signature does not verify.
    #[error("bad signature")]
    BadSignature,
}

/// Base64url without padding (RFC 4648 section 5), as JOSE uses it.
#[must_use]
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url, refusing every encoding but the canonical one: no
/// padding, no characters outside the URL-safe alphabet, zero trailing
/// bits.
pub fn b64u_decode(s: &[u8]) -> Result<Vec<u8>, JoseError> {
    let v = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| JoseError::Encoding("not canonical base64url"))?;
    // The engine already refuses padding and trailing bits; a re-encode
    // proves the bytes are the one spelling of the value.
    if URL_SAFE_NO_PAD.encode(&v).as_bytes() == s {
        Ok(v)
    } else {
        Err(JoseError::Encoding("not canonical base64url"))
    }
}

fn b64u_fixed<const N: usize>(v: Option<&Value>, what: &'static str) -> Result<[u8; N], JoseError> {
    let s = v.and_then(Value::as_str).ok_or(JoseError::Key(what))?;
    b64u_decode(s.as_bytes())?
        .try_into()
        .map_err(|_| JoseError::Key(what))
}

/// A JWS `alg` this crate verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    /// ECDSA on P-256 with SHA-256 (RFC 7518).
    Es256,
    /// `EdDSA` on Ed25519 (RFC 8037), also spelled `Ed25519` (RFC 9864).
    EdDsa,
}

impl Alg {
    /// Reads a JWS `alg` value. `none` and every symmetric or unsupported
    /// algorithm give `None`.
    #[must_use]
    pub fn from_jws(s: &str) -> Option<Self> {
        match s {
            "ES256" => Some(Self::Es256),
            "EdDSA" | "Ed25519" => Some(Self::EdDsa),
            _ => None,
        }
    }

    /// The `alg` value a signer writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// Members that only a private or symmetric JWK has (RFC 7518 section 6).
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A public key as a JWK names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicJwk {
    /// `kty` EC, `crv` P-256: the affine coordinates, 32 bytes each.
    P256 {
        /// `x`.
        x: [u8; 32],
        /// `y`.
        y: [u8; 32],
    },
    /// `kty` OKP, `crv` Ed25519: the public key.
    Ed25519 {
        /// `x`.
        x: [u8; 32],
    },
}

impl PublicJwk {
    /// Reads a JWK object. Refuses private key material, key types other
    /// than P-256 and Ed25519, coordinates that are not full length, and
    /// points that are not valid keys. Other members (`kid`, `use`, ...) are
    /// allowed and play no part.
    pub fn from_value(v: &Value) -> Result<Self, JoseError> {
        let o = v.as_object().ok_or(JoseError::Key("not an object"))?;
        if PRIVATE_MEMBERS.iter().any(|m| o.contains_key(*m)) {
            return Err(JoseError::PrivateKey);
        }
        let kty = o.get("kty").and_then(Value::as_str);
        let crv = o.get("crv").and_then(Value::as_str);
        let key = match (kty, crv) {
            (Some("EC"), Some("P-256")) => Self::P256 {
                x: b64u_fixed(o.get("x"), "x is not 32 bytes")?,
                y: b64u_fixed(o.get("y"), "y is not 32 bytes")?,
            },
            (Some("OKP"), Some("Ed25519")) => Self::Ed25519 {
                x: b64u_fixed(o.get("x"), "x is not 32 bytes")?,
            },
            _ => return Err(JoseError::Key("unsupported kty or crv")),
        };
        key.check_point()?;
        Ok(key)
    }

    fn check_point(&self) -> Result<(), JoseError> {
        match self {
            Self::P256 { .. } => self.p256().map(|_| ()),
            Self::Ed25519 { .. } => self.ed25519().map(|_| ()),
        }
    }

    fn p256(&self) -> Result<p256::ecdsa::VerifyingKey, JoseError> {
        let Self::P256 { x, y } = self else {
            return Err(JoseError::AlgMismatch);
        };
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| JoseError::Key("not a point on P-256"))
    }

    fn ed25519(&self) -> Result<ed25519_dalek::VerifyingKey, JoseError> {
        let Self::Ed25519 { x } = self else {
            return Err(JoseError::AlgMismatch);
        };
        ed25519_dalek::VerifyingKey::from_bytes(x).map_err(|_| JoseError::Key("not an Ed25519 key"))
    }

    /// The RFC 7638 input: the required members in lexicographic order,
    /// no whitespace (RFC 8037 appendix A.3 for OKP).
    #[must_use]
    pub fn thumbprint_input(&self) -> String {
        match self {
            Self::P256 { x, y } => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64u(x),
                b64u(y)
            ),
            Self::Ed25519 { x } => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, b64u(x)),
        }
    }

    /// The JWK SHA-256 thumbprint (RFC 7638).
    #[must_use]
    pub fn thumbprint(&self) -> Thumbprint {
        Thumbprint(sha256(self.thumbprint_input().as_bytes()))
    }

    /// The JWK as a JSON object with only its required members.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        match self {
            Self::P256 { x, y } => {
                o.insert("kty".into(), "EC".into());
                o.insert("crv".into(), "P-256".into());
                o.insert("x".into(), b64u(x).into());
                o.insert("y".into(), b64u(y).into());
            }
            Self::Ed25519 { x } => {
                o.insert("kty".into(), "OKP".into());
                o.insert("crv".into(), "Ed25519".into());
                o.insert("x".into(), b64u(x).into());
            }
        }
        Value::Object(o)
    }

    /// Verifies a JWS signature over `signing_input` with this key.
    ///
    /// ES256 takes the 64-byte `R ‖ S` form of RFC 7518 3.4 and refuses a
    /// high `s` ([`JoseError::NonCanonicalSignature`]); `EdDSA` is checked
    /// with `verify_strict`.
    pub fn verify(&self, alg: Alg, signing_input: &[u8], sig: &[u8]) -> Result<(), JoseError> {
        match alg {
            Alg::Es256 => {
                use p256::ecdsa::signature::Verifier as _;
                let vk = self.p256()?;
                let sig =
                    p256::ecdsa::Signature::from_slice(sig).map_err(|_| JoseError::BadSignature)?;
                if sig.normalize_s() != sig {
                    return Err(JoseError::NonCanonicalSignature);
                }
                vk.verify(signing_input, &sig)
                    .map_err(|_| JoseError::BadSignature)
            }
            Alg::EdDsa => {
                let vk = self.ed25519()?;
                let sig: [u8; 64] = sig.try_into().map_err(|_| JoseError::BadSignature)?;
                vk.verify_strict(signing_input, &ed25519_dalek::Signature::from_bytes(&sig))
                    .map_err(|_| JoseError::BadSignature)
            }
        }
    }
}

/// A compact JWS, decoded. The header and payload are JSON objects read as
/// I-JSON; the signature is not checked yet.
#[derive(Debug, Clone, PartialEq)]
pub struct Jws {
    /// The protected header.
    pub header: Map<String, Value>,
    /// The payload (the JWT claims).
    pub payload: Map<String, Value>,
    /// `ASCII(BASE64URL(header) ‖ '.' ‖ BASE64URL(payload))`, the bytes
    /// the signature covers.
    pub signing_input: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Decodes a compact JWS: exactly three canonical base64url parts, a header
/// and a payload that are JSON objects naming no member twice.
pub fn parse_compact(token: &[u8]) -> Result<Jws, JoseError> {
    let mut parts = token.split(|b| *b == b'.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JoseError::Encoding("not three dot-separated parts"));
    };
    let header = object(&b64u_decode(h)?)?;
    let payload = object(&b64u_decode(p)?)?;
    let signature = b64u_decode(s)?;
    let signing_input = token[..h.len() + 1 + p.len()].to_vec();
    Ok(Jws {
        header,
        payload,
        signing_input,
        signature,
    })
}

fn object(json: &[u8]) -> Result<Map<String, Value>, JoseError> {
    match bnap_core::manifest::parse_strict(json) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => Err(JoseError::Json("not an object".into())),
        Err(e) => Err(JoseError::Json(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8037_ed25519_thumbprint() {
        // RFC 8037 appendix A.3.
        let jwk: Value = serde_json::from_str(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        let k = PublicJwk::from_value(&jwk).unwrap();
        assert_eq!(
            k.thumbprint().to_b64u(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// The `DPoP` proof of RFC 9449 figure 13, with its access token.
    const RFC9449_PROOF: &str = concat!(
        "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik",
        "VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR",
        "nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE",
        "QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj",
        "oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z",
        "WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF",
        "c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E",
        "OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA",
    );
    const RFC9449_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

    #[test]
    fn rfc_9449_example_proof_decodes_and_its_key_matches_the_jkt() {
        let jws = parse_compact(RFC9449_PROOF.as_bytes()).unwrap();
        assert_eq!(jws.header["typ"], "dpop+jwt");
        let key = PublicJwk::from_value(&jws.header["jwk"]).unwrap();
        // RFC 9449 section 6.1: the cnf.jkt of a token bound to this key.
        assert_eq!(
            key.thumbprint().to_b64u(),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
        // RFC 9449 section 4.2: ath is the base64url SHA-256 of the token.
        assert_eq!(
            jws.payload["ath"],
            b64u(&sha256(RFC9449_TOKEN.as_bytes())).as_str()
        );
        // The example signature verifies under ES256; whichever s it
        // carries, its canonical (low-s) twin verifies under the strict
        // check, and only one of the two spellings is accepted.
        let sig = p256::ecdsa::Signature::from_slice(&jws.signature).unwrap();
        let low = sig.normalize_s();
        let mut low_bytes = low.to_bytes().to_vec();
        key.verify(Alg::Es256, &jws.signing_input, &low_bytes)
            .unwrap();
        let high = p256::ecdsa::Signature::from_scalars(low.r(), -*low.s()).unwrap();
        assert_eq!(
            key.verify(Alg::Es256, &jws.signing_input, &high.to_bytes()),
            Err(JoseError::NonCanonicalSignature)
        );
        // A flipped bit in the signing input breaks it.
        low_bytes[10] ^= 1;
        assert_eq!(
            key.verify(Alg::Es256, &jws.signing_input, &low_bytes),
            Err(JoseError::BadSignature)
        );
    }

    #[test]
    fn base64url_must_be_canonical() {
        assert_eq!(b64u_decode(b"AQID").unwrap(), [1, 2, 3]);
        // Padding, the standard alphabet and non-zero trailing bits.
        for bad in [&b"AQI="[..], b"+/8", b"AR", b"AQ=="] {
            assert!(b64u_decode(bad).is_err(), "{bad:?}");
        }
        assert!(b64u_decode(b"AQ").is_ok());
    }

    #[test]
    fn private_and_unsupported_keys_are_refused() {
        let with_d: Value = serde_json::from_str(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
        )
        .unwrap();
        assert_eq!(PublicJwk::from_value(&with_d), Err(JoseError::PrivateKey));
        let rsa: Value = serde_json::from_str(r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#).unwrap();
        assert!(matches!(
            PublicJwk::from_value(&rsa),
            Err(JoseError::Key(_))
        ));
        // A P-256 point that is not on the curve.
        let off: Value = serde_json::from_str(&format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}"#,
            b64u(&[1; 32]),
            b64u(&[2; 32])
        ))
        .unwrap();
        assert!(matches!(
            PublicJwk::from_value(&off),
            Err(JoseError::Key(_))
        ));
    }

    #[test]
    fn compact_jws_refuses_duplicates_and_extra_parts() {
        let h = b64u(br#"{"alg":"ES256","alg":"none"}"#);
        let p = b64u(br#"{"a":1}"#);
        let dup = format!("{h}.{p}.AA");
        assert!(matches!(
            parse_compact(dup.as_bytes()),
            Err(JoseError::Json(_))
        ));
        let four = format!("{p}.{p}.AA.AA");
        assert!(matches!(
            parse_compact(four.as_bytes()),
            Err(JoseError::Encoding(_))
        ));
        let not_object = format!("{}.{p}.AA", b64u(b"[1]"));
        assert!(matches!(
            parse_compact(not_object.as_bytes()),
            Err(JoseError::Json(_))
        ));
    }
}
