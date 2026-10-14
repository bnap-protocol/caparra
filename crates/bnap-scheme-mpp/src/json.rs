//! Base64url JCS JSON, as the Payment scheme carries it, read strictly.
//!
//! Every JSON object in `request`, `opaque`, the credential token and the
//! receipt is JCS-serialized (RFC 8785) and then base64url-encoded without
//! padding (draft-httpauth-payment-01 5.1, draft-lightning-charge-00 6). A
//! reader here accepts only that exact form: unpadded base64url with no
//! trailing bits, I-JSON with no member named twice, and bytes equal to
//! their own JCS serialization. Any other spelling is refused, so a body
//! verifies in one byte form only (draft-00 5.1, canonical bodies).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::MppError;

/// `b64u(JCS(value))`.
#[must_use]
pub fn encode(value: &Value) -> String {
    // JCS of a Value holding only strings and objects cannot fail.
    let bytes = serde_json_canonicalizer::to_vec(value).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Reads `b64u(JCS(value))` in its one canonical form.
pub fn decode(text: &[u8]) -> Result<Value, MppError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| MppError::Malformed("not unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes).as_bytes() != text {
        return Err(MppError::Malformed("not canonical base64url"));
    }
    let value =
        bnap_core::manifest::parse_strict(&bytes).map_err(|_| MppError::Malformed("not I-JSON"))?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| MppError::Malformed("not JCS-serializable"))?;
    if canonical != bytes {
        return Err(MppError::Malformed("not JCS-serialized"));
    }
    Ok(value)
}

/// The value as an object whose members are all in `allowed`.
pub fn object<'a>(
    value: &'a Value,
    allowed: &[&str],
    what: &'static str,
) -> Result<&'a Map<String, Value>, MppError> {
    let map = value.as_object().ok_or(MppError::Malformed(what))?;
    if map.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(MppError::Malformed(what));
    }
    Ok(map)
}

/// An optional string member.
pub fn string<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    what: &'static str,
) -> Result<Option<&'a str>, MppError> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(MppError::Malformed(what)),
    }
}

/// A required string member.
pub fn required<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    what: &'static str,
) -> Result<&'a str, MppError> {
    string(map, key, what)?.ok_or(MppError::Malformed(what))
}

/// 32 bytes as 64 lower-case hex digits.
pub fn hex32(s: &str, what: &'static str) -> Result<[u8; 32], MppError> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(MppError::Malformed(what));
    }
    let mut out = [0; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| MppError::Malformed(what))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encoding_is_unpadded_base64url_of_jcs() {
        let v = json!({"b": "2", "a": {"d": "x", "c": "y"}});
        let s = encode(&v);
        let raw = URL_SAFE_NO_PAD.decode(&s).unwrap();
        assert_eq!(raw, br#"{"a":{"c":"y","d":"x"},"b":"2"}"#);
        assert_eq!(decode(s.as_bytes()).unwrap(), v);
    }

    #[test]
    fn only_the_canonical_form_decodes() {
        let enc = |raw: &[u8]| URL_SAFE_NO_PAD.encode(raw);
        for raw in [
            &br#"{"b":"2","a":"1"}"#[..],
            br#"{"a": "1"}"#,
            br#"{"a":"1","a":"1"}"#,
            b"{\"a\":\"\\u0031\"}",
            br#"{"a":"1"} "#,
            b"not json",
        ] {
            assert!(decode(enc(raw).as_bytes()).is_err(), "{raw:?}");
        }
        let good = enc(br#"{"a":"1"}"#);
        assert!(decode(good.as_bytes()).is_ok());
        // Padding, the standard alphabet and trailing bits are refused.
        let padded = base64::engine::general_purpose::URL_SAFE.encode(br#"{"ab":"1"}"#);
        assert!(padded.ends_with('='));
        assert!(decode(padded.as_bytes()).is_err());
        assert!(decode(padded.trim_end_matches('=').as_bytes()).is_ok());
        let std = base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfb, 0xff]);
        assert!(decode(std.as_bytes()).is_err());
        assert!(decode(b"eyJhIjoiMSJ9_").is_err());
    }

    #[test]
    fn hex32_wants_64_lower_case_digits() {
        assert_eq!(hex32(&"ab".repeat(32), "x").unwrap(), [0xab; 32]);
        assert!(hex32(&"AB".repeat(32), "x").is_err());
        assert!(hex32(&"ab".repeat(31), "x").is_err());
        assert!(hex32(&"zz".repeat(32), "x").is_err());
    }
}
