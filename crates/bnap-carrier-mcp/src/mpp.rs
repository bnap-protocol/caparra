//! The MPP MCP forms of `payment:lightning/charge` (MPP MCP transport).
//!
//! Over HTTP an MPP challenge is a `WWW-Authenticate: Payment` value and a
//! credential the token `b64u(JCS(credential))`. Over MCP both travel as
//! JSON: a challenge in `error.data.challenges` with `request` as a JSON
//! object, a credential in `params._meta["org.paymentauth/credential"]`
//! with `challenge.request` (and the correlation data, as `meta`) as JSON
//! objects, and a receipt in `result._meta["org.paymentauth/receipt"]`.
//!
//! The gate turns an MCP credential back into the HTTP token, the scheme's
//! native credential bytes (registry entry), and hands that to the scheme
//! plug. Every JSON object is re-encoded as `b64u(JCS(object))`, so any
//! spelling of one credential gives the same token, and the token is what
//! the Digest and the `ReplayKey` cover (draft-00 5.4).

use bnap_scheme_mpp::{Challenge, json};
use serde_json::{Map, Value};

/// Members of a challenge echo the token form allows.
const ECHO: [&str; 10] = [
    "id",
    "realm",
    "method",
    "intent",
    "request",
    "expires",
    "digest",
    "opaque",
    "header",
    "description",
];

/// The MCP challenge object of a native `Payment` challenge value (the
/// data of an `mpp-challenge` native entry): every auth-param as a string,
/// except `request`, which is the decoded JSON object.
#[must_use]
pub fn challenge_value(header: &str) -> Option<Value> {
    let c = Challenge::parse(header).ok()?;
    let request = json::decode(c.request.as_bytes()).ok()?;
    let mut m = Map::new();
    m.insert("id".into(), Value::String(c.id));
    m.insert("realm".into(), Value::String(c.realm));
    m.insert("method".into(), Value::String(c.method));
    m.insert("intent".into(), Value::String(c.intent));
    m.insert("request".into(), request);
    for (k, v) in [
        ("expires", c.expires),
        ("digest", c.digest),
        ("opaque", c.opaque),
        ("header", c.header),
        ("description", c.description),
    ] {
        if let Some(v) = v {
            m.insert(k.into(), Value::String(v));
        }
    }
    Some(Value::Object(m))
}

/// Why an MCP credential object has no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the MPP credential is malformed: {0}")]
pub struct CredentialShape(pub &'static str);

/// The HTTP token (`b64u(JCS(credential))`) of an MCP credential object.
///
/// `challenge.request` may be the JSON object or its `b64u(JCS(..))`
/// string; the correlation data may be `opaque` (string) or `meta`
/// (object), and when both are sent they must name the same object. The
/// token keeps only members the token form defines; the scheme then reads
/// it strictly and refuses anything it does not verify.
pub fn credential_token(v: &Value) -> Result<String, CredentialShape> {
    let cred = v.as_object().ok_or(CredentialShape("not an object"))?;
    if cred
        .keys()
        .any(|k| !["challenge", "payload", "source"].contains(&k.as_str()))
    {
        return Err(CredentialShape("unknown member"));
    }
    let echo = cred
        .get("challenge")
        .and_then(Value::as_object)
        .ok_or(CredentialShape("challenge"))?;
    let mut out = Map::new();
    for (k, v) in echo {
        match k.as_str() {
            "request" => {
                out.insert(k.clone(), Value::String(encoded(v, "request")?));
            }
            "meta" => {
                let opaque = encoded(v, "meta")?;
                match echo.get("opaque") {
                    Some(o) if encoded(o, "opaque")? != opaque => {
                        return Err(CredentialShape("meta and opaque differ"));
                    }
                    _ => {
                        out.insert("opaque".into(), Value::String(opaque));
                    }
                }
            }
            "opaque" => {
                out.insert(k.clone(), Value::String(encoded(v, "opaque")?));
            }
            k if ECHO.contains(&k) => {
                if !v.is_string() {
                    return Err(CredentialShape("challenge member is not a string"));
                }
                out.insert(k.to_owned(), v.clone());
            }
            _ => return Err(CredentialShape("unknown challenge member")),
        }
    }
    let mut token = Map::new();
    token.insert("challenge".into(), Value::Object(out));
    token.insert(
        "payload".into(),
        cred.get("payload")
            .cloned()
            .ok_or(CredentialShape("payload"))?,
    );
    if let Some(s) = cred.get("source") {
        token.insert("source".into(), s.clone());
    }
    Ok(json::encode(&Value::Object(token)))
}

/// `b64u(JCS(object))` of an object, or a string as sent.
fn encoded(v: &Value, what: &'static str) -> Result<String, CredentialShape> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Object(_) => Ok(json::encode(v)),
        _ => Err(CredentialShape(what)),
    }
}

/// The MCP credential object of an HTTP token, as a client sends it:
/// `challenge.request` and the correlation data (`meta`) as JSON objects.
pub fn credential_value(token: &str) -> Result<Value, CredentialShape> {
    let mut v = json::decode(token.as_bytes()).map_err(|_| CredentialShape("token"))?;
    let echo = v
        .get_mut("challenge")
        .and_then(Value::as_object_mut)
        .ok_or(CredentialShape("challenge"))?;
    if let Some(Value::String(r)) = echo.get("request") {
        let r = json::decode(r.as_bytes()).map_err(|_| CredentialShape("request"))?;
        echo.insert("request".into(), r);
    }
    if let Some(Value::String(o)) = echo.remove("opaque") {
        let o = json::decode(o.as_bytes()).map_err(|_| CredentialShape("opaque"))?;
        echo.insert("meta".into(), o);
    }
    Ok(v)
}

/// The MCP receipt object of a `scheme_result` (the `Payment-Receipt`
/// value `b64u(JCS({challengeId, method, reference, status, timestamp}))`).
#[must_use]
pub fn receipt_value(scheme_result: &[u8]) -> Option<Value> {
    json::decode(scheme_result).ok().filter(Value::is_object)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn challenge() -> Challenge {
        Challenge {
            id: "abc".into(),
            realm: "api.example".into(),
            method: "lightning".into(),
            intent: "charge".into(),
            request: json::encode(&json!({"amount": "21", "currency": "sat"})),
            expires: Some("2026-10-14T00:00:00Z".into()),
            opaque: Some(json::encode(&json!({"bnap_offer": "00"}))),
            ..Challenge::default()
        }
    }

    #[test]
    fn a_challenge_travels_with_its_request_as_json() {
        let v = challenge_value(&challenge().to_header()).unwrap();
        assert_eq!(v["request"], json!({"amount": "21", "currency": "sat"}));
        assert_eq!(v["id"], "abc");
        assert!(v["opaque"].is_string());
        assert!(challenge_value("Bearer x").is_none());
    }

    #[test]
    fn every_spelling_of_a_credential_gives_one_token() {
        let cred = bnap_scheme_mpp::Credential::new(challenge(), [7; 32]);
        let token = cred.encode();
        let mcp = credential_value(&token).unwrap();
        assert!(mcp["challenge"]["request"].is_object());
        assert!(mcp["challenge"]["meta"].is_object());
        assert_eq!(credential_token(&mcp).unwrap(), token);
        // Member order and the string forms do not matter.
        let mut both = mcp.clone();
        both["challenge"]["opaque"] = Value::String(challenge().opaque.unwrap());
        both["challenge"]["request"] = Value::String(challenge().request);
        assert_eq!(credential_token(&both).unwrap(), token);
    }

    #[test]
    fn malformed_credentials_are_refused() {
        let token = bnap_scheme_mpp::Credential::new(challenge(), [7; 32]).encode();
        let good = credential_value(&token).unwrap();
        let mut differ = good.clone();
        differ["challenge"]["opaque"] = Value::String(json::encode(&json!({"bnap_offer": "01"})));
        assert!(credential_token(&differ).is_err());
        let mut extra = good.clone();
        extra["challenge"]["x"] = json!("y");
        assert!(credential_token(&extra).is_err());
        let mut extra = good.clone();
        extra["x"] = json!("y");
        assert!(credential_token(&extra).is_err());
        let mut number = good;
        number["challenge"]["realm"] = json!(1);
        assert!(credential_token(&number).is_err());
        assert!(credential_token(&json!("token")).is_err());
    }

    #[test]
    fn a_receipt_is_the_decoded_payment_receipt() {
        let r = bnap_scheme_mpp::Receipt {
            challenge_id: "abc".into(),
            payment_hash: [1; 32],
            timestamp: 0,
        };
        let v = receipt_value(r.encode().as_bytes()).unwrap();
        assert_eq!(v["challengeId"], "abc");
        assert_eq!(v["status"], "success");
        assert!(receipt_value(b"not").is_none());
    }
}
