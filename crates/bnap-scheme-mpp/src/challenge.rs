//! The `Payment` challenge (draft-httpauth-payment-01 5.1) and its
//! HMAC-bound `id` (5.1.2.1.1).
//!
//! `id = b64u(HMAC-SHA256(secret, realm|method|intent|request|expires|digest|opaque))`,
//! with `header` inserted before `opaque` when present and an empty slot
//! for each absent optional field. Binding the id to every field the client
//! echoes lets the server check a credential without state: this scheme
//! puts the `OfferID` in `opaque`, so the id authenticates the offer too
//! (draft-00 5.4, "an HMAC'd MPP id").

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bnap_core::hash::{hmac_sha256, hmac_sha256_verify};

use crate::MppError;

/// The authentication scheme name.
pub const AUTH_SCHEME: &str = "Payment";

/// A `Payment` challenge, every auth-param as a string, as it travels in
/// `WWW-Authenticate` and in a credential's `challenge` echo.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Challenge {
    /// The HMAC-bound challenge ID.
    pub id: String,
    /// Protection space.
    pub realm: String,
    /// Payment method, such as `lightning`.
    pub method: String,
    /// Intent, such as `charge`.
    pub intent: String,
    /// `b64u(JCS(request object))`.
    pub request: String,
    /// RFC 3339 expiry.
    pub expires: Option<String>,
    /// RFC 9530 content digest.
    pub digest: Option<String>,
    /// `b64u(JCS(flat string map))`: server correlation data.
    pub opaque: Option<String>,
    /// `Payment-Authorization` when the challenge selects that field.
    pub header: Option<String>,
    /// Display text; not bound by the id.
    pub description: Option<String>,
}

impl Challenge {
    /// The HMAC input of 5.1.2.1.1: the pipe-joined slots.
    #[must_use]
    pub fn binding_input(&self) -> String {
        let mut slots = vec![
            self.realm.as_str(),
            self.method.as_str(),
            self.intent.as_str(),
            self.request.as_str(),
            self.expires.as_deref().unwrap_or(""),
            self.digest.as_deref().unwrap_or(""),
        ];
        if let Some(h) = &self.header {
            slots.push(h);
        }
        slots.push(self.opaque.as_deref().unwrap_or(""));
        slots.join("|")
    }

    /// The id this challenge gets under `secret`.
    #[must_use]
    pub fn compute_id(&self, secret: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(secret, self.binding_input().as_bytes()))
    }

    /// Sets `id` from `secret`.
    #[must_use]
    pub fn bound(mut self, secret: &[u8]) -> Self {
        self.id = self.compute_id(secret);
        self
    }

    /// Whether `id` is the HMAC of the other fields under `secret`, compared
    /// in constant time.
    #[must_use]
    pub fn verify_id(&self, secret: &[u8]) -> bool {
        let Ok(tag) = URL_SAFE_NO_PAD.decode(&self.id) else {
            return false;
        };
        let Ok(tag) = <[u8; 32]>::try_from(tag.as_slice()) else {
            return false;
        };
        URL_SAFE_NO_PAD.encode(tag) == self.id
            && hmac_sha256_verify(secret, self.binding_input().as_bytes(), &tag)
    }

    /// The `WWW-Authenticate` field value. A native entry of the offer
    /// carries these exact bytes.
    #[must_use]
    pub fn to_header(&self) -> String {
        let mut out = format!(
            "{AUTH_SCHEME} id=\"{}\", realm=\"{}\", method=\"{}\", intent=\"{}\", request=\"{}\"",
            quote(&self.id),
            quote(&self.realm),
            quote(&self.method),
            quote(&self.intent),
            quote(&self.request),
        );
        for (name, value) in [
            ("expires", &self.expires),
            ("digest", &self.digest),
            ("opaque", &self.opaque),
            ("header", &self.header),
            ("description", &self.description),
        ] {
            if let Some(v) = value {
                // Writing to a String cannot fail.
                let _ = write!(out, ", {name}=\"{}\"", quote(v));
            }
        }
        out
    }

    /// Reads one `Payment` challenge (scheme name in any case). `id`,
    /// `realm`, `method`, `intent` and `request` are required and `id` must
    /// not be empty (5.1.1); unknown parameters are ignored.
    pub fn parse(value: &str) -> Result<Self, MppError> {
        let (scheme, rest) = split_scheme(value).ok_or(MppError::NotPayment)?;
        if !scheme.eq_ignore_ascii_case(AUTH_SCHEME) {
            return Err(MppError::NotPayment);
        }
        let params = auth_params(rest).ok_or(MppError::Malformed("auth-params"))?;
        let get = |name: &str| {
            params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let need = |name: &'static str| get(name).ok_or(MppError::Malformed(name));
        let c = Self {
            id: need("id")?,
            realm: need("realm")?,
            method: need("method")?,
            intent: need("intent")?,
            request: need("request")?,
            expires: get("expires"),
            digest: get("digest"),
            opaque: get("opaque"),
            header: get("header"),
            description: get("description"),
        };
        if c.id.is_empty() {
            return Err(MppError::Malformed("id"));
        }
        Ok(c)
    }
}

/// The `Authorization` field value for a credential token.
#[must_use]
pub fn authorization(token: &str) -> String {
    format!("{AUTH_SCHEME} {token}")
}

/// The credential token of an `Authorization` (or `Payment-Authorization`)
/// field value: what follows the scheme name `Payment` (any case), the
/// native credential bytes of this scheme. `None` for another scheme.
#[must_use]
pub fn credential_from_authorization(value: &str) -> Option<&str> {
    let (scheme, rest) = split_scheme(value)?;
    (scheme.eq_ignore_ascii_case(AUTH_SCHEME) && !rest.is_empty()).then_some(rest)
}

/// Escapes `"` and `\` for a quoted-string (RFC 9110 5.6.4).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Splits a field value into its auth-scheme and the rest, trimmed.
fn split_scheme(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_matches([' ', '\t']);
    let end = value.find([' ', '\t']).unwrap_or(value.len());
    let (scheme, rest) = value.split_at(end);
    if scheme.is_empty() || !scheme.bytes().all(is_tchar) {
        return None;
    }
    Some((scheme, rest.trim_start_matches([' ', '\t'])))
}

/// Parses `#auth-param` (RFC 9110 11.2): names lower-cased, values
/// unquoted. A name given twice, or any syntax error, is `None`.
fn auth_params(input: &str) -> Option<Vec<(String, String)>> {
    let bytes = input.as_bytes();
    let mut at = 0;
    let mut out: Vec<(String, String)> = Vec::new();
    loop {
        while at < bytes.len() && (is_ows(bytes[at]) || bytes[at] == b',') {
            at += 1;
        }
        if at == bytes.len() {
            return Some(out);
        }
        let start = at;
        while at < bytes.len() && is_tchar(bytes[at]) {
            at += 1;
        }
        if at == start {
            return None;
        }
        let name = input[start..at].to_ascii_lowercase();
        while at < bytes.len() && is_ows(bytes[at]) {
            at += 1;
        }
        if bytes.get(at) != Some(&b'=') {
            return None;
        }
        at += 1;
        while at < bytes.len() && is_ows(bytes[at]) {
            at += 1;
        }
        let value = if bytes.get(at) == Some(&b'"') {
            at += 1;
            let mut text = Vec::new();
            loop {
                match bytes.get(at)? {
                    b'"' => {
                        at += 1;
                        break;
                    }
                    b'\\' => {
                        text.push(*bytes.get(at + 1)?);
                        at += 2;
                    }
                    byte => {
                        text.push(*byte);
                        at += 1;
                    }
                }
            }
            String::from_utf8(text).ok()?
        } else {
            let start = at;
            while at < bytes.len() && is_tchar(bytes[at]) {
                at += 1;
            }
            if at == start {
                return None;
            }
            input[start..at].to_owned()
        };
        if out.iter().any(|(n, _)| *n == name) {
            return None;
        }
        out.push((name, value));
        while at < bytes.len() && is_ows(bytes[at]) {
            at += 1;
        }
        match bytes.get(at) {
            None => return Some(out),
            Some(b',') => at += 1,
            Some(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HMAC-SHA256 vectors of draft-httpauth-payment-01 5.1.2.1.1.1.
    #[test]
    fn the_draft_hmac_vectors_reproduce() {
        let secret = b"test-vector-secret";
        let mut c = Challenge {
            realm: "api.example.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: "eyJhbW91bnQiOiIxMDAwMDAwIn0".into(),
            ..Challenge::default()
        };
        assert_eq!(
            c.binding_input(),
            "api.example.com|tempo|charge|eyJhbW91bnQiOiIxMDAwMDAwIn0|||"
        );
        assert_eq!(
            c.compute_id(secret),
            "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4"
        );
        c.header = Some("Payment-Authorization".into());
        assert_eq!(
            c.compute_id(secret),
            "S91xi-OFGZPMs-j7GsX0FDpIkmCcZT1P9XyV58WNy_U"
        );
        c.opaque = Some("eyJwaSI6InBpXzEyMyJ9".into());
        assert_eq!(
            c.binding_input(),
            "api.example.com|tempo|charge|eyJhbW91bnQiOiIxMDAwMDAwIn0|||Payment-Authorization|eyJwaSI6InBpXzEyMyJ9"
        );
        assert_eq!(
            c.compute_id(secret),
            "CJ4X1O4aTDmS59hfdhnhBtxIQjWDOf0bcrhsswwMOW8"
        );
    }

    fn challenge() -> Challenge {
        Challenge {
            realm: "api.example".into(),
            method: "lightning".into(),
            intent: "charge".into(),
            request: "eyJhIjoiMSJ9".into(),
            expires: Some("2026-10-11T06:31:40Z".into()),
            opaque: Some("eyJiIjoiMiJ9".into()),
            ..Challenge::default()
        }
        .bound(b"k")
    }

    #[test]
    fn every_bound_field_changes_the_id() {
        let c = challenge();
        assert!(c.verify_id(b"k"));
        assert!(!c.verify_id(b"other"));
        let mutations: [fn(&mut Challenge); 8] = [
            |c| c.realm.push('x'),
            |c| c.method.push('x'),
            |c| c.intent.push('x'),
            |c| c.request.push('x'),
            |c| c.expires = None,
            |c| c.digest = Some("sha-256=:x:".into()),
            |c| c.opaque = None,
            |c| c.header = Some("Payment-Authorization".into()),
        ];
        for m in mutations {
            let mut changed = c.clone();
            m(&mut changed);
            assert!(!changed.verify_id(b"k"), "{changed:?}");
        }
        // An empty digest and an absent one share a slot, so the binding
        // reads them alike; the credential parser keeps them apart.
        let mut empty = c.clone();
        empty.digest = Some(String::new());
        assert_eq!(empty.binding_input(), c.binding_input());
        // The description is not bound.
        let mut d = c.clone();
        d.description = Some("free text".into());
        assert!(d.verify_id(b"k"));
        // A padded or truncated id is refused.
        let mut padded = c.clone();
        padded.id.push('=');
        assert!(!padded.verify_id(b"k"));
        let mut short = c;
        short.id.pop();
        assert!(!short.verify_id(b"k"));
    }

    #[test]
    fn challenges_round_trip_through_the_header() {
        let c = challenge();
        let h = c.to_header();
        assert!(h.starts_with("Payment id=\""));
        assert_eq!(Challenge::parse(&h).unwrap(), c);
        let mut all = c.clone();
        all.digest = Some("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".into());
        all.header = Some("Payment-Authorization".into());
        all.description = Some("a \"quoted\" \\ text".into());
        assert_eq!(Challenge::parse(&all.to_header()).unwrap(), all);
        // The draft's example form, with unknown parameters, parses.
        let ex = "payment id=\"x7Tg2pLqR9mKvNwY3hBcZa\",\n realm=\"api.example.com\", method=\"example\", intent=charge, future=\"1\", request=\"eyJ9\"";
        let p = Challenge::parse(&ex.replace('\n', "")).unwrap();
        assert_eq!(
            (p.id.as_str(), p.intent.as_str()),
            ("x7Tg2pLqR9mKvNwY3hBcZa", "charge")
        );
    }

    #[test]
    fn bad_challenges_are_refused() {
        assert_eq!(
            Challenge::parse("L402 token=\"x\""),
            Err(MppError::NotPayment)
        );
        assert_eq!(
            Challenge::parse("Payment realm=\"r\", method=\"m\", intent=\"i\", request=\"q\""),
            Err(MppError::Malformed("id"))
        );
        assert_eq!(
            Challenge::parse(
                "Payment id=\"\", realm=\"r\", method=\"m\", intent=\"i\", request=\"q\""
            ),
            Err(MppError::Malformed("id"))
        );
        assert!(Challenge::parse("Payment id=\"a\", id=\"b\"").is_err());
        assert!(Challenge::parse("Payment id=\"a").is_err());
    }

    #[test]
    fn authorization_values_name_their_scheme() {
        assert_eq!(authorization("abc"), "Payment abc");
        assert_eq!(credential_from_authorization("Payment abc"), Some("abc"));
        assert_eq!(credential_from_authorization("payment  abc "), Some("abc"));
        assert_eq!(credential_from_authorization("L402 abc"), None);
        assert_eq!(credential_from_authorization("Payment"), None);
    }
}
