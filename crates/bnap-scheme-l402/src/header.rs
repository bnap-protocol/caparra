//! The L402 HTTP fields: the `WWW-Authenticate` challenge and the
//! `Authorization` credential (bLIP-26).
//!
//! A server sends `L402 version="0", token="T", macaroon="T",
//! invoice="P"`: `token` is the current parameter name and `macaroon` the
//! older one, so clients of either revision can read it (ERRATA row 34).
//! A parser accepts the scheme names `L402` and `LSAT` in any case, and
//! `token=` or `macaroon=` (equal when both are present).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::token::Token;

/// The scheme name a server sends.
pub const AUTH_SCHEME: &str = "L402";
/// The former scheme name, still accepted.
pub const LEGACY_AUTH_SCHEME: &str = "LSAT";
/// The protocol version a server sends.
pub const VERSION: &str = "0";

/// Why a header could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// Not an `L402` or `LSAT` field value.
    #[error("not an L402 field value")]
    NotL402,
    /// The auth-params do not parse.
    #[error("malformed auth-params")]
    Syntax,
    /// A required parameter is missing.
    #[error("missing parameter {0}")]
    Missing(&'static str),
    /// `token` and `macaroon` differ, or a parameter is repeated.
    #[error("conflicting parameter {0}")]
    Conflict(&'static str),
    /// A `version` this implementation does not speak.
    #[error("unsupported L402 version {0}")]
    Version(String),
}

/// An L402 challenge, as a server sends it in `WWW-Authenticate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The macaroon, standard base64 with padding.
    pub token: String,
    /// The BOLT 11 invoice the client pays.
    pub invoice: String,
}

impl Challenge {
    /// The challenge of an offer's two native entries for one L402 pay
    /// entry: the binary macaroon (kind `l402-macaroon`) and the invoice
    /// (kind `bolt11`). `None` when either is missing or the invoice is not
    /// text.
    #[must_use]
    pub fn from_natives(macaroon: &[u8], invoice: &[u8]) -> Option<Self> {
        Some(Self {
            token: STANDARD.encode(macaroon),
            invoice: std::str::from_utf8(invoice).ok()?.to_owned(),
        })
    }

    /// The challenge of the L402 pay entry at `pay_index`, from an offer's
    /// native entries: its `l402-macaroon` and `bolt11` entries.
    #[must_use]
    pub fn of_entries(native: &[bnap_core::offer::NativeEntry], pay_index: u64) -> Option<Self> {
        let get = |kind: &str| {
            native
                .iter()
                .find(|n| n.pay_index == pay_index && n.kind == kind)
                .map(|n| n.data.as_slice())
        };
        Self::from_natives(get(crate::NATIVE_KIND)?, get(crate::INVOICE_KIND)?)
    }

    /// The macaroon's binary serialization, as the `l402-macaroon` native
    /// entry carries it; `None` when `token` is not standard base64.
    #[must_use]
    pub fn macaroon(&self) -> Option<Vec<u8>> {
        STANDARD.decode(&self.token).ok()
    }

    /// The field value: `L402 version="0", token="…", macaroon="…",
    /// invoice="…"`.
    #[must_use]
    pub fn to_header(&self) -> String {
        format!(
            "{AUTH_SCHEME} version=\"{VERSION}\", token=\"{t}\", macaroon=\"{t}\", invoice=\"{i}\"",
            t = quote(&self.token),
            i = quote(&self.invoice),
        )
    }

    /// Reads a challenge: scheme `L402` or `LSAT` in any case, `token` or
    /// `macaroon` (equal if both), `invoice` required, `version` absent or
    /// `"0"`; unknown parameters are ignored, as bLIP-26 requires.
    pub fn parse(value: &str) -> Result<Self, HeaderError> {
        let (scheme, rest) = split_scheme(value).ok_or(HeaderError::NotL402)?;
        if !is_l402(scheme) {
            return Err(HeaderError::NotL402);
        }
        let params = auth_params(rest).ok_or(HeaderError::Syntax)?;
        let get = |name: &str| {
            params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        if let Some(v) = get("version")
            && v != VERSION
        {
            return Err(HeaderError::Version(v));
        }
        let token = match (get("token"), get("macaroon")) {
            (Some(t), Some(m)) if t != m => return Err(HeaderError::Conflict("token")),
            (Some(t), _) | (None, Some(t)) => t,
            (None, None) => return Err(HeaderError::Missing("token")),
        };
        let invoice = get("invoice").ok_or(HeaderError::Missing("invoice"))?;
        Ok(Self { token, invoice })
    }
}

/// The binary macaroon of a minted token (standard base64).
pub(crate) fn macaroon_bytes(token: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(token)
}

/// The `Authorization` field value for a token: `L402 <token>`.
#[must_use]
pub fn authorization(token: &Token) -> String {
    format!("{AUTH_SCHEME} {token}")
}

/// The native credential bytes of an `Authorization` field value: what
/// follows the scheme name `L402` or `LSAT` (any case), the
/// `macaroon:preimage` token as sent. `None` for any other scheme. The
/// token itself is checked by [`Token::parse`].
#[must_use]
pub fn credential_from_authorization(value: &str) -> Option<&str> {
    let (scheme, rest) = split_scheme(value)?;
    (is_l402(scheme) && !rest.is_empty()).then_some(rest)
}

fn is_l402(scheme: &str) -> bool {
    scheme.eq_ignore_ascii_case(AUTH_SCHEME) || scheme.eq_ignore_ascii_case(LEGACY_AUTH_SCHEME)
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
            let vs = at;
            while at < bytes.len() && is_tchar(bytes[at]) {
                at += 1;
            }
            if at == vs {
                return None;
            }
            input[vs..at].to_owned()
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

    fn challenge() -> Challenge {
        Challenge {
            token: "AgEEbHNhdAJCAAA+".into(),
            invoice: "lnfake21sat1abcd".into(),
        }
    }

    #[test]
    fn a_challenge_carries_token_and_macaroon() {
        let h = challenge().to_header();
        assert_eq!(
            h,
            "L402 version=\"0\", token=\"AgEEbHNhdAJCAAA+\", macaroon=\"AgEEbHNhdAJCAAA+\", invoice=\"lnfake21sat1abcd\""
        );
        assert_eq!(Challenge::parse(&h).unwrap(), challenge());
    }

    #[test]
    fn old_and_new_spellings_parse() {
        let want = challenge();
        for v in [
            "LSAT macaroon=\"AgEEbHNhdAJCAAA+\", invoice=\"lnfake21sat1abcd\"",
            "l402 token=\"AgEEbHNhdAJCAAA+\",invoice=lnfake21sat1abcd",
            "L402   version = \"0\" , token=\"AgEEbHNhdAJCAAA+\", invoice=\"lnfake21sat1abcd\", future=\"x\"",
            "lsat Token=\"AgEEbHNhdAJCAAA+\", INVOICE=\"lnfake21sat1abcd\"",
            "L402 token=\"AgEEbHNhdAJC\\AAA+\", invoice=\"lnfake21sat1abcd\"",
        ] {
            assert_eq!(Challenge::parse(v).unwrap(), want, "{v}");
        }
    }

    #[test]
    fn bad_challenges_are_refused() {
        for (v, e) in [
            ("Bearer token=\"x\"", HeaderError::NotL402),
            ("", HeaderError::NotL402),
            ("L402 invoice=\"i\"", HeaderError::Missing("token")),
            ("L402 token=\"t\"", HeaderError::Missing("invoice")),
            (
                "L402 token=\"t\", macaroon=\"u\", invoice=\"i\"",
                HeaderError::Conflict("token"),
            ),
            (
                "L402 version=\"1\", token=\"t\", invoice=\"i\"",
                HeaderError::Version("1".into()),
            ),
            (
                "L402 token=\"t\", token=\"t\", invoice=\"i\"",
                HeaderError::Syntax,
            ),
            ("L402 token=\"t, invoice=\"i\"", HeaderError::Syntax),
            ("L402 token t", HeaderError::Syntax),
            ("L402 token=\"t\" invoice=\"i\"", HeaderError::Syntax),
        ] {
            assert_eq!(Challenge::parse(v), Err(e), "{v}");
        }
    }

    #[test]
    fn authorization_values_name_their_scheme() {
        assert_eq!(
            credential_from_authorization("L402 abc:def"),
            Some("abc:def")
        );
        assert_eq!(
            credential_from_authorization("LSAT abc:def"),
            Some("abc:def")
        );
        assert_eq!(
            credential_from_authorization("lsat  abc:def "),
            Some("abc:def")
        );
        assert_eq!(credential_from_authorization("Payment abc"), None);
        assert_eq!(credential_from_authorization("L402"), None);
        assert_eq!(credential_from_authorization("L402X abc"), None);
    }

    #[test]
    fn quoting_escapes_quotes_and_backslashes() {
        assert_eq!(quote("a\"b\\c"), "a\\\"b\\\\c");
        let params = auth_params("x=\"a\\\"b\\\\c\"").unwrap();
        assert_eq!(params, vec![("x".to_owned(), "a\"b\\c".to_owned())]);
    }
}
