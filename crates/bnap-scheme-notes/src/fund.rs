//! The `BNAP-Fund` request field (8.1, P22).
//!
//! ```text
//! BNAP-Fund: amount=2100, pubkey="02c4…"
//! ```
//!
//! An RFC 9651 Dictionary: `amount` is an Integer, the most the client will
//! pay in sat; `pubkey` is a String of 66 lowercase hex characters, a
//! compressed secp256k1 key the client made fresh for this quote. Other
//! members are ignored. A field that does not parse as a Dictionary is
//! ignored as a whole, as RFC 9651 says.

use crate::wire::{PointBytes, is_point};

/// A parsed `BNAP-Fund` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundRequest {
    /// The most the client will pay, in sat.
    pub amount: u64,
    /// The client's fresh NUT-20 key.
    pub pubkey: PointBytes,
}

/// Why a `BNAP-Fund` field is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("BNAP-Fund: {0}")]
pub struct FundError(pub String);

fn err(m: impl Into<String>) -> FundError {
    FundError(m.into())
}

/// An RFC 9651 bare item, as far as this field needs one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Integer(i64),
    String(String),
    Other,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.i += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }

    fn key(&mut self) -> Result<String, FundError> {
        let start = self.i;
        match self.peek() {
            Some(c) if c.is_ascii_lowercase() || c == b'*' => self.i += 1,
            _ => return Err(err("a key must start with a lowercase letter or *")),
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-.*".contains(&c) {
                self.i += 1;
            } else {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn bare_item(&mut self) -> Result<Item, FundError> {
        match self.peek() {
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'"') => self.string(),
            Some(b'?') => {
                self.i += 1;
                match self.peek() {
                    Some(b'0' | b'1') => {
                        self.i += 1;
                        Ok(Item::Other)
                    }
                    _ => Err(err("a bad boolean")),
                }
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'*' => {
                // A token.
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c) {
                        self.i += 1;
                    } else {
                        break;
                    }
                }
                Ok(Item::Other)
            }
            Some(b':') => {
                // A byte sequence.
                self.i += 1;
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if c == b':' {
                        return Ok(Item::Other);
                    }
                    if !(c.is_ascii_alphanumeric() || b"+/=".contains(&c)) {
                        return Err(err("a bad byte sequence"));
                    }
                }
                Err(err("an unterminated byte sequence"))
            }
            _ => Err(err("a bad item")),
        }
    }

    fn number(&mut self) -> Result<Item, FundError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == digits {
            return Err(err("a number without digits"));
        }
        if self.peek() == Some(b'.') {
            // A Decimal: valid, but not an Integer.
            self.i += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            return Ok(Item::Other);
        }
        if self.i - digits > 15 {
            return Err(err("an Integer of more than 15 digits"));
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| err("not ASCII"))?;
        text.parse()
            .map(Item::Integer)
            .map_err(|_| err("a bad Integer"))
    }

    fn string(&mut self) -> Result<Item, FundError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(err("an unterminated String")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(Item::String(out));
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => {
                            out.push(char::from(c));
                            self.i += 1;
                        }
                        _ => return Err(err("a bad escape")),
                    }
                }
                Some(c @ 0x20..=0x7e) => {
                    out.push(char::from(c));
                    self.i += 1;
                }
                Some(_) => return Err(err("a String with a non-printable character")),
            }
        }
    }

    fn parameters(&mut self) -> Result<(), FundError> {
        while self.peek() == Some(b';') {
            self.i += 1;
            self.skip_sp();
            self.key()?;
            if self.peek() == Some(b'=') {
                self.i += 1;
                self.bare_item()?;
            }
        }
        Ok(())
    }

    fn dictionary(&mut self) -> Result<Vec<(String, Item)>, FundError> {
        let mut out: Vec<(String, Item)> = Vec::new();
        self.skip_sp();
        if self.i == self.s.len() {
            return Ok(out);
        }
        loop {
            let key = self.key()?;
            let item = if self.peek() == Some(b'=') {
                self.i += 1;
                if self.peek() == Some(b'(') {
                    return Err(err("inner lists are not used here"));
                }
                self.bare_item()?
            } else {
                Item::Other
            };
            self.parameters()?;
            // A key named twice: the last value wins (RFC 9651 4.2.2).
            out.retain(|(k, _)| k != &key);
            out.push((key, item));
            self.skip_ows();
            if self.i == self.s.len() {
                return Ok(out);
            }
            if self.peek() != Some(b',') {
                return Err(err("members must be separated by commas"));
            }
            self.i += 1;
            self.skip_ows();
            if self.i == self.s.len() {
                return Err(err("a trailing comma"));
            }
        }
    }
}

impl FundRequest {
    /// Parses the field value. `amount` must be an Integer of at least 1,
    /// and `pubkey` a String of 66 lowercase hex characters naming a
    /// compressed point.
    pub fn parse_header(value: &str) -> Result<Self, FundError> {
        let members = Parser {
            s: value.trim_matches(' ').as_bytes(),
            i: 0,
        }
        .dictionary()?;
        let get = |k: &str| members.iter().find(|(key, _)| key == k).map(|(_, v)| v);
        let amount = match get("amount") {
            Some(Item::Integer(n)) if *n >= 1 => u64::try_from(*n).map_err(|_| err("amount"))?,
            Some(_) => return Err(err("amount must be a positive Integer")),
            None => return Err(err("no amount")),
        };
        let pubkey = match get("pubkey") {
            Some(Item::String(s))
                if s.len() == 66
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                let bytes: PointBytes = hex::decode(s)
                    .map_err(|_| err("pubkey is not hex"))?
                    .try_into()
                    .map_err(|_| err("pubkey is not 33 bytes"))?;
                if !is_point(&bytes) {
                    return Err(err("pubkey is not a compressed point"));
                }
                bytes
            }
            Some(_) => return Err(err("pubkey must be 66 lowercase hex characters")),
            None => return Err(err("no pubkey")),
        };
        Ok(Self { amount, pubkey })
    }

    /// The field value a client sends.
    #[must_use]
    pub fn to_header(&self) -> String {
        format!(
            "amount={}, pubkey=\"{}\"",
            self.amount,
            hex::encode(self.pubkey)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        hex::encode(bnap_core::note::hash_to_curve(b"k").unwrap())
    }

    #[test]
    fn the_spec_example_parses() {
        let v = format!("amount=2100, pubkey=\"{}\"", key());
        let r = FundRequest::parse_header(&v).unwrap();
        assert_eq!(r.amount, 2100);
        assert_eq!(r.to_header(), v);
        assert_eq!(FundRequest::parse_header(&r.to_header()).unwrap(), r);
    }

    #[test]
    fn other_members_and_parameters_are_ignored() {
        let v = format!(
            "x=?1, pubkey=\"{}\";a=1, amount=5;b=tok, y=:AAA=:, z=1.5",
            key()
        );
        assert_eq!(FundRequest::parse_header(&v).unwrap().amount, 5);
    }

    #[test]
    fn bad_fields_are_refused() {
        let k = key();
        for v in [
            format!("amount=0, pubkey=\"{k}\""),
            format!("amount=-1, pubkey=\"{k}\""),
            format!("amount=\"5\", pubkey=\"{k}\""),
            format!("amount=5, pubkey=\"{}\"", k.to_uppercase()),
            format!("amount=5, pubkey={k}"),
            format!("amount=5, pubkey=\"{}\"", &k[..64]),
            format!("amount=5 pubkey=\"{k}\""),
            format!("amount=5, pubkey=\"{k}\","),
            "amount=5".to_owned(),
            format!("pubkey=\"{k}\""),
            format!("amount=1234567890123456, pubkey=\"{k}\""),
            format!("amount=5, pubkey=\"02{}\"", "00".repeat(32)),
        ] {
            assert!(FundRequest::parse_header(&v).is_err(), "{v}");
        }
    }
}
