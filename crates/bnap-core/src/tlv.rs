//! TLV streams (draft-00 section 2): BOLT 1 records, the type ranges, the
//! even/odd rule and entry lists.
//!
//! A stream is `BigSize(type) ‖ BigSize(length) ‖ value`, repeated, with types
//! strictly increasing and no duplicates. [`TlvStream::parse`] enforces the
//! framing, minimal BigSize, the order, and for nested streams the allowed
//! type ranges. The even/odd rule for unknown types is applied by the object
//! parsers, which know which types they define, through [`Fields`].

use crate::encoding::{len_u64, read_bigsize, read_lp, write_bigsize, write_lp};
use crate::error::MalformedKind;

/// Highest type of the socket-field range, `0..=239`.
pub const SOCKET_MAX: u64 = 239;
/// First type of the signature range, `240..=1000`.
pub const SIGNATURE_MIN: u64 = 240;
/// Last type of the signature range, `240..=1000`.
pub const SIGNATURE_MAX: u64 = 1000;
/// First type reserved for future socket fields, `1001..=999_999_999`.
pub const FUTURE_MIN: u64 = 1001;
/// Last type reserved for future socket fields.
pub const FUTURE_MAX: u64 = 999_999_999;
/// First experimental type, `1_000_000_000..=1_999_999_999`.
pub const EXPERIMENTAL_MIN: u64 = 1_000_000_000;
/// Last experimental type.
pub const EXPERIMENTAL_MAX: u64 = 1_999_999_999;
/// First GREASE type, `3_000_000_001..=3_000_000_999`, odd only.
pub const GREASE_MIN: u64 = 3_000_000_001;
/// Last GREASE type.
pub const GREASE_MAX: u64 = 3_000_000_999;

/// The draft-00 type range a record type falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRange {
    /// `0..=239`: socket fields defined by draft-00.
    Socket,
    /// `240..=1000`: signature records, never covered by any signature or MAC.
    Signature,
    /// `1001..=999_999_999`: reserved for future socket fields.
    Future,
    /// `1_000_000_000..=1_999_999_999`: experimental, never registered.
    Experimental,
    /// `3_000_000_001..=3_000_000_999`, odd only: GREASE.
    Grease,
    /// Every other value.
    Reserved,
}

impl TypeRange {
    /// Classifies a record type.
    #[must_use]
    pub fn of(typ: u64) -> Self {
        match typ {
            0..=SOCKET_MAX => Self::Socket,
            SIGNATURE_MIN..=SIGNATURE_MAX => Self::Signature,
            FUTURE_MIN..=FUTURE_MAX => Self::Future,
            EXPERIMENTAL_MIN..=EXPERIMENTAL_MAX => Self::Experimental,
            GREASE_MIN..=GREASE_MAX if typ % 2 == 1 => Self::Grease,
            _ => Self::Reserved,
        }
    }
}

/// True for the signature range `240..=1000`.
#[must_use]
pub fn is_signature_type(typ: u64) -> bool {
    (SIGNATURE_MIN..=SIGNATURE_MAX).contains(&typ)
}

/// True for a GREASE type: odd, in `3_000_000_001..=3_000_000_999`.
#[must_use]
pub fn is_grease_type(typ: u64) -> bool {
    TypeRange::of(typ) == TypeRange::Grease
}

/// Maps 16 bits of caller-supplied randomness to a GREASE type.
///
/// Senders SHOULD add one GREASE record of random odd type and random short
/// value to every Offer and Credential (draft-00 section 2). This crate has
/// no RNG; the caller supplies the randomness.
#[must_use]
pub fn grease_type(seed: u16) -> u64 {
    // 500 odd values: 3_000_000_001, 3_000_000_003, ..., 3_000_000_999.
    GREASE_MIN + 2 * (u64::from(seed) % 500)
}

/// Whether a stream is a top-level socket stream or a nested one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// A top-level socket stream: every type is allowed by the framing; the
    /// even/odd rule decides what unknown types mean.
    TopLevel,
    /// A nested stream, such as a pay entry. Draft-00 section 2: nested
    /// streams use only `0..=239`, the experimental range and GREASE. A type
    /// outside those is MALFORMED.
    Nested,
}

/// An owned TLV stream: records with strictly increasing types.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TlvStream {
    records: Vec<(u64, Vec<u8>)>,
}

impl TlvStream {
    /// An empty stream.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a record. Its type must be greater than every type already in
    /// the stream.
    pub fn push(&mut self, typ: u64, value: impl Into<Vec<u8>>) -> Result<(), MalformedKind> {
        if let Some(&(prev, _)) = self.records.last()
            && typ <= prev
        {
            return Err(MalformedKind::TypeOrder { prev, typ });
        }
        self.records.push((typ, value.into()));
        Ok(())
    }

    /// Inserts a record at its place in type order. A duplicate type is an
    /// error.
    pub fn insert(&mut self, typ: u64, value: impl Into<Vec<u8>>) -> Result<(), MalformedKind> {
        match self.records.binary_search_by_key(&typ, |(t, _)| *t) {
            Ok(_) => Err(MalformedKind::TypeOrder { prev: typ, typ }),
            Err(at) => {
                self.records.insert(at, (typ, value.into()));
                Ok(())
            }
        }
    }

    /// Builds a stream from records in any order. Duplicate types are an
    /// error.
    pub fn from_records(
        records: impl IntoIterator<Item = (u64, Vec<u8>)>,
    ) -> Result<Self, MalformedKind> {
        let mut s = Self::new();
        for (t, v) in records {
            s.insert(t, v)?;
        }
        Ok(s)
    }

    /// The records, in type order.
    #[must_use]
    pub fn records(&self) -> &[(u64, Vec<u8>)] {
        &self.records
    }

    /// The value of record `typ`, if present.
    #[must_use]
    pub fn get(&self, typ: u64) -> Option<&[u8]> {
        self.records
            .binary_search_by_key(&typ, |(t, _)| *t)
            .ok()
            .map(|i| self.records[i].1.as_slice())
    }

    /// True when the stream has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serializes the stream.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (t, v) in &self.records {
            write_record(&mut out, *t, v);
        }
        out
    }

    /// Serializes every record outside the signature range `240..=1000` and
    /// not listed in `exclude`, in stream order.
    ///
    /// This is `S` of draft-00 4.2 (with `exclude` empty), `S₀` (with
    /// `exclude = [26]`, `native`) and the input of the Response ack (8.1).
    #[must_use]
    pub fn signed_bytes(&self, exclude: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        for (t, v) in &self.records {
            if !is_signature_type(*t) && !exclude.contains(t) {
                write_record(&mut out, *t, v);
            }
        }
        out
    }

    /// Parses a stream that fills all of `buf`.
    ///
    /// Enforces minimal BigSize, framing, strictly increasing types, and for
    /// [`StreamKind::Nested`] the allowed type ranges.
    pub fn parse(buf: &[u8], kind: StreamKind) -> Result<Self, MalformedKind> {
        let mut records = Vec::new();
        let mut i = 0usize;
        let mut prev: Option<u64> = None;
        while i < buf.len() {
            let (typ, a) = read_bigsize(buf.get(i..).ok_or(MalformedKind::Truncated)?)?;
            let j = i + a;
            let (len, b) = read_bigsize(buf.get(j..).ok_or(MalformedKind::Truncated)?)?;
            if let Some(p) = prev
                && typ <= p
            {
                return Err(MalformedKind::TypeOrder { prev: p, typ });
            }
            if kind == StreamKind::Nested && !nested_type_allowed(typ) {
                return Err(MalformedKind::TypeNotAllowed(typ));
            }
            let len = usize::try_from(len).map_err(|_| MalformedKind::Truncated)?;
            let k = j + b;
            let end = k.checked_add(len).ok_or(MalformedKind::Truncated)?;
            let value = buf.get(k..end).ok_or(MalformedKind::Truncated)?;
            records.push((typ, value.to_vec()));
            prev = Some(typ);
            i = end;
        }
        Ok(Self { records })
    }
}

/// Appends one record `BigSize(type) ‖ BigSize(length) ‖ value` to `out`.
pub fn write_record(out: &mut Vec<u8>, typ: u64, value: &[u8]) {
    write_bigsize(out, typ);
    write_bigsize(out, len_u64(value.len()));
    out.extend_from_slice(value);
}

/// The type ranges a nested stream may use: `0..=239`, experimental, GREASE.
#[must_use]
pub fn nested_type_allowed(typ: u64) -> bool {
    matches!(
        TypeRange::of(typ),
        TypeRange::Socket | TypeRange::Experimental | TypeRange::Grease
    )
}

/// Serializes an entry list: `lp(stream₁) ‖ lp(stream₂) ‖ …`.
#[must_use]
pub fn entry_list<S: AsRef<[u8]>>(streams: &[S]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in streams {
        write_lp(&mut out, s.as_ref());
    }
    out
}

/// Splits an entry list into its items. The items are not parsed.
pub fn parse_entry_list(buf: &[u8]) -> Result<Vec<&[u8]>, MalformedKind> {
    let mut out = Vec::new();
    let mut rest = buf;
    while !rest.is_empty() {
        let (item, used) = read_lp(rest)?;
        out.push(item);
        rest = rest.get(used..).ok_or(MalformedKind::Truncated)?;
    }
    Ok(out)
}

/// Field access over a parsed stream that applies the even/odd rule.
///
/// An object parser takes each type it defines, then calls
/// [`Fields::finish`], which rejects any remaining even type as MALFORMED and
/// returns the remaining odd records, which the receiver ignores but which a
/// signature still covers.
#[derive(Debug)]
pub struct Fields<'a> {
    stream: &'a TlvStream,
    taken: Vec<bool>,
}

impl<'a> Fields<'a> {
    /// Starts field access over `stream`.
    #[must_use]
    pub fn new(stream: &'a TlvStream) -> Self {
        Self { stream, taken: vec![false; stream.records.len()] }
    }

    /// Takes record `typ`, if present.
    pub fn take(&mut self, typ: u64) -> Option<&'a [u8]> {
        let i = self.stream.records.binary_search_by_key(&typ, |(t, _)| *t).ok()?;
        self.taken[i] = true;
        Some(self.stream.records[i].1.as_slice())
    }

    /// Takes a required record.
    pub fn required(&mut self, typ: u64) -> Result<&'a [u8], MalformedKind> {
        self.take(typ).ok_or(MalformedKind::MissingRecord(typ))
    }

    /// Takes an optional `tu64` record.
    pub fn tu64(&mut self, typ: u64) -> Result<Option<u64>, MalformedKind> {
        self.take(typ).map(|v| crate::encoding::read_tu64(v, typ)).transpose()
    }

    /// Takes a required `tu64` record.
    pub fn required_tu64(&mut self, typ: u64) -> Result<u64, MalformedKind> {
        crate::encoding::read_tu64(self.required(typ)?, typ)
    }

    /// Takes a flag: absent is false, present with an empty value is true,
    /// and a non-empty value is MALFORMED.
    pub fn flag(&mut self, typ: u64) -> Result<bool, MalformedKind> {
        match self.take(typ) {
            None => Ok(false),
            Some([]) => Ok(true),
            Some(_) => Err(MalformedKind::FlagNotEmpty(typ)),
        }
    }

    /// Takes an optional UTF-8 record.
    pub fn utf8(&mut self, typ: u64) -> Result<Option<String>, MalformedKind> {
        self.take(typ).map(|v| utf8(v, typ)).transpose()
    }

    /// Takes a required UTF-8 record.
    pub fn required_utf8(&mut self, typ: u64) -> Result<String, MalformedKind> {
        utf8(self.required(typ)?, typ)
    }

    /// Takes an optional fixed-length record.
    pub fn fixed<const N: usize>(&mut self, typ: u64) -> Result<Option<[u8; N]>, MalformedKind> {
        self.take(typ).map(|v| fixed::<N>(v, typ)).transpose()
    }

    /// Takes a required fixed-length record.
    pub fn required_fixed<const N: usize>(&mut self, typ: u64) -> Result<[u8; N], MalformedKind> {
        fixed::<N>(self.required(typ)?, typ)
    }

    /// Applies the even/odd rule to every record not taken.
    ///
    /// An unknown even type is MALFORMED. Unknown odd records are returned,
    /// signature-range ones included.
    pub fn finish(self) -> Result<Vec<(u64, Vec<u8>)>, MalformedKind> {
        let mut unknown = Vec::new();
        for (i, (t, v)) in self.stream.records.iter().enumerate() {
            if self.taken[i] {
                continue;
            }
            if t % 2 == 0 {
                return Err(MalformedKind::UnknownEvenType(*t));
            }
            unknown.push((*t, v.clone()));
        }
        Ok(unknown)
    }
}

/// Decodes a UTF-8 record value.
pub fn utf8(v: &[u8], typ: u64) -> Result<String, MalformedKind> {
    String::from_utf8(v.to_vec()).map_err(|_| MalformedKind::NotUtf8(typ))
}

/// Decodes a fixed-length record value.
pub fn fixed<const N: usize>(v: &[u8], typ: u64) -> Result<[u8; N], MalformedKind> {
    <[u8; N]>::try_from(v).map_err(|_| MalformedKind::Length { typ, len: v.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(TypeRange::of(0), TypeRange::Socket);
        assert_eq!(TypeRange::of(239), TypeRange::Socket);
        assert_eq!(TypeRange::of(240), TypeRange::Signature);
        assert_eq!(TypeRange::of(1000), TypeRange::Signature);
        assert_eq!(TypeRange::of(1001), TypeRange::Future);
        assert_eq!(TypeRange::of(999_999_999), TypeRange::Future);
        assert_eq!(TypeRange::of(1_000_000_000), TypeRange::Experimental);
        assert_eq!(TypeRange::of(1_999_999_999), TypeRange::Experimental);
        assert_eq!(TypeRange::of(2_000_000_000), TypeRange::Reserved);
        assert_eq!(TypeRange::of(3_000_000_000), TypeRange::Reserved);
        assert_eq!(TypeRange::of(3_000_000_001), TypeRange::Grease);
        assert_eq!(TypeRange::of(3_000_000_002), TypeRange::Reserved);
        assert_eq!(TypeRange::of(3_000_000_999), TypeRange::Grease);
        assert_eq!(TypeRange::of(3_000_001_001), TypeRange::Reserved);
        assert_eq!(TypeRange::of(u64::MAX), TypeRange::Reserved);
        for seed in [0u16, 1, 499, 500, u16::MAX] {
            assert!(is_grease_type(grease_type(seed)));
        }
    }

    #[test]
    fn order_and_duplicates_rejected() {
        // types 2 then 0
        assert_eq!(
            TlvStream::parse(&[2, 0, 0, 0], StreamKind::TopLevel),
            Err(MalformedKind::TypeOrder { prev: 2, typ: 0 })
        );
        // duplicate type 2
        assert_eq!(
            TlvStream::parse(&[2, 0, 2, 0], StreamKind::TopLevel),
            Err(MalformedKind::TypeOrder { prev: 2, typ: 2 })
        );
        // non-minimal type
        assert_eq!(
            TlvStream::parse(&[0xfd, 0, 1, 0], StreamKind::TopLevel),
            Err(MalformedKind::NonMinimalBigSize)
        );
        // truncated value
        assert_eq!(TlvStream::parse(&[0, 2, 1], StreamKind::TopLevel), Err(MalformedKind::Truncated));
    }

    #[test]
    fn nested_ranges_enforced() {
        let mut s = TlvStream::new();
        s.push(240, vec![]).unwrap();
        let b = s.to_bytes();
        assert!(TlvStream::parse(&b, StreamKind::TopLevel).is_ok());
        assert_eq!(TlvStream::parse(&b, StreamKind::Nested), Err(MalformedKind::TypeNotAllowed(240)));
    }

    #[test]
    fn even_odd_rule() {
        let s = TlvStream::from_records([(0, vec![1]), (3, vec![]), (4, vec![])]).unwrap();
        let mut f = Fields::new(&s);
        f.take(0);
        assert_eq!(f.finish(), Err(MalformedKind::UnknownEvenType(4)));
        let mut f = Fields::new(&s);
        f.take(0);
        f.take(4);
        assert_eq!(f.finish(), Ok(vec![(3, vec![])]));
    }

    #[test]
    fn entry_lists() {
        let l = entry_list(&[b"ab".as_slice(), b"", b"c"]);
        assert_eq!(l, b"\x02ab\x00\x01c");
        assert_eq!(parse_entry_list(&l).unwrap(), vec![&b"ab"[..], b"", b"c"]);
        assert!(parse_entry_list(b"\x05ab").is_err());
        assert!(parse_entry_list(b"").unwrap().is_empty());
    }
}
