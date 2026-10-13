//! Primitive encodings of draft-00 section 2: BigSize, `tu64` and `lp(x)`.
//!
//! Every reader here enforces the canonical form. A non-minimal BigSize or
//! `tu64` is MALFORMED, so one value has exactly one encoding and a signature
//! over the bytes is a signature over the value.

use crate::error::MalformedKind;

/// Largest value a one-byte BigSize holds.
const BIGSIZE_U8_MAX: u64 = 0xfc;

/// Appends the BigSize encoding of `n` (BOLT 1) to `out`.
///
/// The encoding is always minimal: one byte below `0xfd`, then `fd` and two
/// bytes, `fe` and four bytes, or `ff` and eight bytes, all big-endian.
pub fn write_bigsize(out: &mut Vec<u8>, n: u64) {
    if n <= BIGSIZE_U8_MAX {
        // Lossless: the branch bounds `n` below 0xfd.
        out.push(n.to_be_bytes()[7]);
    } else if let Ok(v) = u16::try_from(n) {
        out.push(0xfd);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(n) {
        out.push(0xfe);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Returns the BigSize encoding of `n`.
#[must_use]
pub fn bigsize(n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    write_bigsize(&mut out, n);
    out
}

/// Number of bytes the BigSize encoding of `n` takes.
#[must_use]
pub fn bigsize_len(n: u64) -> usize {
    if n <= BIGSIZE_U8_MAX {
        1
    } else if n <= u64::from(u16::MAX) {
        3
    } else if n <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

/// Reads one BigSize from the front of `buf`.
///
/// Returns the value and the number of bytes consumed. A truncated or
/// non-minimal encoding is an error.
pub fn read_bigsize(buf: &[u8]) -> Result<(u64, usize), MalformedKind> {
    let (&first, rest) = buf.split_first().ok_or(MalformedKind::Truncated)?;
    match first {
        0xfd => {
            let b: [u8; 2] = take_array(rest)?;
            let v = u64::from(u16::from_be_bytes(b));
            if v <= BIGSIZE_U8_MAX {
                return Err(MalformedKind::NonMinimalBigSize);
            }
            Ok((v, 3))
        }
        0xfe => {
            let b: [u8; 4] = take_array(rest)?;
            let v = u64::from(u32::from_be_bytes(b));
            if v <= u64::from(u16::MAX) {
                return Err(MalformedKind::NonMinimalBigSize);
            }
            Ok((v, 5))
        }
        0xff => {
            let b: [u8; 8] = take_array(rest)?;
            let v = u64::from_be_bytes(b);
            if v <= u64::from(u32::MAX) {
                return Err(MalformedKind::NonMinimalBigSize);
            }
            Ok((v, 9))
        }
        small => Ok((u64::from(small), 1)),
    }
}

fn take_array<const N: usize>(buf: &[u8]) -> Result<[u8; N], MalformedKind> {
    buf.get(..N)
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or(MalformedKind::Truncated)
}

/// Returns the `tu64` encoding of `n`: big-endian with leading zero bytes
/// removed. Zero is the empty string.
#[must_use]
pub fn tu64(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    bytes[skip..].to_vec()
}

/// Decodes a `tu64` value that fills all of `value`.
///
/// More than eight bytes, or a leading zero byte, is an error. `typ` names
/// the record for the error.
pub fn read_tu64(value: &[u8], typ: u64) -> Result<u64, MalformedKind> {
    if value.len() > 8 {
        return Err(MalformedKind::Tu64Overflow(typ));
    }
    if value.first() == Some(&0) {
        return Err(MalformedKind::NonMinimalTu64(typ));
    }
    Ok(value.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

/// Appends `lp(x) = BigSize(len(x)) ‖ x` to `out`.
pub fn write_lp(out: &mut Vec<u8>, x: &[u8]) {
    write_bigsize(out, len_u64(x.len()));
    out.extend_from_slice(x);
}

/// Returns `lp(x) = BigSize(len(x)) ‖ x`.
#[must_use]
pub fn lp(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(x.len() + 9);
    write_lp(&mut out, x);
    out
}

/// Reads one `lp(x)` from the front of `buf`.
///
/// Returns `x` and the number of bytes consumed.
pub fn read_lp(buf: &[u8]) -> Result<(&[u8], usize), MalformedKind> {
    let (n, used) = read_bigsize(buf)?;
    let n = usize::try_from(n).map_err(|_| MalformedKind::Truncated)?;
    let end = used.checked_add(n).ok_or(MalformedKind::Truncated)?;
    let x = buf.get(used..end).ok_or(MalformedKind::Truncated)?;
    Ok((x, end))
}

/// Converts a length to `u64`. Lengths of in-memory buffers always fit.
pub(crate) fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigsize_boundaries() {
        for (n, len) in [
            (0u64, 1),
            (0xfc, 1),
            (0xfd, 3),
            (0xffff, 3),
            (0x1_0000, 5),
            (0xffff_ffff, 5),
            (0x1_0000_0000, 9),
            (u64::MAX, 9),
        ] {
            let enc = bigsize(n);
            assert_eq!(enc.len(), len, "{n}");
            assert_eq!(bigsize_len(n), len);
            assert_eq!(read_bigsize(&enc), Ok((n, len)));
        }
    }

    #[test]
    fn bigsize_rejects_non_minimal() {
        for bad in [
            &[0xfd, 0x00, 0xfc][..],
            &[0xfd, 0x00, 0x00],
            &[0xfe, 0x00, 0x00, 0xff, 0xff],
            &[0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(read_bigsize(bad), Err(MalformedKind::NonMinimalBigSize));
        }
    }

    #[test]
    fn bigsize_rejects_truncation() {
        for bad in [&[][..], &[0xfd, 0x01], &[0xfe, 1, 2, 3], &[0xff, 1, 2, 3, 4, 5, 6, 7]] {
            assert_eq!(read_bigsize(bad), Err(MalformedKind::Truncated));
        }
    }

    #[test]
    fn tu64_rules() {
        assert_eq!(tu64(0), Vec::<u8>::new());
        assert_eq!(read_tu64(&[], 0), Ok(0));
        assert_eq!(read_tu64(&[0], 7), Err(MalformedKind::NonMinimalTu64(7)));
        assert_eq!(read_tu64(&[0, 1], 7), Err(MalformedKind::NonMinimalTu64(7)));
        assert_eq!(read_tu64(&[1; 9], 7), Err(MalformedKind::Tu64Overflow(7)));
        assert_eq!(read_tu64(&tu64(u64::MAX), 0), Ok(u64::MAX));
    }

    #[test]
    fn lp_roundtrip_and_truncation() {
        let enc = lp(b"abc");
        assert_eq!(enc, b"\x03abc");
        assert_eq!(read_lp(&enc), Ok((&b"abc"[..], 4)));
        assert_eq!(read_lp(b"\x04abc"), Err(MalformedKind::Truncated));
        assert_eq!(lp(b""), vec![0]);
    }
}
