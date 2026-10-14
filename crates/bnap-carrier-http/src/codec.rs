//! `b64u`: base64url without padding (RFC 4648 section 5), as draft-00
//! section 2 defines it.
//!
//! Decoding is strict: one encoding per byte string. Padding, characters
//! outside the alphabet, whitespace and non-zero trailing bits are refused,
//! so a field value has exactly one meaning.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `b64u(bytes)`.
#[must_use]
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of a `b64u` string, or `None` when it is not the one
/// canonical encoding of any byte string.
#[must_use]
pub fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    let v = URL_SAFE_NO_PAD.decode(s).ok()?;
    (URL_SAFE_NO_PAD.encode(&v) == s).then_some(v)
}

/// The length of `b64u` of `n` bytes: `ceil(4n / 3)`.
#[must_use]
pub const fn b64u_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_lengths() {
        for n in 0..40 {
            let v: Vec<u8> = (0..n).map(|i| u8::try_from(i * 7 % 256).unwrap()).collect();
            let s = b64u(&v);
            assert_eq!(s.len(), b64u_len(n));
            assert_eq!(b64u_decode(&s).unwrap(), v);
        }
        assert_eq!(b64u_len(9216), 12_288);
    }

    #[test]
    fn only_the_canonical_encoding_decodes() {
        assert_eq!(b64u_decode("AAEB").unwrap(), vec![0, 1, 1]);
        // Padding, the standard alphabet, whitespace and trailing bits.
        for bad in ["AAE=", "AA==", "+/8", "AA EB", "AAEC\n", "AB", "AAF"] {
            assert!(b64u_decode(bad).is_none(), "{bad:?} decoded");
        }
        // "AB" has non-zero trailing bits; "AA" is its canonical twin.
        assert_eq!(b64u_decode("AA").unwrap(), vec![0]);
    }
}
