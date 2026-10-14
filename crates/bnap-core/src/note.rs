//! The operator's notes: the NUT-00 map from a note's secret to its point.
//!
//! A note (`schemes/bnap-notes.md`, Cashu NUT-00) is a secret and an
//! unblinded signature `C = k·Y` on the point `Y = hash_to_curve(secret)`,
//! where `k` is the issuer's key for the note's amount. `Y` is always
//! derived from the secret, never taken from a credential: from one note
//! `(Y, C)`, every multiple `(m·Y, m·C)` also satisfies `C = k·Y`, so a check
//! on a `Y` the caller names would let one note pass as many. The signer
//! computes `Y` itself (`bnap_plug::Signer::verify_unblinded`), and the
//! commit consumes the note once under `H_"bnap/note"(Y)`
//! ([`crate::pricing::note_id`]).

use bitcoin::secp256k1::PublicKey;

use crate::hash::sha256;

/// NUT-00's domain separator for [`hash_to_curve`].
pub const DOMAIN_SEPARATOR: &[u8] = b"Secp256k1_HashToCurve_Cashu_";

/// NUT-00 `hash_to_curve`: the point `Y` of a note whose secret is
/// `secret` (the UTF-8 bytes of the secret string), as a 33-byte compressed
/// point with an even `y` coordinate.
///
/// `msg = SHA256(DOMAIN_SEPARATOR ‖ secret)`; for `counter` from 0, the first
/// `SHA256(msg ‖ counter as 4 bytes little endian)` that is the `x`
/// coordinate of a curve point gives `Y = 0x02 ‖ x`. `None` when no counter
/// below 2¹⁶ gives one, which happens with probability about 2⁻⁶⁵⁵³⁶: such a
/// secret names no note.
#[must_use]
pub fn hash_to_curve(secret: &[u8]) -> Option<[u8; 33]> {
    let msg = sha256(&[DOMAIN_SEPARATOR, secret].concat());
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(&msg);
    for counter in 0..(1u32 << 16) {
        buf[32..].copy_from_slice(&counter.to_le_bytes());
        let mut point = [0u8; 33];
        point[0] = 0x02;
        point[1..].copy_from_slice(&sha256(&buf));
        if PublicKey::from_slice(&point).is_ok() {
            return Some(point);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_curve_matches_the_nut_00_vectors() {
        // NUT-00 test vectors; the secret is the 32 bytes shown in hex. The
        // third one needs a few counters before it finds a point.
        for (secret, y) in [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f",
            ),
        ] {
            let got = hash_to_curve(&hex::decode(secret).unwrap()).unwrap();
            assert_eq!(hex::encode(got), y);
        }
    }

    #[test]
    fn different_secrets_map_to_different_points() {
        let a = hash_to_curve(b"a").unwrap();
        let b = hash_to_curve(b"b").unwrap();
        assert_ne!(a, b);
        assert_eq!(hash_to_curve(b"a"), Some(a), "deterministic");
    }
}
