//! The official BIP-340 test vectors (bitcoin/bips, `bip-0340/test-vectors.csv`,
//! BSD-2-Clause; see `tests/data/README.md`), run through this crate's
//! Schnorr wrappers.

use bnap_core::schnorr::{Key, Signature, SigningKey};

const CSV: &str = include_str!("data/bip340-test-vectors.csv");

fn arr<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).unwrap();
    <[u8; N]>::try_from(v.as_slice()).unwrap()
}

#[test]
fn official_bip340_vectors() {
    let mut checked = 0;
    let mut signed = 0;
    for line in CSV.lines().skip(1) {
        let cols: Vec<&str> = line.splitn(8, ',').collect();
        assert_eq!(cols.len(), 8, "{line}");
        let (index, sk, pk, aux, msg, sig, ok) = (cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6]);
        let msg = hex::decode(msg).unwrap();
        let Ok(msg) = <[u8; 32]>::try_from(msg.as_slice()) else {
            // Rows 15 to 18: messages that are not 32 bytes long; the
            // secp256k1 0.29 API takes 32-byte messages only.
            assert!(matches!(index, "15" | "16" | "17" | "18"), "row {index}");
            continue;
        };
        let key = Key(arr::<32>(pk));
        let sig = Signature(arr::<64>(sig));
        if !sk.is_empty() {
            let k = SigningKey::from_secret_bytes(&arr::<32>(sk)).unwrap();
            assert_eq!(k.public_key(), key, "row {index}: public key");
            assert_eq!(k.sign(&msg, &arr::<32>(aux)), sig, "row {index}: signature");
            signed += 1;
        }
        let expect = ok == "TRUE";
        assert_eq!(key.verify(&msg, &sig).is_ok(), expect, "row {index}: verification");
        checked += 1;
    }
    assert_eq!(checked, 15);
    assert_eq!(signed, 4);
}
