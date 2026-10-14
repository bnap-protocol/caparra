//! Loading key material: file permissions, the key file format, keysets
//! against the notes draft's vectors, and secrets kept out of every `Debug`
//! and error message.

use std::sync::Arc;

use bnap_core::hash::{Scope, sha256};
use bnap_core::manifest::KeyUse;
use bnap_core::offer::{OfferFields, PayEntry};
use bnap_core::response::Status;
use bnap_core::schnorr::Key;
use bnap_core::sign::UnsignedOffer;
use bnap_core::test_support::block_on;
use bnap_plug::{BlindedOutput, ChangeLimit, KeysetId, Point, Signer, SignerError};
use bnap_signer_file::keyfile::{self, MAX_KEY_FILE};
use bnap_signer_file::keyset::KeysetError;
use bnap_signer_file::{FileSigner, HeldKey, LoadError, NotesKeyset};

const OFFER_SECRET: &str = "bda3aea2a2aae7f8373847fa9ea2937fa8befc1da0d83a3071da3c458f13a6b6";
const RECEIPT_SECRET: &str = "03cd229c5c5926c3fba5ce72f70d3ac6d632506b9a461c12201b4e8849d9b494";
const SEED: &str = "4a7627233f8531b73f6cd8d2b708fede917ebf29f7a518537cc7e0ac5a77c998";

fn key_file() -> String {
    format!(
        "[[key]]\nuse = \"offer\"\nsecret = \"{OFFER_SECRET}\"\nnot_after = 2000000000\n\n\
         [[key]]\nuse = \"receipt\"\nsecret = \"{RECEIPT_SECRET}\"\n\n\
         [[keyset]]\nseed = \"{SEED}\"\nindex = 0\ninput_fee_ppk = 100\n\
         final_expiry = 1900000000\norders = 16\n"
    )
}

/// Every secret of [`key_file`], in both cases.
fn secrets() -> Vec<String> {
    [OFFER_SECRET, RECEIPT_SECRET, SEED]
        .iter()
        .flat_map(|s| [s.to_string(), s.to_uppercase(), s[..16].to_string()])
        .collect()
}

fn assert_no_secret(text: &str) {
    for s in secrets() {
        assert!(!text.contains(&s), "a secret leaked into: {text}");
    }
}

// ----------------------------------------------------------- permissions

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    fn write(dir: &tempfile::TempDir, mode: u32) -> PathBuf {
        let path = dir.path().join("keys.toml");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, key_file()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_key_file_others_can_access_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [
            0o644, 0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o660, 0o666, 0o777,
        ] {
            let path = write(&dir, mode);
            let err = FileSigner::load(&path).unwrap_err();
            assert_eq!(
                err,
                LoadError::Permissions {
                    path: path.clone(),
                    mode
                },
                "mode {mode:o}"
            );
            assert!(err.to_string().contains("chmod 600"));
            assert_no_secret(&format!("{err} {err:?}"));
        }
    }

    #[test]
    fn a_key_file_only_its_owner_can_access_loads() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o400, 0o700] {
            let path = write(&dir, mode);
            let signer = FileSigner::load(&path).unwrap();
            assert_eq!(signer.keys().len(), 2);
            assert_eq!(signer.keysets().len(), 1);
        }
    }

    #[test]
    fn a_symbolic_link_or_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, 0o600);
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            FileSigner::load(&link).unwrap_err(),
            LoadError::Symlink { path: link }
        );
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            FileSigner::load(&sub).unwrap_err(),
            LoadError::NotAFile { path: sub }
        );
    }

    #[test]
    fn a_missing_or_oversized_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("none.toml");
        assert!(matches!(
            FileSigner::load(&missing).unwrap_err(),
            LoadError::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            }
        ));
        let big = dir.path().join("big.toml");
        let mut text = key_file();
        text.push_str(&"#".repeat(usize::try_from(MAX_KEY_FILE).unwrap()));
        std::fs::write(&big, text).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            FileSigner::load(&big).unwrap_err(),
            LoadError::TooLarge { .. }
        ));
    }

    #[test]
    fn read_returns_the_text_of_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, 0o600);
        assert_eq!(*keyfile::read(&path).unwrap(), key_file());
    }
}

// ------------------------------------------------------------ the format

#[test]
fn the_key_file_gives_keys_for_their_uses_and_keysets() {
    let signer = FileSigner::from_toml(&key_file()).unwrap();
    let keys = signer.keys();
    assert_eq!(*keys[0].key_use(), KeyUse::Offer);
    assert_eq!(keys[0].not_after(), Some(2_000_000_000));
    // The draft-00 test offer key (section 14).
    assert_eq!(
        keys[0].public_key().to_hex(),
        "b28dad5f717c5144bdb0aa6db94bb6c79afa9b8bd9bc84825a2c1baafe64add9"
    );
    assert_eq!(*keys[1].key_use(), KeyUse::Receipt);
    let ks = &signer.keysets()[0];
    assert_eq!(
        (ks.input_fee_ppk(), ks.final_expiry(), ks.active()),
        (100, 1_900_000_000, true)
    );
    assert_eq!(ks.unit(), "sat");
    assert_eq!(
        ks.public_keys().keys().copied().collect::<Vec<_>>(),
        (0..16).map(|i| 1u64 << i).collect::<Vec<_>>()
    );
    assert_eq!(ks.id()[0], 0x01);
    assert!(signer.keyset(&ks.id()).is_some());
}

/// A key file's text and the error it must give.
type Case = (String, fn(&LoadError) -> bool);

/// One case per way a key file can be wrong, most with a secret where the
/// error could quote it.
#[allow(clippy::too_many_lines)]
fn malformed_cases() -> Vec<Case> {
    vec![
        // A TOML syntax error on the line that holds the secret.
        (
            format!("[[key]]\nuse = \"offer\"\nsecret = \"{OFFER_SECRET}\" oops\n"),
            |e| matches!(e, LoadError::Syntax { line: 3, .. }),
        ),
        // A secret where a number belongs: serde would quote it.
        (
            format!("[[keyset]]\nseed = \"{SEED}\"\nindex = \"{SEED}\"\nfinal_expiry = 1\n"),
            |e| matches!(e, LoadError::Syntax { line: 3, .. }),
        ),
        // A secret as a field name.
        (
            format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{OFFER_SECRET}\"\nk{RECEIPT_SECRET} = 1\n"
            ),
            |e| matches!(e, LoadError::Syntax { line: 4, .. }),
        ),
        // A secret in the use field.
        (
            format!("[[key]]\nuse = \"{SEED}\"\nsecret = \"{OFFER_SECRET}\"\n"),
            |e| matches!(e, LoadError::Field { field: "use", .. }),
        ),
        // A secret one character short, and one that is not hex.
        (
            format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{}\"\n",
                &OFFER_SECRET[1..]
            ),
            |e| {
                matches!(
                    e,
                    LoadError::Field {
                        field: "secret",
                        index: 1,
                        ..
                    }
                )
            },
        ),
        (
            format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{}z\"\n",
                &OFFER_SECRET[1..]
            ),
            |e| {
                matches!(
                    e,
                    LoadError::Field {
                        field: "secret",
                        ..
                    }
                )
            },
        ),
        (
            format!(
                "[[keyset]]\nseed = \"{}\"\nindex = 0\nfinal_expiry = 1\n",
                &SEED[1..]
            ),
            |e| matches!(e, LoadError::Field { field: "seed", .. }),
        ),
        // A seed below BIP-32's 16 bytes.
        (
            format!(
                "[[keyset]]\nseed = \"{}\"\nindex = 0\nfinal_expiry = 1\n",
                &SEED[..30]
            ),
            |e| {
                matches!(
                    e,
                    LoadError::Keyset {
                        error: KeysetError::SeedLength(15),
                        ..
                    }
                )
            },
        ),
        // The zero key.
        (
            format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{}\"\n",
                "0".repeat(64)
            ),
            |e| matches!(e, LoadError::Key { .. }),
        ),
        // One key for two uses.
        (
            format!(
                "[[key]]\nuse = \"offer\"\nsecret = \"{OFFER_SECRET}\"\n\
                 [[key]]\nuse = \"receipt\"\nsecret = \"{OFFER_SECRET}\"\n"
            ),
            |e| matches!(e, LoadError::DuplicateKey { index: 2 }),
        ),
        // One keyset twice.
        (
            format!(
                "[[keyset]]\nseed = \"{SEED}\"\nindex = 3\nfinal_expiry = 9\n\
                 [[keyset]]\nseed = \"{SEED}\"\nindex = 3\nfinal_expiry = 9\n"
            ),
            |e| matches!(e, LoadError::DuplicateKeyset { index: 2 }),
        ),
        // No final expiry, and orders out of range.
        (
            format!("[[keyset]]\nseed = \"{SEED}\"\nindex = 0\nfinal_expiry = 0\n"),
            |e| {
                matches!(
                    e,
                    LoadError::Keyset {
                        error: KeysetError::FinalExpiry,
                        ..
                    }
                )
            },
        ),
        (
            format!("[[keyset]]\nseed = \"{SEED}\"\nindex = 0\nfinal_expiry = 9\norders = 65\n"),
            |e| {
                matches!(
                    e,
                    LoadError::Keyset {
                        error: KeysetError::Orders(65),
                        ..
                    }
                )
            },
        ),
        // Nothing at all.
        ("# empty\n".to_string(), |e| matches!(e, LoadError::Empty)),
    ]
}

#[test]
fn malformed_key_files_are_refused_without_quoting_them() {
    for (text, expected) in malformed_cases() {
        let err = FileSigner::from_toml(&text).unwrap_err();
        assert!(expected(&err), "unexpected error {err:?} for a case");
        assert_no_secret(&format!("{err} {err:?}"));
    }
}

#[test]
fn no_secret_appears_in_debug_output() {
    let signer = FileSigner::from_toml(&key_file()).unwrap();
    let text = format!("{signer:?} {signer:#?}");
    assert_no_secret(&text);
    assert!(text.contains("b28dad5f717c5144"), "the public key is shown");
    let parsed = keyfile::parse(&key_file()).unwrap();
    assert_no_secret(&format!("{parsed:?}"));
    for k in signer.keys() {
        assert_no_secret(&format!("{k:?}"));
    }
    for ks in signer.keysets() {
        assert_no_secret(&format!("{ks:?} {ks:#?}"));
    }
    let held = HeldKey::new(KeyUse::Offer, &sha256(b"bnap test offer key"), None).unwrap();
    assert_no_secret(&format!("{held:?}"));
}

// ------------------------------------------------------------- keysets

/// The private key of amount `m` in the notes draft's test keyset `label`
/// (18.1): SHA-256 of `bnap notes test keyset <label> <m>`.
fn draft_keyset(label: &str, fee: u64, final_expiry: u64) -> NotesKeyset {
    let keys: Vec<(u64, [u8; 32])> = (0..16)
        .map(|i| {
            let m = 1u64 << i;
            (
                m,
                sha256(format!("bnap notes test keyset {label} {m}").as_bytes()),
            )
        })
        .collect();
    NotesKeyset::from_secret_keys(&keys, fee, final_expiry, true).unwrap()
}

#[test]
fn keyset_ids_match_the_notes_draft_vectors() {
    // Notes draft 18.1: keysets A, B and C.
    for (label, fee, final_expiry, id) in [
        (
            "A",
            100,
            1_830_000_000,
            "011decbc482233faf1b58395ddb55c465e3bf6d8fa1c5a5b17219f7d5883b112a7",
        ),
        (
            "B",
            0,
            1_800_000_000,
            "014423cf221427bb65863007387bbc9b74963e47b24c3ec3a25ddd673e9ed6e898",
        ),
        (
            "C",
            2000,
            1_830_000_000,
            "01fd899e9c7a7f4940273d43ec1dcd3bafc9fe4fe80ba292b9f021ab09b5aecf46",
        ),
    ] {
        assert_eq!(
            hex::encode(draft_keyset(label, fee, final_expiry).id()),
            id,
            "keyset {label}"
        );
    }
}

#[test]
fn derived_keysets_are_deterministic_and_distinct() {
    let seed = hex::decode(SEED).unwrap();
    let derive = |seed: &[u8], index, orders, fee, expiry| {
        NotesKeyset::derive(seed, index, orders, fee, expiry, true).unwrap()
    };
    let a = derive(&seed, 0, 16, 100, 1_900_000_000);
    assert_eq!(a.id(), derive(&seed, 0, 16, 100, 1_900_000_000).id());
    assert_eq!(
        a.public_keys(),
        derive(&seed, 0, 16, 100, 1_900_000_000).public_keys()
    );
    // The keys depend on seed and index only; the ID on every parameter.
    let fee = derive(&seed, 0, 16, 0, 1_900_000_000);
    assert_eq!(a.public_keys(), fee.public_keys());
    assert_ne!(a.id(), fee.id());
    assert_ne!(a.id(), derive(&seed, 0, 16, 100, 1_900_000_001).id());
    assert_ne!(
        a.public_keys(),
        derive(&seed, 1, 16, 100, 1_900_000_000).public_keys()
    );
    let mut other = seed.clone();
    other[0] ^= 1;
    assert_ne!(
        a.public_keys(),
        derive(&other, 0, 16, 100, 1_900_000_000).public_keys()
    );
    let longer = derive(&seed, 0, 32, 100, 1_900_000_000);
    assert_ne!(a.id(), longer.id());
    assert_eq!(longer.public_key(1), a.public_key(1));
    assert_eq!(longer.public_keys().len(), 32);
    // Pinned so a change of derivation path cannot pass unnoticed. The key
    // was checked with an independent BIP-32 implementation at
    // m/1651401072'/0'/0'/0' (0x626e6170 = 1651401072).
    assert_eq!(
        hex::encode(a.public_key(1).unwrap()),
        "02aec64b15c90cbf0de67b6a74a088a28b66d4dfe5c19b3974da27cdf69b9fa71e"
    );
    assert_eq!(
        hex::encode(a.id()),
        "015535ba766a6dbf40bd4977cb3ed4dec0e34722184643765f8c2fa7da0eaf40e3"
    );
    assert!(matches!(
        NotesKeyset::derive(&seed[..15], 0, 16, 0, 1, true),
        Err(KeysetError::SeedLength(15))
    ));
    assert!(matches!(
        NotesKeyset::derive(&[7; 65], 0, 16, 0, 1, true),
        Err(KeysetError::SeedLength(65))
    ));
    assert!(matches!(
        NotesKeyset::derive(&seed, 0, 0, 0, 1, true),
        Err(KeysetError::Orders(0))
    ));
}

#[test]
fn explicit_keysets_refuse_bad_amounts_and_keys() {
    let k = sha256(b"k");
    assert_eq!(
        NotesKeyset::from_secret_keys(&[(3, k)], 0, 1, true).unwrap_err(),
        KeysetError::Amount(3)
    );
    assert_eq!(
        NotesKeyset::from_secret_keys(&[(2, k), (2, k)], 0, 1, true).unwrap_err(),
        KeysetError::Amount(2)
    );
    assert_eq!(
        NotesKeyset::from_secret_keys(&[(2, [0; 32])], 0, 1, true).unwrap_err(),
        KeysetError::InvalidSecret(2)
    );
    assert_eq!(
        NotesKeyset::from_secret_keys(&[], 0, 1, true).unwrap_err(),
        KeysetError::NoKeys
    );
}

// --------------------------------------------------------------- clocks

fn offer_message(key: Key) -> UnsignedOffer {
    let mut f = OfferFields::new(Scope([1; 32]), 1_999_999_000, key, [0; 16]);
    f.pay.push(PayEntry::new("bnap:notes", 21, "sat"));
    UnsignedOffer::new(&f, Some(&[7; 32])).unwrap()
}

#[test]
fn a_key_past_its_not_after_signs_nothing() {
    let at = |now: u64| {
        FileSigner::from_toml(&key_file())
            .unwrap()
            .with_clock(move || now)
    };
    let key = at(0).keys()[0].public_key();
    let unsigned = offer_message(key);
    let signer = at(2_000_000_000);
    block_on(signer.schnorr(unsigned.message())).unwrap();
    let signer = at(2_000_000_001);
    assert!(matches!(
        block_on(signer.schnorr(unsigned.message())),
        Err(SignerError::Refused(_))
    ));
}

#[test]
fn a_keyset_past_its_final_expiry_accepts_and_signs_nothing() {
    let final_expiry = 1_900_000_000;
    let at = |now: u64| -> Arc<FileSigner> {
        Arc::new(
            FileSigner::from_toml(&key_file())
                .unwrap()
                .with_clock(move || now),
        )
    };
    let signer = at(final_expiry);
    let id = KeysetId(signer.keysets()[0].id().to_vec());
    let secret = b"a note".to_vec();
    let (b, r) = cashu::dhke::blind_message(&secret, None).unwrap();
    let limit = ChangeLimit {
        replay_key: bnap_core::hash::ReplayKey([4; 32]),
        status: Status::Ok,
        unit: "sat".into(),
        cap: 8,
        keep_until: u64::MAX,
    };
    let out = BlindedOutput {
        amount: 8,
        blinded: Point(b.to_bytes()),
    };
    let sig = block_on(signer.blind_sign(&id, &[out], &limit)).unwrap();
    let a = cashu::PublicKey::from_slice(&signer.keysets()[0].public_key(8).unwrap()).unwrap();
    let c = cashu::dhke::unblind_message(
        &cashu::PublicKey::from_slice(&sig[0].signature.0).unwrap(),
        &r,
        &a,
    )
    .unwrap();
    let c = Point(c.to_bytes());
    // Inputs verify until the final expiry plus the 60 s skew.
    for (now, accepted) in [(final_expiry + 60, true), (final_expiry + 61, false)] {
        let got = block_on(at(now).verify_unblinded(&id, "sat", 8, &secret, &c)).unwrap();
        assert_eq!(
            got.is_some(),
            accepted,
            "at final_expiry + {}",
            now - final_expiry
        );
    }
    // Outputs are signed only until the final expiry.
    assert!(matches!(
        block_on(at(final_expiry + 1).blind_sign(&id, &[out], &limit)),
        Err(SignerError::Refused(_))
    ));
}
