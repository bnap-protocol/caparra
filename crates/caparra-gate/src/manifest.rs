//! The manifest (draft-00 9): signed offline by the root key with
//! `caparra-gate manifest sign`, loaded and checked by the gate at start,
//! and served byte for byte at `/.well-known/bnap`.

use bnap_core::limits::{CLOCK_SKEW, Limits};
use bnap_core::manifest::{KeyUse, Manifest, ManifestKey, ManifestLimits, SignedManifest};
use bnap_core::schnorr::{Key, SigningKey};

use crate::config::{Config, RoutePlan};

/// Why a manifest was refused.
#[derive(Debug, thiserror::Error)]
#[error("manifest: {0}")]
pub struct ManifestCheckError(pub String);

fn bad(m: impl Into<String>) -> ManifestCheckError {
    ManifestCheckError(m.into())
}

/// A manifest the gate may serve, with what it takes from it.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The bytes as signed.
    pub bytes: Vec<u8>,
    /// The parsed document.
    pub manifest: Manifest,
    /// The socket limits it sets.
    pub limits: Limits,
    /// The offer key the gate signs offers with.
    pub offer_key: ManifestKey,
    /// The receipt key the gate signs receipts with.
    pub receipt_key: ManifestKey,
}

/// Checks a signed manifest against the configuration at `now`:
///
/// - `sig` verifies under its own `root`, and `root` is the configured pin
///   when one is set;
/// - `bnap` is 1, `origin` is the gate's, `carriers` lists `http`;
/// - it is not issued in the future or past `max_age` (60 s of skew),
///   and `max_age` is at most 30 days;
/// - `routes` are exactly the routes the configuration resolves to, so
///   what clients pin is what the gate enforces;
/// - its limits are usable and every offer lifetime fits the replay window;
/// - it lists an offer key and a receipt key that are live: the latest
///   `not_after` of each use, which must leave room for a whole offer.
pub fn check(
    bytes: &[u8],
    cfg: &Config,
    plans: &[RoutePlan],
    now: u64,
) -> Result<Loaded, ManifestCheckError> {
    let signed = SignedManifest::parse(bytes).map_err(|e| bad(e.to_string()))?;
    signed
        .verify()
        .map_err(|e| bad(format!("signature: {e}")))?;
    let m = signed.manifest().clone();
    if let Some(pin) = &cfg.manifest.root {
        let want = Key::from_hex(pin).map_err(|_| bad("manifest.root is not a hex key"))?;
        if m.root != want {
            return Err(bad("it is not signed by the configured root key"));
        }
    }
    if m.bnap != 1 {
        return Err(bad("bnap is not 1"));
    }
    if m.origin != cfg.gate.origin {
        return Err(bad(format!(
            "origin {:?} is not gate.origin {:?}",
            m.origin, cfg.gate.origin
        )));
    }
    if !m.carriers.iter().any(|c| c == "http") {
        return Err(bad("carriers does not list http"));
    }
    if m.max_age > 2_592_000 {
        return Err(bad("max_age is over 30 days"));
    }
    if m.issued > now + CLOCK_SKEW {
        return Err(bad("issued in the future"));
    }
    if now > m.issued + m.max_age + CLOCK_SKEW {
        return Err(bad("expired (issued + max_age is past): sign a new one"));
    }
    let want: Vec<_> = plans.iter().map(|p| p.manifest.clone()).collect();
    if m.routes != want {
        return Err(bad(
            "its routes differ from the configuration's: sign it again from this configuration",
        ));
    }
    let limits = Limits::from_manifest(&m.limits).map_err(|e| bad(e.to_string()))?;
    let longest = cfg
        .gate
        .offer_lifetime_s
        .max(cfg.gate.route_offer_lifetime_s);
    limits
        .check_offer_lifetime(longest)
        .map_err(|e| bad(e.to_string()))?;
    let pick = |u: KeyUse| {
        m.keys
            .iter()
            .filter(|k| k.key_use == u)
            .max_by_key(|k| k.not_after)
            .cloned()
    };
    let offer_key = pick(KeyUse::Offer).ok_or_else(|| bad("it lists no offer key"))?;
    let receipt_key = pick(KeyUse::Receipt).ok_or_else(|| bad("it lists no receipt key"))?;
    if offer_key.not_after < now + longest {
        return Err(bad(
            "every offer key expires before an offer issued now would: rotate the keys",
        ));
    }
    if receipt_key.not_after < now + limits.pending_timeout {
        return Err(bad(
            "every receipt key expires within pending_timeout: rotate the keys",
        ));
    }
    Ok(Loaded {
        bytes: bytes.to_vec(),
        manifest: m,
        limits,
        offer_key,
        receipt_key,
    })
}

/// What `caparra-gate manifest sign` needs besides the configuration.
#[derive(Debug, Clone)]
pub struct SignInput {
    /// The offline root key.
    pub root: SigningKey,
    /// The backup key's public half.
    pub backup: Key,
    /// The sequence number; higher than every manifest signed before.
    pub seq: u64,
    /// The online keys to list.
    pub keys: Vec<ManifestKey>,
    /// Issue time.
    pub issued: u64,
    /// BIP-340 auxiliary randomness.
    pub aux: [u8; 32],
}

/// Builds and signs the manifest of a configuration: the JCS bytes to
/// serve (draft-00 9.1).
pub fn sign(
    cfg: &Config,
    plans: &[RoutePlan],
    input: &SignInput,
) -> Result<Vec<u8>, ManifestCheckError> {
    if !input.keys.iter().any(|k| k.key_use == KeyUse::Offer)
        || !input.keys.iter().any(|k| k.key_use == KeyUse::Receipt)
    {
        return Err(bad("list at least one offer key and one receipt key"));
    }
    let m = Manifest {
        bnap: 1,
        origin: cfg.gate.origin.clone(),
        seq: input.seq,
        issued: input.issued,
        max_age: cfg.manifest.max_age_s,
        root: input.root.public_key(),
        backup: input.backup,
        keys: input.keys.clone(),
        required: cfg.manifest.required,
        limits: ManifestLimits {
            replay_window: Some(cfg.gate.replay_window_s),
            pending_timeout: Some(cfg.gate.pending_timeout_s),
            ..ManifestLimits::default()
        },
        carriers: vec!["http".into()],
        routes: plans.iter().map(|p| p.manifest.clone()).collect(),
    };
    m.sign(&input.root, &input.aux)
        .map_err(|e| bad(e.to_string()))
}
