//! Size limits, time skew and the timeout defaults.

/// Default maximum Offer size in bytes (draft-00 section 2).
pub const MAX_OFFER: usize = 4096;
/// Default maximum Credential size in bytes (draft-00 section 2).
pub const MAX_CREDENTIAL: usize = 16_384;
/// Default maximum Response size in bytes (draft-00 section 2).
pub const MAX_RESPONSE: usize = 8192;
/// Clock skew allowed on every expiry check, in seconds (draft-00 section 2).
pub const CLOCK_SKEW: u64 = 60;
/// Default `pending_timeout` in seconds when the manifest omits it
/// (DECISIONS row 21).
pub const DEFAULT_PENDING_TIMEOUT: u64 = 300;
/// Default `replay_window` in seconds when the manifest omits it
/// (DECISIONS row 21).
pub const DEFAULT_REPLAY_WINDOW: u64 = 86_400;

/// Effective limits for one origin.
///
/// Draft-00 section 2: the size defaults hold "unless the manifest's limits
/// raise them". [`Limits::from_manifest`] therefore takes the larger of the
/// default and the manifest value for each size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum Offer size in bytes.
    pub max_offer: usize,
    /// Maximum Credential size in bytes.
    pub max_credential: usize,
    /// Maximum Response size in bytes.
    pub max_response: usize,
    /// How long outcome records are kept, in seconds.
    pub replay_window: u64,
    /// How long an outcome may stay PENDING, in seconds.
    pub pending_timeout: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_offer: MAX_OFFER,
            max_credential: MAX_CREDENTIAL,
            max_response: MAX_RESPONSE,
            replay_window: DEFAULT_REPLAY_WINDOW,
            pending_timeout: DEFAULT_PENDING_TIMEOUT,
        }
    }
}

impl Limits {
    /// Effective limits from a manifest's `limits` member.
    #[must_use]
    pub fn from_manifest(m: &crate::manifest::ManifestLimits) -> Self {
        let d = Self::default();
        let size = |v: Option<u64>, def: usize| {
            v.map_or(def, |v| usize::try_from(v).unwrap_or(usize::MAX).max(def))
        };
        Self {
            max_offer: size(m.max_offer, d.max_offer),
            max_credential: size(m.max_credential, d.max_credential),
            max_response: size(m.max_response, d.max_response),
            replay_window: m.replay_window.unwrap_or(d.replay_window),
            pending_timeout: m.pending_timeout.unwrap_or(d.pending_timeout),
        }
    }
}

/// True when `deadline` has passed at `now`, allowing [`CLOCK_SKEW`].
#[must_use]
pub fn expired(deadline: u64, now: u64) -> bool {
    now > deadline.saturating_add(CLOCK_SKEW)
}

/// True when `t` lies in the future at `now`, beyond [`CLOCK_SKEW`].
#[must_use]
pub fn in_future(t: u64, now: u64) -> bool {
    t > now.saturating_add(CLOCK_SKEW)
}
