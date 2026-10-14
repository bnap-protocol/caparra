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
/// How long past `pending_timeout` an outcome record must be kept at
/// least, so a client can still replay a timed-out outcome and collect its
/// refund (6.4): two clock skews, one for the offer's expiry check and one
/// between the gate's own clocks (ERRATA N3b-21).
pub const REFUND_MARGIN: u64 = 2 * CLOCK_SKEW;

/// Limits that would let a timed-out outcome's refund be lost.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LimitsError {
    /// `replay_window` is shorter than `pending_timeout` plus
    /// [`REFUND_MARGIN`] plus the longest offer lifetime checked: the
    /// record of a crash-orphaned PENDING outcome could leave its window
    /// before, or too soon after, the timeout lets a replay collect its
    /// refund, and every later replay would be SPENT, so the crash would
    /// cost the client (6.4).
    #[error(
        "replay_window {replay_window} s is below {min} s (pending_timeout \
         {pending_timeout} s + {REFUND_MARGIN} s + offer lifetime {offer_lifetime} s)"
    )]
    ReplayWindowTooShort {
        /// The `replay_window`.
        replay_window: u64,
        /// The `pending_timeout`.
        pending_timeout: u64,
        /// The offer lifetime checked; 0 for the manifest alone.
        offer_lifetime: u64,
        /// The shortest `replay_window` allowed.
        min: u64,
    },
}

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
    ///
    /// Refuses a `replay_window` shorter than `pending_timeout` plus
    /// [`REFUND_MARGIN`] ([`Self::validate`]). Draft-00 states no relation
    /// between the two, but with a shorter window a crash that leaves an
    /// outcome PENDING costs the client: the first replay after the timeout
    /// finds the record already past its window and answers SPENT, and the
    /// sweep deletes the refund with the record (ERRATA N3b-21).
    pub fn from_manifest(m: &crate::manifest::ManifestLimits) -> Result<Self, LimitsError> {
        let d = Self::default();
        let size = |v: Option<u64>, def: usize| {
            v.map_or(def, |v| usize::try_from(v).unwrap_or(usize::MAX).max(def))
        };
        let l = Self {
            max_offer: size(m.max_offer, d.max_offer),
            max_credential: size(m.max_credential, d.max_credential),
            max_response: size(m.max_response, d.max_response),
            replay_window: m.replay_window.unwrap_or(d.replay_window),
            pending_timeout: m.pending_timeout.unwrap_or(d.pending_timeout),
        };
        l.validate()?;
        Ok(l)
    }

    /// The shortest `replay_window` these limits allow for offers that
    /// live up to `offer_lifetime` seconds: `pending_timeout +`
    /// [`REFUND_MARGIN`] `+ offer_lifetime`, saturating.
    #[must_use]
    pub fn min_replay_window(&self, offer_lifetime: u64) -> u64 {
        self.pending_timeout
            .saturating_add(REFUND_MARGIN)
            .saturating_add(offer_lifetime)
    }

    /// Checks that a timed-out outcome stays collectable:
    /// `replay_window >= pending_timeout + REFUND_MARGIN`.
    pub fn validate(&self) -> Result<(), LimitsError> {
        self.check_offer_lifetime(0)
    }

    /// Checks that a gate issuing offers that live up to `lifetime`
    /// seconds keeps every outcome record longer than any replay its offer
    /// still allows, past the timeout included:
    /// `replay_window >= pending_timeout + REFUND_MARGIN + lifetime`. A
    /// gate calls this at start-up with its longest offer lifetime.
    pub fn check_offer_lifetime(&self, lifetime: u64) -> Result<(), LimitsError> {
        let min = self.min_replay_window(lifetime);
        if self.replay_window < min {
            return Err(LimitsError::ReplayWindowTooShort {
                replay_window: self.replay_window,
                pending_timeout: self.pending_timeout,
                offer_lifetime: lifetime,
                min,
            });
        }
        Ok(())
    }

    /// How long outcome records are kept and answered, from commit:
    /// `replay_window`, but never less than `pending_timeout +`
    /// [`REFUND_MARGIN`]. Limits from [`Self::from_manifest`] always have
    /// `replay_window` here; the floor protects limits built by hand, so a
    /// timed-out refund stays collectable whatever the source. The outcome
    /// state machine and the sweep use this, never `replay_window` alone.
    #[must_use]
    pub fn record_window(&self) -> u64 {
        self.replay_window.max(self.min_replay_window(0))
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
