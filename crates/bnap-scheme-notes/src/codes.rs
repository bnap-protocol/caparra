//! The scheme's error codes (section 13).
//!
//! Every rejection is socket `BAD_CREDENTIAL` (10) with one of these
//! `scheme_code` values, namespaced `bnap:notes/…`. A rail, issuer store or
//! signer that cannot be reached is UNAVAILABLE instead, never an admission.

use bnap_plug::SchemeError;

use crate::SCHEME_ID;

/// The body or witness breaks the canonical form of 3.5, a non-minimal
/// `BigSize` or `tu64` inside them included (2.1).
pub const NON_CANONICAL: &str = "NON_CANONICAL";
/// The body has neither inputs nor a fund quote.
pub const EMPTY: &str = "EMPTY";
/// More inputs or outputs than `max_inputs` or `max_outputs`.
pub const LIMIT: &str = "LIMIT";
/// An input keyset is not in the offer, unknown, revoked or past its final
/// expiry, or an output keyset is not active; also a unit other than `sat`.
pub const UNKNOWN_KEYSET: &str = "UNKNOWN_KEYSET";
/// An amount is not a power of two with a key, the arithmetic overflows, or
/// the fees exceed inputs plus fund.
pub const BAD_AMOUNT: &str = "BAD_AMOUNT";
/// The outputs are not a complete ladder covering the value.
pub const BAD_OUTPUTS: &str = "BAD_OUTPUTS";
/// A note, an input signature or the fund signature failed.
pub const BAD_SIGNATURE: &str = "BAD_SIGNATURE";
/// The fund quote is unknown, unpaid, not BOLT11 in sat, has no NUT-20 key,
/// or the rail does not confirm its payment.
pub const QUOTE_UNPAID: &str = "QUOTE_UNPAID";
/// Reserved by section 13.1 and never sent: verification does not reject a
/// reused output and settlement signs it again (7.4).
pub const OUTPUT_REUSED: &str = "OUTPUT_REUSED";

/// Every code this scheme sends, in the order of section 13.1.
pub const SENT: [&str; 8] = [
    NON_CANONICAL,
    EMPTY,
    LIMIT,
    UNKNOWN_KEYSET,
    BAD_AMOUNT,
    BAD_OUTPUTS,
    BAD_SIGNATURE,
    QUOTE_UNPAID,
];

/// A rejection with the namespaced code `bnap:notes/{code}`.
pub(crate) fn reject(code: &str, detail: impl Into<String>) -> SchemeError {
    SchemeError::rejected(SCHEME_ID, code, detail)
}

/// The full scheme code, such as `bnap:notes/BAD_SIGNATURE`.
#[must_use]
pub fn scheme_code(code: &str) -> String {
    format!("{SCHEME_ID}/{code}")
}

/// The short code of a [`SchemeError::Rejected`] this scheme sent, such as
/// `BAD_SIGNATURE`; `None` for any other error.
#[must_use]
pub fn code_of(err: &SchemeError) -> Option<&str> {
    match err {
        SchemeError::Rejected { scheme_code, .. } => scheme_code
            .strip_prefix(SCHEME_ID)
            .and_then(|c| c.strip_prefix('/')),
        _ => None,
    }
}
