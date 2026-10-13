//! The signer plug and the capped view of it that schemes get.
//!
//! The signer is operator-trusted and keeps every key in its own process:
//! offer and receipt keys for BIP-340, issuer keys for blind signatures. No
//! plug ever sees a secret key; the trait only moves public data.
//!
//! - [`Signer::schnorr`] takes a [`CoreMessage`], which only bnap-core can
//!   build, so the signer never signs raw bytes:
//!
//!   ```compile_fail
//!   async fn forge(s: &dyn bnap_plug::Signer) {
//!       // A plug cannot pass its own 32 bytes.
//!       let _ = s.schnorr(&[0u8; 32]).await;
//!   }
//!   ```
//!
//! - A scheme never holds the [`Signer`]. It gets a [`CappedSigner`], which
//!   can check unblinded notes and sign blinded outputs worth at most the
//!   change cap bnap-core computed (`value - charged`), and nothing more: it
//!   has no way to sign a message at all, so a scheme can never get an
//!   offer or a receipt signed.

use std::fmt;
use std::sync::Arc;

use bnap_core::ErrorCode;
use bnap_core::pricing::ChangeCap;
use bnap_core::schnorr::Signature;
use bnap_core::sign::CoreMessage;

/// A compressed secp256k1 point, 33 bytes: a note's `Y` or `C`, a blinded
/// output `B'` or a blind signature `C'`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point(pub [u8; 33]);

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Point({})", hex::encode(self.0))
    }
}

/// An issuer keyset ID, as the issuer names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeysetId(pub Vec<u8>);

/// A blinded output to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindedOutput {
    /// Its amount, in the keyset's unit.
    pub amount: u64,
    /// `B'`.
    pub blinded: Point,
}

/// A NUT-12 DLEQ proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dleq {
    /// The challenge.
    pub e: [u8; 32],
    /// The response.
    pub s: [u8; 32],
}

/// A blind signature on one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindSignature {
    /// The output's amount.
    pub amount: u64,
    /// `C'`.
    pub signature: Point,
    /// Proof that `C'` was made with the keyset's key for `amount`.
    pub dleq: Dleq,
}

/// Why the signer did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The outputs are worth more than the change cap.
    #[error("outputs worth {sum} exceed the cap {cap}")]
    OverCap {
        /// What the outputs add up to (saturating).
        sum: u64,
        /// The cap.
        cap: u64,
    },
    /// The signer refused: an unknown key or keyset, a key held for another
    /// use, a verify-only capped signer, or a malformed answer.
    #[error("signer refused: {0}")]
    Refused(String),
    /// The signer cannot be reached.
    #[error("signer unavailable: {0}")]
    Unavailable(String),
}

impl SignerError {
    /// UNAVAILABLE: the gate fails closed whenever the signer does not sign
    /// (draft-00 8.2, section 12 "Fail closed").
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::Unavailable
    }
}

/// The signer plug (operator-trusted). Keys stay in its process.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Signs a message bnap-core built, with the key it names.
    ///
    /// MUST refuse unless the signer holds [`CoreMessage::key`] for the use
    /// [`CoreMessage::purpose`] needs (`offer` for an offer signature,
    /// `receipt` for an ack).
    async fn schnorr(&self, msg: &CoreMessage) -> Result<Signature, SignerError>;

    /// Checks an unblinded note: `c` is the keyset's key for `amount` times
    /// `y`.
    async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        amount: u64,
        y: &Point,
        c: &Point,
    ) -> Result<bool, SignerError>;

    /// Signs blinded outputs. MUST refuse when their amounts add up to more
    /// than `cap`, which bnap-core set to `value - charged`.
    async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
        cap: u64,
    ) -> Result<Vec<BlindSignature>, SignerError>;
}

/// The signer as a scheme sees it: unblinded-note checks, and blind
/// signatures up to the change cap. See the module docs.
#[derive(Clone)]
pub struct CappedSigner {
    inner: Arc<dyn Signer>,
    cap: Option<ChangeCap>,
}

impl fmt::Debug for CappedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CappedSigner")
            .field("cap", &self.cap())
            .finish_non_exhaustive()
    }
}

impl CappedSigner {
    /// The view a scheme's `verify` gets: it can check notes and sign
    /// nothing.
    #[must_use]
    pub fn verify_only(inner: Arc<dyn Signer>) -> Self {
        Self { inner, cap: None }
    }

    /// The view a scheme's `settle` gets: blind signatures worth at most
    /// `cap`, which only [`bnap_core::pricing::Admission::settle`] makes.
    #[must_use]
    pub fn for_change(inner: Arc<dyn Signer>, cap: ChangeCap) -> Self {
        Self {
            inner,
            cap: Some(cap),
        }
    }

    /// The change cap; `None` for a verify-only view.
    #[must_use]
    pub fn cap(&self) -> Option<u64> {
        self.cap.map(ChangeCap::get)
    }

    /// Checks an unblinded note (see [`Signer::verify_unblinded`]).
    pub async fn verify_unblinded(
        &self,
        keyset: &KeysetId,
        amount: u64,
        y: &Point,
        c: &Point,
    ) -> Result<bool, SignerError> {
        self.inner.verify_unblinded(keyset, amount, y, c).await
    }

    /// Signs blinded outputs worth at most the cap.
    ///
    /// Refuses before the signer is called when the view is verify-only or
    /// the outputs exceed the cap, and passes the cap on so the signer
    /// enforces it as well. Refuses an answer that does not hold exactly
    /// one signature per output, with the output's amount.
    pub async fn blind_sign(
        &self,
        keyset: &KeysetId,
        outputs: &[BlindedOutput],
    ) -> Result<Vec<BlindSignature>, SignerError> {
        let Some(cap) = self.cap() else {
            return Err(SignerError::Refused(
                "a verify-only signer signs nothing".into(),
            ));
        };
        let sum = outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount));
        match sum {
            Some(sum) if sum <= cap => {}
            sum => {
                return Err(SignerError::OverCap {
                    sum: sum.unwrap_or(u64::MAX),
                    cap,
                });
            }
        }
        let sigs = self.inner.blind_sign(keyset, outputs, cap).await?;
        let matches = sigs.len() == outputs.len()
            && sigs.iter().zip(outputs).all(|(s, o)| s.amount == o.amount);
        if !matches {
            return Err(SignerError::Refused(
                "the signer's answer does not match the outputs".into(),
            ));
        }
        Ok(sigs)
    }
}
