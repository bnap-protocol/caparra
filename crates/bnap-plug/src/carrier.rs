//! The carrier plug: names the action, finds the credential, and carries
//! offers, receipts and errors (draft-00 sections 3 and 10).
//!
//! A carrier is contained: it computes scopes from the request as received
//! and moves bytes. It never decides admission.

use bnap_core::error::{Error, ErrorObject};
use bnap_core::hash::Scope;
use bnap_core::offer::Offer;
use bnap_core::response::Response as Receipt;

/// A credential as the carrier found it in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawCredential {
    /// A BNAP Credential (`BNAP-Credential` on HTTP), decoded.
    Bnap(Vec<u8>),
    /// A scheme's own credential, such as an L402 token, for that scheme's
    /// adapter to recover (5.4).
    Native {
        /// Scheme ID whose native header carried it.
        scheme: String,
        /// The native credential bytes as the registry entry defines them.
        bytes: Vec<u8>,
    },
}

/// A scheme's own challenge, sent next to the BNAP offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeChallenge {
    /// Scheme ID.
    pub scheme: String,
    /// The challenge as the scheme writes it, such as an L402
    /// `WWW-Authenticate` value, made from the native entries of one pay
    /// entry of an offer in the same challenge (9.3): an MPP challenge is
    /// its `mpp-challenge` entry byte for byte, an L402 challenge carries
    /// its `l402-macaroon` and `bolt11` entries.
    pub value: String,
}

/// Everything a 402 (or the carrier's equivalent) carries.
#[derive(Debug, Clone, Copy)]
pub struct Challenge<'a> {
    /// Signed offers, such as a route offer and an exact offer.
    pub offers: &'a [Offer],
    /// Native challenges.
    pub natives: &'a [NativeChallenge],
    /// The error that caused the challenge, such as REQUIRED or STALE.
    pub error: Option<&'a ErrorObject>,
}

/// A carrier (HTTP, MCP, ...). `Request` and `Response` are the carrier's
/// own types.
pub trait Carrier: Send + Sync {
    /// The carrier's request type.
    type Request;
    /// The carrier's response type.
    type Response;

    /// The registered carrier name, such as `http`.
    fn name(&self) -> &str;

    /// The action scope of this request (10.1 for HTTP).
    fn action_scope(&self, req: &Self::Request) -> Result<Scope, Error>;

    /// The route scope of a manifest route (10.1 for HTTP).
    fn route_scope(&self, route_id: &str) -> Scope;

    /// The credential the request carries, if any. A request carrying more
    /// than one value credential, native or BNAP, is MALFORMED (5.4); an
    /// oversize credential is `TOO_LARGE`.
    fn extract(&self, req: &Self::Request) -> Result<Option<RawCredential>, Error>;

    /// Writes a challenge: every offer, every native challenge, and the
    /// error.
    fn offer(&self, challenge: &Challenge<'_>, out: &mut Self::Response);

    /// Attaches a receipt to a response (or its trailer or final event).
    fn receipt(&self, receipt: &Receipt, out: &mut Self::Response);

    /// Writes an error, with the carrier's status for its code.
    fn error(&self, error: &ErrorObject, out: &mut Self::Response);
}
