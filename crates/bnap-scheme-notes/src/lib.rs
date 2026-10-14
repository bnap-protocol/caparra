//! The `bnap:notes` credential scheme (`spec/schemes/bnap-notes-draft-00.md`).
//!
//! The operator runs its own Cashu-style issuer for its own origin. A client
//! buys credit over Lightning (NUT-23, NUT-04, NUT-20), or inside the 402
//! that asked it to pay, and holds it as notes: Cashu proofs whose secret
//! is `hex(K)`. To pay, it puts notes and blinded outputs in the body of a
//! socket Credential and signs the socket's Digest with each `K`. The gate
//! checks the notes offline, the socket commits each note's `Y` as a
//! single-use ID, and settlement signs exactly `value - charged` of the
//! client's outputs as change.
//!
//! | Module | Spec | What it holds |
//! | --- | --- | --- |
//! | [`wire`] | 3, 5, 7.3 | Body, witness, parameters and `scheme_result` bytes, read in their one canonical form |
//! | [`amount`] | 6.3, 7.2 | Value, input fees, the output ladder, the change selection |
//! | [`keyset`] | 4.2, 5.2, 10 | The keyset table, NUT-02 IDs, the issuer's key math, rotation |
//! | [`issuer`] | 7.4, 8, 10 | The issuer's tables: keysets, fund quotes, signed outputs |
//! | [`scheme`] | 5 to 9 | [`NotesScheme`], the server side: offer, verify, settle, fund quotes |
//! | [`mint`] | 8.5 | NUT-04 minting of a paid quote, committed in the use store |
//! | [`fund`] | 8.1 | The `BNAP-Fund` request field |
//! | [`client`] | 4, 6.3, 7.3, 8.3, 12 | Wallet building blocks |
//! | [`codes`] | 13 | The `bnap:notes/…` scheme codes |
//!
//! # How a gate uses it
//!
//! The gate runs the flow of `notes/n3-core.md` with [`NotesScheme`] as the
//! `bnap:notes` plug, registered with `refund = "atomic"` and use model
//! `single`, and adds four steps of its own:
//!
//! 1. **Offers.** `scheme.offer(cx)` gives the route-scope parameters. For a
//!    request that carried `BNAP-Fund` ([`fund::FundRequest`]), on a route
//!    that funds, [`NotesScheme::create_fund_quote`] makes the quote and
//!    [`NotesScheme::offer_with_quote`] the exact-scope entry; that offer is
//!    never cached (5.4).
//! 2. **Rail references.** A funded credential returns one `ln` rail
//!    reference; confirm it with `confirm_rail_id` and map a failure with
//!    [`scheme::rail_error`] (`QUOTE_UNPAID`, or UNAVAILABLE). On a route
//!    that requires unlinkable payment, answer POLICY when
//!    [`scheme::funded`] is true (8.4).
//! 3. **Admission cutoff.** Give `outcome::process` the offer fields of
//!    [`scheme::admission_fields`], not the offer's own: a new notes
//!    credential after the cutoff of 5.4 is then STALE, while a replay is
//!    still answered from its outcome.
//! 4. **Minting.** Serve NUT-04 with [`NotesScheme::mint`], NUT-23 checks
//!    with [`NotesScheme::quote_state`] and NUT-09 with
//!    [`NotesScheme::restore`].
//!
//! The scheme never holds a key: notes are checked and outputs signed by
//! the operator's signer, seen only through the `CappedSigner` the gate
//! passes in, whose change budget bnap-core computed and the use store
//! bounds.

pub mod amount;
pub mod client;
pub mod codes;
pub mod fund;
pub mod issuer;
pub mod keyset;
pub mod mint;
pub mod scheme;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod wire;

/// The registered scheme ID.
pub const SCHEME_ID: &str = "bnap:notes";

pub use fund::FundRequest;
pub use issuer::{IssuerError, IssuerStore, QuoteRecord, SignedOutput};
pub use keyset::{IssuerKeyset, KeysetInfo, KeysetState};
pub use mint::{MintEnv, MintError, rk_mint};
pub use scheme::{
    NotesConfig, NotesScheme, admission_cutoff, admission_fields, funded, rail_error,
};
pub use wire::{Body, FundQuote, Input, Output, Params, SignatureEntry, Witness};
