//! Carries BNAP messages in HTTP requests and responses (draft-00
//! section 10).
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`codec`] | `b64u`, the strict base64url of draft-00 section 2 |
//! | [`fields`] | The header fields of 10.2: names, the `BNAP` challenge, credential extraction under the size cap of DECISIONS row 30 |
//! | [`carrier`] | [`HttpCarrier`], the [`bnap_plug::Carrier`] for HTTP: action and route scopes (10.1), challenges, receipts and errors |
//! | [`layer`] | [`BnapLayer`], a tower `Layer` that puts a [`Gatekeeper`] in front of any `tower::Service`, axum and hyper apps included |
//! | [`client`] | Client helpers: read offers, receipts and errors from a response, write a `BNAP-Credential` |
//!
//! The carrier computes scopes and moves bytes. It never decides
//! admission: that is the [`Gatekeeper`]'s, which runs the socket
//! (`bnap_core::outcome::process`) for every request.
//!
//! # Header fields
//!
//! | Field | Direction | Value |
//! | --- | --- | --- |
//! | `WWW-Authenticate: BNAP offer="…"` | 402 | `b64u(Offer)`, one challenge per field, next to native challenges (L402, `Payment`) in their own fields |
//! | `BNAP-Credential` | request | `b64u(Credential)`, at most 12,288 characters (9,216 bytes) |
//! | `BNAP-Context` | request, optional | `b64u(Context)`; MALFORMED when it differs from the Context the gate computed |
//! | `BNAP-Receipt` | response | `b64u(Response)` on every response to a request that reached commit |
//! | `BNAP-Error` | response | `b64u(Error)`, with the HTTP status of 8.2 |
//!
//! Every answer to a BNAP route carries `Cache-Control: private, no-store`.

pub mod carrier;
pub mod client;
pub mod codec;
pub mod fields;
pub mod layer;

pub use carrier::{HttpCarrier, HttpRequest, NativeAuth};
pub use codec::{b64u, b64u_decode};
pub use layer::{
    Admit, BnapLayer, BnapService, BodyLimits, BoxBody, ClientAddr, Done, GateRequest, Gatekeeper,
    Run, Ticket,
};
