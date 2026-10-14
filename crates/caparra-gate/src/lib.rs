//! `caparra-gate`: the BNAP gate in front of an HTTP application.
//!
//! The gate runs bnap-core's `process()` for every paid request, with the
//! HTTP carrier of draft-00 section 10, the operator's signer, use store and
//! rails, and the scheme plugs the configuration enables.

pub mod config;
pub mod gate;
pub mod issuer;
pub mod limiter;
pub mod manifest;
pub mod meter;
pub mod plugs;
pub mod proxy;
pub mod registry;
pub mod server;
