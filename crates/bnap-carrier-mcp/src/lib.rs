//! Carries BNAP messages in MCP tool calls and results (provisional).
//!
//! The MCP carrier of the overview's Carriers table: the scope of one call
//! is the server URI, the tool name and the RFC 8785 canonical JSON of the
//! arguments ([`scope`]); offers travel in the JSON-RPC error of a
//! `tools/call`, credentials in `params._meta` and receipts in
//! `result._meta`, aligned with the MPP MCP transport ([`wire`], [`mpp`]).
//! No BNAP document defines this carrier yet; the BNAP MCP carrier note
//! will, and until then every tag and key here may change.
//!
//! [`PricedTools`] wraps any rmcp server handler: the operator prices
//! tools on a [`Gate`] ([`ToolPrice`]: pay entries, attest entries,
//! `require`), and every call to a priced tool runs through
//! `bnap_core::outcome::process`. [`router`] serves it over rmcp's
//! streamable HTTP transport behind the [`strict`] JSON layer, which
//! refuses messages that name a JSON member twice. There is no TLS
//! binding: MCP credentials rely on scope binding, and a credential that
//! carries a binding is refused (BINDING).
//!
//! [`client`] has what an MCP client needs to read offers and receipts
//! and to attach a credential.

pub mod client;
pub mod config;
pub mod gate;
pub mod mpp;
pub mod priced;
pub mod scope;
pub mod strict;
pub mod wire;

pub use config::{Clock, ConfigError, GateConfig, Price, SchemeConfig, ToolPrice, system_clock};
pub use gate::{Gate, GateBuilder, Presented};
pub use priced::{PricedTools, router};
pub use strict::{StrictConfig, StrictJson, strict_json};
