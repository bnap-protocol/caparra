//! A BNAP signer served from a separate process.
//!
//! The keys live in the `bnap-signer` binary of this crate, which loads a
//! key file ([`bnap_signer_file`], mode `0600`) and listens on a Unix
//! socket. The gate holds a [`ProcessSigner`], which implements
//! [`bnap_plug::Signer`] by asking that process. No key ever crosses the
//! socket.
//!
//! # Two users
//!
//! The separate process keeps the keys from the gate only if the gate runs
//! as another user: a process of the signer's own user can read the key
//! file and trace the signer. So, in production:
//!
//! - the signer runs as a user of its own, which owns the key file (mode
//!   `0600`) and the socket's directory (for example `0750`, with the
//!   gate's group);
//! - the socket is bound with [`SocketAccess::Group`] (`bnap-signer
//!   --socket-group GATE_GID --allow-uid GATE_UID`): mode `0660` with the
//!   gate's group, so the gate can connect, and of the processes that can
//!   reach it only the signer's user and the listed users are served
//!   ([`SignerSocket::admits`], on the connection's peer credentials);
//! - the gate names the signer's user:
//!   `ProcessSigner::new(path).with_signer_uid(SIGNER_UID)`.
//!
//! [`SocketAccess::Owner`] (mode `0600`, the default) admits the signer's
//! own user only: right for tests and single-user setups, where it gives no
//! protection of the keys against a compromised gate.
//!
//! Both sides require the socket's directory to have no group or other
//! write bit (a sticky `/tmp` is refused), and the client talks only to a
//! process running as the signer's user
//! ([`ProcessSigner::with_signer_uid`]), so another local user cannot
//! answer in the signer's place while it is down.
//!
//! # Only messages bnap-core built
//!
//! A sealed [`bnap_core::CoreMessage`] cannot cross a process boundary, so
//! the client sends what the message is the hash of
//! ([`bnap_core::CoreMessage::signed_bytes`]: an offer's `S`, or a
//! Response's records outside 240 to 1000), its purpose and its key. The
//! signer process parses those bytes with bnap-core as the object the
//! purpose names, checks that the object names that key and that it holds
//! the key for the purpose's use, and signs the tagged hash it computed
//! itself ([`bnap_signer_file::object::recompute`]). A request that carries
//! a digest, or any bytes that are not such an object, is refused.
//!
//! # Change
//!
//! The gate signs change and refunds through
//! [`bnap_plug::CappedSigner::for_change`] over its use store, as with any
//! signer: every output is reserved in the outcome's record, one durable
//! total per `ReplayKey`, before this client is called. The signer process
//! then refuses, on its own:
//!
//! - empty batches and outputs of amount 0;
//! - outputs that would take its running total for the outcome past the
//!   cap the request names (its [`bnap_plug::ChangeLedger`]);
//! - when it is given the use store too ([`ServeOptions::store`]), any
//!   output the store has not reserved for that outcome.
//!
//! # Protocol
//!
//! Length-prefixed JSON frames of at most [`wire::MAX_FRAME`] bytes, one
//! request and one reply each; see [`wire`]. The server bounds the time to
//! read and write a frame, the idle time between requests and the number
//! of connections served at once; the client bounds every call.

#![cfg(unix)]

mod client;
mod server;
mod trust;
pub mod wire;

pub use client::{DEFAULT_TIMEOUT, ProcessSigner};
pub use server::{BindError, ServeOptions, Server, SignerSocket, SocketAccess, check_reserved};
