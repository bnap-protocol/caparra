//! Client wallet that holds funds and answers BNAP payment challenges.

pub mod error;
pub mod invoice;
pub mod paysource;
pub mod policy;
pub mod rank;
pub mod registry;
pub mod store;
pub mod transport;

pub use error::{Code, Refusal, Result};
