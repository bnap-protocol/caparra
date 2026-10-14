//! Binding classes (draft-00 sections 4.3, 5.1 and 11).
//!
//! A scheme's class comes from its registry entry, never from the plug. The
//! socket checks that use classes take a lookup function, so this crate holds
//! no registry.

use std::fmt;
use std::str::FromStr;

/// How a scheme's credential is tied to the offer and the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingClass {
    /// A signature over the Digest.
    S,
    /// A client-made artifact embeds the Context.
    A,
    /// A server-made artifact embeds the `OfferID`.
    O,
    /// A bearer credential.
    None,
}

impl BindingClass {
    /// The registry spelling: `S`, `A`, `O` or `none`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S => "S",
            Self::A => "A",
            Self::O => "O",
            Self::None => "none",
        }
    }

    /// True for S and A, the classes a route-scope offer may list (4.3).
    #[must_use]
    pub fn route_scope_allowed(self) -> bool {
        matches!(self, Self::S | Self::A)
    }

    /// True for S, A and O, the classes that may waive, discount or carry a
    /// quota (section 7).
    #[must_use]
    pub fn may_affect_price(self) -> bool {
        matches!(self, Self::S | Self::A | Self::O)
    }
}

impl fmt::Display for BindingClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A string that is not a binding class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a binding class (S, A, O or none)")]
pub struct UnknownBindingClass;

impl FromStr for BindingClass {
    type Err = UnknownBindingClass;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S" => Ok(Self::S),
            "A" => Ok(Self::A),
            "O" => Ok(Self::O),
            "none" => Ok(Self::None),
            _ => Err(UnknownBindingClass),
        }
    }
}
