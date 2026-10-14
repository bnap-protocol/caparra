//! MCP scopes (provisional): what one priced tool call is.
//!
//! ```text
//! action scope = H_"bnap/scope/mcp"( lp(server URI) ‖ lp(tool name) ‖ lp(H(JCS(arguments))) )
//! route scope  = H_"bnap/route/mcp"( lp(server URI) ‖ lp(route id) )
//! ```
//!
//! This is the overview's MCP row ("server URI, tool name, RFC 8785
//! canonical JSON of the arguments") written the way draft-00 10.1 writes
//! the HTTP scopes. No BNAP document defines it yet; the BNAP MCP carrier
//! note will, and until then the tags and the layout may change.
//!
//! - **server URI** is the URI the operator configures for the MCP
//!   endpoint, such as `https://api.example/mcp`, never the `Host` the
//!   server sees, so the scope stays the same behind a front.
//! - **tool name** is `params.name` exactly as sent.
//! - **arguments** is `params.arguments`, canonicalized with JCS (RFC
//!   8785). Absent arguments count as the empty object `{}`: MCP defines
//!   `arguments` as an object and a tool reads both the same way. JCS
//!   assumes I-JSON (RFC 7493), so arguments that name a member twice at
//!   any depth are refused before canonicalization, and so is any integer
//!   whose magnitude is above 2⁵³, which JCS would round to another number.

use bnap_core::encoding::write_lp;
use bnap_core::hash::{Scope, sha256, tagged_hash};
use bnap_core::manifest::{ManifestError, parse_strict};
use serde_json::{Map, Value};

/// Tag of the MCP action scope.
pub const SCOPE_TAG: &str = "bnap/scope/mcp";

/// Tag of the MCP route scope.
pub const ROUTE_TAG: &str = "bnap/route/mcp";

/// The largest integer magnitude JCS keeps exact: 2⁵³.
pub const MAX_EXACT_INTEGER: u64 = 1 << 53;

/// Why arguments have no scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// An object names a member twice (I-JSON).
    #[error("the arguments name the member {0:?} twice")]
    DuplicateMember(String),
    /// The bytes are not one JSON value.
    #[error("the arguments are not JSON")]
    NotJson,
    /// The arguments are JSON but not an object.
    #[error("the arguments are not a JSON object")]
    NotObject,
    /// An integer whose magnitude is above 2⁵³: JCS would round it.
    #[error("a number in the arguments is outside the exact range of 2^53")]
    NumberOutOfRange,
}

/// The canonical bytes of `arguments`: JCS of the object, `{}` when absent.
pub fn arguments_jcs(arguments: Option<&Map<String, Value>>) -> Result<Vec<u8>, ScopeError> {
    let Some(args) = arguments else {
        return Ok(b"{}".to_vec());
    };
    for v in args.values() {
        check_numbers(v)?;
    }
    // JCS of a parsed object of finite numbers cannot fail; refuse rather
    // than hash an empty string if it ever does.
    serde_json_canonicalizer::to_vec(args).map_err(|_| ScopeError::NumberOutOfRange)
}

/// The action scope of a call to `tool` on the server at `server_uri`
/// with already parsed `arguments`.
///
/// The parsed form cannot show a member named twice: a server must read
/// the request with [`parse_arguments`] (or behind [`crate::strict`]) so
/// that duplicates are refused before they are folded.
pub fn action_scope(
    server_uri: &str,
    tool: &str,
    arguments: Option<&Map<String, Value>>,
) -> Result<Scope, ScopeError> {
    let jcs = arguments_jcs(arguments)?;
    let mut buf = Vec::new();
    write_lp(&mut buf, server_uri.as_bytes());
    write_lp(&mut buf, tool.as_bytes());
    write_lp(&mut buf, &sha256(&jcs));
    Ok(Scope(tagged_hash(SCOPE_TAG, &buf)))
}

/// Reads arguments from raw JSON bytes as I-JSON: a member named twice at
/// any depth, trailing bytes, or anything but an object is refused.
pub fn parse_arguments(raw: &[u8]) -> Result<Map<String, Value>, ScopeError> {
    match parse_strict(raw) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(ScopeError::NotObject),
        Err(ManifestError::DuplicateMember(name)) => Err(ScopeError::DuplicateMember(name)),
        Err(_) => Err(ScopeError::NotJson),
    }
}

/// [`action_scope`] over raw argument bytes, read with [`parse_arguments`].
/// `None` means the call has no arguments.
pub fn action_scope_json(
    server_uri: &str,
    tool: &str,
    raw_arguments: Option<&[u8]>,
) -> Result<Scope, ScopeError> {
    let parsed = raw_arguments.map(parse_arguments).transpose()?;
    action_scope(server_uri, tool, parsed.as_ref())
}

/// The route scope of `route_id` on the server at `server_uri`.
#[must_use]
pub fn route_scope(server_uri: &str, route_id: &str) -> Scope {
    let mut buf = Vec::new();
    write_lp(&mut buf, server_uri.as_bytes());
    write_lp(&mut buf, route_id.as_bytes());
    Scope(tagged_hash(ROUTE_TAG, &buf))
}

fn check_numbers(v: &Value) -> Result<(), ScopeError> {
    match v {
        Value::Number(n) => {
            let exact = if let Some(u) = n.as_u64() {
                u <= MAX_EXACT_INTEGER
            } else if let Some(i) = n.as_i64() {
                i.unsigned_abs() <= MAX_EXACT_INTEGER
            } else {
                n.as_f64().is_some_and(f64::is_finite)
            };
            if exact {
                Ok(())
            } else {
                Err(ScopeError::NumberOutOfRange)
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_numbers),
        Value::Object(map) => map.values().try_for_each(check_numbers),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const URI: &str = "https://api.example/mcp";

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn the_scope_is_pinned() {
        // Pinned so an accidental change of tag or layout shows up. The
        // preimage is lp(URI) ‖ lp("weather") ‖ lp(H(`{"city":"Bern"}`)).
        let args = obj(json!({"city": "Bern"}));
        let s = action_scope(URI, "weather", Some(&args)).unwrap();
        let mut buf = vec![23];
        buf.extend_from_slice(URI.as_bytes());
        buf.push(7);
        buf.extend_from_slice(b"weather");
        buf.push(32);
        buf.extend_from_slice(&sha256(br#"{"city":"Bern"}"#));
        assert_eq!(s.0, tagged_hash("bnap/scope/mcp", &buf));
        assert_eq!(hex::encode(s.0), PINNED_SCOPE);
    }

    const PINNED_SCOPE: &str = "to be pinned";

    #[test]
    fn member_order_and_spelling_do_not_change_the_scope() {
        let a = action_scope_json(URI, "t", Some(br#"{"b":1,"a":{"y":"A","x":2.0}}"#));
        let b = action_scope_json(URI, "t", Some(br#"{ "a" : { "x" : 2, "y" : "A" }, "b" : 1 }"#));
        assert_eq!(a.unwrap(), b.unwrap());
    }

    #[test]
    fn every_input_changes_the_scope() {
        let args = obj(json!({"q": "x"}));
        let base = action_scope(URI, "t", Some(&args)).unwrap();
        assert_ne!(base, action_scope("https://api.example/mcp2", "t", Some(&args)).unwrap());
        assert_ne!(base, action_scope(URI, "u", Some(&args)).unwrap());
        assert_ne!(base, action_scope(URI, "t", Some(&obj(json!({"q": "y"})))).unwrap());
        assert_ne!(base, action_scope(URI, "t", None).unwrap());
        // Length prefixes keep the URI and the tool name apart.
        assert_ne!(
            action_scope("ab", "c", None).unwrap(),
            action_scope("a", "bc", None).unwrap()
        );
        // A route scope never equals an action scope.
        assert_ne!(route_scope(URI, "t").0, action_scope(URI, "t", None).unwrap().0);
    }

    #[test]
    fn absent_arguments_are_the_empty_object() {
        assert_eq!(
            action_scope(URI, "t", None).unwrap(),
            action_scope(URI, "t", Some(&Map::new())).unwrap()
        );
    }

    #[test]
    fn a_member_named_twice_is_refused_at_any_depth() {
        for raw in [
            &br#"{"city":"Bern","city":"Zug"}"#[..],
            br#"{"a":{"b":1,"b":2}}"#,
            br#"{"a":[{"b":1,"b":1}]}"#,
            br#"{"city":"Bern","city":"Zug"}"#,
        ] {
            assert!(
                matches!(
                    action_scope_json(URI, "t", Some(raw)),
                    Err(ScopeError::DuplicateMember(_))
                ),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        // The same name in two different objects is fine.
        assert!(action_scope_json(URI, "t", Some(br#"{"a":{"n":1},"b":{"n":1}}"#)).is_ok());
    }

    #[test]
    fn non_objects_and_non_json_are_refused() {
        assert_eq!(
            action_scope_json(URI, "t", Some(b"[1]")),
            Err(ScopeError::NotObject)
        );
        assert_eq!(
            action_scope_json(URI, "t", Some(b"{\"a\":1} x")),
            Err(ScopeError::NotJson)
        );
    }

    #[test]
    fn integers_jcs_would_round_are_refused() {
        // 2^53 + 1 rounds to 2^53 under JCS: two different calls, one scope.
        let ok = obj(json!({ "n": MAX_EXACT_INTEGER }));
        let big = obj(json!({ "n": MAX_EXACT_INTEGER + 1 }));
        let neg = obj(json!({ "n": [-(i64::try_from(MAX_EXACT_INTEGER).unwrap()) - 1] }));
        assert!(action_scope(URI, "t", Some(&ok)).is_ok());
        assert_eq!(
            action_scope(URI, "t", Some(&big)),
            Err(ScopeError::NumberOutOfRange)
        );
        assert_eq!(
            action_scope(URI, "t", Some(&neg)),
            Err(ScopeError::NumberOutOfRange)
        );
    }
}
