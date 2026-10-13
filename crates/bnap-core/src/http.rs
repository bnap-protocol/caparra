//! HTTP carrier scopes (draft-00 section 10.1).
//!
//! ```text
//! action scope = H_"bnap/scope/http"( lp(method) ‖ lp(target) ‖ lp(content hash, or empty)
//!                                    ‖ BigSize(h) ‖ lp(name₁) ‖ lp(value₁) ‖ … )
//! route scope  = H_"bnap/route/http"( lp(origin) ‖ lp(route id from the manifest) )
//! ```

use crate::encoding::{len_u64, write_bigsize, write_lp};
use crate::hash::{Scope, sha256, tagged_hash, tags};

/// Largest Credential the HTTP carrier accepts, in bytes: 12,288 base64url
/// characters (DECISIONS row 30). Larger credentials are TOO_LARGE.
pub const HTTP_MAX_CREDENTIAL: usize = 9216;

/// The HTTP action scope of one request.
///
/// - `method`: the request method exactly as sent (case-sensitive).
/// - `target`: the manifest's `origin` followed by the request-target in
///   origin form, exactly as received; see [`target`].
/// - `content`: the request content as sent, after any content coding.
///   Empty content counts as no content, so its hash is the empty string,
///   as in the reference encoder.
/// - `headers`: the fields the route lists, in that order, as (name, value
///   as received). Names are lower-cased here; an absent field has an empty
///   value.
#[must_use]
pub fn action_scope(method: &str, target: &str, content: &[u8], headers: &[(&str, &[u8])]) -> Scope {
    let mut buf = Vec::new();
    write_lp(&mut buf, method.as_bytes());
    write_lp(&mut buf, target.as_bytes());
    if content.is_empty() {
        write_lp(&mut buf, &[]);
    } else {
        write_lp(&mut buf, &sha256(content));
    }
    write_bigsize(&mut buf, len_u64(headers.len()));
    for (name, value) in headers {
        write_lp(&mut buf, name.to_ascii_lowercase().as_bytes());
        write_lp(&mut buf, value);
    }
    Scope(tagged_hash(tags::SCOPE_HTTP, &buf))
}

/// The HTTP route scope of a manifest route.
#[must_use]
pub fn route_scope(origin: &str, route_id: &str) -> Scope {
    let mut buf = Vec::new();
    write_lp(&mut buf, origin.as_bytes());
    write_lp(&mut buf, route_id.as_bytes());
    Scope(tagged_hash(tags::ROUTE_HTTP, &buf))
}

/// The scope `target`: the manifest origin followed by the request-target in
/// origin form, unchanged. Using the manifest origin keeps the scope the same
/// behind a TLS-terminating front.
#[must_use]
pub fn target(manifest_origin: &str, request_target: &str) -> String {
    let mut t = String::with_capacity(manifest_origin.len() + request_target.len());
    t.push_str(manifest_origin);
    t.push_str(request_target);
    t
}
