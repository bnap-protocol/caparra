//! Meters: how many units an application's answer used (draft-00 7).

/// The count at JSON pointer `pointer` in a JSON answer: a non-negative
/// integer, or an error that settles the action FAILED (an answer that
/// cannot be metered is never given out for free).
pub fn count(pointer: &str, content_type: Option<&str>, body: &[u8]) -> Result<u64, String> {
    let json = content_type.is_some_and(|c| {
        let essence = c.split(';').next().unwrap_or("").trim();
        essence.eq_ignore_ascii_case("application/json")
    });
    if !json {
        return Err(format!(
            "the answer is {}, not application/json",
            content_type.unwrap_or("untyped")
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("the answer is not JSON: {e}"))?;
    v.pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("the answer has no non-negative integer at {pointer}"))
}

/// True when an OpenAI-compatible request asks for a streamed answer
/// (`"stream": true`).
#[must_use]
pub fn asks_for_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_usage_total_tokens() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":840,"total_tokens":850}}"#;
        let p = "/usage/total_tokens";
        assert_eq!(
            count(p, Some("application/json; charset=utf-8"), body),
            Ok(850)
        );
        assert!(count(p, Some("text/event-stream"), body).is_err());
        assert!(count(p, None, body).is_err());
        assert!(
            count(
                p,
                Some("application/json"),
                br#"{"usage":{"total_tokens":-1}}"#
            )
            .is_err()
        );
        assert!(
            count(
                p,
                Some("application/json"),
                br#"{"usage":{"total_tokens":"9"}}"#
            )
            .is_err()
        );
        assert!(count(p, Some("application/json"), b"{}").is_err());
    }

    #[test]
    fn spots_stream_requests() {
        assert!(asks_for_stream(br#"{"stream":true}"#));
        assert!(!asks_for_stream(br#"{"stream":false}"#));
        assert!(!asks_for_stream(b"not json"));
    }
}
