//! RFC 3339 timestamps in UTC, to the second: `YYYY-MM-DDTHH:MM:SSZ`.

/// Formats Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian,
/// UTC), the form the Payment scheme uses for `expires` and receipts.
#[must_use]
pub fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Days to a civil date (H. Hinnant's algorithm), in unsigned arithmetic:
    // day 0 is 1970-01-01, which is day 719,468 after 0000-03-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn known_instants_format_as_utc() {
        for (t, s) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_736_942_700, "2025-01-15T12:05:00Z"),
            (1_791_700_000, "2026-10-11T06:26:40Z"),
            (4_102_444_799, "2099-12-31T23:59:59Z"),
        ] {
            assert_eq!(rfc3339(t), s);
        }
    }
}
