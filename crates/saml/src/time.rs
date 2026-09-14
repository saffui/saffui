use chrono::{DateTime, NaiveDateTime};

/// A SAML time read: `xs:dateTime` in UTC, fractional seconds allowed, with a
/// `Z` or no zone at all. An offset is refused rather than converted.
pub(crate) fn instant_of(text: &str) -> Option<i64> {
    let local = text.strip_suffix('Z').unwrap_or(text);
    NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|instant| instant.and_utc().timestamp())
}

/// A SAML time written: whole seconds in UTC, with the `Z` every party reads.
pub(crate) fn written_instant(seconds: i64) -> Option<String> {
    DateTime::from_timestamp(seconds, 0)
        .map(|instant| instant.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::{instant_of, written_instant};

    /// A written time reads back to the same second, and a second no calendar
    /// holds is not written.
    #[test]
    fn a_written_time_reads_back() {
        let written = written_instant(1_789_372_800).expect("a time");
        assert_eq!(written, "2026-09-14T08:00:00Z");
        assert_eq!(instant_of(&written), Some(1_789_372_800));
        assert_eq!(written_instant(i64::MAX), None);
    }
}
