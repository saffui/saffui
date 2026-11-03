use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Writes an instant as RFC 3339, in UTC.
#[must_use]
pub fn write_instant(instant: OffsetDateTime) -> String {
    instant
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Reads an instant written in RFC 3339.
#[must_use]
pub fn read_instant(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{read_instant, write_instant};

    #[test]
    fn an_instant_is_written_in_utc_with_its_fraction() {
        let instant = OffsetDateTime::from_unix_timestamp_nanos(1_767_268_800_123_456_000)
            .expect("an instant in range");

        assert_eq!(write_instant(instant), "2026-01-01T12:00:00.123456Z");
    }

    #[test]
    fn an_instant_is_read_back_from_what_it_was_written_as_and_nothing_else_is() {
        let instant = OffsetDateTime::from_unix_timestamp(1_767_268_800).expect("an instant");

        assert_eq!(read_instant(&write_instant(instant)), Some(instant));
        assert_eq!(
            read_instant("2026-01-01T13:00:00+01:00"),
            Some(instant),
            "an offset is read as the instant it names"
        );
        for text in ["2026-01-01", "1767268800", "tomorrow", ""] {
            assert_eq!(read_instant(text), None, "{text:?}");
        }
    }
}
