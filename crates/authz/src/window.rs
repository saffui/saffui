//! One instant against one window.
//!
//! Whether the window is one any instant could satisfy is a separate question,
//! answered by `TimeWindow::defect` in the model and asked before this. What is
//! left here is the comparison.

use chrono::{DateTime, Datelike, Timelike, Utc};
use models::entities::authz::TimeWindow;

/// Whether the instant falls inside the window, or `None` when it cannot be
/// placed against it.
///
/// The two epoch bounds are one sided by design: a policy in force from a date
/// with no end is an ordinary thing to write. The five calendar pairs are not,
/// and a half stated one never reaches here, so each is either unconstrained or
/// a closed interval.
pub(crate) fn within(window: &TimeWindow, now: DateTime<Utc>) -> Option<bool> {
    let seconds = now.timestamp();
    let bounded = window.not_before.is_some() || window.not_on_or_after.is_some();
    if bounded && seconds < 0 {
        // An instant before the epoch cannot be compared with a bound that
        // counts seconds after it. Nothing to answer rather than outside.
        return None;
    }
    let seconds = seconds.max(0) as u64;

    // Inclusive below, exclusive above, so two windows written back to back
    // meet without overlapping and without leaving a second between them.
    if let Some(from) = window.not_before
        && seconds < from
    {
        return Some(false);
    }
    if let Some(until) = window.not_on_or_after
        && seconds >= until
    {
        return Some(false);
    }

    let inside = closed(now.year().max(0) as u64, window.year, window.year_end)
        && closed(u64::from(now.month()), window.month, window.month_end)
        && closed(
            u64::from(now.day()),
            window.day_of_month,
            window.day_of_month_end,
        )
        && closed(u64::from(now.hour()), window.hour, window.hour_end)
        && closed(u64::from(now.minute()), window.minute, window.minute_end);
    Some(inside)
}

/// A closed interval, or no constraint at all.
///
/// The half stated cases are absent because they are refused as a defect. One
/// end alone reads as an exact value to one administrator and as an open range
/// to another, and the row cannot say which was meant.
fn closed(value: u64, start: Option<u64>, end: Option<u64>) -> bool {
    match (start, end) {
        (Some(start), Some(end)) => value >= start && value <= end,
        _ => true,
    }
}
