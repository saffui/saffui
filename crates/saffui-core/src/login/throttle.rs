//! The brake on guesses, checked before any password is hashed.
//!
//! Three counters, kept per realm in buckets of five minutes. What one
//! address may attempt, whatever names it types: a hash is ours to pay, and
//! an address that types a new name each time would otherwise never be
//! slowed. What one address failed for one name: a few guesses, then that
//! address is locked out of that name, and nobody else is. What one name
//! failed from everywhere: a much higher bound, against guesses spread over
//! many addresses. A counter is kept by a keyed digest, whether or not the
//! name is someone's: a locked name tells nothing about who exists.

use std::net::IpAddr;

use time::{Duration, OffsetDateTime};

/// Failures are counted in buckets of this many seconds.
const BUCKET_SECONDS: i64 = 300;

/// How many failures the current bucket and the one before may hold
/// together before every attempt is refused.
pub const MAX_RECENT_FAILURES: u32 = 5;

/// How many times one address may try to sign in to a realm in the window.
pub const MAX_RECENT_ATTEMPTS_PER_ADDRESS: u32 = 30;

/// How many failures a name may gather from every address together.
pub const MAX_RECENT_FAILURES_PER_NAME: u32 = 50;

/// The start of the bucket an instant falls in.
#[must_use]
pub fn start_bucket(now: OffsetDateTime) -> OffsetDateTime {
    let seconds = now.unix_timestamp();
    OffsetDateTime::from_unix_timestamp(seconds - seconds.rem_euclid(BUCKET_SECONDS)).unwrap_or(now)
}

/// The start of the oldest bucket that still counts at `now`.
#[must_use]
pub fn start_window(now: OffsetDateTime) -> OffsetDateTime {
    start_bucket(now) - Duration::seconds(BUCKET_SECONDS)
}

#[must_use]
pub fn is_locked(recent_failures: u32) -> bool {
    recent_failures >= MAX_RECENT_FAILURES
}

/// What an address is counted as, by every counter of the realm: itself for
/// IPv4, its /64 for IPv6, the network one subscriber is given whole. An
/// IPv4 address written as IPv6 (`::ffff:a.b.c.d`) is counted as itself.
#[must_use]
pub fn write_address_bucket(address: IpAddr) -> String {
    match address.to_canonical() {
        IpAddr::V6(address) => {
            let [a, b, c, d, ..] = address.segments();
            format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
        }
        address @ IpAddr::V4(_) => address.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use std::net::IpAddr;

    use super::{is_locked, start_bucket, start_window, write_address_bucket};

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).expect("an instant in range")
    }

    #[test]
    fn an_instant_falls_in_the_five_minute_bucket_that_holds_it() {
        assert_eq!(start_bucket(at(1_200)), at(1_200));
        assert_eq!(start_bucket(at(1_499)), at(1_200));
        assert_eq!(start_bucket(at(1_500)), at(1_500));
    }

    #[test]
    fn the_window_is_the_current_bucket_and_the_one_before() {
        assert_eq!(start_window(at(1_499)), at(900));
        assert_eq!(start_window(at(1_500)), at(1_200));
    }

    #[test]
    fn the_fifth_failure_locks() {
        assert!(!is_locked(4));
        assert!(is_locked(5));
    }

    #[test]
    fn an_ipv6_network_of_one_subscriber_is_counted_as_one_address() {
        let read = |text: &str| text.parse::<IpAddr>().expect("an address");
        assert_eq!(
            write_address_bucket(read("2001:db8:1:2:aaaa::1")),
            write_address_bucket(read("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            write_address_bucket(read("2001:db8:1:2::1")),
            write_address_bucket(read("2001:db8:1:3::1"))
        );
        assert_eq!(
            write_address_bucket(read("::ffff:203.0.113.7")),
            write_address_bucket(read("203.0.113.7")),
            "an IPv4 address a dual listener writes as IPv6 is itself"
        );
        assert_ne!(
            write_address_bucket(read("203.0.113.7")),
            write_address_bucket(read("203.0.113.8"))
        );
    }
}
