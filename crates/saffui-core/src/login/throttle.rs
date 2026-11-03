//! The brake on guesses, checked before any password is hashed.
//!
//! Counters kept per realm, by a keyed digest, whether or not the name is
//! someone's: a locked name tells nothing about who exists. In buckets of
//! five minutes, over ten: what one address may attempt, whatever names it
//! types, since a hash is ours to pay; what one address failed for one name,
//! a few guesses before that address is locked out of that name and nobody
//! else is; what one name failed from everywhere, a much higher bound. In
//! buckets of an hour, over a day: what one name failed, which no window
//! resets. A browser where the person signed in before is counted apart, by
//! its mark, and the counts of the name do not lock it out.

use std::net::IpAddr;

use time::{Duration, OffsetDateTime};

use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::UnitOfWork;

/// Failures are counted in buckets of this many seconds.
const BUCKET_SECONDS: i64 = 300;

/// How many failures the current bucket and the one before may hold
/// together before every attempt is refused.
pub const MAX_RECENT_FAILURES: u32 = 5;

/// How many times one address may try to sign in to a realm in the window.
pub const MAX_RECENT_ATTEMPTS_PER_ADDRESS: u32 = 30;

/// How many failures a name may gather from every address together.
pub const MAX_RECENT_FAILURES_PER_NAME: u32 = 50;

/// The long horizon is counted in buckets of an hour, over a day.
const LONG_BUCKET_SECONDS: i64 = 3_600;
const LONG_WINDOW_BUCKETS: i64 = 24;

/// How many failures a name may gather in a day, whatever the windows: the
/// short window alone would let guesses resume every ten minutes. Nothing
/// resets it but time: a sign-in that did would give the guesses back.
pub const MAX_DAILY_FAILURES: u32 = 100;

/// How many failures a browser that signed in before may make in a day,
/// apart from the name. Its mark can be left on a shared machine.
pub const MAX_DAILY_FAILURES_PER_BROWSER: u32 = 20;

/// How many sign-ins one address may leave waiting in a realm in the
/// window, before any session: each keeps a row for ten minutes, and asking
/// for one takes nothing but a request.
pub const MAX_PENDING_SIGN_INS_PER_ADDRESS: u32 = 60;

/// The start of the bucket an instant falls in.
#[must_use]
pub fn start_bucket(now: OffsetDateTime) -> OffsetDateTime {
    let seconds = now.unix_timestamp();
    OffsetDateTime::from_unix_timestamp(seconds - seconds.rem_euclid(BUCKET_SECONDS)).unwrap_or(now)
}

/// The start of the hour an instant falls in, for the long horizon.
#[must_use]
pub fn start_long_bucket(now: OffsetDateTime) -> OffsetDateTime {
    let seconds = now.unix_timestamp();
    OffsetDateTime::from_unix_timestamp(seconds - seconds.rem_euclid(LONG_BUCKET_SECONDS))
        .unwrap_or(now)
}

/// The start of the oldest hour that still counts at `now`: a day of them.
#[must_use]
pub fn start_long_window(now: OffsetDateTime) -> OffsetDateTime {
    start_long_bucket(now) - Duration::seconds(LONG_BUCKET_SECONDS * (LONG_WINDOW_BUCKETS - 1))
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

/// The network an IPv6 address shares the hashers with, beyond its /64: its
/// /48, the network a site is given whole, 65536 subscribers of a /64 each.
/// An IPv4 address has none: each costs its holder alone.
#[must_use]
pub fn write_network_bucket(address: IpAddr) -> Option<String> {
    match address.to_canonical() {
        IpAddr::V6(address) => {
            let [a, b, c, ..] = address.segments();
            Some(format!("{a:x}:{b:x}:{c:x}::/48"))
        }
        IpAddr::V4(_) => None,
    }
}

/// Counts one more sign-in left waiting by the caller, in the unit of work
/// that keeps it, or refuses it once the address left too many in the
/// window. An address unknown is not counted, as the brake does not count it.
///
/// # Errors
///
/// Returns [`ErrorCode::SignInRequestsTooFrequent`], or the storage failure.
pub(crate) async fn admit_pending_sign_in(
    app: &App,
    work: &mut dyn UnitOfWork,
    caller: Option<IpAddr>,
) -> Result<(), Failure> {
    let Some(address) = caller.map(write_address_bucket) else {
        return Ok(());
    };
    let scope = work.scope();
    // A kind of its own, as each counter of the brake: no address counted
    // here is counted as an attempt to sign in.
    let mut written = vec![4_u8];
    written.extend_from_slice(address.as_bytes());
    written.push(0);
    let counter = app
        .sealer
        .digest_typed_name(scope.tenant().as_uuid(), scope.realm().as_uuid(), &written)
        .map_err(|_| Failure::new(ErrorCode::CryptoUnavailable))?;
    let now = app.now();
    if work
        .count_login_failures(&counter, start_window(now))
        .await?
        >= MAX_PENDING_SIGN_INS_PER_ADDRESS
    {
        return Err(Failure::new(ErrorCode::SignInRequestsTooFrequent));
    }
    work.record_login_failure(&counter, start_bucket(now))
        .await?;
    Ok(())
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
