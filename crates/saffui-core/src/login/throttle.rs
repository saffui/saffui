//! The brake on guesses, checked before any password is hashed.
//!
//! Counters kept per realm, by a keyed digest, whether or not the name is
//! someone's: a locked name tells nothing about who exists. In buckets of
//! five minutes, over ten: what one address may attempt, whatever names it
//! types, which bounds the hashes, ours to pay; what one address failed for
//! one name, a few guesses before that address is locked out of that name
//! and nobody else is; what one name failed from everywhere, a much higher
//! bound. In buckets of an hour, over a day: what one name failed, which no
//! window resets. A browser where the person signed in before is counted
//! apart, by its mark, and the counts of the name do not lock it out. A code
//! hashes nothing and is not counted against its address: the lock of the
//! name bounds it, and so does its person, whose codes ten wrong in a row
//! suspend.

use std::net::IpAddr;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::login::device::{DeviceMark, MOST_MARKS};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

/// Failures are counted in buckets of this many seconds.
const BUCKET_SECONDS: i64 = 300;

/// How many failures the current bucket and the one before may hold
/// together before every attempt is refused.
pub const MAX_RECENT_FAILURES: u32 = 5;

/// How many times one address may try to sign in to a realm in the window.
pub const MAX_RECENT_ATTEMPTS_PER_ADDRESS: u32 = 30;

/// How many times a browser the realm knows may try in the window. Counted
/// under its mark, it is not held to the bound of an address it shares.
pub const MAX_RECENT_ATTEMPTS_PER_BROWSER: u32 = 30;

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

/// How many sign-ins one address, or one known browser, may leave waiting
/// in a realm in the window, before any session: each keeps a row for ten
/// minutes, and asking for one takes nothing but a request.
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

/// Digests what the brake counts under. Each kind starts with a byte of its
/// own, and each part ends with a byte no text holds: no name anybody types
/// is counted as an address, and no address as a name.
fn digest_counter(
    app: &App,
    scope: RealmScope,
    kind: u8,
    parts: &[&[u8]],
) -> Result<Vec<u8>, Failure> {
    let mut written = vec![kind];
    for part in parts {
        written.extend_from_slice(part);
        written.push(0);
    }
    app.sealer
        .digest_typed_name(scope.tenant().as_uuid(), scope.realm().as_uuid(), &written)
        .map_err(|_| Failure::new(ErrorCode::CryptoUnavailable))
}

/// The two counters that lock a name for everyone: the window, and the day.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the sealer cannot digest.
pub(crate) fn digest_name_locks(
    app: &App,
    scope: RealmScope,
    typed: &str,
) -> Result<[Vec<u8>; 2], Failure> {
    let typed = typed.as_bytes();
    Ok([
        digest_counter(app, scope, 1, &[typed])?,
        digest_counter(app, scope, 5, &[typed])?,
    ])
}

/// The keys of a browser that signed in with this name before: its own
/// count, apart from the guesses made on the name from elsewhere.
struct BrowserCounters {
    device: Uuid,
    attempts: Vec<u8>,
    recent: Vec<u8>,
    today: Vec<u8>,
}

/// The counters one attempt on a name is counted under: the name, its
/// address, and the browser of the person when the realm knows it.
pub(crate) struct Brake {
    name: Vec<u8>,
    name_today: Vec<u8>,
    address: Option<Vec<u8>>,
    address_and_name: Option<Vec<u8>>,
    browser: Option<BrowserCounters>,
}

impl Brake {
    /// The counters of an attempt on what was typed, from `caller`. Kept
    /// under a key the database does not hold: people type passwords into
    /// the wrong field.
    pub(crate) fn of(
        app: &App,
        scope: RealmScope,
        typed: &str,
        caller: Option<IpAddr>,
    ) -> Result<Self, Failure> {
        let address = caller.map(write_address_bucket);
        let address = address.as_deref();
        let [name, name_today] = digest_name_locks(app, scope, typed)?;
        let typed = typed.as_bytes();
        Ok(Self {
            name,
            name_today,
            address: address
                .map(|address| digest_counter(app, scope, 2, &[address.as_bytes()]))
                .transpose()?,
            address_and_name: address
                .map(|address| digest_counter(app, scope, 3, &[address.as_bytes(), typed]))
                .transpose()?,
            browser: None,
        })
    }

    /// Counts the attempt under a browser the realm keeps for this person,
    /// apart from the name and from the address.
    pub(crate) fn count_browser_apart(
        &mut self,
        app: &App,
        scope: RealmScope,
        typed: &str,
        device: Uuid,
    ) -> Result<(), Failure> {
        let parts: [&[u8]; 2] = [device.as_bytes(), typed.as_bytes()];
        self.browser = Some(BrowserCounters {
            device,
            attempts: digest_counter(app, scope, 10, &[device.as_bytes()])?,
            recent: digest_counter(app, scope, 6, &parts)?,
            today: digest_counter(app, scope, 7, &parts)?,
        });
        Ok(())
    }

    /// The device of the browser counted apart, if any.
    pub(crate) fn browser(&self) -> Option<Uuid> {
        self.browser.as_ref().map(|browser| browser.device)
    }

    /// Counts an attempt against its address, or refuses it once the address
    /// tried too often in the window: a hash is ours to pay, whatever name is
    /// typed. A browser the realm knows is counted under its mark instead: an
    /// address it shares does not hold it.
    pub(crate) async fn admit(
        &self,
        work: &mut dyn UnitOfWork,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let (counter, most) = match &self.browser {
            Some(browser) => (Some(&browser.attempts), MAX_RECENT_ATTEMPTS_PER_BROWSER),
            None => (self.address.as_ref(), MAX_RECENT_ATTEMPTS_PER_ADDRESS),
        };
        let Some(counter) = counter else {
            return Ok(());
        };
        if work
            .count_login_failures(counter, start_window(now))
            .await?
            >= most
        {
            return Err(Failure::new(ErrorCode::HashingBusy));
        }
        work.record_login_failure(counter, start_bucket(now))
            .await?;
        Ok(())
    }

    /// Tells whether the name is locked for this attempt. A known browser
    /// answers for its own failures, and only for them.
    pub(crate) async fn is_name_locked(
        &self,
        work: &mut dyn UnitOfWork,
        now: OffsetDateTime,
    ) -> Result<bool, Failure> {
        let (window, day) = (start_window(now), start_long_window(now));
        if let Some(browser) = &self.browser {
            return Ok(
                is_locked(work.count_login_failures(&browser.recent, window).await?)
                    || work.count_login_failures(&browser.today, day).await?
                        >= MAX_DAILY_FAILURES_PER_BROWSER,
            );
        }
        let failed_for_the_name = work.count_login_failures(&self.name, window).await?;
        let failed_today = work.count_login_failures(&self.name_today, day).await?;
        let recently = match &self.address_and_name {
            // Known addresses are held to a few guesses each. The name alone is
            // held to a bound that guesses spread over many addresses reach.
            Some(by_both) => {
                is_locked(work.count_login_failures(by_both, window).await?)
                    || failed_for_the_name >= MAX_RECENT_FAILURES_PER_NAME
            }
            None => is_locked(failed_for_the_name),
        };
        Ok(recently || failed_today >= MAX_DAILY_FAILURES)
    }

    /// Counts a failed guess. Every failure counts in the day of the name: a
    /// known browser is spared the lock, not the count.
    pub(crate) async fn record_failure(
        &self,
        work: &mut dyn UnitOfWork,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let (bucket, hour) = (start_bucket(now), start_long_bucket(now));
        work.record_login_failure(&self.name_today, hour).await?;
        if let Some(browser) = &self.browser {
            work.record_login_failure(&browser.recent, bucket).await?;
            work.record_login_failure(&browser.today, hour).await?;
        } else {
            work.record_login_failure(&self.name, bucket).await?;
            if let Some(by_both) = &self.address_and_name {
                work.record_login_failure(by_both, bucket).await?;
            }
        }
        Ok(())
    }

    /// Clears the browser that proved the person. The count of the day of
    /// the name ages alone, so that a sign-in gives no guess back.
    pub(crate) async fn forget_browser_failures(
        &self,
        work: &mut dyn UnitOfWork,
    ) -> Result<(), Failure> {
        if let Some(browser) = &self.browser {
            work.forget_login_failures(&browser.recent).await?;
            work.forget_login_failures(&browser.today).await?;
        }
        Ok(())
    }
}

/// Counts one more sign-in left waiting by the caller, in the unit of work
/// that keeps it, or refuses it once the caller left too many in the window.
/// A browser the realm keeps for someone is counted under its device: an
/// address it shares does not hold it. Its mark is not proven here, since no
/// name is typed yet, but its device is a random number only that browser
/// was given, and a device the realm does not keep counts for nothing. An
/// address unknown is not counted, as the brake does not count it.
///
/// # Errors
///
/// Returns [`ErrorCode::SignInRequestsTooFrequent`], or the storage failure.
pub(crate) async fn admit_pending_sign_in(
    app: &App,
    work: &mut dyn UnitOfWork,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<(), Failure> {
    let now = app.now();
    let devices: Vec<Uuid> = known_browsers
        .iter()
        .take(MOST_MARKS)
        .map(|mark| mark.device)
        .collect();
    let live = if devices.is_empty() {
        Vec::new()
    } else {
        work.read_live_browsers(&devices, now).await?
    };
    // Of the marks the realm keeps, the first of the cookie: the latest.
    let kept = devices
        .into_iter()
        .find(|device| live.iter().any(|browser| browser.device == *device));
    // A kind of its own for each, as each counter of the brake: nothing
    // counted here is counted as an attempt to sign in.
    let written = match (kept, caller) {
        (Some(device), _) => [&[11_u8][..], device.as_bytes()].concat(),
        (None, Some(address)) => {
            [&[4_u8][..], write_address_bucket(address).as_bytes(), &[0]].concat()
        }
        (None, None) => return Ok(()),
    };
    let scope = work.scope();
    let counter = app
        .sealer
        .digest_typed_name(scope.tenant().as_uuid(), scope.realm().as_uuid(), &written)
        .map_err(|_| Failure::new(ErrorCode::CryptoUnavailable))?;
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
