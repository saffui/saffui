use std::net::IpAddr;

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::create::translate_hashing_failure;
use crate::directory::{PASSWORD_MAX_BYTES, Person, normalize_username};
use crate::error::{ErrorCode, Failure};
use crate::login::device::{DeviceMark, issue_device_mark, recognize_device_mark};
use crate::login::session::{SessionTicket, open_session};
use crate::login::throttle::{
    MAX_DAILY_FAILURES, MAX_DAILY_FAILURES_PER_BROWSER, MAX_RECENT_ATTEMPTS_PER_ADDRESS,
    MAX_RECENT_FAILURES_PER_NAME, is_locked, start_bucket, start_long_bucket, start_long_window,
    start_window, write_address_bucket, write_network_bucket,
};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// A person who just signed in, the ticket of their new session, and the
/// mark their browser keeps from now on.
#[derive(Debug)]
pub struct SignedIn {
    pub person: Person,
    pub session: Uuid,
    pub ticket: SessionTicket,
    pub device_mark: DeviceMark,
}

/// The keys the brake counts under, for one attempt.
struct Counters {
    name: Vec<u8>,
    name_today: Vec<u8>,
    address: Option<Vec<u8>>,
    address_and_name: Option<Vec<u8>>,
}

/// The keys of a browser that signed in with this name before: its own
/// count, apart from the guesses made on the name from elsewhere.
struct DeviceCounters {
    recent: Vec<u8>,
    today: Vec<u8>,
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

fn name_counters(
    app: &App,
    scope: RealmScope,
    typed: &str,
    caller: Option<IpAddr>,
) -> Result<Counters, Failure> {
    let address = caller.map(write_address_bucket);
    let address = address.as_deref();
    let [name, name_today] = digest_name_locks(app, scope, typed)?;
    let typed = typed.as_bytes();
    Ok(Counters {
        name,
        name_today,
        address: address
            .map(|address| digest_counter(app, scope, 2, &[address.as_bytes()]))
            .transpose()?,
        address_and_name: address
            .map(|address| digest_counter(app, scope, 3, &[address.as_bytes(), typed]))
            .transpose()?,
    })
}

fn device_counters(
    app: &App,
    scope: RealmScope,
    typed: &str,
    device: Uuid,
) -> Result<DeviceCounters, Failure> {
    let parts: [&[u8]; 2] = [device.as_bytes(), typed.as_bytes()];
    Ok(DeviceCounters {
        recent: digest_counter(app, scope, 6, &parts)?,
        today: digest_counter(app, scope, 7, &parts)?,
    })
}

/// Counts an attempt against its address, or refuses it once the address
/// tried too often in the window: a hash is ours to pay, whatever name is
/// typed.
async fn admit_attempt(
    work: &mut dyn UnitOfWork,
    counters: &Counters,
    now: OffsetDateTime,
) -> Result<(), Failure> {
    let Some(counter) = &counters.address else {
        return Ok(());
    };
    if work
        .count_login_failures(counter, start_window(now))
        .await?
        >= MAX_RECENT_ATTEMPTS_PER_ADDRESS
    {
        return Err(Failure::new(ErrorCode::HashingBusy));
    }
    work.record_login_failure(counter, start_bucket(now))
        .await?;
    Ok(())
}

/// Signs a person in with a username and a password.
///
/// An unknown name, a wrong password, a disabled person and a locked name
/// are one refusal, after the same work: the unknown name is verified too,
/// against a hash nobody's password matches. A locked name is refused before
/// anything is hashed, and so is an address that spent what it may attempt.
/// No transaction is held while the password is hashed.
///
/// A browser that brings the mark of an earlier sign-in with this name is
/// counted apart: guesses made on the name from elsewhere do not lock it
/// out, and its own failures do not lock the name for anyone else.
///
/// # Errors
///
/// Returns [`ErrorCode::SignInFailed`] for every refusal above but the last,
/// [`ErrorCode::HashingBusy`] when the address spent its attempts, or the
/// realm or the /48 of an IPv6 caller runs its share of hashes already, or
/// the storage failure.
pub async fn sign_in(
    app: &App,
    scope: RealmScope,
    typed_name: &str,
    password: Secret,
    caller: Option<IpAddr>,
    known_browser: Option<&DeviceMark>,
) -> Result<SignedIn, Failure> {
    let refused = || Failure::new(ErrorCode::SignInFailed);
    let username = normalize_username(typed_name).ok();
    // A password past the bound is no guess: it cannot be right. Nothing is
    // hashed for it and nothing is counted, so it locks nobody out.
    if password.expose().len() > PASSWORD_MAX_BYTES {
        return Err(refused());
    }
    // What was typed, not who it is: the brake holds for names nobody has.
    // Kept under a key the database does not hold: people type passwords
    // into the wrong field.
    let typed = typed_name.trim().to_lowercase();
    let counters = name_counters(app, scope, &typed, caller)?;
    let now = app.now();
    let (window, day) = (start_window(now), start_long_window(now));
    let device = match known_browser {
        Some(mark) if recognize_device_mark(app, scope, mark, &typed, now)? => {
            Some(device_counters(app, scope, &typed, mark.device)?)
        }
        _ => None,
    };

    // One unit of work reads the counters and counts this attempt against
    // its address. It commits before anything is hashed: attempts made
    // together are each counted, and none holds a transaction meanwhile.
    let mut work = app.storage.begin(scope).await?;
    admit_attempt(work.as_mut(), &counters, now).await?;
    // A known browser answers for its own failures, and only for them.
    let locked = if let Some(device) = &device {
        is_locked(work.count_login_failures(&device.recent, window).await?)
            || work.count_login_failures(&device.today, day).await?
                >= MAX_DAILY_FAILURES_PER_BROWSER
    } else {
        let failed_for_the_name = work.count_login_failures(&counters.name, window).await?;
        let failed_today = work.count_login_failures(&counters.name_today, day).await?;
        let recently = match &counters.address_and_name {
            // Known addresses are held to a few guesses each. The name alone
            // is held to a bound that guesses spread over many addresses reach.
            Some(by_both) => {
                is_locked(work.count_login_failures(by_both, window).await?)
                    || failed_for_the_name >= MAX_RECENT_FAILURES_PER_NAME
            }
            None => is_locked(failed_for_the_name),
        };
        recently || failed_today >= MAX_DAILY_FAILURES
    };
    let person = match (&username, locked) {
        (Some(username), false) => work.read_person_by_username(username).await?,
        _ => None,
    };
    // Read for an unknown name too, under an identifier no person has: the
    // two paths make as many trips to the storage, and take as long.
    let reading_for = person.as_ref().map_or(Uuid::nil(), |person| person.id);
    let stored = work.read_password(reading_for).await?;
    work.commit().await?;
    if locked {
        return Err(refused());
    }

    let against = match stored {
        Some(hash) => hash,
        None => app.read_decoy_hash().await?,
    };
    // Held for the hash alone: the realm, and the /48 of an IPv6 caller,
    // run no more than their share at once, and an idle one is never refused.
    let verified = {
        let _share = app
            .hashing_shares
            .take(scope.realm(), caller.and_then(write_network_bucket))
            .ok_or_else(|| Failure::new(ErrorCode::HashingBusy))?;
        app.hasher
            .verify_password(password, against)
            .await
            .map_err(translate_hashing_failure)?
    };

    let mut work = app.storage.begin(scope).await?;
    let Some(person) = person.filter(|person| verified && person.enabled) else {
        let (bucket, hour) = (start_bucket(now), start_long_bucket(now));
        // Every failure counts in the day of the name: a known browser is
        // spared the lock, not the count.
        work.record_login_failure(&counters.name_today, hour)
            .await?;
        if let Some(device) = &device {
            work.record_login_failure(&device.recent, bucket).await?;
            work.record_login_failure(&device.today, hour).await?;
        } else {
            work.record_login_failure(&counters.name, bucket).await?;
            if let Some(by_both) = &counters.address_and_name {
                work.record_login_failure(by_both, bucket).await?;
            }
        }
        work.commit().await?;
        return Err(refused());
    };
    // The browser that proved the password is cleared; the count of the day
    // of the name ages alone, so that a sign-in gives no guess back.
    if let Some(device) = &device {
        work.forget_login_failures(&device.recent).await?;
        work.forget_login_failures(&device.today).await?;
    }
    let (session, ticket) = open_session(app, work.as_mut(), person.id).await?;
    let opened =
        json!({ "person_id": person.id.to_string(), "session_id": session.id.to_string() });
    record_event(app, work.as_mut(), EventKind::SessionOpened, opened).await?;
    work.commit().await?;
    Ok(SignedIn {
        person,
        session: session.id,
        ticket,
        device_mark: issue_device_mark(app, scope, &typed)?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::sign_in;
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::login::device::DeviceMark;
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::testkit::clock::FixedClock;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::testkit::memory::MemoryStorage;

    const PASSWORD: &str = "correct horse battery";

    fn attempt(
        app: &App,
        scope: RealmScope,
        name: &str,
        password: &str,
    ) -> Result<String, ErrorCode> {
        complete(sign_in(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            None,
            None,
        ))
        .map(|signed_in| signed_in.person.username)
        .map_err(|failure| failure.code)
    }

    #[test]
    fn the_right_password_opens_a_session_whatever_the_case_of_the_name() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        assert_eq!(
            attempt(&app, scope, " Ada ", PASSWORD),
            Ok("ada".to_owned())
        );
        let kinds: Vec<String> = storage
            .read_audit_envelopes(scope.realm())
            .iter()
            .filter_map(|event| event["kind"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(kinds.last().map(String::as_str), Some("session.opened"));
    }

    #[test]
    fn a_wrong_password_an_unknown_name_and_a_disabled_person_are_one_refusal() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        complete(create_person(&app, scope, "bob", PASSWORD));
        storage.disable_person("bob");
        let refused = Err(ErrorCode::SignInFailed);

        assert_eq!(attempt(&app, scope, "ada", "not the password"), refused);
        assert_eq!(attempt(&app, scope, "nobody", PASSWORD), refused);
        assert_eq!(attempt(&app, scope, "not a name!", PASSWORD), refused);
        assert_eq!(attempt(&app, scope, "bob", PASSWORD), refused);
        assert_eq!(attempt(&app, scope, "ada", &"a".repeat(1025)), refused);
    }

    #[test]
    fn five_failures_lock_a_name_even_for_the_right_password_until_the_window_has_passed() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        for _ in 0..5 {
            assert_eq!(
                attempt(&app, scope, "ada", "a guess"),
                Err(ErrorCode::SignInFailed)
            );
        }
        assert_eq!(
            attempt(&app, scope, "ada", PASSWORD),
            Err(ErrorCode::SignInFailed),
            "locked: the right password is refused like any other"
        );

        clock.advance(Duration::from_mins(10));
        assert_eq!(attempt(&app, scope, "ada", PASSWORD), Ok("ada".to_owned()));
    }

    #[test]
    fn the_brake_counts_what_was_typed_so_a_name_nobody_has_locks_too() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        for _ in 0..5 {
            let _ = attempt(&app, scope, "nobody", "a guess");
        }
        let units_before = storage.count_units_of_work();
        assert_eq!(
            attempt(&app, scope, "nobody", "a guess"),
            Err(ErrorCode::SignInFailed)
        );
        assert_eq!(
            storage.count_units_of_work(),
            units_before + 1,
            "a locked name is refused after one read, before anything is hashed or written"
        );
        assert_eq!(
            attempt(&app, scope, "ada", PASSWORD),
            Ok("ada".to_owned()),
            "one name locked does not lock another"
        );
    }

    #[test]
    fn a_password_too_long_to_be_one_is_refused_and_locks_nobody_out() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let too_long = "x".repeat(1025);

        for _ in 0..8 {
            assert_eq!(
                attempt(&app, scope, "ada", &too_long),
                Err(ErrorCode::SignInFailed)
            );
        }

        assert_eq!(attempt(&app, scope, "ada", PASSWORD), Ok("ada".to_owned()));
    }

    fn attempt_from(
        app: &App,
        scope: RealmScope,
        address: &str,
        name: &str,
        password: &str,
    ) -> Result<String, ErrorCode> {
        let caller = Some(address.parse().expect("an address"));
        complete(sign_in(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            caller,
            None,
        ))
        .map(|signed_in| signed_in.person.username)
        .map_err(|failure| failure.code)
    }

    #[test]
    fn an_address_that_guessed_too_much_is_locked_out_of_that_name_and_nobody_else_is() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        complete(create_person(&app, scope, "bob", PASSWORD));
        let refused = Err(ErrorCode::SignInFailed);

        for _ in 0..5 {
            assert_eq!(
                attempt_from(&app, scope, "203.0.113.7", "ada", "a guess"),
                refused
            );
        }

        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "ada", PASSWORD),
            refused,
            "the address that guessed is locked out, right password included"
        );
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "the person still signs in from where they are"
        );
        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "bob", PASSWORD),
            Ok("bob".to_owned()),
            "and the address is locked out of that one name only"
        );
    }

    #[test]
    fn an_address_spends_its_attempts_whatever_names_it_types_and_then_nothing_is_hashed() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        for round in 0..30 {
            assert_eq!(
                attempt_from(
                    &app,
                    scope,
                    "203.0.113.7",
                    &format!("nobody-{round}"),
                    "a guess"
                ),
                Err(ErrorCode::SignInFailed)
            );
        }
        let units_before = storage.count_units_of_work();

        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "nobody-new", "a guess"),
            Err(ErrorCode::HashingBusy),
            "a new name each time is no way around the brake"
        );
        assert_eq!(
            storage.count_units_of_work(),
            units_before + 1,
            "the refusal reads the counter and stops: nothing is hashed, nothing recorded"
        );
        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "ada", PASSWORD),
            Err(ErrorCode::HashingBusy)
        );
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "another address is not slowed"
        );
    }

    #[test]
    fn a_network_hashes_no_more_than_its_share_and_its_subscribers_still_sign_in() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let other = complete(create_realm(&app, "globex"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        // A guess from each of 300 /64 networks of one /48 closes nothing:
        // the network is bounded by the hashes it runs at once, not by a count.
        for subscriber in 0..300 {
            let address = format!("2001:db8:7:{subscriber:x}::1");
            assert_eq!(
                attempt_from(
                    &app,
                    scope,
                    &address,
                    &format!("nobody-{subscriber}"),
                    "a guess"
                ),
                Err(ErrorCode::SignInFailed)
            );
        }
        assert_eq!(
            attempt_from(&app, scope, "2001:db8:7:ffff::1", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "a /64 of that /48 still signs in"
        );

        // Four hashers: the one a /48 may hold is taken, from another realm.
        let held = app
            .hashing_shares
            .take(other.realm(), Some("2001:db8:7::/48".to_owned()))
            .expect("a share");
        assert_eq!(
            attempt_from(&app, scope, "2001:db8:7:ffff::1", "ada", PASSWORD),
            Err(ErrorCode::HashingBusy),
            "the /48 runs its share already"
        );
        assert_eq!(
            attempt_from(&app, scope, "2001:db8:8::1", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "another /48 is not slowed"
        );
        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "ada", PASSWORD),
            Ok("ada".to_owned())
        );
        drop(held);
        assert_eq!(
            attempt_from(&app, scope, "2001:db8:7:ffff::1", "ada", PASSWORD),
            Ok("ada".to_owned())
        );
    }

    #[test]
    fn a_realm_hashes_no_more_than_its_share_and_another_realm_still_signs_in() {
        let (app, _storage) = MemoryStorage::wire();
        let flooded = complete(create_realm(&app, "acme"));
        let other = complete(create_realm(&app, "globex"));
        complete(create_person(&app, flooded, "ada", PASSWORD));
        complete(create_person(&app, other, "ada", PASSWORD));
        // Four hashers: the two a realm may hold are taken.
        let held = [
            app.hashing_shares
                .take(flooded.realm(), None)
                .expect("a share"),
            app.hashing_shares
                .take(flooded.realm(), None)
                .expect("a share"),
        ];

        assert_eq!(
            attempt(&app, flooded, "ada", PASSWORD),
            Err(ErrorCode::HashingBusy)
        );
        assert_eq!(attempt(&app, other, "ada", PASSWORD), Ok("ada".to_owned()));
        drop(held);
        assert_eq!(
            attempt(&app, flooded, "ada", PASSWORD),
            Ok("ada".to_owned())
        );
    }

    #[test]
    fn guesses_spread_over_many_addresses_lock_the_name_for_everyone_in_the_end() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        for host in 0..50 {
            let address = format!("203.0.113.{host}");
            assert_eq!(
                attempt_from(&app, scope, &address, "ada", "a guess"),
                Err(ErrorCode::SignInFailed)
            );
        }

        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Err(ErrorCode::SignInFailed)
        );
    }

    /// Signs in from a browser that may bring the mark of an earlier sign-in.
    fn attempt_with_mark(
        app: &App,
        scope: RealmScope,
        address: &str,
        name: &str,
        password: &str,
        mark: Option<&DeviceMark>,
    ) -> Result<super::SignedIn, ErrorCode> {
        let caller = Some(address.parse().expect("an address"));
        complete(sign_in(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            caller,
            mark,
        ))
        .map_err(|failure| failure.code)
    }

    /// A hundred guesses on `ada`, five a window from addresses each used
    /// once: under every short bound, and spread over a few hours.
    fn guess_a_hundred_times(app: &App, scope: RealmScope, clock: &FixedClock) {
        for round in 0..20 {
            for host in 0..5 {
                let address = format!("203.0.{round}.{host}");
                assert_eq!(
                    attempt_from(app, scope, &address, "ada", "a guess"),
                    Err(ErrorCode::SignInFailed)
                );
            }
            clock.advance(Duration::from_mins(11));
        }
    }

    #[test]
    fn guesses_spread_over_windows_and_addresses_meet_a_bound_of_the_day() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));

        guess_a_hundred_times(&app, scope, &clock);

        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Err(ErrorCode::SignInFailed),
            "a hundred failures in a day lock the name, windows apart or not"
        );
        clock.advance(Duration::from_hours(24));
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Ok("ada".to_owned())
        );
    }

    #[test]
    fn a_browser_that_signed_in_before_passes_a_lock_that_holds_every_other_until_the_day_ends() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let home = attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, None)
            .expect("a first sign-in")
            .device_mark;

        guess_a_hundred_times(&app, scope, &clock);

        assert_eq!(
            attempt_with_mark(&app, scope, "198.51.100.10", "ada", PASSWORD, None).map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "a browser that never signed in is held by the lock"
        );
        let again = attempt_with_mark(&app, scope, "198.51.100.10", "ada", PASSWORD, Some(&home))
            .expect("the browser of the person passes");
        assert_ne!(again.device_mark, home, "each sign-in gives a new mark");
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.11", "ada", PASSWORD),
            Err(ErrorCode::SignInFailed),
            "a sign-in gives no guess back: the count of the day ages alone"
        );
        clock.advance(Duration::from_hours(24));
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.11", "ada", PASSWORD),
            Ok("ada".to_owned())
        );
    }

    #[test]
    fn a_known_browser_answers_for_its_own_failures_and_for_its_name_only() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        complete(create_person(&app, scope, "bob", PASSWORD));
        let mark = attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, None)
            .expect("a first sign-in")
            .device_mark;

        for _ in 0..5 {
            assert_eq!(
                attempt_with_mark(&app, scope, "198.51.100.9", "ada", "a typo", Some(&mark))
                    .map(|_| ()),
                Err(ErrorCode::SignInFailed)
            );
        }
        assert_eq!(
            attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, Some(&mark))
                .map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "five failures lock that browser out of the name"
        );
        assert_eq!(
            attempt_from(&app, scope, "198.51.100.9", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "the same address without the mark passes: the failures were the browser's alone"
        );

        // Bob locked from one address: the mark of Ada does not pass it.
        for _ in 0..5 {
            let _ = attempt_from(&app, scope, "198.51.100.21", "bob", "a guess");
        }
        assert_eq!(
            attempt_with_mark(&app, scope, "198.51.100.21", "bob", PASSWORD, Some(&mark))
                .map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "a mark made for another name is no mark"
        );
    }

    #[test]
    fn a_mark_nobody_issued_passes_no_lock() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        for _ in 0..5 {
            let _ = attempt_from(&app, scope, "198.51.100.30", "ada", "a guess");
        }
        let made_up = DeviceMark::parse(&format!(
            "{}.0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69.{}",
            app.now().unix_timestamp() + 3_600,
            "A".repeat(43)
        ))
        .expect("the shape of a mark");

        assert_eq!(
            attempt_with_mark(
                &app,
                scope,
                "198.51.100.30",
                "ada",
                PASSWORD,
                Some(&made_up)
            )
            .map(|_| ()),
            Err(ErrorCode::SignInFailed)
        );
    }

    #[test]
    fn a_known_browser_has_a_budget_of_the_day_of_its_own() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let mark = attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, None)
            .expect("a first sign-in")
            .device_mark;

        // Four a window, under the lock of the window: twenty in the day.
        for _ in 0..5 {
            for _ in 0..4 {
                let _ =
                    attempt_with_mark(&app, scope, "198.51.100.9", "ada", "a guess", Some(&mark));
            }
            clock.advance(Duration::from_mins(11));
        }

        assert_eq!(
            attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, Some(&mark))
                .map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "a mark left on a shared machine buys twenty guesses a day, no more"
        );
    }
}
