//! The first step of signing in: a name and a password.

use std::net::IpAddr;

use uuid::Uuid;

use crate::app::App;
use crate::directory::create::translate_hashing_failure;
use crate::directory::{PASSWORD_MAX_BYTES, Person, normalize_username};
use crate::error::{ErrorCode, Failure};
use crate::login::device::{DeviceMark, find_known_browser, prove_device_marks};
use crate::login::throttle::{Brake, write_network_bucket};
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// A password proven: the person, what they typed, and the brake the
/// attempt was counted under, which the flow clears.
pub(crate) struct ProvenPassword {
    pub person: Person,
    /// What was typed, trimmed and in lower case: what a mark is made for.
    pub typed: String,
    pub brake: Brake,
}

/// Proves who a person is by their name and their password. It opens no
/// session: what the proof is worth is for the flow to say.
///
/// An unknown name, a wrong password, a disabled person and a locked name
/// are one refusal, after the same work: the unknown name is verified too,
/// against a hash nobody's password matches. A locked name is refused before
/// anything is hashed, and so is an address that spent what it may attempt.
/// No transaction is held while the password is hashed.
///
/// A browser that brings the mark of an earlier sign-in with this name, and
/// that the realm still keeps for this person, is counted apart: guesses
/// made on the name from elsewhere do not lock it out, an address it shares
/// does not hold it, and its own failures do not lock the name for anyone
/// else. A cookie may carry the marks of a few people.
///
/// # Errors
///
/// Returns [`ErrorCode::SignInFailed`] for every refusal above but the last,
/// [`ErrorCode::HashingBusy`] when the address spent its attempts, or the
/// realm or the /48 of an IPv6 caller runs its share of hashes already, or
/// the storage failure.
pub(crate) async fn verify_password(
    app: &App,
    scope: RealmScope,
    typed_name: &str,
    password: Secret,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<ProvenPassword, Failure> {
    let refused = || Failure::new(ErrorCode::SignInFailed);
    let username = normalize_username(typed_name).ok();
    // A password past the bound is no guess: it cannot be right. Nothing is
    // hashed for it and nothing is counted, so it locks nobody out.
    if password.expose().len() > PASSWORD_MAX_BYTES {
        return Err(refused());
    }
    // What was typed, not who it is: the brake holds for names nobody has.
    let typed = typed_name.trim().to_lowercase();
    let mut brake = Brake::of(app, scope, &typed, caller)?;
    let network = caller.and_then(write_network_bucket);
    // No hasher free now: refused before the attempt is counted, so that a
    // busy node costs the address nothing. The share is taken further down.
    if !app
        .hashing_shares
        .has_free_share(scope.realm(), network.as_deref())
    {
        return Err(Failure::new(ErrorCode::HashingBusy));
    }
    let now = app.now();
    let proven = prove_device_marks(app, scope, known_browsers, &typed, now)?;

    // One unit of work reads the counters and counts this attempt against
    // its address. It commits before anything is hashed: attempts made
    // together are each counted, and none holds a transaction meanwhile.
    let mut work = app.storage.begin(scope).await?;
    // Read whether or not the name is locked: both paths read as much.
    let person = match &username {
        Some(username) => work.read_person_by_username(username).await?,
        None => None,
    };
    if let Some(device) = find_known_browser(work.as_mut(), &proven, person.as_ref(), now).await? {
        brake.count_browser_apart(app, scope, &typed, device)?;
    }
    brake.admit(work.as_mut(), now).await?;
    let locked = brake.is_name_locked(work.as_mut(), now).await?;
    let person = person.filter(|_| !locked);
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
            .take(scope.realm(), network)
            .ok_or_else(|| Failure::new(ErrorCode::HashingBusy))?;
        app.hasher
            .verify_password(password, against)
            .await
            .map_err(translate_hashing_failure)?
    };

    if let Some(person) = person.filter(|person| verified && person.enabled) {
        return Ok(ProvenPassword {
            person,
            typed,
            brake,
        });
    }
    let mut work = app.storage.begin(scope).await?;
    brake.record_failure(work.as_mut(), now).await?;
    work.commit().await?;
    Err(refused())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::login::device::DeviceMark;
    use crate::login::flow::{FirstStep, SignedIn, sign_in_with_password};
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::testkit::clock::FixedClock;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::testkit::memory::MemoryStorage;

    const PASSWORD: &str = "correct horse battery";

    /// Nobody in these tests set up a second factor: the password opens.
    fn read_who_signed_in(step: FirstStep) -> SignedIn {
        step.into_signed_in()
            .expect("a person without a second factor owes nothing more")
    }

    fn attempt(
        app: &App,
        scope: RealmScope,
        name: &str,
        password: &str,
    ) -> Result<String, ErrorCode> {
        complete(sign_in_with_password(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            None,
            &[],
        ))
        .map(|step| read_who_signed_in(step).person.username)
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
        complete(sign_in_with_password(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            caller,
            &[],
        ))
        .map(|step| read_who_signed_in(step).person.username)
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
    fn a_node_with_no_hasher_free_refuses_before_it_counts_the_attempt_of_the_address() {
        use crate::login::throttle::MAX_RECENT_ATTEMPTS_PER_ADDRESS;

        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let held = [
            app.hashing_shares
                .take(scope.realm(), None)
                .expect("a share"),
            app.hashing_shares
                .take(scope.realm(), None)
                .expect("a share"),
        ];
        let units_before = storage.count_units_of_work();

        for _ in 0..=MAX_RECENT_ATTEMPTS_PER_ADDRESS {
            assert_eq!(
                attempt_from(&app, scope, "203.0.113.7", "ada", PASSWORD),
                Err(ErrorCode::HashingBusy)
            );
        }

        assert_eq!(
            storage.count_units_of_work(),
            units_before,
            "nothing was read, nothing was counted"
        );
        drop(held);
        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "the address kept every attempt it may make"
        );
    }

    #[test]
    fn a_network_that_runs_its_share_is_refused_before_the_attempt_of_the_address_is_counted() {
        use crate::login::throttle::MAX_RECENT_ATTEMPTS_PER_ADDRESS;

        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let other = complete(create_realm(&app, "globex"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        // Four hashers: the one a /48 may hold is taken, from another realm.
        let held = app
            .hashing_shares
            .take(other.realm(), Some("2001:db8:7::/48".to_owned()))
            .expect("a share");
        let units_before = storage.count_units_of_work();

        for _ in 0..=MAX_RECENT_ATTEMPTS_PER_ADDRESS {
            assert_eq!(
                attempt_from(&app, scope, "2001:db8:7:ffff::1", "ada", PASSWORD),
                Err(ErrorCode::HashingBusy),
                "the /48 runs its share already"
            );
        }

        assert_eq!(
            storage.count_units_of_work(),
            units_before,
            "nothing was read, nothing was counted"
        );
        drop(held);
        assert_eq!(
            attempt_from(&app, scope, "2001:db8:7:ffff::1", "ada", PASSWORD),
            Ok("ada".to_owned()),
            "the address kept every attempt it may make"
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
    ) -> Result<SignedIn, ErrorCode> {
        let caller = Some(address.parse().expect("an address"));
        complete(sign_in_with_password(
            app,
            scope,
            name,
            Secret::new(password.as_bytes().to_vec()),
            caller,
            mark.map_or(&[][..], std::slice::from_ref),
        ))
        .map(read_who_signed_in)
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
    fn a_mark_made_for_the_name_on_a_browser_kept_for_another_person_passes_no_lock() {
        use crate::login::device::issue_device_mark;

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        complete(create_person(&app, scope, "bob", PASSWORD));
        let ours = attempt_with_mark(&app, scope, "198.51.100.9", "ada", PASSWORD, None)
            .expect("a sign-in of ada")
            .device_mark;
        let bobs = attempt_with_mark(&app, scope, "198.51.100.10", "bob", PASSWORD, None)
            .expect("a sign-in of bob")
            .device_mark;
        // Its MAC holds for the name typed, but the realm keeps its browser for bob.
        let borrowed = issue_device_mark(&app, scope, "ada", Some(bobs.device)).expect("a mark");
        let there = "192.0.2.9";
        for _ in 0..5 {
            assert_eq!(
                attempt_with_mark(&app, scope, there, "ada", "a guess", None).map(|_| ()),
                Err(ErrorCode::SignInFailed)
            );
        }

        assert_eq!(
            attempt_with_mark(&app, scope, there, "ada", PASSWORD, Some(&borrowed)).map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "a browser kept for bob answers for bob only"
        );
        assert!(
            attempt_with_mark(&app, scope, there, "ada", PASSWORD, Some(&ours)).is_ok(),
            "the browser kept for ada passes the same lock"
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

    #[test]
    fn a_known_browser_behind_an_address_that_spent_its_attempts_still_signs_in() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let shared = "203.0.113.7";
        let mark = attempt_with_mark(&app, scope, shared, "ada", PASSWORD, None)
            .expect("a first sign-in")
            .device_mark;
        // Others behind the same address spend what it may attempt.
        for round in 0..30 {
            let name = format!("nobody-{round}");
            let _ = attempt_with_mark(&app, scope, shared, &name, "a guess", None);
        }

        assert_eq!(
            attempt_with_mark(&app, scope, shared, "ada", PASSWORD, None).map(|_| ()),
            Err(ErrorCode::HashingBusy),
            "a browser the realm does not know is held with its address"
        );
        assert!(
            attempt_with_mark(&app, scope, shared, "ada", PASSWORD, Some(&mark)).is_ok(),
            "the known browser is counted under its mark, not its address"
        );
    }

    #[test]
    fn a_mark_whose_browser_the_realm_no_longer_keeps_passes_no_lock() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let mut marks = Vec::new();
        // Eleven browsers, a second apart: the realm keeps the ten that
        // expire last, and forgets the first.
        for browser in 0..11 {
            let address = format!("198.51.100.{}", browser + 1);
            marks.push(
                attempt_with_mark(&app, scope, &address, "ada", PASSWORD, None)
                    .expect("a sign-in")
                    .device_mark,
            );
            clock.advance(Duration::from_secs(1));
        }
        // Five guesses from one address lock the name there, for every
        // browser the realm does not know.
        let there = "192.0.2.9";
        for _ in 0..5 {
            assert_eq!(
                attempt_with_mark(&app, scope, there, "ada", "a guess", None).map(|_| ()),
                Err(ErrorCode::SignInFailed)
            );
        }
        assert_eq!(
            attempt_with_mark(&app, scope, there, "ada", PASSWORD, None).map(|_| ()),
            Err(ErrorCode::SignInFailed)
        );

        assert!(
            attempt_with_mark(&app, scope, "192.0.2.9", "ada", PASSWORD, Some(&marks[10])).is_ok(),
            "a browser the realm keeps passes the lock"
        );
        assert_eq!(
            attempt_with_mark(&app, scope, "192.0.2.9", "ada", PASSWORD, Some(&marks[0]))
                .map(|_| ()),
            Err(ErrorCode::SignInFailed),
            "its MAC still holds, but the realm forgot the browser"
        );
    }
}
