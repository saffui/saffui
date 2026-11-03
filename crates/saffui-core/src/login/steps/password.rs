use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::create::translate_hashing_failure;
use crate::directory::{PASSWORD_MAX_BYTES, Person, normalize_username};
use crate::error::{ErrorCode, Failure};
use crate::login::session::{SessionTicket, open_session};
use crate::login::throttle::{
    MAX_RECENT_ATTEMPTS_PER_ADDRESS, MAX_RECENT_FAILURES_PER_NAME, is_locked, start_bucket,
    start_window, write_address_bucket,
};
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// A person who just signed in, and the ticket of their new session.
#[derive(Debug)]
pub struct SignedIn {
    pub person: Person,
    pub session: Uuid,
    pub ticket: SessionTicket,
}

/// The keys the brake counts under, for one attempt.
struct Counters {
    name: Vec<u8>,
    address: Option<Vec<u8>>,
    address_and_name: Option<Vec<u8>>,
}

/// Digests what the brake counts under. Each kind starts with a byte of its
/// own, and an address ends with a byte no address holds: no name anybody
/// types is counted as an address, and no address as a name.
fn name_counters(
    app: &App,
    scope: RealmScope,
    typed: &str,
    address: Option<&str>,
) -> Result<Counters, Failure> {
    let digest = |kind: u8, parts: &[&str]| {
        let mut written = vec![kind];
        for part in parts {
            written.extend_from_slice(part.as_bytes());
            written.push(0);
        }
        app.sealer
            .digest_typed_name(scope.tenant().as_uuid(), scope.realm().as_uuid(), &written)
            .map_err(|_| Failure::new(ErrorCode::CryptoUnavailable))
    };
    Ok(Counters {
        name: digest(1, &[typed])?,
        address: address.map(|address| digest(2, &[address])).transpose()?,
        address_and_name: address
            .map(|address| digest(3, &[address, typed]))
            .transpose()?,
    })
}

/// Signs a person in with a username and a password.
///
/// An unknown name, a wrong password, a disabled person and a locked name
/// are one refusal, after the same work: the unknown name is verified too,
/// against a hash nobody's password matches. A locked name is refused before
/// anything is hashed, and so is an address that spent what it may attempt.
/// No transaction is held while the password is hashed.
///
/// # Errors
///
/// Returns [`ErrorCode::SignInFailed`] for every refusal above but the last,
/// [`ErrorCode::HashingBusy`] when the address spent its attempts or too
/// many passwords are being hashed, or the storage failure.
pub async fn sign_in(
    app: &App,
    scope: RealmScope,
    typed_name: &str,
    password: Secret,
    caller: Option<IpAddr>,
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
    let address = caller.map(write_address_bucket);
    let counters = name_counters(app, scope, &typed, address.as_deref())?;
    let now = app.now();
    let window = start_window(now);

    // One unit of work reads the three counters and counts this attempt
    // against its address. It commits before anything is hashed: attempts
    // made together are each counted, and none holds a transaction meanwhile.
    let mut work = app.storage.begin(scope).await?;
    if let Some(by_address) = &counters.address {
        if work.count_login_failures(by_address, window).await? >= MAX_RECENT_ATTEMPTS_PER_ADDRESS {
            return Err(Failure::new(ErrorCode::HashingBusy));
        }
        work.record_login_failure(by_address, start_bucket(now))
            .await?;
    }
    let failed_for_the_name = work.count_login_failures(&counters.name, window).await?;
    let locked = match &counters.address_and_name {
        // Known addresses are held to a few guesses each. The name alone is
        // held to a bound that guesses spread over many addresses reach.
        Some(by_both) => {
            is_locked(work.count_login_failures(by_both, window).await?)
                || failed_for_the_name >= MAX_RECENT_FAILURES_PER_NAME
        }
        None => is_locked(failed_for_the_name),
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
    let verified = app
        .hasher
        .verify_password(password, against)
        .await
        .map_err(translate_hashing_failure)?;

    let mut work = app.storage.begin(scope).await?;
    let Some(person) = person.filter(|person| verified && person.enabled) else {
        work.record_login_failure(&counters.name, start_bucket(now))
            .await?;
        if let Some(by_both) = &counters.address_and_name {
            work.record_login_failure(by_both, start_bucket(now))
                .await?;
        }
        work.commit().await?;
        return Err(refused());
    };
    let (session, ticket) = open_session(app, work.as_mut(), person.id).await?;
    let opened =
        json!({ "person_id": person.id.to_string(), "session_id": session.id.to_string() });
    record_event(app, work.as_mut(), EventKind::SessionOpened, opened).await?;
    work.commit().await?;
    Ok(SignedIn {
        person,
        session: session.id,
        ticket,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::sign_in;
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
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
}
