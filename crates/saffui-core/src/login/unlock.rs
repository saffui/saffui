//! Lifting the lock on a name. Guesses made from everywhere lock a name for
//! a day, the right password included: only an administrator of the realm
//! gives it back before the day ends, and the chain says who did.

use serde_json::json;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::normalize_username;
use crate::error::{ErrorCode, Failure};
use crate::login::steps::password::digest_name_locks;
use crate::tenancy::RealmScope;

/// Forgets what the name of a person failed, in the window and in the day.
/// What one address failed for the name stays: that address is the one
/// that guessed.
///
/// # Errors
///
/// Returns [`ErrorCode::PersonNotFound`] for a name nobody has, or the
/// failure of the sealer or of the storage.
pub async fn unlock_person(
    app: &App,
    scope: RealmScope,
    username: &str,
    unlocked_by: &str,
) -> Result<(), Failure> {
    let not_found = || Failure::new(ErrorCode::PersonNotFound);
    let username = normalize_username(username).map_err(|_| not_found())?;
    let mut work = app.storage.begin(scope).await?;
    let person = work
        .read_person_by_username(&username)
        .await?
        .ok_or_else(not_found)?;
    // The brake counts what was typed, trimmed and in lower case: the name
    // of the person is written so already.
    for counter in digest_name_locks(app, scope, &person.username)? {
        work.forget_login_failures(&counter).await?;
    }
    let told = json!({
        "person_id": person.id.to_string(),
        "actor": { "client_id": unlocked_by },
    });
    record_event(app, work.as_mut(), EventKind::PersonUnlocked, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::unlock_person;
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::login::steps::password::sign_in;
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::testkit::memory::MemoryStorage;

    const PASSWORD: &str = "correct horse battery";

    fn attempt_from(
        app: &App,
        scope: RealmScope,
        address: &str,
        password: &str,
    ) -> Result<(), ErrorCode> {
        complete(sign_in(
            app,
            scope,
            "ada",
            Secret::new(password.as_bytes().to_vec()),
            Some(address.parse().expect("an address")),
            &[],
        ))
        .map(|_| ())
        .map_err(|failure| failure.code)
    }

    #[test]
    fn an_administrator_gives_back_a_name_the_day_locked_and_the_chain_says_who() {
        let (app, storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        // A hundred guesses from addresses that each stay under their own
        // bound, over a day of windows: the name is locked until the day ends.
        for round in 0..100_u32 {
            if round % 40 == 0 {
                clock.advance(Duration::from_mins(11));
            }
            let address = format!("198.51.{}.{}", round / 4, round % 4 + 1);
            assert_eq!(
                attempt_from(&app, scope, &address, "a guess"),
                Err(ErrorCode::SignInFailed)
            );
        }
        clock.advance(Duration::from_mins(11));
        assert_eq!(
            attempt_from(&app, scope, "203.0.113.7", PASSWORD),
            Err(ErrorCode::SignInFailed),
            "the day locks the name, the right password included"
        );

        complete(unlock_person(&app, scope, " Ada ", "operator")).expect("an unlock");

        assert_eq!(attempt_from(&app, scope, "203.0.113.7", PASSWORD), Ok(()));
        let unlocked = storage
            .read_audit_envelopes(scope.realm())
            .into_iter()
            .find(|event| event["kind"] == "person.unlocked")
            .expect("the unlock is in the chain");
        assert_eq!(unlocked["payload"]["actor"]["client_id"], "operator");
    }

    #[test]
    fn a_name_nobody_has_is_not_found() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));

        for name in ["nobody", "not a name!"] {
            assert_eq!(
                complete(unlock_person(&app, scope, name, "operator"))
                    .map_err(|failure| failure.code),
                Err(ErrorCode::PersonNotFound),
                "{name}"
            );
        }
    }
}
