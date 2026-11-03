//! What an administrator does with the people of a realm.

use serde_json::json;

use super::{Person, check_password_bounds, normalize_email, normalize_username};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::is_unshowable;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::crypto::PasswordHashingFailure;
use crate::ports::storage::StorageError;
use crate::secret::Secret;
use crate::tenancy::RealmScope;

pub struct NewPerson<'a> {
    pub username: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub password: Option<Secret>,
    /// The client of the administration plane that asks, when one does.
    pub created_by: Option<&'a str>,
}

pub(crate) fn translate_hashing_failure(failure: PasswordHashingFailure) -> Failure {
    match failure {
        PasswordHashingFailure::Busy => Failure::new(ErrorCode::HashingBusy),
        PasswordHashingFailure::Failed => Failure::new(ErrorCode::CryptoUnavailable),
    }
}

/// Creates a person, with a first password when one is given.
///
/// The password is hashed before the unit of work opens: a transaction is
/// never held across work that is slow on purpose.
///
/// # Errors
///
/// Returns the code of what is refused, [`ErrorCode::UsernameTaken`] or
/// [`ErrorCode::EmailTaken`], [`ErrorCode::HashingBusy`] when too many
/// passwords are being hashed, or the storage failure.
pub async fn create_person(
    app: &App,
    scope: RealmScope,
    wanted: NewPerson<'_>,
) -> Result<Person, Failure> {
    let username = normalize_username(wanted.username)?;
    let email = wanted.email.map(normalize_email).transpose()?;
    let display_name = wanted
        .display_name
        .map(str::trim)
        .filter(|name| !name.is_empty());
    if display_name
        .is_some_and(|name| name.chars().count() > 120 || name.chars().any(is_unshowable))
    {
        return Err(Failure::new(ErrorCode::DisplayNameInvalid));
    }
    let hash = match wanted.password {
        Some(password) => {
            check_password_bounds(password.expose())?;
            let _share = app
                .hashing_shares
                .take(scope.realm(), None)
                .ok_or_else(|| Failure::new(ErrorCode::HashingBusy))?;
            Some(
                app.hasher
                    .hash_password(password)
                    .await
                    .map_err(translate_hashing_failure)?,
            )
        }
        None => None,
    };

    let person = Person {
        id: mint_id(app)?,
        username,
        email,
        email_verified: false,
        display_name: display_name.map(str::to_owned),
        enabled: true,
        created_at: app.now(),
    };
    let mut work = app.storage.begin(scope).await?;
    work.insert_person(&person)
        .await
        .map_err(|error| match error {
            StorageError::Taken("username") => Failure::new(ErrorCode::UsernameTaken),
            StorageError::Taken("email") => Failure::new(ErrorCode::EmailTaken),
            other => other.into(),
        })?;
    if let Some(hash) = hash {
        work.insert_password(person.id, &hash, person.created_at)
            .await?;
    }
    // The identifier, not the name or the address: an audit chain is kept
    // long after a person asks to be forgotten.
    let mut created = json!({ "person_id": person.id.to_string() });
    if let Some(actor) = wanted.created_by {
        created["actor"] = json!({ "client_id": actor });
    }
    record_event(app, work.as_mut(), EventKind::PersonCreated, created).await?;
    work.commit().await?;
    Ok(person)
}

#[cfg(test)]
mod tests {
    use super::{NewPerson, create_person};
    use crate::error::ErrorCode;
    use crate::secret::Secret;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;

    fn ask<'a>(username: &'a str, email: Option<&'a str>, password: &[u8]) -> NewPerson<'a> {
        NewPerson {
            username,
            email,
            display_name: None,
            password: Some(Secret::new(password.to_vec())),
            created_by: None,
        }
    }

    #[test]
    fn a_person_is_kept_as_typed_once_normalized_and_recorded_by_identifier_alone() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let wanted = NewPerson {
            created_by: Some("operator"),
            display_name: Some("  Ada Lovelace "),
            ..ask(
                " Lovelace ",
                Some("Lovelace@Example.ORG"),
                b"correct horse battery",
            )
        };

        let person = complete(create_person(&app, scope, wanted)).expect("a person");

        assert_eq!(person.username, "lovelace");
        assert_eq!(person.email.as_deref(), Some("lovelace@example.org"));
        assert_eq!(person.display_name.as_deref(), Some("Ada Lovelace"));
        assert!(person.enabled && !person.email_verified);
        let created = storage
            .read_audit_envelopes(scope.realm())
            .last()
            .cloned()
            .expect("an event");
        assert_eq!(created["kind"], "person.created");
        assert_eq!(created["payload"]["person_id"], person.id.to_string());
        assert_eq!(created["payload"]["actor"]["client_id"], "operator");
        let told = created.to_string();
        // Not a letter of these is a hexadecimal digit: no identifier holds them.
        assert!(
            !told.to_lowercase().contains("lovelace"),
            "a chain is kept long after a person asks to be forgotten: {told}"
        );
    }

    #[test]
    fn a_name_or_an_address_taken_a_name_that_cannot_be_shown_and_a_password_out_of_bounds_are_refused()
     {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let create = |wanted: NewPerson<'_>| {
            complete(create_person(&app, scope, wanted))
                .map(|_| ())
                .map_err(|failure| failure.code)
        };
        assert_eq!(
            create(ask("ada", Some("ada@example.org"), b"12345678")),
            Ok(())
        );

        assert_eq!(
            create(ask("ADA", None, b"12345678")),
            Err(ErrorCode::UsernameTaken)
        );
        assert_eq!(
            create(ask("bob", Some("ADA@example.org"), b"12345678")),
            Err(ErrorCode::EmailTaken)
        );
        assert_eq!(
            create(ask("bob", None, b"1234567")),
            Err(ErrorCode::PasswordUnacceptable)
        );
        assert_eq!(
            create(ask("bob", None, &[b'a'; 1025])),
            Err(ErrorCode::PasswordUnacceptable)
        );
        assert_eq!(
            create(ask("bob smith", None, b"12345678")),
            Err(ErrorCode::UsernameInvalid)
        );
        assert_eq!(
            create(ask("bob", Some("bob"), b"12345678")),
            Err(ErrorCode::EmailInvalid)
        );
        for name in ["Bob\u{202e}evil", "Bob\u{200b}", "Bob\nSmith"] {
            let wanted = NewPerson {
                display_name: Some(name),
                ..ask("bob", None, b"12345678")
            };
            assert_eq!(
                create(wanted),
                Err(ErrorCode::DisplayNameInvalid),
                "{name:?}"
            );
        }
        assert_eq!(create(ask("bob", None, b"12345678")), Ok(()));
    }
}
