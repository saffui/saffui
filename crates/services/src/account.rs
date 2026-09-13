use auth::login::lockout;
use auth::password::{self, Compared, Unkept};
use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::realm::RealmModel;
use models::entities::user::{RequiredAction, UserModel, UserStorage};
use secrecy::SecretBox;
use store::providers::{sessions, users};

/// Why a person's own password was not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unchanged {
    /// Counted against the person like a failed sign-in, and the count is
    /// written even though nothing else is.
    #[error("the current password is not this account's")]
    Mismatch,
    #[error("too many wrong passwords; try again later")]
    LockedOut,
    /// A directory owns the password, or the account keeps none at all.
    #[error("this account keeps no password here to change")]
    NotHeldHere,
    /// The realm's policy said no, in words the person is meant to read.
    #[error("{0}")]
    Refused(&'static str),
    #[error("the store could not be written")]
    Backend,
}

/// Where a person changing their own password stands.
pub struct Changing<'a> {
    pub realm: &'a RealmModel,
    pub person: &'a UserModel,
    /// The login the change is made from, the only one that outlives it.
    pub session_id: &'a str,
    pub from: Option<&'a str>,
    pub now: DateTime<Utc>,
}

/// Replace a person's password on proof of the current one, and say how many
/// of their other logins ended with it.
///
/// Checked in a login's order: the lock first, verifying nothing, then the
/// password, a wrong one counted against the same lock. The replacement goes
/// through the writer every door shares, so the realm's policy and history
/// speak here too. Every other login ends, with what clients got from it:
/// whoever else knew the old password is shut out, and the login making the
/// change keeps working.
///
/// A mismatch has written its count, and the caller commits it: rolled back,
/// a wrong guess costs nothing. Every other outcome is the caller's to commit
/// or drop whole.
pub async fn change_own_password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    changing: &Changing<'_>,
    current: &SecretBox<String>,
    replacement: &SecretBox<String>,
) -> Result<usize, Unchanged> {
    let person = changing.person;
    if person.user_storage == Some(UserStorage::Ldap) {
        return Err(Unchanged::NotHeldHere);
    }
    let locked = lockout::until(transaction, changing.realm, &person.user_id, changing.now)
        .await
        .map_err(|_| Unchanged::Backend)?;
    if locked.is_some() {
        return Err(Unchanged::LockedOut);
    }
    match password::compare_with_held(transaction, provider, &person.user_id, current)
        .await
        .map_err(|_| Unchanged::Backend)?
    {
        Compared::Matches => {}
        Compared::NoneHeld => return Err(Unchanged::NotHeldHere),
        Compared::Differs => {
            lockout::count(
                transaction,
                changing.realm,
                &person.user_id,
                changing.from,
                changing.now,
            )
            .await
            .map_err(|_| Unchanged::Backend)?;
            return Err(Unchanged::Mismatch);
        }
    }
    lockout::clear(transaction, &person.user_id)
        .await
        .map_err(|_| Unchanged::Backend)?;

    let cost = changing
        .realm
        .password_policy
        .as_ref()
        .map_or_else(Default::default, |policy| policy.hashing);
    password::keep(
        transaction,
        provider,
        cost,
        &person.metadata.tenant,
        &person.realm_id,
        &person.user_id,
        &person.user_id,
        replacement,
    )
    .await
    .map_err(|why| match why {
        Unkept::Refused(said) => Unchanged::Refused(said.spoken()),
        Unkept::NoSuchPerson | Unkept::Unwritable => Unchanged::Backend,
    })?;
    for done in [
        RequiredAction::UpdatePassword,
        RequiredAction::ResetPassword,
    ] {
        users::clear_required_action(transaction, &person.user_id, done)
            .await
            .map_err(|_| Unchanged::Backend)?;
    }
    sessions::end_others_of_user(transaction, &person.user_id, changing.session_id)
        .await
        .map_err(|_| Unchanged::Backend)
}
