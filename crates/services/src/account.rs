use auth::login::lockout;
use auth::password::{self, Compared, Unkept};
use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::credentials::{CredentialModel, CredentialType};
use models::entities::realm::RealmModel;
use models::entities::user::{RequiredAction, UserModel, UserStorage};
use secrecy::SecretBox;
use store::providers::webauthn::EnrolledCredential;
use store::providers::{credentials, sessions, users, webauthn};

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

/// How recently a person must have signed in to remove one of their factors.
pub const FRESH_SIGN_IN_SECONDS: i64 = 300;

const LAST_SECOND_FACTOR: &str = "this is the last second factor: add another before removing it";
const ONLY_WAY_IN: &str = "this key is the only way this account signs in";

/// Why a factor was not removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unremoved {
    /// The login the request rides was proven too long ago.
    #[error("sign in again before changing this account's factors")]
    NotFresh,
    /// The factor is the last of what keeps the account safe, in words the
    /// person reads.
    #[error("{0}")]
    LastFactor(&'static str),
    #[error("no such factor on this account")]
    NotFound,
    #[error("the store could not be read")]
    Backend,
}

/// What a person holds to sign in with, never the material.
pub struct OwnFactors {
    pub password: bool,
    /// Authenticator apps, time or counter based.
    pub apps: Vec<CredentialModel>,
    pub keys: Vec<EnrolledCredential>,
    pub recovery_codes: i64,
    /// Until when the login the request rides may remove a factor, if it still may.
    pub fresh_until: Option<i64>,
}

impl OwnFactors {
    fn second_factors(&self) -> usize {
        self.apps.len() + self.keys.len()
    }

    /// Why an app has to stay, when it has to.
    pub fn app_kept_because(&self) -> Option<&'static str> {
        (self.second_factors() <= 1).then_some(LAST_SECOND_FACTOR)
    }

    /// Why a key has to stay, when it has to. An account without a password
    /// signs in by key, so its last key stays whatever else it holds.
    pub fn key_kept_because(&self) -> Option<&'static str> {
        if !self.password && self.keys.len() <= 1 {
            return Some(ONLY_WAY_IN);
        }
        (self.second_factors() <= 1).then_some(LAST_SECOND_FACTOR)
    }
}

/// Which of a person's own factors a removal names.
pub enum OwnFactor<'a> {
    App(&'a str),
    Key(&'a [u8]),
    RecoveryCodes,
}

/// What a person holds to sign in with, read for the person themselves.
pub async fn own_factors(
    transaction: &Transaction<'_>,
    user_id: &str,
    session_id: &str,
    now: DateTime<Utc>,
) -> Result<OwnFactors, Unremoved> {
    let of_type = |kind| credentials::load_for_user_of_type(transaction, user_id, kind);
    let password = !of_type(CredentialType::Password)
        .await
        .map_err(|_| Unremoved::Backend)?
        .is_empty();
    let mut apps = of_type(CredentialType::Totp)
        .await
        .map_err(|_| Unremoved::Backend)?;
    apps.extend(
        of_type(CredentialType::Hotp)
            .await
            .map_err(|_| Unremoved::Backend)?,
    );
    let keys = webauthn::of_user(transaction, user_id)
        .await
        .map_err(|_| Unremoved::Backend)?;
    let recovery_codes = credentials::count_recovery_codes(transaction, user_id)
        .await
        .map_err(|_| Unremoved::Backend)?;
    let fresh_until = sessions::load(transaction, session_id)
        .await
        .map_err(|_| Unremoved::Backend)?
        .and_then(|login| login.auth_time)
        .map(|proven| proven + FRESH_SIGN_IN_SECONDS)
        .filter(|until| *until >= now.timestamp());
    Ok(OwnFactors {
        password,
        apps,
        keys,
        recovery_codes,
        fresh_until,
    })
}

/// Remove one of a person's own factors.
///
/// Only from a login proven moments ago: a console left open, or a token lifted
/// from one, does not strip an account of its defences. One writer per person
/// holds while the rule is read, so two removals racing cannot each leave the
/// other as the last factor. The last second factor stays until another takes
/// its place, a key stays where it is the only way in, and the sheet of codes
/// may always go.
pub async fn remove_own_factor(
    transaction: &Transaction<'_>,
    user_id: &str,
    session_id: &str,
    now: DateTime<Utc>,
    factor: OwnFactor<'_>,
) -> Result<(), Unremoved> {
    credentials::hold_factors(transaction, user_id)
        .await
        .map_err(|_| Unremoved::Backend)?;
    let held = own_factors(transaction, user_id, session_id, now).await?;
    if held.fresh_until.is_none() {
        return Err(Unremoved::NotFresh);
    }
    match factor {
        OwnFactor::RecoveryCodes => {
            let removed = credentials::delete_recovery_codes(transaction, user_id)
                .await
                .map_err(|_| Unremoved::Backend)?;
            if removed == 0 {
                return Err(Unremoved::NotFound);
            }
        }
        OwnFactor::App(credential_id) => {
            if !held
                .apps
                .iter()
                .any(|app| app.credential_id == credential_id)
            {
                return Err(Unremoved::NotFound);
            }
            if let Some(why) = held.app_kept_because() {
                return Err(Unremoved::LastFactor(why));
            }
            credentials::delete(transaction, credential_id)
                .await
                .map_err(|_| Unremoved::Backend)?;
        }
        OwnFactor::Key(credential_id) => {
            if !held
                .keys
                .iter()
                .any(|key| key.credential_id == credential_id)
            {
                return Err(Unremoved::NotFound);
            }
            if let Some(why) = held.key_kept_because() {
                return Err(Unremoved::LastFactor(why));
            }
            webauthn::delete(transaction, user_id, credential_id)
                .await
                .map_err(|_| Unremoved::Backend)?;
        }
    }
    Ok(())
}
