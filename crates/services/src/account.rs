use auth::login::authenticator::Authenticator;
use auth::login::{lockout, throttle};
use auth::password::{self, Compared, Unkept};
use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use models::entities::acr::AcrLoaMap;
use models::entities::auth::{AuthenticationExecutionModel, ExecutionStep};
use models::entities::credentials::{CredentialModel, CredentialType};
use models::entities::realm::RealmModel;
use models::entities::user::{RequiredAction, UserModel, UserStorage};
use secrecy::SecretBox;
use store::providers::webauthn::EnrolledCredential;
use store::providers::{auth_flows, clients, credentials, realms, sessions, users, webauthn};
use store::tenancy::UnitOfWork;

/// Why a person's own password was not changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unchanged {
    /// Counted against the person like a failed sign-in, and the count is
    /// written even though nothing else is.
    #[error("the current password is not this account's")]
    Mismatch,
    #[error("too many wrong passwords; try again later")]
    LockedOut,
    /// Too many failures from where the change came from, until this instant.
    #[error("too many failed attempts from this address; try again later")]
    Throttled { until: i64 },
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
/// Checked in a login's order: the address and the lock first, verifying
/// nothing, then the password, a wrong one counted against the same lock and
/// the same address as at every other door. The replacement goes
/// through the writer every door shares, so the realm's policy and history
/// speak here too. Every other login ends, with what clients got from it:
/// whoever else knew the old password is shut out, and the login making the
/// change keeps working.
///
/// A mismatch or a lock has written its counts, and the caller commits them:
/// rolled back, a wrong guess costs nothing. Every other outcome is the
/// caller's to commit or drop whole.
pub async fn change_own_password(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    changing: &Changing<'_>,
    current: &SecretBox<String>,
    replacement: &SecretBox<String>,
) -> Result<usize, Unchanged> {
    let person = changing.person;
    if person.user_storage == Some(UserStorage::Ldap) {
        return Err(Unchanged::NotHeldHere);
    }
    let knock = throttle::Knock::new(provider, changing.from, Some(&person.user_name))
        .map_err(|_| Unchanged::Backend)?;
    if let Some(until) = throttle::until(transaction, changing.realm, &knock, changing.now)
        .await
        .map_err(|_| Unchanged::Backend)?
    {
        return Err(Unchanged::Throttled { until });
    }
    let locked = lockout::until(transaction, changing.realm, &person.user_id, changing.now)
        .await
        .map_err(|_| Unchanged::Backend)?;
    if locked.is_some() {
        throttle::count(transaction, changing.realm, &knock, changing.now)
            .await
            .map_err(|_| Unchanged::Backend)?;
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
            throttle::count(transaction, changing.realm, &knock, changing.now)
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
    /// The login is recent but weaker than the flow lets this person sign in.
    #[error("sign in with the strongest factor this account can use")]
    StrongerSignInNeeded,
    /// The factor is the last of what keeps the account safe, in words the
    /// person reads.
    #[error("{0}")]
    LastFactor(&'static str),
    #[error("no such factor on this account")]
    NotFound,
    #[error("the store could not be read")]
    Backend,
}

/// The store could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the store could not be read")]
pub struct Unread;

impl From<Unread> for Unremoved {
    fn from(_: Unread) -> Self {
        Unremoved::Backend
    }
}

/// How recently and how strongly a login was proven, against what a sensitive
/// change to the account asks of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInStanding {
    /// Until when the login counts as recent, if it still does.
    pub fresh_until: Option<i64>,
    /// The strongest level the flow lets this person reach, where the realm maps levels.
    pub reachable_level: Option<i32>,
    /// The name the realm gives that level.
    pub reachable_acr: Option<String>,
    /// The level the login reached, zero where none was recorded.
    pub reached: i32,
}

impl SignInStanding {
    /// Whether the login reached what the flow lets this person reach.
    pub fn is_strong_enough(&self) -> bool {
        self.reachable_level
            .is_none_or(|needed| self.reached >= needed)
    }

    /// Whether a sensitive change may go ahead on this login.
    pub fn allows_sensitive_change(&self) -> bool {
        self.fresh_until.is_some() && self.is_strong_enough()
    }
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
    /// Whether that login is recent but weaker than the flow lets this person
    /// sign in, so a removal waits for a stronger one.
    pub stronger_sign_in_needed: bool,
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
///
/// A removal needs a login both recent and as strong as the flow the presenting
/// client signs in with lets this person reach: a weaker way in offered beside
/// a second factor does not get to strip it.
pub async fn own_factors(
    transaction: &UnitOfWork,
    user_id: &str,
    session_id: &str,
    presenter: Option<&str>,
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
    let authenticator_app = !apps.is_empty();
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
    let holds = Holdings {
        password,
        authenticator_app,
        passkey: !keys.is_empty(),
        recovery_codes: recovery_codes > 0,
        verified_phone: read_verified_phone(transaction, user_id).await?,
    };
    let standing = judge_sign_in(transaction, session_id, presenter, &holds, now).await?;
    let strong = standing.is_strong_enough();
    Ok(OwnFactors {
        password,
        apps,
        keys,
        recovery_codes,
        stronger_sign_in_needed: standing.fresh_until.is_some() && !strong,
        fresh_until: standing.fresh_until.filter(|_| strong),
    })
}

/// How the login a request rides stands for a sensitive change to the person's
/// account: whether it is recent, and whether it is as strong as the flow the
/// presenting client signs in with lets this person reach with what they hold.
pub async fn read_sign_in_standing(
    transaction: &UnitOfWork,
    user_id: &str,
    session_id: &str,
    presenter: Option<&str>,
    now: DateTime<Utc>,
) -> Result<SignInStanding, Unread> {
    let of_type = |kind| credentials::load_for_user_of_type(transaction, user_id, kind);
    let holds = Holdings {
        password: !of_type(CredentialType::Password)
            .await
            .map_err(|_| Unread)?
            .is_empty(),
        authenticator_app: !of_type(CredentialType::Totp)
            .await
            .map_err(|_| Unread)?
            .is_empty(),
        passkey: !webauthn::of_user(transaction, user_id)
            .await
            .map_err(|_| Unread)?
            .is_empty(),
        recovery_codes: credentials::count_recovery_codes(transaction, user_id)
            .await
            .map_err(|_| Unread)?
            > 0,
        verified_phone: read_verified_phone(transaction, user_id).await?,
    };
    judge_sign_in(transaction, session_id, presenter, &holds, now).await
}

async fn read_verified_phone(transaction: &UnitOfWork, user_id: &str) -> Result<bool, Unread> {
    Ok(users::load(transaction, user_id)
        .await
        .map_err(|_| Unread)?
        .and_then(|person| person.phone_number_verified)
        .unwrap_or(false))
}

/// How a login stands, given what the person holds.
async fn judge_sign_in(
    transaction: &UnitOfWork,
    session_id: &str,
    presenter: Option<&str>,
    holds: &Holdings,
    now: DateTime<Utc>,
) -> Result<SignInStanding, Unread> {
    let signed_in = sessions::load(transaction, session_id)
        .await
        .map_err(|_| Unread)?;
    let fresh_until = signed_in
        .as_ref()
        .and_then(|login| login.auth_time)
        .map(|proven| proven + FRESH_SIGN_IN_SECONDS)
        .filter(|until| *until >= now.timestamp());

    let realm = realms::of_context(transaction).await.map_err(|_| Unread)?;
    let (level, acr) = match realm.as_ref().and_then(|realm| realm.acr_loa_map.as_ref()) {
        None => (None, None),
        Some(levels) => {
            let bound = realm
                .as_ref()
                .and_then(|realm| realm.browser_flow.as_deref());
            let steps = match flow_signing_in(transaction, presenter, bound).await? {
                Some(flow_id) => auth_flows::executions_of(transaction, &flow_id)
                    .await
                    .map_err(|_| Unread)?,
                None => Vec::new(),
            };
            let level = reachable_level(levels, &steps, holds);
            let acr = level
                .and_then(|level| levels.acr_for_loa(level))
                .map(str::to_owned);
            (level, acr)
        }
    };
    Ok(SignInStanding {
        fresh_until,
        reachable_level: level,
        reachable_acr: acr,
        reached: signed_in.as_ref().and_then(|login| login.loa).unwrap_or(0),
    })
}

/// The flow the presenting client signs in with: its own binding, else the
/// realm's, else the one aliased `browser`.
async fn flow_signing_in(
    transaction: &UnitOfWork,
    presenter: Option<&str>,
    realm_bound: Option<&str>,
) -> Result<Option<String>, Unread> {
    if let Some(presenter) = presenter
        && let Some(client) = clients::load(transaction, presenter)
            .await
            .map_err(|_| Unread)?
    {
        return crate::authorize::browser_flow(transaction, &client)
            .await
            .map(Some)
            .map_err(|_| Unread);
    }
    Ok(
        auth_flows::flow_by_alias(transaction, realm_bound.unwrap_or("browser"))
            .await
            .map_err(|_| Unread)?
            .map(|flow| flow.flow_id),
    )
}

/// Which kinds of factor a person holds, as the steps of a flow ask for them.
#[derive(Debug, Clone, Copy, Default)]
struct Holdings {
    password: bool,
    authenticator_app: bool,
    passkey: bool,
    recovery_codes: bool,
    verified_phone: bool,
}

impl Holdings {
    fn can_answer(&self, authenticator: Authenticator) -> bool {
        match authenticator {
            Authenticator::Password => self.password,
            Authenticator::Totp => self.authenticator_app,
            Authenticator::Webauthn => self.passkey,
            Authenticator::RecoveryCode => self.recovery_codes,
            Authenticator::SmsOtp => self.verified_phone,
            Authenticator::MagicLink | Authenticator::Kerberos => true,
        }
    }
}

/// The strongest level a sign-in through these steps lets this person reach,
/// counting only the enabled steps they can answer; nothing where none maps.
fn reachable_level(
    levels: &AcrLoaMap,
    steps: &[AuthenticationExecutionModel],
    holds: &Holdings,
) -> Option<i32> {
    steps
        .iter()
        .filter(|step| step.is_enabled())
        .filter_map(|step| match &step.step {
            ExecutionStep::Authenticator { authenticator, .. } => {
                authenticator.parse::<Authenticator>().ok()
            }
            ExecutionStep::SubFlow { .. } => None,
        })
        .filter(|authenticator| holds.can_answer(*authenticator))
        .filter_map(|authenticator| levels.loa_of(authenticator.context()))
        .max()
}

/// Remove one of a person's own factors.
///
/// Only from a login proven moments ago: a console left open, or a token lifted
/// from one, does not strip an account of its defences, and a login weaker than
/// the flow allows does not strip it of a stronger factor. One writer per person
/// holds while the rule is read, so two removals racing cannot each leave the
/// other as the last factor. The last second factor stays until another takes
/// its place, a key stays where it is the only way in, and the sheet of codes
/// may always go.
pub async fn remove_own_factor(
    transaction: &UnitOfWork,
    user_id: &str,
    session_id: &str,
    presenter: Option<&str>,
    now: DateTime<Utc>,
    factor: OwnFactor<'_>,
) -> Result<(), Unremoved> {
    credentials::hold_factors(transaction, user_id)
        .await
        .map_err(|_| Unremoved::Backend)?;
    let held = own_factors(transaction, user_id, session_id, presenter, now).await?;
    if held.stronger_sign_in_needed {
        return Err(Unremoved::StrongerSignInNeeded);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::auth::{AuthenticationExecutionMutationModel, AuthenticatorRequirement};

    fn step(
        authenticator: &str,
        requirement: AuthenticatorRequirement,
    ) -> AuthenticationExecutionModel {
        AuthenticationExecutionMutationModel {
            alias: authenticator.to_owned(),
            flow_id: "flow".to_owned(),
            priority: 10,
            step: ExecutionStep::Authenticator {
                authenticator: authenticator.to_owned(),
                config_id: None,
            },
            requirement,
        }
        .into_model(
            authenticator.to_owned(),
            "main".to_owned(),
            AuditableModel::from_creator("local".to_owned(), "test".to_owned()),
        )
    }

    fn levels() -> AcrLoaMap {
        AcrLoaMap::from_pairs([("password", 1), ("mfa", 2)])
    }

    /// The level a flow lets a person reach counts only the steps they can
    /// answer: a code step for a person with an app, never a key step for a
    /// person with no key, and never a step the flow switched off.
    #[test]
    fn the_reachable_level_counts_only_steps_the_person_can_answer() {
        use AuthenticatorRequirement::{Alternative, Disabled, Required};
        let with_password = Holdings {
            password: true,
            ..Holdings::default()
        };
        let with_app = Holdings {
            authenticator_app: true,
            ..with_password
        };

        let strong = [step("password", Required), step("totp", Required)];
        assert_eq!(reachable_level(&levels(), &strong, &with_app), Some(2));
        assert_eq!(reachable_level(&levels(), &strong, &with_password), Some(1));

        let keyed = [step("password", Required), step("webauthn", Required)];
        assert_eq!(reachable_level(&levels(), &keyed, &with_app), Some(1));

        let switched_off = [step("password", Required), step("totp", Disabled)];
        assert_eq!(
            reachable_level(&levels(), &switched_off, &with_app),
            Some(1)
        );

        let offered = [
            step("magic-link", Alternative),
            step("password", Alternative),
            step("sms-otp", Alternative),
        ];
        let with_phone = Holdings {
            verified_phone: true,
            ..Holdings::default()
        };
        assert_eq!(reachable_level(&levels(), &offered, &with_phone), Some(2));
        assert_eq!(
            reachable_level(&levels(), &offered, &Holdings::default()),
            Some(1)
        );

        let unknown = [step("invented-elsewhere", Required)];
        assert_eq!(reachable_level(&levels(), &unknown, &with_app), None);
        assert_eq!(reachable_level(&AcrLoaMap::new(), &strong, &with_app), None);
    }
}
