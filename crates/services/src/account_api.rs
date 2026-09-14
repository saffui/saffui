use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::sessions::records::{UserSessionModel, UserSessionState};
use secrecy::SecretBox;
use serde_json::{Map, Value};
use store::providers::{realms, sessions, users};
use store::tenancy::TenantContext;

use crate::account::{
    Changing, FRESH_SIGN_IN_SECONDS, OwnFactor, OwnFactors, SignInStanding, Unchanged, Unread,
    Unremoved, change_own_password, own_factors, read_sign_in_standing, remove_own_factor,
};
use crate::context::minted_at;
use crate::token::Verified;

/// The one client whose tokens reach the account API: the realm's account console.
pub const ACCOUNT_CONSOLE: &str = "account-console";
/// The scope a token needs to reach the account API.
pub const ACCOUNT_SCOPE: &str = "account";

/// Who a request to the account API comes from, established from its token and
/// from what the realm holds.
#[derive(Debug, Clone)]
pub struct AccountCaller {
    pub tenant: TenantContext,
    /// The person the token's login belongs to, never read off the subject,
    /// which may be pairwise.
    pub user_id: String,
    pub session_id: String,
    /// Read once, so everything the request decides shares an instant.
    pub now: DateTime<Utc>,
}

/// Why a token does not reach the account API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotAdmitted {
    #[error("the token is not an access token the account console obtained")]
    NotForAccountConsole,
    #[error("the token does not carry the account scope")]
    MissingScope,
    #[error("the login the token names is not open in this realm")]
    LoggedOut,
    #[error("the account is switched off, or its tokens were cut after this one")]
    Withdrawn,
    #[error("the store could not be read")]
    Backend,
}

/// What a login has to prove before a sensitive change, in the terms RFC 9470
/// gives a resource to ask for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUp {
    /// The level to reach, by the name the realm gives it.
    pub acr_values: Option<String>,
    /// How many seconds old the sign-in may be.
    pub max_age: i64,
}

/// Where the account console's sign-in comes back to, under the realm's issuer.
pub fn compose_account_console_redirect(issuer: &str) -> String {
    format!("{issuer}/account/login/return")
}

fn read_text_claim<'v>(verified: &'v Verified, name: &str) -> Option<&'v str> {
    verified
        .claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

/// The login an account console token names, or why the token is not one.
///
/// An access token, obtained by the account console and minted for it, naming a
/// login, and only then carrying the scope: a token another client obtained is
/// refused whatever scope it carries.
pub fn read_account_token(verified: &Verified) -> Result<&str, NotAdmitted> {
    let obtained_by_the_console = read_text_claim(verified, "typ") == Some("Bearer")
        && read_text_claim(verified, "azp") == Some(ACCOUNT_CONSOLE)
        && verified
            .audiences
            .iter()
            .any(|audience| audience == ACCOUNT_CONSOLE);
    if !obtained_by_the_console {
        return Err(NotAdmitted::NotForAccountConsole);
    }
    let session_id = read_text_claim(verified, "sid").ok_or(NotAdmitted::NotForAccountConsole)?;
    if !verified
        .scope
        .split_whitespace()
        .any(|held| held == ACCOUNT_SCOPE)
    {
        return Err(NotAdmitted::MissingScope);
    }
    Ok(session_id)
}

/// Whether a login is open and belongs to this realm.
///
/// Open whatever the token's scope: `offline_access` lets a token outlive its
/// login elsewhere, and a person changing their account is at that login.
pub fn judge_session(
    session: &UserSessionModel,
    realm_id: &str,
    now: i64,
) -> Result<(), NotAdmitted> {
    let open = session.state == UserSessionState::LoggedIn
        && !session.expiration.is_some_and(|ends| ends <= now)
        && session.realm_id == realm_id;
    if open {
        Ok(())
    } else {
        Err(NotAdmitted::LoggedOut)
    }
}

/// Whether the realm still stands behind a person and a token minted at
/// `minted_at`: the account switched on, and not cut after the token was minted.
/// A cut the token cannot be placed against refuses, since reading the clock
/// instead would let every past cut pass.
pub fn judge_person(
    enabled: bool,
    not_before: Option<i64>,
    minted_at: Option<i64>,
) -> Result<(), NotAdmitted> {
    if !enabled {
        return Err(NotAdmitted::Withdrawn);
    }
    match (not_before, minted_at) {
        (Some(cut), Some(issued)) if issued < cut => Err(NotAdmitted::Withdrawn),
        (Some(_), None) => Err(NotAdmitted::Withdrawn),
        _ => Ok(()),
    }
}

/// Establish who a verified token lets reach the account API.
///
/// The person is the one the token's login belongs to, read off that login and
/// never off the subject.
pub async fn establish_account_caller(
    transaction: &Transaction<'_>,
    tenant: TenantContext,
    verified: &Verified,
    now: DateTime<Utc>,
) -> Result<AccountCaller, NotAdmitted> {
    let session_id = read_account_token(verified)?;
    let session = sessions::load(transaction, session_id)
        .await
        .map_err(|_| NotAdmitted::Backend)?
        .ok_or(NotAdmitted::LoggedOut)?;
    judge_session(&session, &tenant.realm_id, now.timestamp())?;
    let person = users::load(transaction, &session.user_id)
        .await
        .map_err(|_| NotAdmitted::Backend)?
        .ok_or(NotAdmitted::Withdrawn)?;
    judge_person(person.enabled, person.not_before, minted_at(verified))?;
    Ok(AccountCaller {
        tenant,
        user_id: person.user_id,
        session_id: session.session_id,
        now,
    })
}

/// What a login still has to prove before a sensitive change, if anything.
pub fn read_step_up(standing: &SignInStanding) -> Option<StepUp> {
    (!standing.allows_sensitive_change()).then(|| compose_step_up(standing))
}

/// The step-up a login is asked for: the level the flow lets the person reach, by
/// the realm's name for it, and a sign-in no older than a sensitive change allows.
fn compose_step_up(standing: &SignInStanding) -> StepUp {
    StepUp {
        acr_values: standing.reachable_acr.clone(),
        max_age: FRESH_SIGN_IN_SECONDS,
    }
}

/// What the caller's login still has to prove before a sensitive change, judged
/// against the flow the account console signs in with.
pub async fn find_needed_step_up(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
) -> Result<Option<StepUp>, Unread> {
    let standing = read_sign_in_standing(
        transaction,
        &caller.user_id,
        &caller.session_id,
        Some(ACCOUNT_CONSOLE),
        caller.now,
    )
    .await?;
    Ok(read_step_up(&standing))
}

/// What the realm holds of the caller, as the claims they read about themselves.
///
/// All of it, since it is theirs, with nothing held back by scope. The subject is
/// left out: it may be pairwise, and the console has no use for it.
pub async fn read_me(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
) -> Result<Map<String, Value>, Unread> {
    let person = users::load(transaction, &caller.user_id)
        .await
        .map_err(|_| Unread)?
        .ok_or(Unread)?;
    let mut claims = crate::userinfo::held_claims(&person);
    claims.remove("sub");
    Ok(claims)
}

/// Why a change to the caller's own account did not go ahead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unmade {
    /// The login has to be proven again, recently and strongly enough, first.
    #[error("the login has to be proven again first")]
    StepUp(StepUp),
    #[error("{0}")]
    Password(Unchanged),
    #[error("{0}")]
    LastFactor(&'static str),
    #[error("the caller holds no such factor")]
    NotFound,
    #[error("the store could not be read")]
    Backend,
}

/// Replace the caller's password on proof of the current one, from a login recent
/// and strong enough, and say how many of their other logins ended.
///
/// A wrong current password has written its count against the lock by the time it
/// is refused, and the caller commits that count.
pub async fn change_caller_password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    caller: &AccountCaller,
    from: Option<&str>,
    current: &SecretBox<String>,
    replacement: &SecretBox<String>,
) -> Result<usize, Unmade> {
    if let Some(step_up) = find_needed_step_up(transaction, caller)
        .await
        .map_err(|_| Unmade::Backend)?
    {
        return Err(Unmade::StepUp(step_up));
    }
    let realm = realms::load(transaction, &caller.tenant.realm_id)
        .await
        .map_err(|_| Unmade::Backend)?
        .ok_or(Unmade::Backend)?;
    let person = users::load(transaction, &caller.user_id)
        .await
        .map_err(|_| Unmade::Backend)?
        .ok_or(Unmade::Backend)?;
    change_own_password(
        transaction,
        provider,
        &Changing {
            realm: &realm,
            person: &person,
            session_id: &caller.session_id,
            from,
            now: caller.now,
        },
        current,
        replacement,
    )
    .await
    .map_err(Unmade::Password)
}

/// What the caller holds to sign in with, judged against the flow the account
/// console signs in with.
pub async fn read_caller_factors(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
) -> Result<OwnFactors, Unremoved> {
    own_factors(
        transaction,
        &caller.user_id,
        &caller.session_id,
        Some(ACCOUNT_CONSOLE),
        caller.now,
    )
    .await
}

/// Remove one of the caller's own factors, from a login recent and strong enough.
///
/// The removal judges the login itself, under the lock on the person's factors, so
/// the level to step up to is read only once it has refused.
pub async fn remove_caller_factor(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    factor: OwnFactor<'_>,
) -> Result<(), Unmade> {
    let removed = remove_own_factor(
        transaction,
        &caller.user_id,
        &caller.session_id,
        Some(ACCOUNT_CONSOLE),
        caller.now,
        factor,
    )
    .await;
    match removed {
        Ok(()) => Ok(()),
        Err(Unremoved::NotFresh | Unremoved::StrongerSignInNeeded) => {
            let standing = read_sign_in_standing(
                transaction,
                &caller.user_id,
                &caller.session_id,
                Some(ACCOUNT_CONSOLE),
                caller.now,
            )
            .await
            .map_err(|_| Unmade::Backend)?;
            Err(Unmade::StepUp(compose_step_up(&standing)))
        }
        Err(Unremoved::LastFactor(why)) => Err(Unmade::LastFactor(why)),
        Err(Unremoved::NotFound) => Err(Unmade::NotFound),
        Err(Unremoved::Backend) => Err(Unmade::Backend),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verified(claims: Value, audiences: &[&str], scope: &str) -> Verified {
        Verified {
            subject: "pairwise-subject".to_owned(),
            audiences: audiences.iter().map(|held| (*held).to_owned()).collect(),
            scope: scope.to_owned(),
            token_id: None,
            claims: claims.as_object().cloned().expect("an object"),
        }
    }

    fn console_claims() -> Value {
        json!({ "typ": "Bearer", "azp": ACCOUNT_CONSOLE, "sid": "session-1" })
    }

    /// Only an access token the account console obtained, minted for it and naming
    /// a login, names one, and its scope is read only then: a token another client
    /// obtained is refused as not being one whatever scope it carries.
    #[test]
    fn only_an_account_console_token_names_a_login() {
        let scoped = "openid account";
        assert_eq!(
            read_account_token(&verified(console_claims(), &[ACCOUNT_CONSOLE], scoped)),
            Ok("session-1")
        );
        for (claims, audiences) in [
            (
                json!({ "typ": "Refresh", "azp": ACCOUNT_CONSOLE, "sid": "session-1" }),
                vec![ACCOUNT_CONSOLE],
            ),
            (
                json!({ "typ": "Bearer", "azp": "app", "sid": "session-1" }),
                vec![ACCOUNT_CONSOLE],
            ),
            (
                json!({ "typ": "Bearer", "sid": "session-1" }),
                vec![ACCOUNT_CONSOLE],
            ),
            (console_claims(), vec!["app"]),
            (
                json!({ "typ": "Bearer", "azp": ACCOUNT_CONSOLE }),
                vec![ACCOUNT_CONSOLE],
            ),
            (
                json!({ "typ": "Bearer", "azp": ACCOUNT_CONSOLE, "sid": "" }),
                vec![ACCOUNT_CONSOLE],
            ),
        ] {
            assert_eq!(
                read_account_token(&verified(claims.clone(), &audiences, scoped)),
                Err(NotAdmitted::NotForAccountConsole),
                "{claims} {audiences:?}"
            );
        }
        assert_eq!(
            read_account_token(&verified(
                json!({ "typ": "Bearer", "azp": "app", "sid": "session-1" }),
                &[ACCOUNT_CONSOLE],
                "openid"
            )),
            Err(NotAdmitted::NotForAccountConsole)
        );
        for scope in ["openid", "openid accounts", ""] {
            assert_eq!(
                read_account_token(&verified(console_claims(), &[ACCOUNT_CONSOLE], scope)),
                Err(NotAdmitted::MissingScope),
                "{scope}"
            );
        }
    }

    fn session(
        state: UserSessionState,
        expiration: Option<i64>,
        realm_id: &str,
    ) -> UserSessionModel {
        UserSessionModel {
            tenant: "acme".into(),
            session_id: "session-1".into(),
            realm_id: realm_id.into(),
            user_id: "ada".into(),
            login_username: "ada".into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            user_agent: None,
            started_at: 1_789_372_800,
            auth_time: None,
            loa: None,
            expiration,
            state,
            browser_state: None,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        }
    }

    /// A login counts while it is open, unexpired and in this realm, and in no
    /// other state.
    #[test]
    fn only_an_open_login_of_this_realm_counts() {
        let now = 1_789_372_800;
        for held in [
            session(UserSessionState::LoggedIn, None, "main"),
            session(UserSessionState::LoggedIn, Some(now + 1), "main"),
        ] {
            assert_eq!(judge_session(&held, "main", now), Ok(()));
        }
        for held in [
            session(UserSessionState::LoggedOut, None, "main"),
            session(UserSessionState::LoggingOut, None, "main"),
            session(UserSessionState::LoggedIn, Some(now), "main"),
            session(UserSessionState::LoggedIn, None, "other"),
        ] {
            assert_eq!(
                judge_session(&held, "main", now),
                Err(NotAdmitted::LoggedOut),
                "{:?} {:?} {}",
                held.state,
                held.expiration,
                held.realm_id
            );
        }
    }

    /// The realm stands behind a person switched on and not cut after the token
    /// was minted, and not behind a cut the token cannot be placed against.
    #[test]
    fn a_switched_off_or_cut_account_is_withdrawn() {
        assert_eq!(judge_person(true, None, None), Ok(()));
        assert_eq!(judge_person(true, Some(100), Some(100)), Ok(()));
        assert_eq!(
            judge_person(false, None, Some(100)),
            Err(NotAdmitted::Withdrawn)
        );
        assert_eq!(
            judge_person(true, Some(101), Some(100)),
            Err(NotAdmitted::Withdrawn)
        );
        assert_eq!(
            judge_person(true, Some(100), None),
            Err(NotAdmitted::Withdrawn)
        );
    }

    fn standing(
        fresh_until: Option<i64>,
        reachable: Option<(i32, &str)>,
        reached: i32,
    ) -> SignInStanding {
        SignInStanding {
            fresh_until,
            reachable_level: reachable.map(|(level, _)| level),
            reachable_acr: reachable.map(|(_, acr)| acr.to_owned()),
            reached,
        }
    }

    /// A recent login as strong as the person could make it needs nothing more; one
    /// too old or too weak is asked for the level by name and for five minutes of
    /// age at most.
    #[test]
    fn a_step_up_names_the_level_and_the_age_a_change_needs() {
        let fresh = Some(1_789_373_100);
        let asked = |acr: Option<&str>| {
            Some(StepUp {
                acr_values: acr.map(str::to_owned),
                max_age: 300,
            })
        };
        assert_eq!(read_step_up(&standing(fresh, Some((2, "mfa")), 2)), None);
        assert_eq!(read_step_up(&standing(fresh, None, 0)), None);
        assert_eq!(
            read_step_up(&standing(None, Some((1, "password")), 1)),
            asked(Some("password"))
        );
        assert_eq!(
            read_step_up(&standing(fresh, Some((2, "mfa")), 1)),
            asked(Some("mfa"))
        );
        assert_eq!(read_step_up(&standing(None, None, 0)), asked(None));
    }
}
