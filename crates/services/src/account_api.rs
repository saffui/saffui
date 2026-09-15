use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use secrecy::SecretBox;
use serde_json::{Map, Value};
use store::providers::{clients, consents, realms, sessions, users};
use store::tenancy::TenantContext;

use crate::account::{
    Changing, FRESH_SIGN_IN_SECONDS, OwnFactor, OwnFactors, SignInStanding, Unchanged, Unread,
    Unremoved, change_own_password, own_factors, read_sign_in_standing, remove_own_factor,
};
use crate::context::minted_at;
use crate::grant::Signing;
use crate::logout::{Notice, notice_for_client, notices_for};
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

/// How one of the caller's logins still stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStanding {
    Open,
    /// Closed or run out, while an application keeps an offline grant born of it.
    OfflineOnly,
}

fn is_live(grant: &ClientSessionModel, now: i64) -> bool {
    !grant.expiration.is_some_and(|ends| ends <= now)
}

/// Whether a login still stands for its person: open, or closed while an offline
/// grant born of it lives on. Anything else is history the sweeper has not reached.
pub fn judge_login_standing(
    session: &UserSessionModel,
    grants: &[ClientSessionModel],
    now: i64,
) -> Option<LoginStanding> {
    let open = session.state == UserSessionState::LoggedIn
        && !session.expiration.is_some_and(|ends| ends <= now);
    if open {
        return Some(LoginStanding::Open);
    }
    grants
        .iter()
        .any(|grant| grant.offline == Some(true) && is_live(grant, now))
        .then_some(LoginStanding::OfflineOnly)
}

/// Whether a grant is shown under its login: alive, and offline where the login
/// stands only for its offline grants.
pub fn keep_shown_grant(standing: LoginStanding, grant: &ClientSessionModel, now: i64) -> bool {
    is_live(grant, now) && (standing == LoginStanding::Open || grant.offline == Some(true))
}

/// What an application still holds from one of the caller's logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldGrant {
    pub client_id: String,
    /// The name the realm shows the application by.
    pub name: String,
    pub offline: bool,
    pub expiration: Option<i64>,
}

/// One of the caller's logins, as they read it.
#[derive(Debug, Clone)]
pub struct HeldLogin {
    pub session: UserSessionModel,
    pub standing: LoginStanding,
    /// Whether the request rides this login.
    pub current: bool,
    pub grants: Vec<HeldGrant>,
}

/// The caller's logins that still stand, newest first, each with what its
/// applications still hold from it.
pub async fn list_caller_logins(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
) -> Result<Vec<HeldLogin>, Unread> {
    let now = caller.now.timestamp();
    let logins = sessions::load_for_user(transaction, &caller.user_id)
        .await
        .map_err(|_| Unread)?;
    let mut held = Vec::new();
    for session in logins {
        let grants = sessions::client_sessions_of(transaction, &session.session_id)
            .await
            .map_err(|_| Unread)?;
        let Some(standing) = judge_login_standing(&session, &grants, now) else {
            continue;
        };
        let mut shown = Vec::new();
        for grant in grants
            .into_iter()
            .filter(|grant| keep_shown_grant(standing, grant, now))
        {
            let name = clients::load(transaction, &grant.client_id)
                .await
                .map_err(|_| Unread)?
                .map_or_else(
                    || grant.client_id.clone(),
                    |client| name_application(&grant.client_id, &client.display_name, &client.name),
                );
            shown.push(HeldGrant {
                name,
                offline: grant.offline == Some(true),
                expiration: grant.expiration,
                client_id: grant.client_id,
            });
        }
        held.push(HeldLogin {
            current: session.session_id == caller.session_id,
            standing,
            grants: shown,
            session,
        });
    }
    Ok(held)
}

/// Why an ending asked by the caller did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unended {
    #[error("the caller holds no such login")]
    NotFound,
    #[error("the application holds nothing from that login")]
    NoSuchGrant,
    #[error("the application holds no consent from the caller")]
    NoSuchConsent,
    #[error("the store could not be read")]
    Backend,
}

/// End one of the caller's logins and everything its applications got from it,
/// offline grants included, and hand back the logout notices they are owed.
///
/// The notices are minted while the login can still be read, and sent by the caller
/// once the ending has committed, the way a logout does it. Named through the
/// caller, so an identifier from somebody else's listing reaches nothing.
pub async fn end_caller_login(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    signing: Option<&Signing<'_>>,
    issuer: &str,
    session_id: &str,
) -> Result<Vec<Notice>, Unended> {
    let held = sessions::load(transaction, session_id)
        .await
        .map_err(|_| Unended::Backend)?
        .filter(|session| session.user_id == caller.user_id)
        .ok_or(Unended::NotFound)?;
    let notices = match signing {
        Some(signing) => {
            notices_for(transaction, signing, issuer, &held.session_id, caller.now).await
        }
        None => Vec::new(),
    };
    sessions::close(transaction, &held.session_id)
        .await
        .map_err(|_| Unended::Backend)?;
    Ok(notices)
}

/// End every login of the caller's but the one the request rides, with what their
/// applications got from them, and hand back how many ended and the logout notices
/// their applications are owed.
pub async fn end_caller_other_logins(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    signing: Option<&Signing<'_>>,
    issuer: &str,
) -> Result<(usize, Vec<Notice>), Unended> {
    let mut notices = Vec::new();
    if let Some(signing) = signing {
        let logins = sessions::load_for_user(transaction, &caller.user_id)
            .await
            .map_err(|_| Unended::Backend)?;
        for session in logins
            .iter()
            .filter(|session| session.session_id != caller.session_id)
        {
            notices.extend(
                notices_for(
                    transaction,
                    signing,
                    issuer,
                    &session.session_id,
                    caller.now,
                )
                .await,
            );
        }
    }
    let ended = sessions::end_others_of_user(transaction, &caller.user_id, &caller.session_id)
        .await
        .map_err(|_| Unended::Backend)?;
    Ok((ended, notices))
}

/// Take back what one application got from one of the caller's logins, leaving the
/// login and every other application alone, and hand back the logout notice the
/// application is owed for that login.
pub async fn revoke_caller_grant(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    signing: Option<&Signing<'_>>,
    issuer: &str,
    session_id: &str,
    client_id: &str,
) -> Result<Vec<Notice>, Unended> {
    sessions::load(transaction, session_id)
        .await
        .map_err(|_| Unended::Backend)?
        .filter(|session| session.user_id == caller.user_id)
        .ok_or(Unended::NotFound)?;
    take_back_grant(transaction, caller, signing, issuer, session_id, client_id)
        .await?
        .ok_or(Unended::NoSuchGrant)
}

/// Take back one application's grant from one login, with the notice it is owed when it
/// registered where to be told; None when it held nothing there. The notice names the
/// login, which reads the same after the grant is gone.
async fn take_back_grant(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    signing: Option<&Signing<'_>>,
    issuer: &str,
    session_id: &str,
    client_id: &str,
) -> Result<Option<Vec<Notice>>, Unended> {
    let taken = sessions::close_client_session_of(transaction, session_id, client_id)
        .await
        .map_err(|_| Unended::Backend)?;
    if !taken {
        return Ok(None);
    }
    let notice = match signing {
        Some(signing) => {
            notice_for_client(
                transaction,
                signing,
                issuer,
                session_id,
                client_id,
                caller.now,
            )
            .await
        }
        None => None,
    };
    Ok(Some(notice.into_iter().collect()))
}

/// The applications the realm keeps for itself, which the account API neither lists nor
/// takes back: the account console, and each client the admin console signs in as.
pub fn list_realm_consoles(admin_parties: &[String]) -> Vec<String> {
    std::iter::once(ACCOUNT_CONSOLE.to_owned())
        .chain(admin_parties.iter().cloned())
        .collect()
}

/// The name the realm shows an application by: its display name, else its name, else
/// its identifier.
pub fn name_application(client_id: &str, display_name: &str, name: &str) -> String {
    [display_name, name]
        .into_iter()
        .find(|held| !held.trim().is_empty())
        .unwrap_or(client_id)
        .to_owned()
}

/// Where a person may go to reach an application: its home page, else its root address,
/// and only an address a browser may safely be sent to.
pub fn choose_application_home(client_uri: Option<&str>, root_url: Option<&str>) -> Option<String> {
    [client_uri, root_url]
        .into_iter()
        .flatten()
        .find(|held| commons::address::is_https_or_loopback(held))
        .map(str::to_owned)
}

/// What an application holds from the caller's logins, gathered across them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAccess {
    /// How many of the caller's logins it holds a grant from.
    pub logins: usize,
    /// Whether any of those grants reaches the account while the person is away.
    pub offline: bool,
    /// When the last of those grants runs out; None when one never does.
    pub expiration: Option<i64>,
}

/// What each application holds across the logins shown, by its identifier.
pub fn gather_application_access(logins: &[HeldLogin]) -> BTreeMap<String, HeldAccess> {
    let mut gathered = BTreeMap::<String, HeldAccess>::new();
    for grant in logins.iter().flat_map(|login| &login.grants) {
        let access = gathered
            .entry(grant.client_id.clone())
            .or_insert(HeldAccess {
                logins: 0,
                offline: false,
                expiration: grant.expiration,
            });
        access.logins += 1;
        access.offline |= grant.offline;
        access.expiration = access
            .expiration
            .zip(grant.expiration)
            .map(|(one, other)| one.max(other));
    }
    gathered
}

/// What the caller agreed an application may have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreedConsent {
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    /// Whether the application asks for agreement before it signs the person in, so
    /// that a withdrawn consent is asked for again.
    pub asks_consent: bool,
}

/// An application that holds something of the caller: what they agreed it may have,
/// what it holds from their logins, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldApplication {
    pub client_id: String,
    pub name: String,
    /// Where the person may go to reach it, when the realm gave a safe address.
    pub home: Option<String>,
    pub consent: Option<AgreedConsent>,
    pub access: Option<HeldAccess>,
}

/// The applications that hold something of the caller, by name, leaving out the realm's
/// own consoles.
pub async fn list_caller_applications(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    consoles: &[String],
) -> Result<Vec<HeldApplication>, Unread> {
    let logins = list_caller_logins(transaction, caller).await?;
    let mut access = gather_application_access(&logins);
    let mut agreed: BTreeMap<String, consents::Consent> =
        consents::of_user(transaction, &caller.user_id)
            .await
            .map_err(|_| Unread)?
            .into_iter()
            .map(|consent| (consent.client_id.clone(), consent))
            .collect();
    let named: BTreeSet<String> = access
        .keys()
        .chain(agreed.keys())
        .filter(|client_id| !consoles.contains(client_id))
        .cloned()
        .collect();
    let mut held = Vec::new();
    for client_id in named {
        let client = clients::load(transaction, &client_id)
            .await
            .map_err(|_| Unread)?;
        let asks_consent = client
            .as_ref()
            .is_some_and(|client| client.consent_required == Some(true));
        held.push(HeldApplication {
            name: client.as_ref().map_or_else(
                || client_id.clone(),
                |client| name_application(&client_id, &client.display_name, &client.name),
            ),
            home: client.as_ref().and_then(|client| {
                choose_application_home(client.client_uri.as_deref(), client.root_url.as_deref())
            }),
            consent: agreed.remove(&client_id).map(|consent| AgreedConsent {
                scopes: consent.scopes,
                granted_at: consent.granted_at,
                asks_consent,
            }),
            access: access.remove(&client_id),
            client_id,
        });
    }
    held.sort_by(|one, other| {
        one.name
            .to_lowercase()
            .cmp(&other.name.to_lowercase())
            .then_with(|| one.client_id.cmp(&other.client_id))
    });
    Ok(held)
}

/// Withdraw what the caller agreed an application may have. What it already holds keeps
/// working, and its next sign-in asks again where the application asks at all.
pub async fn withdraw_caller_consent(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    client_id: &str,
    consoles: &[String],
) -> Result<(), Unended> {
    if consoles.iter().any(|console| console == client_id) {
        return Err(Unended::NoSuchConsent);
    }
    let withdrawn = consents::withdraw(transaction, &caller.user_id, client_id)
        .await
        .map_err(|_| Unended::Backend)?;
    withdrawn.then_some(()).ok_or(Unended::NoSuchConsent)
}

/// Take back everything one application got from any of the caller's logins, offline
/// grants included, and hand back how many grants went and the notices the application
/// is owed, one for each login it was signed in through. A console of the realm's is
/// not taken back here: ending the login is how it goes.
pub async fn take_back_caller_access(
    transaction: &Transaction<'_>,
    caller: &AccountCaller,
    signing: Option<&Signing<'_>>,
    issuer: &str,
    client_id: &str,
    consoles: &[String],
) -> Result<(usize, Vec<Notice>), Unended> {
    if consoles.iter().any(|console| console == client_id) {
        return Err(Unended::NoSuchGrant);
    }
    let logins = sessions::load_for_user(transaction, &caller.user_id)
        .await
        .map_err(|_| Unended::Backend)?;
    let mut taken = 0;
    let mut notices = Vec::new();
    for login in &logins {
        if let Some(told) = take_back_grant(
            transaction,
            caller,
            signing,
            issuer,
            &login.session_id,
            client_id,
        )
        .await?
        {
            taken += 1;
            notices.extend(told);
        }
    }
    if taken == 0 {
        return Err(Unended::NoSuchGrant);
    }
    Ok((taken, notices))
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

    fn grant(offline: bool, expiration: Option<i64>) -> ClientSessionModel {
        ClientSessionModel {
            tenant: "acme".into(),
            session_id: "grant-1".into(),
            realm_id: "main".into(),
            user_id: "ada".into(),
            user_session_id: "session-1".into(),
            client_id: "app".into(),
            auth_method: None,
            redirect_uri: None,
            started_at: 1_789_372_800,
            expiration,
            notes: None,
            current_refresh_token: None,
            current_refresh_token_use_count: None,
            offline: Some(offline),
            requested_claims: None,
        }
    }

    /// A login stands while it is open, or while an offline grant born of it lives on
    /// after it closed or ran out; one left with nothing alive, or only with grants
    /// that end with it, is history.
    #[test]
    fn a_login_stands_while_open_or_while_an_offline_grant_outlives_it() {
        let now = 1_789_372_800;
        let open = session(UserSessionState::LoggedIn, Some(now + 60), "main");
        assert_eq!(
            judge_login_standing(&open, &[], now),
            Some(LoginStanding::Open)
        );
        let closed = session(UserSessionState::LoggedOut, None, "main");
        let run_out = session(UserSessionState::LoggedIn, Some(now), "main");
        for ended in [&closed, &run_out] {
            assert_eq!(
                judge_login_standing(ended, &[grant(true, Some(now + 60))], now),
                Some(LoginStanding::OfflineOnly)
            );
            assert_eq!(
                judge_login_standing(
                    ended,
                    &[grant(true, Some(now)), grant(false, Some(now + 60))],
                    now
                ),
                None
            );
            assert_eq!(judge_login_standing(ended, &[], now), None);
        }
    }

    /// An open login shows every grant still alive; a login that stands only for its
    /// offline grants shows those alone.
    #[test]
    fn a_login_shows_the_grants_that_still_hold_something() {
        let now = 1_789_372_800;
        let online = grant(false, Some(now + 60));
        let offline = grant(true, None);
        let over = grant(true, Some(now));
        assert!(keep_shown_grant(LoginStanding::Open, &online, now));
        assert!(keep_shown_grant(LoginStanding::Open, &offline, now));
        assert!(!keep_shown_grant(LoginStanding::Open, &over, now));
        assert!(!keep_shown_grant(LoginStanding::OfflineOnly, &online, now));
        assert!(keep_shown_grant(LoginStanding::OfflineOnly, &offline, now));
        assert!(!keep_shown_grant(LoginStanding::OfflineOnly, &over, now));
    }

    /// An application goes by the name the realm shows it by: its display name, else its
    /// name, else its identifier.
    #[test]
    fn an_application_goes_by_the_name_the_realm_shows() {
        assert_eq!(name_application("app", "Grafana", "grafana"), "Grafana");
        assert_eq!(name_application("app", "  ", "grafana"), "grafana");
        assert_eq!(name_application("app", "", " "), "app");
    }

    /// A person is sent to an application only through an address a browser may safely
    /// follow: its home page first, then its root address.
    #[test]
    fn an_application_is_reached_only_through_a_safe_address() {
        assert_eq!(
            choose_application_home(
                Some("https://app.example/home"),
                Some("https://app.example")
            ),
            Some("https://app.example/home".to_owned())
        );
        assert_eq!(
            choose_application_home(Some("javascript:alert(1)"), Some("https://app.example")),
            Some("https://app.example".to_owned())
        );
        assert_eq!(
            choose_application_home(Some("http://app.example"), None),
            None
        );
        assert_eq!(
            choose_application_home(None, Some("http://localhost:3000")),
            Some("http://localhost:3000".to_owned())
        );
        assert_eq!(choose_application_home(None, None), None);
    }

    /// What an application holds is gathered across the person's logins: how many it
    /// holds a grant from, whether any reaches the account offline, and when the last runs
    /// out, which is never when one of them never does.
    #[test]
    fn what_an_application_holds_is_gathered_across_logins() {
        let held = |client_id: &str, offline: bool, expiration: Option<i64>| HeldGrant {
            client_id: client_id.to_owned(),
            name: client_id.to_owned(),
            offline,
            expiration,
        };
        let login = |grants: Vec<HeldGrant>| HeldLogin {
            session: session(UserSessionState::LoggedIn, None, "main"),
            standing: LoginStanding::Open,
            current: false,
            grants,
        };
        let gathered = gather_application_access(&[
            login(vec![
                held("app", false, Some(100)),
                held("spa", false, None),
            ]),
            login(vec![held("app", true, Some(300))]),
        ]);
        assert_eq!(
            gathered["app"],
            HeldAccess {
                logins: 2,
                offline: true,
                expiration: Some(300)
            }
        );
        assert_eq!(
            gathered["spa"],
            HeldAccess {
                logins: 1,
                offline: false,
                expiration: None
            }
        );
        let forever = gather_application_access(&[
            login(vec![held("app", false, None)]),
            login(vec![held("app", false, Some(300))]),
        ]);
        assert_eq!(forever["app"].expiration, None);
    }

    /// The realm's own consoles are the account console and every client the admin
    /// console signs in as.
    #[test]
    fn the_realms_consoles_are_the_account_console_and_the_admin_parties() {
        assert_eq!(
            list_realm_consoles(&["saffui-console".to_owned(), "ops-console".to_owned()]),
            ["account-console", "saffui-console", "ops-console"]
        );
    }
}
