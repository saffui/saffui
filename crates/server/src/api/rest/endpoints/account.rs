use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::PublicOrigin;
use data_encoding::BASE64URL_NOPAD;
use secrecy::SecretBox;
use services::account::{OwnFactor, OwnFactors, Unchanged};
use services::account_api::{
    AccountCaller, HeldApplication, HeldLogin, LoginStanding, Unended, Unmade,
    change_caller_password, end_caller_login, end_caller_other_logins, find_needed_step_up,
    list_caller_applications, list_caller_logins, list_realm_consoles, read_caller_factors,
    read_me, remove_caller_factor, revoke_caller_grant, take_back_caller_access,
    withdraw_caller_consent,
};
use services::agent::read_agent;
use services::grant::Signing;
use store::tenancy::{Tenancy, UnitOfWork};

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::admin::dto::PasswordChange;
use crate::api::rest::endpoints::protocol::backchannel;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::middleware::account_guard::AccountRefusal;
use crate::middleware::admin_policy::AdminPolicy;

/// What the realm holds of the caller, as they read it about themselves.
pub async fn show_me(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let claims = read_me(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(claims))
}

/// Whether the caller's login may make a sensitive change now: no content when it
/// may, and the step-up challenge when it has to sign in again first.
pub async fn check_recent_sign_in(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    match find_needed_step_up(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Failed)?
    {
        Some(step_up) => Err(AccountRefusal::StepUp(step_up)),
        None => Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish()),
    }
}

/// The caller's password, replaced on proof of the current one from a login recent
/// and strong enough. Every other login of theirs ends, and the answer says how many.
pub async fn change_password(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    request: HttpRequest,
    body: web::Json<PasswordChange>,
) -> Result<HttpResponse, AccountRefusal> {
    let PasswordChange {
        current_password,
        new_password,
    } = body.into_inner();
    if current_password.is_empty() {
        return Err(AccountRefusal::Refused(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the current password is required",
        )));
    }
    if new_password.is_empty() {
        return Err(AccountRefusal::Refused(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a new password is required",
        )));
    }
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let from = read_provenance(&request).address;
    let changed = change_caller_password(
        &transaction,
        sealing.provider.as_ref(),
        &caller,
        from.as_deref(),
        &SecretBox::new(Box::new(current_password)),
        &SecretBox::new(Box::new(new_password)),
    )
    .await;
    match changed {
        Ok(ended) => {
            transaction
                .commit()
                .await
                .map_err(|_| AccountRefusal::Failed)?;
            Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(serde_json::json!({ "ended_sessions": ended })))
        }
        // The count is the refusal: rolled back, a wrong guess would cost nothing
        // and the lock would never close.
        Err(Unmade::Password(Unchanged::Mismatch)) => {
            transaction
                .commit()
                .await
                .map_err(|_| AccountRefusal::Failed)?;
            Err(refuse(Unmade::Password(Unchanged::Mismatch)))
        }
        Err(why) => Err(refuse(why)),
    }
}

/// What the caller holds to sign in with, and why any of it has to stay.
pub async fn list_factors(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let held = read_caller_factors(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(describe_own_factors(&held)))
}

/// Take away one of the caller's authenticator apps.
pub async fn remove_app(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, credential_id) = path.into_inner();
    remove(&caller, &tenancy, OwnFactor::App(&credential_id)).await
}

/// Take away one of the caller's passkeys, named as the listing spells it.
pub async fn remove_key(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, credential) = path.into_inner();
    let credential_id = BASE64URL_NOPAD
        .decode(credential.as_bytes())
        .map_err(|_| AccountRefusal::Refused(ApiError::new(ErrorCode::BadRequest)))?;
    remove(&caller, &tenancy, OwnFactor::Key(&credential_id)).await
}

/// Take away the caller's whole sheet of recovery codes.
pub async fn remove_recovery_codes(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    remove(&caller, &tenancy, OwnFactor::RecoveryCodes).await
}

async fn remove(
    caller: &AccountCaller,
    tenancy: &Tenancy,
    factor: OwnFactor<'_>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    remove_caller_factor(&transaction, caller, factor)
        .await
        .map_err(refuse)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish())
}

/// A change refused, in the words the account API answers with.
fn refuse(why: Unmade) -> AccountRefusal {
    let refused = |code| AccountRefusal::Refused(ApiError::new(code));
    match why {
        Unmade::StepUp(step_up) => AccountRefusal::StepUp(step_up),
        Unmade::Password(Unchanged::Mismatch) => refused(ErrorCode::CurrentPasswordMismatch),
        Unmade::Password(Unchanged::LockedOut) => refused(ErrorCode::UserLockedOut),
        Unmade::Password(Unchanged::NotHeldHere) => refused(ErrorCode::PasswordNotHeldHere),
        Unmade::Password(Unchanged::Refused(said)) => {
            AccountRefusal::Refused(ApiError::with_detail(ErrorCode::ValidationError, said))
        }
        Unmade::LastFactor(said) => {
            AccountRefusal::Refused(ApiError::with_detail(ErrorCode::AccountLastFactor, said))
        }
        Unmade::NotFound => refused(ErrorCode::CredentialNotFound),
        Unmade::Password(Unchanged::Backend) | Unmade::Backend => AccountRefusal::Failed,
    }
}

/// What a person holds to sign in with, as both doors to their own account answer it.
pub(crate) fn describe_own_factors(held: &OwnFactors) -> serde_json::Value {
    let app_kept = held.app_kept_because();
    let key_kept = held.key_kept_because();
    serde_json::json!({
        "password": held.password,
        "apps": held.apps.iter().map(|app| serde_json::json!({
            "id": app.credential_id,
            "kind": app.credential_type.to_string(),
            "label": app.user_label,
            "created_at": app.metadata.created_at,
            "kept_because": app_kept,
        })).collect::<Vec<_>>(),
        "keys": held.keys.iter().map(|key| serde_json::json!({
            "id": BASE64URL_NOPAD.encode(&key.credential_id),
            "label": key.label,
            "enrolled_at": key.enrolled_at,
            "last_used_at": key.last_used_at,
            "kept_because": key_kept,
        })).collect::<Vec<_>>(),
        "recovery_codes": held.recovery_codes,
        "fresh_until": held.fresh_until,
        "stronger_sign_in_needed": held.stronger_sign_in_needed,
    })
}

/// The caller's logins that still stand, newest first: which one the request rides,
/// when each opened and last authenticated, where from, and what each application
/// still holds from it.
pub async fn list_sessions(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let held = list_caller_logins(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .json(held.iter().map(describe_login).collect::<Vec<_>>()))
}

/// End one of the caller's logins, the one the request rides included, with what its
/// applications got from it. The applications registered to hear of it are told once
/// the ending has committed.
pub async fn end_session(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, session_id) = path.into_inner();
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let ring = open_realm_keys(&transaction, &sealing, &caller).await;
    let signing = ring.as_ref().map(|ring| sign_with(&sealing, ring));
    let notices = end_caller_login(
        &transaction,
        &caller,
        signing.as_ref(),
        &origin.issuer(&caller.tenant.realm_id),
        &session_id,
    )
    .await
    .map_err(refuse_ending)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    backchannel::deliver(notices, **egress).await;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish())
}

/// End every login of the caller's but the one the request rides, and say how many
/// ended. The applications registered to hear of them are told once it committed.
pub async fn end_other_sessions(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let ring = open_realm_keys(&transaction, &sealing, &caller).await;
    let signing = ring.as_ref().map(|ring| sign_with(&sealing, ring));
    let (ended, notices) = end_caller_other_logins(
        &transaction,
        &caller,
        signing.as_ref(),
        &origin.issuer(&caller.tenant.realm_id),
    )
    .await
    .map_err(refuse_ending)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    backchannel::deliver(notices, **egress).await;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .json(serde_json::json!({ "ended_sessions": ended })))
}

/// Take back what one application got from one of the caller's logins. The
/// application is told, when it registered to hear of it, once the taking committed.
pub async fn revoke_grant(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, session_id, client_id) = path.into_inner();
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let ring = open_realm_keys(&transaction, &sealing, &caller).await;
    let signing = ring.as_ref().map(|ring| sign_with(&sealing, ring));
    let notices = revoke_caller_grant(
        &transaction,
        &caller,
        signing.as_ref(),
        &origin.issuer(&caller.tenant.realm_id),
        &session_id,
        &client_id,
    )
    .await
    .map_err(refuse_ending)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    backchannel::deliver(notices, **egress).await;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish())
}

/// The applications that hold something of the caller: what they agreed each may have,
/// and what each holds from their logins. The realm's own consoles are left out.
pub async fn list_applications(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    policy: web::Data<AdminPolicy>,
) -> Result<HttpResponse, AccountRefusal> {
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let held =
        list_caller_applications(&transaction, &caller, &list_realm_consoles(&policy.parties))
            .await
            .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .json(held.iter().map(describe_application).collect::<Vec<_>>()))
}

/// Withdraw what the caller agreed one application may have. What it already holds
/// keeps working.
pub async fn withdraw_consent(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    policy: web::Data<AdminPolicy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, client_id) = path.into_inner();
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    withdraw_caller_consent(
        &transaction,
        &caller,
        &client_id,
        &list_realm_consoles(&policy.parties),
    )
    .await
    .map_err(refuse_ending)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish())
}

/// Take back everything one application got from the caller's logins, and say how many
/// grants went. The application is told once for each login, once the taking committed.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a piece of app state this door reads"
)]
pub async fn take_back_access(
    caller: web::ReqData<AccountCaller>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
    policy: web::Data<AdminPolicy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, client_id) = path.into_inner();
    let transaction = tenancy
        .begin(&caller.tenant)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let ring = open_realm_keys(&transaction, &sealing, &caller).await;
    let signing = ring.as_ref().map(|ring| sign_with(&sealing, ring));
    let (taken, notices) = take_back_caller_access(
        &transaction,
        &caller,
        signing.as_ref(),
        &origin.issuer(&caller.tenant.realm_id),
        &client_id,
        &list_realm_consoles(&policy.parties),
    )
    .await
    .map_err(refuse_ending)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    backchannel::deliver(notices, **egress).await;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .json(serde_json::json!({ "ended_grants": taken })))
}

/// The realm's keys, opened to sign the logout notices an ending owes. None when they
/// cannot be opened: the ending goes ahead, and nobody is told.
async fn open_realm_keys(
    transaction: &UnitOfWork,
    sealing: &Sealing,
    caller: &AccountCaller,
) -> Option<store::keyring::RealmKeyring> {
    store::keyring::load(
        transaction,
        &sealing.envelope,
        &caller.tenant.tenant,
        &caller.tenant.realm_id,
    )
    .await
    .ok()
}

fn sign_with<'a>(sealing: &'a Sealing, ring: &'a store::keyring::RealmKeyring) -> Signing<'a> {
    Signing {
        provider: sealing.provider.as_ref(),
        ring,
        envelope: &sealing.envelope,
    }
}

/// An ending refused, in the words the account API answers with.
fn refuse_ending(why: Unended) -> AccountRefusal {
    match why {
        Unended::NotFound => AccountRefusal::Refused(ApiError::new(ErrorCode::SessionNotFound)),
        Unended::NoSuchGrant => AccountRefusal::Refused(ApiError::new(ErrorCode::GrantNotFound)),
        Unended::NoSuchConsent => {
            AccountRefusal::Refused(ApiError::new(ErrorCode::ConsentNotFound))
        }
        Unended::Backend => AccountRefusal::Failed,
    }
}

/// A login as its person reads it: the browser and the system read from what the
/// browser sent, which itself stays behind.
fn describe_login(held: &HeldLogin) -> serde_json::Value {
    let read = held.session.user_agent.as_deref().map(read_agent);
    let brokered = held.session.auth_method.as_deref() == Some("broker");
    serde_json::json!({
        "session_id": held.session.session_id,
        "current": held.current,
        "open": held.standing == LoginStanding::Open,
        "auth_method": held.session.auth_method,
        "provider": held.session.broker_session_id.as_deref().filter(|_| brokered),
        "ip_address": held.session.ip_address,
        "browser": read.as_ref().and_then(|read| read.browser),
        "system": read.as_ref().and_then(|read| read.system),
        "mobile": read.as_ref().is_some_and(|read| read.mobile),
        "started_at": held.session.started_at,
        "auth_time": held.session.auth_time,
        "expiration": held.session.expiration,
        "grants": held.grants.iter().map(|grant| serde_json::json!({
            "client_id": grant.client_id,
            "name": grant.name,
            "offline": grant.offline,
            "expiration": grant.expiration,
        })).collect::<Vec<_>>(),
    })
}

/// An application as its person reads it: what they agreed it may have, and what it
/// holds from their logins, never a secret nor an address a browser should not follow.
fn describe_application(held: &HeldApplication) -> serde_json::Value {
    serde_json::json!({
        "client_id": held.client_id,
        "name": held.name,
        "home": held.home,
        "consent": held.consent.as_ref().map(|agreed| serde_json::json!({
            "scopes": agreed.scopes,
            "granted_at": agreed.granted_at,
            "asks_consent": agreed.asks_consent,
        })),
        "access": held.access.as_ref().map(|access| serde_json::json!({
            "logins": access.logins,
            "offline": access.offline,
            "expiration": access.expiration,
        })),
    })
}
