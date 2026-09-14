use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use services::account::{OwnFactor, OwnFactors, Unchanged};
use services::account_api::{
    AccountCaller, Unmade, change_caller_password, find_needed_step_up, read_caller_factors,
    read_me, remove_caller_factor,
};
use store::tenancy::Tenancy;

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::admin::dto::PasswordChange;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::middleware::account_guard::AccountRefusal;

/// What the realm holds of the caller, as they read it about themselves.
pub async fn show_me(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let mut connection = pool.get().await.map_err(|_| AccountRefusal::Unavailable)?;
    let transaction = tenancy
        .transaction(&mut connection, &caller.tenant)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    let claims = read_me(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(claims))
}

/// Whether the caller's login may make a sensitive change now: no content when it
/// may, and the step-up challenge when it has to sign in again first.
pub async fn check_recent_sign_in(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let mut connection = pool.get().await.map_err(|_| AccountRefusal::Unavailable)?;
    let transaction = tenancy
        .transaction(&mut connection, &caller.tenant)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    match find_needed_step_up(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?
    {
        Some(step_up) => Err(AccountRefusal::StepUp(step_up)),
        None => Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::NO_CONTENT)).finish()),
    }
}

/// The caller's password, replaced on proof of the current one from a login recent
/// and strong enough. Every other login of theirs ends, and the answer says how many.
pub async fn change_password(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
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
    let mut connection = pool.get().await.map_err(|_| AccountRefusal::Unavailable)?;
    let transaction = tenancy
        .transaction(&mut connection, &caller.tenant)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
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
                .map_err(|_| AccountRefusal::Unavailable)?;
            Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(serde_json::json!({ "ended_sessions": ended })))
        }
        // The count is the refusal: rolled back, a wrong guess would cost nothing
        // and the lock would never close.
        Err(Unmade::Password(Unchanged::Mismatch)) => {
            transaction
                .commit()
                .await
                .map_err(|_| AccountRefusal::Unavailable)?;
            Err(refuse(Unmade::Password(Unchanged::Mismatch)))
        }
        Err(why) => Err(refuse(why)),
    }
}

/// What the caller holds to sign in with, and why any of it has to stay.
pub async fn list_factors(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    let mut connection = pool.get().await.map_err(|_| AccountRefusal::Unavailable)?;
    let transaction = tenancy
        .transaction(&mut connection, &caller.tenant)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    let held = read_caller_factors(&transaction, &caller)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    Ok(uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(describe_own_factors(&held)))
}

/// Take away one of the caller's authenticator apps.
pub async fn remove_app(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, credential_id) = path.into_inner();
    remove(&caller, &pool, &tenancy, OwnFactor::App(&credential_id)).await
}

/// Take away one of the caller's passkeys, named as the listing spells it.
pub async fn remove_key(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, AccountRefusal> {
    let (_, credential) = path.into_inner();
    let credential_id = BASE64URL_NOPAD
        .decode(credential.as_bytes())
        .map_err(|_| AccountRefusal::Refused(ApiError::new(ErrorCode::BadRequest)))?;
    remove(&caller, &pool, &tenancy, OwnFactor::Key(&credential_id)).await
}

/// Take away the caller's whole sheet of recovery codes.
pub async fn remove_recovery_codes(
    caller: web::ReqData<AccountCaller>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> Result<HttpResponse, AccountRefusal> {
    remove(&caller, &pool, &tenancy, OwnFactor::RecoveryCodes).await
}

async fn remove(
    caller: &AccountCaller,
    pool: &Pool,
    tenancy: &Tenancy,
    factor: OwnFactor<'_>,
) -> Result<HttpResponse, AccountRefusal> {
    let mut connection = pool.get().await.map_err(|_| AccountRefusal::Unavailable)?;
    let transaction = tenancy
        .transaction(&mut connection, &caller.tenant)
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
    remove_caller_factor(&transaction, caller, factor)
        .await
        .map_err(refuse)?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountRefusal::Unavailable)?;
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
        Unmade::Password(Unchanged::Backend) | Unmade::Backend => AccountRefusal::Unavailable,
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
