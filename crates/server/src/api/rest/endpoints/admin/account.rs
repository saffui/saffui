use actix_web::{HttpRequest, HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use data_encoding::BASE64URL_NOPAD;
use secrecy::SecretBox;
use services::account::{self, Changing, OwnFactor, Unchanged, Unremoved};
use store::tenancy::Tenancy;

use super::dto::PasswordChange;
use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::account::describe_own_factors;
use crate::api::rest::endpoints::within;
use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;

/// The caller's own password, replaced on proof of the current one.
///
/// Nothing in the request names a person: the account is the one the token
/// speaks for, so this door cannot be pointed at somebody else's.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn change_own_password(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    request: HttpRequest,
    path: web::Path<String>,
    body: web::Json<PasswordChange>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let PasswordChange {
        current_password,
        new_password,
    } = body.into_inner();
    if current_password.is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "the current password is required",
        ));
    }
    if new_password.is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a new password is required",
        ));
    }
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let realm = store::providers::realms::load(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(internal)?;
    let from = read_provenance(&request).address;
    let changing = Changing {
        realm: &realm,
        person: admin.context.principal.user(),
        session_id: &admin.context.session_id,
        from: from.as_deref(),
        now: admin.context.now,
    };
    let changed = account::change_own_password(
        &transaction,
        sealing.provider.as_ref(),
        &changing,
        &SecretBox::new(Box::new(current_password)),
        &SecretBox::new(Box::new(new_password)),
    )
    .await;
    match changed {
        Ok(ended) => {
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::Ok().json(serde_json::json!({ "ended_sessions": ended })))
        }
        // The count is the refusal: rolled back, a wrong guess would cost
        // nothing and the lock would never close.
        Err(Unchanged::Mismatch) => {
            transaction.commit().await.map_err(|_| internal())?;
            Err(ApiError::new(ErrorCode::CurrentPasswordMismatch))
        }
        Err(Unchanged::LockedOut) => Err(ApiError::new(ErrorCode::UserLockedOut)),
        Err(Unchanged::NotHeldHere) => Err(ApiError::new(ErrorCode::PasswordNotHeldHere)),
        Err(Unchanged::Refused(said)) => {
            Err(ApiError::with_detail(ErrorCode::ValidationError, said))
        }
        Err(Unchanged::Backend) => Err(internal()),
    }
}

/// What the caller holds to sign in with, and why any of it has to stay.
///
/// No secret leaves: a kind, a name, dates, and the reason a factor is kept.
/// `fresh_until` says until when the caller's login may remove a factor, so a
/// screen can ask for a new sign-in before a removal is refused for want of one,
/// and `stronger_sign_in_needed` says a recent one was weaker than it may be.
pub async fn list_own_factors(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = account::own_factors(
        &transaction,
        admin.context.principal.id(),
        &admin.context.session_id,
        admin.context.presenter.as_deref(),
        admin.context.now,
    )
    .await
    .map_err(unremoved)?;
    Ok(HttpResponse::Ok().json(describe_own_factors(&held)))
}

/// Take away one of the caller's authenticator apps.
pub async fn remove_own_app(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, credential_id) = path.into_inner();
    remove_own(&admin, &tenancy, &realm_id, OwnFactor::App(&credential_id)).await
}

/// Take away one of the caller's passkeys, named as the listing spells it.
pub async fn remove_own_key(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, credential) = path.into_inner();
    let credential_id = BASE64URL_NOPAD
        .decode(credential.as_bytes())
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    remove_own(&admin, &tenancy, &realm_id, OwnFactor::Key(&credential_id)).await
}

/// Take away the caller's whole sheet of recovery codes.
pub async fn remove_own_recovery_codes(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    remove_own(&admin, &tenancy, &realm_id, OwnFactor::RecoveryCodes).await
}

async fn remove_own(
    admin: &Admin,
    tenancy: &Tenancy,
    realm_id: &str,
    factor: OwnFactor<'_>,
) -> Result<HttpResponse, ApiError> {
    let transaction = tenancy
        .begin(&within(admin, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    account::remove_own_factor(
        &transaction,
        admin.context.principal.id(),
        &admin.context.session_id,
        admin.context.presenter.as_deref(),
        admin.context.now,
        factor,
    )
    .await
    .map_err(unremoved)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn unremoved(why: Unremoved) -> ApiError {
    match why {
        Unremoved::NotFresh => ApiError::new(ErrorCode::AccountReauthenticationRequired),
        Unremoved::StrongerSignInNeeded => ApiError::new(ErrorCode::AccountStrongerSignInRequired),
        Unremoved::LastFactor(said) => ApiError::with_detail(ErrorCode::AccountLastFactor, said),
        Unremoved::NotFound => ApiError::new(ErrorCode::CredentialNotFound),
        Unremoved::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
