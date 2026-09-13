use actix_web::{HttpRequest, HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use services::account::{self, Changing, Unchanged};
use store::tenancy::Tenancy;

use super::dto::PasswordChange;
use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::within;
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
    pool: web::Data<Pool>,
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
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
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

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
