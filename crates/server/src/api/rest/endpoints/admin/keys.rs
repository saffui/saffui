//! The keys a user enrolled, over the admin plane.
//!
//! Listing and revocation, and deliberately nothing else: enrolment happens in
//! the login, where the key's holder is the one holding the ceremony.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Pool;
use services::admin::keys::Unreachable;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::rest::endpoints::admin::dto::KeyBrief;
use crate::middleware::admin_guard::Admin;

/// The keys this user may present.
pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let held = services::admin::keys::of_user(&transaction, &user_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(
        held.into_iter()
            .map(|credential| KeyBrief {
                credential_id: BASE64URL_NOPAD.encode(&credential.credential_id),
                label: credential.label,
                enrolled_at: credential.enrolled_at,
                last_used_at: credential.last_used_at,
            })
            .collect::<Vec<_>>(),
    ))
}

/// Revoke one of this user's keys.
pub async fn revoke(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, credential) = path.into_inner();
    // The identifier as the listing spelled it. Anything else is a malformed
    // request, not a credential that happens to be absent.
    let credential_id = BASE64URL_NOPAD
        .decode(credential.as_bytes())
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    // Scoped to the user in the path: a caller must not reach past the user it
    // named, however it learned the identifier.
    services::admin::keys::revoke(&transaction, &user_id, &credential_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;

    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unreachable) -> ApiError {
    ApiError::new(match why {
        Unreachable::NoSuchUser => ErrorCode::UserNotFound,
        Unreachable::NotFound => ErrorCode::CredentialNotFound,
        Unreachable::Unreadable => ErrorCode::InternalError,
    })
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
