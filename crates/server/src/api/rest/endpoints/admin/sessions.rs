//! The logins a user has open, over the admin plane.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use services::admin::sessions::Unreachable;
use services::agent::read_agent;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::rest::endpoints::admin::dto::{GrantBrief, SessionBrief};
use crate::middleware::admin_guard::Admin;

/// What this user has open, newest first.
///
/// The browser and the system are read out of the stored `User-Agent` here
/// rather than written into the row when the login opened. What the browser
/// sent does not change and what can be told from it does, so the reading
/// improves for every session at once.
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

    // The user first, so an empty list means "no logins" and never "no user".
    services::admin::users::get(&transaction, &user_id)
        .await
        .map_err(|_| ApiError::new(ErrorCode::UserNotFound))?;

    let open = services::admin::sessions::of_user(&transaction, &user_id)
        .await
        .map_err(refused)?;
    let mut shown = Vec::with_capacity(open.len());
    for (session, grants) in open {
        let read = session.user_agent.as_deref().map(read_agent);
        shown.push(SessionBrief {
            grants: grants
                .into_iter()
                .map(|grant| GrantBrief {
                    client_id: grant.client_id,
                    offline: grant.offline == Some(true),
                    expiration: grant.expiration,
                })
                .collect(),
            session_id: session.session_id,
            auth_method: session.auth_method,
            ip_address: session.ip_address,
            browser: read.as_ref().and_then(|read| read.browser),
            system: read.as_ref().and_then(|read| read.system),
            mobile: read.as_ref().is_some_and(|read| read.mobile),
            user_agent: session.user_agent,
            started_at: session.started_at,
            auth_time: session.auth_time,
            expiration: session.expiration,
        });
    }
    Ok(HttpResponse::Ok().json(shown))
}

/// End one login, and everything any client got out of it.
pub async fn close(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, session_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    // Named by the user it belongs to, so an identifier from another user's
    // listing ends nothing here.
    services::admin::sessions::close(&transaction, &user_id, &session_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Take back what one client got out of one login, leaving the login and every
/// other client alone. Which is how an offline grant is revoked: it outlives
/// the login, so ending the login is not what ends it.
pub async fn revoke(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, session_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    services::admin::sessions::revoke_grant(&transaction, &user_id, &session_id, &client_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn refused(why: Unreachable) -> ApiError {
    ApiError::new(match why {
        Unreachable::NotFound => ErrorCode::SessionNotFound,
        Unreachable::NoSuchGrant => ErrorCode::GrantNotFound,
        Unreachable::Unreadable => ErrorCode::InternalError,
    })
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
