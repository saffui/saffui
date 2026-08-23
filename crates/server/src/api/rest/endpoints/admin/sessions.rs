//! The logins a user has open, over the admin plane.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use services::agent::read_agent;
use store::providers::{sessions, users};
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
    users::load(&transaction, &user_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::UserNotFound))?;

    let open = sessions::load_for_user(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    let mut shown = Vec::with_capacity(open.len());
    for session in open {
        let grants = sessions::client_sessions_of(&transaction, &session.session_id)
            .await
            .map_err(|_| internal())?;
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
    let held = sessions::load(&transaction, &session_id)
        .await
        .map_err(|_| internal())?
        .filter(|session| session.user_id == user_id)
        .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound))?;

    sessions::close(&transaction, &held.session_id)
        .await
        .map_err(|_| internal())?;
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

    sessions::load(&transaction, &session_id)
        .await
        .map_err(|_| internal())?
        .filter(|session| session.user_id == user_id)
        .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound))?;

    let taken = sessions::close_client_session_of(&transaction, &session_id, &client_id)
        .await
        .map_err(|_| internal())?;
    if !taken {
        return Err(ApiError::new(ErrorCode::GrantNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
