use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use services::admin::sessions::Unreachable;
use services::agent::read_agent;
use store::tenancy::{Tenancy, TenantContext};

use super::users::named_user;
use crate::api::rest::endpoints::admin::dto::{GrantBrief, RealmSessionBrief, SessionBrief};
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
    let user_id = named_user(&transaction, &user_id).await?;
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

/// Everything open in this realm, newest first, a page at a time.
///
/// Without the grants each login handed out: this listing is read to find
/// something in a realm that may hold thousands, and a query per row to
/// decorate it would make the screen somebody opens during a breach the slowest
/// one in the console. One session's grants are one session's listing away.
pub async fn list_realm_sessions(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    paging: web::Query<models::paging::PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let open = services::admin::sessions::list_sessions_of_realm(
        &transaction,
        &realm_id,
        window.first,
        window.max,
    )
    .await
    .map_err(refused)?;
    let shown: Vec<_> = open
        .into_iter()
        .map(|session| {
            let read = session.user_agent.as_deref().map(read_agent);
            RealmSessionBrief {
                session_id: session.session_id,
                user_id: session.user_id,
                login_username: session.login_username,
                auth_method: session.auth_method,
                ip_address: session.ip_address,
                browser: read.as_ref().and_then(|read| read.browser),
                system: read.as_ref().and_then(|read| read.system),
                started_at: session.started_at,
                auth_time: session.auth_time,
                expiration: session.expiration,
            }
        })
        .collect();
    Ok(HttpResponse::Ok().json(models::paging::Page {
        first: window.first,
        max: window.max,
        total: None,
        items: shown,
    }))
}

/// End every login in this realm, saying how many went.
///
/// Half of a breach answer, and the response says so. The logins stop renewing;
/// the access tokens already handed out live out their span unless the realm's
/// own cut is struck as well, which is a separate write on the realm itself.
/// Offering one as though it were both would be offering a revocation that is
/// not one.
pub async fn end_realm_sessions(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let ended = services::admin::sessions::end_sessions_of_realm(&transaction, &realm_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "ended": ended,
        // Said plainly rather than left for somebody to discover: the tokens
        // already out there are answered by the realm's cut, not by this.
        "tokens_still_valid_until_their_span": true,
    })))
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

    let user_id = named_user(&transaction, &user_id).await?;
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

    let user_id = named_user(&transaction, &user_id).await?;
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
