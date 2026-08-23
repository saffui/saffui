//! The logins a user has open, over the admin plane.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use services::agent::read_agent;
use store::providers::{sessions, users};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::rest::endpoints::admin::dto::SessionBrief;
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
    Ok(HttpResponse::Ok().json(
        open.into_iter()
            .map(|session| {
                let read = session.user_agent.as_deref().map(read_agent);
                SessionBrief {
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
                }
            })
            .collect::<Vec<_>>(),
    ))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
