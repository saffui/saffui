use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use deadpool_postgres::Pool;
use services::account_api::{AccountCaller, find_needed_step_up, read_me};
use store::tenancy::Tenancy;

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
