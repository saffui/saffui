//! Where a client asks for a token.
//!
//! Reached without a bearer, because the caller is asking for one. The only door
//! on this plane with no gate in front of it, so what a gate would have checked,
//! it checks itself.

use actix_web::{HttpResponse, web};
use deadpool_postgres::Pool;
use store::tenancy::resolve;

use crate::api::rest::endpoints::protocol::dto::{Asked, Denied};

/// Ask for a token. The realm is resolved before the body is read, since parsing
/// against a realm nobody has is work done for a request that cannot be
/// answered.
pub async fn ask(
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
) -> HttpResponse {
    let Ok(connection) = pool.get().await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    // Not "no such realm": telling that from a refused client is a way to read
    // off which realms a deployment holds.
    if resolve::realm_by_name(&connection, &realm).await.is_err() {
        return Denied::InvalidClient.answer("the client could not be authenticated");
    }

    // A request failure and not a client one: nothing has identified the client
    // yet. Wrong media type and past the ceiling land here together, since
    // telling them apart tells a caller how much it may send.
    let Some(asked) = asked else {
        return Denied::InvalidRequest.answer("the body could not be read as a form");
    };

    let Some(grant_type) = asked.grant_type.as_deref().filter(|it| !it.is_empty()) else {
        return Denied::InvalidRequest.answer("grant_type is required");
    };

    match grant_type {
        "authorization_code" | "refresh_token" | "client_credentials" => {
            Denied::UnsupportedGrantType.answer("this grant is not performed yet")
        }
        _ => Denied::UnsupportedGrantType.answer("no such grant"),
    }
}
