//! Where a client asks for a token.
//!
//! Reached without a bearer, because the caller is asking for one. The only door
//! on this plane with no gate in front of it, so what a gate would have checked,
//! it checks itself.

use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use services::client::{self, Unauthenticated};
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::{Asked, Denied};

/// Ask for a token. The realm is resolved before the body is read, since parsing
/// against a realm nobody has is work done for a request that cannot be
/// answered.
pub async fn ask(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    // Not "no such realm": telling that from a refused client is a way to read
    // off which realms a deployment holds.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return Denied::InvalidClient.answer("the client could not be authenticated");
    };

    // A request failure and not a client one: nothing has identified the client
    // yet. Wrong media type and past the ceiling land here together, since
    // telling them apart tells a caller how much it may send.
    let Some(asked) = asked else {
        return Denied::InvalidRequest.answer("the body could not be read as a form");
    };

    let presented = match client::read_presented(
        basic::credentials(&request),
        asked.client_id.as_deref(),
        asked
            .client_secret
            .clone()
            .map(|secret| SecretBox::new(Box::new(secret))),
    ) {
        Ok(presented) => presented,
        Err(why) => return refused(why),
    };

    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };

    // Before the grant is even read. A grant added later cannot be added
    // without this, because there is nowhere below here to add it.
    if let Err(why) = client::authenticate(&transaction, &presented, now).await {
        return refused(why);
    }

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

/// What a client is told. Everything about who it is collapses to one answer;
/// only the two protocol faults are named, because a caller can act on those.
fn refused(why: Unauthenticated) -> HttpResponse {
    match why {
        Unauthenticated::Ambiguous => {
            Denied::InvalidRequest.answer("more than one client authentication method was used")
        }
        Unauthenticated::Unreadable => {
            Denied::InvalidRequest.answer("the client could not be read")
        }
        _ => Denied::InvalidClient.answer("the client could not be authenticated"),
    }
}
