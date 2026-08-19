//! Where a client asks for a token.
//!
//! Reached without a bearer, because the caller is asking for one. The only door
//! on this plane with no gate in front of it, so what a gate would have checked,
//! it checks itself.

use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use services::client::{self, Unauthenticated};
use services::grant::{self, Granted, Ungranted};
use store::keyring;
use store::providers::realms;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::{Asked, Denied, uncached};

/// Ask for a token. The realm is resolved before the body is read, since parsing
/// against a realm nobody has is work done for a request that cannot be
/// answered.
pub async fn ask(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
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

    let Ok(Some(realm)) = realms::load(&transaction, &context.realm_id).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    // What the realm mints passwords at. A secret converted from the plaintext
    // column is hashed at the cost this realm chose, not at one this endpoint
    // picked.
    let cost = realm
        .password_policy
        .as_ref()
        .map(|policy| policy.hashing)
        .unwrap_or_default();

    // Before the grant is even read. A grant added later cannot be added
    // without this, because there is nowhere below here to add it.
    let client = match client::authenticate(
        &transaction,
        sealing.provider.as_ref(),
        cost,
        &presented,
        now,
    )
    .await
    {
        Ok(client) => client,
        Err(why) => return refused(why),
    };

    let Some(grant_type) = asked.grant_type.as_deref().filter(|it| !it.is_empty()) else {
        return Denied::InvalidRequest.answer("grant_type is required");
    };

    let granted = match grant_type {
        "client_credentials" => {
            let Ok(ring) = keyring::load(
                &transaction,
                &sealing.envelope,
                &context.tenant,
                &context.realm_id,
            )
            .await
            else {
                return Denied::InvalidRequest.answer("the realm could not be read");
            };

            grant::client_credentials(
                &transaction,
                &grant::Signing {
                    provider: sealing.provider.as_ref(),
                    ring: &ring,
                    envelope: &sealing.envelope,
                },
                &grant::Within {
                    tenant: &context,
                    realm: &realm,
                    issuer: &origin.issuer(&context.realm_id),
                },
                &client,
                now,
            )
            .await
        }
        "authorization_code" | "refresh_token" => {
            return Denied::UnsupportedGrantType.answer("this grant is not performed yet");
        }
        _ => return Denied::UnsupportedGrantType.answer("no such grant"),
    };

    let granted = match granted {
        Ok(granted) => granted,
        Err(why) => return ungranted(why),
    };

    // The token is handed out only once the rows binding it exist. Answering
    // first and committing after would hand out a token whose login the gate
    // that reads it cannot find.
    if transaction.commit().await.is_err() {
        return Denied::InvalidRequest.answer("the grant could not be recorded");
    }
    answer(granted)
}

/// What a client gets when it worked.
fn answer(granted: Granted) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(
        actix_web::http::StatusCode::OK,
    ))
    .json(crate::api::rest::endpoints::protocol::dto::Granted {
        access_token: granted.access_token,
        token_type: "Bearer",
        expires_in: granted.expires_in,
        refresh_token: None,
        id_token: None,
        scope: (!granted.scope.is_empty()).then_some(granted.scope),
    })
}

/// A client that authenticated and may not have what it asked for is told so,
/// which §5.2 separates from failing to authenticate at all.
fn ungranted(why: Ungranted) -> HttpResponse {
    match why {
        Ungranted::Unauthorized => {
            Denied::UnauthorizedClient.answer("this client may not use this grant")
        }
        _ => Denied::InvalidRequest.answer("the grant could not be performed"),
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
