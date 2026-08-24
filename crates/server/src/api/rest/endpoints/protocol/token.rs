//! Where a client asks for a token.
//!
//! Reached without a bearer, because the caller is asking for one. The only door
//! on this plane with no gate in front of it, so what a gate would have checked,
//! it checks itself.

use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use services::client::{self, Unauthenticated};
use services::grant::{self, Granted, Ungranted};
use store::keyring;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::protocol::caller;
use crate::api::rest::endpoints::protocol::dto::{Asked, Denied, uncached};

/// Ask for a token. The realm is resolved before the body is read, since parsing
/// against a realm nobody has is work done for a request that cannot be
/// answered.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn ask(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
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

    let (transaction, client) = match caller::establish(
        &request,
        asked.client_id.as_deref(),
        asked.client_secret.clone(),
        asked
            .client_assertion_type
            .as_deref()
            .zip(asked.client_assertion.as_deref())
            .map(|(kind, assertion)| client::Signed { kind, assertion }),
        &mut connection,
        &tenancy,
        &sealing,
        &origin,
        **egress,
        &context,
        now,
    )
    .await
    {
        Ok(established) => established,
        Err(response) => return response,
    };

    let Ok(Some(realm)) = services::realm::named(&transaction, &context.realm_id).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
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
                &read_provenance(&request),
                now,
            )
            .await
        }
        "authorization_code" => {
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
            let Some(code) = asked.code.as_deref().filter(|it| !it.is_empty()) else {
                return Denied::InvalidRequest.answer("code is required");
            };

            grant::authorization_code(
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
                &grant::Redeeming {
                    code,
                    redirect_uri: asked.redirect_uri.as_deref(),
                    code_verifier: asked.code_verifier.as_deref(),
                },
                now,
            )
            .await
        }
        "refresh_token" => {
            let (Ok(ring), Ok(keys)) = (
                keyring::load(
                    &transaction,
                    &sealing.envelope,
                    &context.tenant,
                    &context.realm_id,
                )
                .await,
                services::realm::published_keys(&transaction).await,
            ) else {
                return Denied::InvalidRequest.answer("the realm could not be read");
            };
            let Some(refresh_token) = asked.refresh_token.as_deref().filter(|it| !it.is_empty())
            else {
                return Denied::InvalidRequest.answer("refresh_token is required");
            };

            grant::refresh_token(
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
                &grant::Renewing {
                    refresh_token,
                    keys: &keys,
                },
                now,
            )
            .await
        }
        _ => return Denied::UnsupportedGrantType.answer("no such grant"),
    };

    let granted = match granted {
        // A refused grant may still have consumed something. An authorization
        // code is spent by the attempt and not by the attempt succeeding, and
        // rolling back here would hand it back: a code refused for its redirect
        // could then be presented again with the right one.
        Err(why @ (Ungranted::InvalidGrant | Ungranted::Replayed)) => {
            let _ = transaction.commit().await;
            return ungranted(why);
        }
        Err(why) => return ungranted(why),
        Ok(granted) => granted,
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
        refresh_token: granted.refresh_token,
        id_token: granted.id_token,
        scope: (!granted.scope.is_empty()).then_some(granted.scope),
    })
}

/// A client that authenticated and may not have what it asked for is told so,
/// which §5.2 separates from failing to authenticate at all.
fn ungranted(why: Ungranted) -> HttpResponse {
    tracing::warn!(why = ?why, "grant refused");
    match why {
        Ungranted::Unauthorized => {
            Denied::UnauthorizedClient.answer("this client may not use this grant")
        }
        // A replay is told apart from any other refusal only by what the store
        // now holds: the session is gone. Saying so would confirm a guess to
        // whoever presented a token they should not have.
        Ungranted::InvalidGrant | Ungranted::Replayed => {
            Denied::InvalidGrant.answer("the grant presented was not honoured")
        }
        _ => Denied::InvalidRequest.answer("the grant could not be performed"),
    }
}

/// What a client is told. Everything about who it is collapses to one answer;
/// only the two protocol faults are named, because a caller can act on those.
pub(crate) fn refused(why: Unauthenticated) -> HttpResponse {
    tracing::warn!(why = ?why, "client not established");
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
