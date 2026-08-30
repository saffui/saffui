use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use services::client::{self, Unauthenticated};
use services::grant::{self, Granted, Ungranted};
use store::keyring;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::provenance::read_client_certificate;
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

    // RFC 8705 §3. Read only from a proxy this deployment named: a header is
    // what an ordinary caller writes, and this one decides who a token belongs
    // to.
    let certified_by = read_client_certificate(&request, sealing.provider.as_ref());

    // RFC 9449 §5. A caller that proves a key gets tokens only that key may
    // present; one that proves none gets what it always got. Proven before the
    // grant runs, so a bad proof is refused rather than costing a code.
    let bound_to = match request.headers().get("dpop") {
        None => None,
        Some(proof) => {
            let Ok(proof) = proof.to_str() else {
                return Denied::InvalidDpopProof.answer("the proof could not be read");
            };
            match services::dpop::proven(
                &transaction,
                sealing.provider.as_ref(),
                proof,
                services::dpop::Bound {
                    method: "POST",
                    url: &format!(
                        "{}/realms/{}/protocol/openid-connect/token",
                        origin.as_str(),
                        context.realm_id
                    ),
                    // None here on purpose: this is where a token is handed
                    // out, so there is not one yet for a proof to name.
                    access_token: None,
                },
                now,
            )
            .await
            {
                Ok(proven) => Some(proven.thumbprint),
                Err(_) => {
                    return Denied::InvalidDpopProof.answer("the proof does not bind this request");
                }
            }
        }
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
                    bound_to: bound_to.as_deref(),
                    certified_by: certified_by.as_deref(),
                },
                &client,
                &read_provenance(&request),
                asked.scope.as_deref(),
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
                    bound_to: bound_to.as_deref(),
                    certified_by: certified_by.as_deref(),
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
                    bound_to: bound_to.as_deref(),
                    certified_by: certified_by.as_deref(),
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
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
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
            let Some(subject_token) = asked.subject_token.as_deref().filter(|it| !it.is_empty())
            else {
                return Denied::InvalidRequest.answer("subject_token is required");
            };
            // The one kind this build exchanges, said rather than guessed: a
            // caller naming another kind is told now, not by a verification
            // that was never going to hold.
            if asked.subject_token_type.as_deref() != Some(grant::ACCESS_TOKEN_TYPE) {
                return Denied::InvalidRequest
                    .answer("subject_token_type names the access-token type");
            }
            if let Some(requested) = asked
                .requested_token_type
                .as_deref()
                .filter(|it| !it.is_empty())
                && requested != grant::ACCESS_TOKEN_TYPE
            {
                return Denied::InvalidRequest
                    .answer("requested_token_type names the access-token type");
            }

            grant::token_exchange(
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
                    bound_to: bound_to.as_deref(),
                    certified_by: certified_by.as_deref(),
                },
                &client,
                &grant::Exchanging {
                    subject_token,
                    scope: asked.scope.as_deref(),
                    audience: asked.audience.as_deref(),
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
        issued_token_type: granted.issued_token_type,
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
