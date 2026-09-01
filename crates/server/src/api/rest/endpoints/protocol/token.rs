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

    // A workload that carries no credential but arrived through the proxy's
    // mTLS may be a mesh identity: its certificate's URI names it, and the
    // same trusted platforms that admit tokens admit certificates. Without a
    // carried certificate the request falls through, to be refused as any
    // other caller that never said who it was.
    if asked.grant_type.as_deref() == Some("client_credentials")
        && asked.client_id.is_none()
        && asked.client_secret.is_none()
        && asked.client_assertion.is_none()
        && request.headers().get("authorization").is_none()
        && let Some(answered) = x509_exchange(
            &request,
            &mut connection,
            &tenancy,
            &sealing,
            &origin,
            &context,
            &asked,
            now,
        )
        .await
    {
        return answered;
    }

    // RFC 7523: the assertion is the whole credential, so this grant turns
    // off before the client-authentication door. Nothing in it is believed
    // until the platform's own keys have spoken.
    if asked.grant_type.as_deref() == Some(services::workload::GRANT) {
        return workload_exchange(
            &request,
            &mut connection,
            &tenancy,
            &sealing,
            &origin,
            **egress,
            &context,
            &asked,
            now,
        )
        .await;
    }

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
    // §4.3: one proof and exactly one. Reading the first of two would verify
    // one header while the other rode along unexamined.
    if request.headers().get_all("dpop").count() > 1 {
        return Denied::InvalidDpopProof.answer("one proof, exactly");
    }
    let proven = match request.headers().get("dpop") {
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
                Ok(proven) => Some(proven),
                Err(why) => {
                    tracing::warn!(why = ?why, "dpop proof refused");
                    return Denied::InvalidDpopProof.answer("the proof does not bind this request");
                }
            }
        }
    };
    let bound_to = proven.as_ref().map(|held| held.thumbprint.clone());

    // FAPI 2.0: a client wearing the profile is held to it wherever tokens
    // are asked for. Provisioned against it, it is refused whole; unable to
    // name a key its tokens will be bound to, it gets none.
    if services::fapi::is_fapi2(&client) {
        if services::fapi::conformant(&client).is_err() {
            return Denied::InvalidClient.answer("the client is provisioned against its profile");
        }
        if bound_to.is_none() && certified_by.is_none() {
            return Denied::InvalidRequest
                .answer("the profile requires sender-constrained tokens: prove a key");
        }
    }

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
                    proofs: services::token::Proofs {
                        key: proven.as_ref(),
                        certificate: certified_by.as_deref(),
                    },
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
            // §2.1: the two travel together, and the one kind holds for the
            // actor the way it holds for the subject.
            let actor_token = asked.actor_token.as_deref().filter(|it| !it.is_empty());
            match (actor_token, asked.actor_token_type.as_deref()) {
                (None, Some(_)) => {
                    return Denied::InvalidRequest.answer("actor_token_type rides an actor_token");
                }
                (Some(_), kind) if kind != Some(grant::ACCESS_TOKEN_TYPE) => {
                    return Denied::InvalidRequest
                        .answer("actor_token_type names the access-token type");
                }
                _ => {}
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
                    actor_token,
                    scope: asked.scope.as_deref(),
                    audience: asked.audience.as_deref(),
                    keys: &keys,
                },
                request
                    .app_data::<web::Data<services::pdp::Journal>>()
                    .map(|held| held.get_ref()),
                now,
            )
            .await
        }
        services::device::GRANT => {
            let Some(device_code) = asked.device_code.as_deref().filter(|it| !it.is_empty()) else {
                return Denied::InvalidRequest.answer("device_code is required");
            };
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
            match grant::device_code(
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
                device_code,
                &crate::api::provenance::read_provenance(&request),
                now,
            )
            .await
            {
                Ok(granted) => Ok(granted),
                Err(grant::Unpolled::Words(error, description)) => {
                    // RFC 8628 §3.5 speaks CIBA's polling words, under the
                    // same rule: a pending poll must still commit its
                    // slow-down stamp or every poll reads as the first.
                    let _ = transaction.commit().await;
                    return uncached(&mut actix_web::HttpResponseBuilder::new(
                        actix_web::http::StatusCode::BAD_REQUEST,
                    ))
                    .json(serde_json::json!({
                        "error": error,
                        "error_description": description,
                    }));
                }
                Err(grant::Unpolled::Backend) => {
                    return Denied::InvalidRequest.answer("the realm could not be read");
                }
            }
        }
        services::ciba::GRANT => {
            let Some(auth_req_id) = asked.auth_req_id.as_deref().filter(|it| !it.is_empty()) else {
                return Denied::InvalidRequest.answer("auth_req_id is required");
            };
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
            match grant::ciba(
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
                auth_req_id,
                &crate::api::provenance::read_provenance(&request),
                now,
            )
            .await
            {
                Ok(granted) => Ok(granted),
                Err(grant::Unpolled::Words(error, description)) => {
                    // The polling words of CIBA §11 do not fit the shared
                    // refusal set; a pending poll must still commit its
                    // slow-down stamp or every poll reads as the first.
                    let _ = transaction.commit().await;
                    return uncached(&mut actix_web::HttpResponseBuilder::new(
                        actix_web::http::StatusCode::BAD_REQUEST,
                    ))
                    .json(serde_json::json!({
                        "error": error,
                        "error_description": description,
                    }));
                }
                Err(grant::Unpolled::Backend) => {
                    return Denied::InvalidRequest.answer("the realm could not be read");
                }
            }
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
    answer(granted, bound_to.is_some())
}

/// What a client gets when it worked. RFC 9449 §5: a token bound to a proved
/// key says so in its type, and a client that reads `Bearer` there would
/// present it bare and be refused.
fn answer(granted: Granted, proof_bound: bool) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(
        actix_web::http::StatusCode::OK,
    ))
    .json(crate::api::rest::endpoints::protocol::dto::Granted {
        access_token: granted.access_token,
        token_type: if proof_bound { "DPoP" } else { "Bearer" },
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

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
async fn workload_exchange(
    request: &HttpRequest,
    connection: &mut deadpool_postgres::Object,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    egress: config::serving::Egress,
    context: &store::tenancy::TenantContext,
    asked: &Asked,
    now: chrono::DateTime<chrono::Utc>,
) -> HttpResponse {
    let Some(assertion) = asked.assertion.as_deref().filter(|it| !it.is_empty()) else {
        return Denied::InvalidRequest.answer("assertion carries the platform token");
    };
    let Some(issuer) = services::workload::peeked_issuer(assertion) else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };
    let Ok(transaction) = tenancy.transaction(connection, context).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    let Ok(Some(realm)) = services::realm::named(&transaction, &context.realm_id).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };

    // The one trusted platform with this issuer, still enabled, still
    // reading as one. The issuer only picks the row; the row is the trust.
    let Ok(rows) = store::providers::brokering::list_providers(&transaction).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    let trusted = rows
        .iter()
        .filter(|row| services::workload::is_workload(row) && row.enabled != Some(false))
        .filter_map(|row| services::workload::Trusted::parse(row).ok())
        .find(|held| held.issuer == issuer);
    let Some(trusted) = trusted else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };

    let Some(keys) = super::hosted::fetch(trusted.jwks_uri.clone(), egress).await else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };
    let Ok(keys) = serde_json::from_str::<serde_json::Value>(&keys) else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };
    let Ok(claims) = services::assertion::read_against(&keys, assertion, &trusted.allowed_algs)
    else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };
    let subject = match services::workload::asserted_subject(&trusted, &claims, now.timestamp()) {
        Ok(subject) => subject,
        Err(why) => {
            tracing::debug!(why, "a platform token was refused");
            return Denied::InvalidGrant.answer("the grant presented was not honoured");
        }
    };

    let Ok(Some(client)) = store::providers::clients::load(&transaction, &trusted.client_id).await
    else {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    };
    if client.enabled != Some(true) {
        return Denied::InvalidGrant.answer("the grant presented was not honoured");
    }

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
    let granted = grant::workload(
        &transaction,
        &grant::Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        },
        &grant::Within {
            tenant: context,
            realm: &realm,
            issuer: &origin.issuer(&context.realm_id),
            bound_to: None,
            certified_by: None,
        },
        &client,
        &subject,
        &trusted.issuer,
        asked.scope.as_deref(),
        &crate::api::provenance::read_provenance(request),
        now,
    )
    .await;
    match granted {
        Ok(granted) => {
            if transaction.commit().await.is_err() {
                return Denied::InvalidRequest.answer("the realm could not be read");
            }
            answer(granted, false)
        }
        Err(why) => ungranted(why),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
async fn x509_exchange(
    request: &HttpRequest,
    connection: &mut deadpool_postgres::Object,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    context: &store::tenancy::TenantContext,
    asked: &Asked,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<HttpResponse> {
    let refused = || Some(Denied::InvalidGrant.answer("the grant presented was not honoured"));
    // Only from the proxy the operator named, like every mTLS read here. A
    // request carrying no certificate is not this door's to answer, and
    // falls back out; once one is carried, every refusal is final.
    let proxying = request
        .app_data::<web::Data<config::proxying::Proxying>>()
        .map_or_else(config::proxying::Proxying::none, |held| (***held).clone());
    let named = proxying.certificate_header()?;
    let header = actix_web::http::header::HeaderName::from_bytes(named.as_bytes()).ok()?;
    let carried = request.headers().get(header)?.to_str().ok()?;
    let peer = request.peer_addr().map(|address| address.ip().to_string());
    let carried = proxying.client_certificate(peer.as_deref(), Some(carried))?;
    let Ok(uris) = services::mtls::san_uris(carried) else {
        return refused();
    };
    if uris.is_empty() {
        return refused();
    }

    let Ok(transaction) = tenancy.transaction(connection, context).await else {
        return Some(Denied::InvalidRequest.answer("the realm could not be read"));
    };
    let Ok(Some(realm)) = services::realm::named(&transaction, &context.realm_id).await else {
        return Some(Denied::InvalidRequest.answer("the realm could not be read"));
    };
    let Ok(rows) = store::providers::brokering::list_providers(&transaction).await else {
        return Some(Denied::InvalidRequest.answer("the realm could not be read"));
    };
    let admitted = rows
        .iter()
        .filter(|row| services::workload::is_workload(row) && row.enabled != Some(false))
        .filter_map(|row| services::workload::Trusted::parse(row).ok())
        .find_map(|trusted| {
            uris.iter()
                .find(|uri| trusted.admits(uri))
                .cloned()
                .map(|uri| (trusted, uri))
        });
    let Some((trusted, identity)) = admitted else {
        return refused();
    };

    let Ok(Some(client)) = store::providers::clients::load(&transaction, &trusted.client_id).await
    else {
        return refused();
    };
    if client.enabled != Some(true) {
        return refused();
    }
    let Ok(ring) = keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    else {
        return Some(Denied::InvalidRequest.answer("the realm could not be read"));
    };
    let granted = grant::workload(
        &transaction,
        &grant::Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        },
        &grant::Within {
            tenant: context,
            realm: &realm,
            issuer: &origin.issuer(&context.realm_id),
            bound_to: None,
            certified_by: None,
        },
        &client,
        &identity,
        "x509",
        asked.scope.as_deref(),
        &crate::api::provenance::read_provenance(request),
        now,
    )
    .await;
    match granted {
        Ok(granted) => {
            if transaction.commit().await.is_err() {
                return Some(Denied::InvalidRequest.answer("the realm could not be read"));
            }
            Some(answer(granted, false))
        }
        Err(why) => Some(ungranted(why)),
    }
}
