use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use models::entities::backchannel::{BackchannelRequestModel, BackchannelState};
use serde::Deserialize;
use serde_json::json;
use services::ciba::{self, Hint};
use store::tenancy::{Tenancy, resolve};

use services::client;

use super::caller;
use super::dto::uncached;
use crate::api::config::Sealing;

#[derive(Debug, Deserialize)]
pub struct Opening {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub binding_message: Option<String>,
    pub requested_expiry: Option<String>,
}

fn told(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).json(json!({
        "error": error,
        "error_description": description,
    }))
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn open(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Opening>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "the client could not be authenticated",
        );
    };
    let Some(asked) = asked else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body could not be read as a form",
        );
    };

    let (transaction, presented) = match caller::establish(
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

    if presented.public_client == Some(true) || !ciba::allows_ciba(&presented) {
        return told(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "this client does not sign people in over the backchannel",
        );
    }

    let asked = match ciba::read_initiation(
        asked.scope.as_deref(),
        asked.login_hint.as_deref(),
        asked.id_token_hint.as_deref(),
        asked.binding_message.as_deref(),
        asked.requested_expiry.as_deref(),
    ) {
        Ok(asked) => asked,
        Err(refused) => return told(StatusCode::BAD_REQUEST, refused.error, refused.detail),
    };

    // Resolve the person the hint names. An unknown hint opens a ghost, a
    // request nobody can ever approve, so which names exist stays unsaid.
    let named = match &asked.hint {
        Hint::Named(hint) => {
            let found = if hint.contains('@') {
                store::providers::users::load_by_email(&transaction, hint).await
            } else {
                store::providers::users::load_by_name(&transaction, hint).await
            };
            match found {
                Ok(person) => person.filter(|held| held.enabled),
                Err(_) => {
                    return told(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "the realm could not be read",
                    );
                }
            }
        }
        Hint::IdToken(token) => {
            let Ok(keys) = services::realm::published_keys(&transaction).await else {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the realm could not be read",
                );
            };
            match services::token::verify_presented(
                &transaction,
                &keys,
                token,
                services::token::Binding::Reported,
                now,
            )
            .await
            {
                Ok(verified) => {
                    let account = services::pairwise::account_for(
                        &transaction,
                        Some(&presented),
                        &verified.subject,
                    )
                    .await
                    .ok();
                    match account {
                        Some(account) => store::providers::users::load(&transaction, &account)
                            .await
                            .ok()
                            .flatten()
                            .filter(|held| held.enabled),
                        None => None,
                    }
                }
                Err(_) => {
                    return told(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "id_token_hint does not verify",
                    );
                }
            }
        }
    };

    let auth_req_id = match drawn_request_id(sealing.provider.as_ref()) {
        Some(id) => id,
        None => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the request could not be opened",
            );
        }
    };
    let opened = store::providers::backchannel::open(
        &transaction,
        sealing.provider.digest(),
        &auth_req_id,
        &BackchannelRequestModel {
            tenant: context.tenant.clone(),
            realm_id: context.realm_id.clone(),
            client_id: presented.client_id.clone(),
            user_id: named.map(|person| person.user_id),
            scope: asked.scope.clone(),
            binding_message: asked.binding_message.clone(),
            state: BackchannelState::Pending,
            interval_secs: ciba::POLL_INTERVAL,
            last_polled_at: None,
            approved_at: None,
            expires_at: now + asked.expiry,
            created_at: None,
        },
    )
    .await;
    if opened.is_err() || transaction.commit().await.is_err() {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request could not be opened",
        );
    }

    uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({
        "auth_req_id": auth_req_id,
        "expires_in": asked.expiry.num_seconds(),
        "interval": i64::from(ciba::POLL_INTERVAL),
    }))
}

fn drawn_request_id(provider: &dyn crypto::provider::CryptoProvider) -> Option<String> {
    let mut bytes = [0_u8; 32];
    provider.rand().fill(&mut bytes).ok()?;
    Some(data_encoding::BASE64URL_NOPAD.encode(&bytes))
}

/// The person behind a bearer token, resolved the way the exchange resolves
/// its subject: verified against this realm's keys, un-pairwised through the
/// presenting client, and still enabled.
async fn bearer_person(
    request: &HttpRequest,
    transaction: &deadpool_postgres::Transaction<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<models::entities::user::UserModel, HttpResponse> {
    let refused = || {
        told(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "a bearer token of this realm decides here",
        )
    };
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|held| held.to_str().ok())
        .and_then(|held| held.strip_prefix("Bearer "))
        .ok_or_else(refused)?;
    let keys = services::realm::published_keys(transaction)
        .await
        .map_err(|_| refused())?;
    let verified = services::token::verify_presented(
        transaction,
        &keys,
        bearer,
        services::token::Binding::Reported,
        now,
    )
    .await
    .map_err(|_| refused())?;
    if verified.subject.is_empty() {
        return Err(refused());
    }
    let presenting = match verified
        .claims
        .get("azp")
        .and_then(serde_json::Value::as_str)
    {
        Some(azp) => store::providers::clients::load(transaction, azp)
            .await
            .map_err(|_| refused())?,
        None => None,
    };
    let account =
        services::pairwise::account_for(transaction, presenting.as_ref(), &verified.subject)
            .await
            .map_err(|_| refused())?;
    store::providers::users::load(transaction, &account)
        .await
        .map_err(|_| refused())?
        .filter(|held| held.enabled)
        .ok_or_else(refused)
}

pub async fn pending(
    request: HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "a bearer token of this realm decides here",
        );
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    let person = match bearer_person(&request, &transaction, now).await {
        Ok(person) => person,
        Err(response) => return response,
    };
    let Ok(standing) =
        store::providers::backchannel::pending_for(&transaction, &person.user_id, now).await
    else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({
        "pending": standing
            .iter()
            .map(|(digest, request)| ciba::shown_pending(digest, request))
            .collect::<Vec<_>>(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct Decision {
    pub request: Option<String>,
    pub decision: Option<String>,
}

pub async fn decide(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Json<Decision>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(body) = body.map(|held| held.into_inner()) else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the body could not be read",
        );
    };
    let Some(digest) = body
        .request
        .as_deref()
        .and_then(|held| data_encoding::BASE64URL_NOPAD.decode(held.as_bytes()).ok())
    else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request names a pending request",
        );
    };
    let approved = match body.decision.as_deref() {
        Some("approve") => true,
        Some("deny") => false,
        _ => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "decision is approve or deny",
            );
        }
    };

    let Ok(mut connection) = pool.get().await else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "a bearer token of this realm decides here",
        );
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        );
    };
    let person = match bearer_person(&request, &transaction, now).await {
        Ok(person) => person,
        Err(response) => return response,
    };
    let landed = store::providers::backchannel::decide(
        &transaction,
        &digest,
        &person.user_id,
        approved,
        now,
    )
    .await;
    match landed {
        Ok(true) => {
            if transaction.commit().await.is_err() {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the realm could not be read",
                );
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(json!({ "decided": if approved { "approved" } else { "denied" } }))
        }
        // Somebody else's, already decided, expired, or never there: one face.
        Ok(false) => told(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "no pending request of yours answers to that",
        ),
        Err(_) => told(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the realm could not be read",
        ),
    }
}
