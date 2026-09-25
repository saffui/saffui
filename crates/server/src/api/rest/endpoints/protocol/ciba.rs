use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::{Egress, PublicOrigin};
use models::entities::backchannel::{BackchannelRequestModel, BackchannelState};
use serde::Deserialize;
use serde_json::json;
use services::oidc::ciba;
use store::error::StoreError;
use store::tenancy::{RealmNamed, Tenancy, TenantContext, UnitOfWork};

use services::client;

use super::caller;
use super::dto::{answer_unavailable, uncached};
use outbound::Sealing;
use outbound::egress::{may_dial, outward_agent};

#[derive(Debug, Deserialize)]
pub struct Opening {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub scope: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint_token: Option<String>,
    pub binding_message: Option<String>,
    pub requested_expiry: Option<String>,
    pub client_notification_token: Option<String>,
    pub user_code: Option<String>,
    /// CIBA §7.1: the whole initiation, as one token the client signed. A
    /// client registered for signing sends this and nothing beside it.
    pub request: Option<String>,
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
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let now = Utc::now();
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return answer_unavailable();
        }
        Err(_) => {
            return told(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "the client could not be authenticated",
            );
        }
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

    let delivery = match ciba::delivery_of(&presented) {
        Some(delivery) if presented.public_client != Some(true) => delivery,
        _ => {
            return told(
                StatusCode::BAD_REQUEST,
                "unauthorized_client",
                "this client does not sign people in over the backchannel",
            );
        }
    };
    // A signed request, or a hint token, is verified against the keys the
    // client publishes, read afresh when they were due.
    let (transaction, presented) = if asked.request.is_some() || asked.login_hint_token.is_some() {
        match caller::with_client_keys_read(
            &tenancy,
            &context,
            transaction,
            presented,
            **egress,
            now,
        )
        .await
        {
            Ok(held) => held,
            Err(StoreError::Unavailable) => return answer_unavailable(),
            Err(_) => {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the client could not be read",
                );
            }
        }
    } else {
        (transaction, presented)
    };
    // §7.1: a client registered for signed requests speaks only in them, and
    // one that is not registered may not present one. The parameters then
    // come from inside the token alone.
    let mut asked = asked.into_inner();
    let mut spent = false;
    match (
        ciba::signing_alg_of(&presented),
        asked.request.as_deref().map(str::to_owned),
    ) {
        (None, None) => {}
        (None, Some(_)) => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this client did not register request signing",
            );
        }
        (Some(_), None) => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this client signs its backchannel requests",
            );
        }
        (Some(algorithm), Some(token)) => {
            let issuer = origin.issuer(&context.realm_id);
            let inside =
                match ciba::read_signed_request(&presented, algorithm, &token, &issuer, now) {
                    Ok(inside) => inside,
                    Err(refused) => {
                        return told(StatusCode::BAD_REQUEST, refused.error, refused.detail);
                    }
                };
            if let Err(refused) = ciba::spend_signed_request(
                &transaction,
                sealing.provider.as_ref(),
                &presented,
                &inside,
            )
            .await
            {
                return told(StatusCode::BAD_REQUEST, refused.error, refused.detail);
            }
            spent = true;
            let text = |named: &str| {
                inside
                    .get(named)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            asked = Opening {
                client_id: asked.client_id,
                client_secret: None,
                client_assertion_type: None,
                client_assertion: None,
                scope: text("scope"),
                login_hint: text("login_hint"),
                id_token_hint: text("id_token_hint"),
                login_hint_token: text("login_hint_token"),
                binding_message: text("binding_message"),
                requested_expiry: inside.get("requested_expiry").map(|held| match held {
                    serde_json::Value::String(spelled) => spelled.clone(),
                    other => other.to_string(),
                }),
                client_notification_token: text("client_notification_token"),
                user_code: text("user_code"),
                request: None,
            };
        }
    }

    // The identifier spent above has to outlive whatever this request then
    // decides: rolled back with a refusal, the same request would present
    // again for as long as its window lasts.
    let transaction = if spent {
        if transaction.commit().await.is_err() {
            return answer_unavailable();
        }
        match tenancy.begin(&context).await {
            Ok(fresh) => fresh,
            Err(StoreError::Unavailable) => return answer_unavailable(),
            Err(_) => {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the request could not be read",
                );
            }
        }
    } else {
        transaction
    };

    let notification_token = match ciba::read_notification_token(
        &delivery,
        asked.client_notification_token.as_deref(),
    ) {
        Ok(held) => held,
        Err(refused) => return told(StatusCode::BAD_REQUEST, refused.error, refused.detail),
    };

    let user_code = asked.user_code.clone();
    // The realm's pacing where it set one; like the device flow, the row
    // keeps its birth interval, so a later retune never reshapes a request
    // already in someone's hand.
    let realm_row = services::realm::read_current_realm(&transaction)
        .await
        .ok()
        .flatten();
    let (realm_expiry, poll_interval) = match &realm_row {
        Some(realm) => (
            realm.ciba_expiry,
            realm.ciba_interval.unwrap_or(ciba::POLL_INTERVAL),
        ),
        None => (None, ciba::POLL_INTERVAL),
    };
    let asked = match ciba::read_initiation(
        asked.scope.as_deref(),
        asked.login_hint.as_deref(),
        asked.id_token_hint.as_deref(),
        asked.login_hint_token.as_deref(),
        asked.binding_message.as_deref(),
        asked.requested_expiry.as_deref(),
        realm_expiry,
    ) {
        Ok(asked) => asked,
        Err(refused) => return told(StatusCode::BAD_REQUEST, refused.error, refused.detail),
    };

    // Resolve the person the hint names. An unknown hint opens a ghost, a
    // request nobody can ever approve, so which names exist stays unsaid.
    let named = match ciba::read_hinted_person(&transaction, &presented, &asked.hint, now).await {
        Ok(named) => named,
        Err(refused) => return told(StatusCode::BAD_REQUEST, refused.error, refused.detail),
    };

    // The person's own code, when they set one: a miss opens a ghost, so
    // nothing is enumerated and nobody's device rings.
    let named = named.filter(|person| {
        let expected = person
            .attributes
            .as_ref()
            .and_then(|bag| bag.get(ciba::USER_CODE_DIGEST))
            .and_then(models::entities::attributes::AttributeValue::as_str);
        ciba::user_code_stands(expected, user_code.as_deref(), |code| {
            sealing
                .provider
                .digest()
                .hash(crypto::provider::HashAlg::Sha256, code.as_bytes())
                .ok()
                .map(|held| data_encoding::HEXLOWER.encode(&held))
        })
    });

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
    // Ping must speak the request id back in the clear later, and only its
    // digest lives in the row: the clear rides under the realm's seal.
    let sealed_request = match &delivery {
        ciba::Delivery::Poll => None,
        ciba::Delivery::Ping { .. } => {
            let Ok(ring) = store::keyring::load(
                &transaction,
                &sealing.envelope,
                &context.tenant,
                &context.realm_id,
            )
            .await
            else {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the request could not be opened",
                );
            };
            match ring
                .seal(
                    &sealing.envelope,
                    "ciba-ping",
                    "request",
                    auth_req_id.as_bytes(),
                )
                .await
            {
                Ok(sealed) => Some(sealed),
                Err(_) => {
                    return told(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "the request could not be opened",
                    );
                }
            }
        }
    };
    // The person's phone rings only when everything lines up: the realm can
    // text, the number is proven, and the brakes say yes. A request nobody
    // was told about still stands, because the doorbell page answers it
    // either way; what a held brake costs is only the message.
    let texting = doorbell_text(
        &transaction,
        &sealing,
        &context,
        &origin,
        realm_row.as_ref(),
        named.as_ref(),
        now,
    )
    .await;

    let opened = ciba::open_request(
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
            delivery: delivery.as_str().to_owned(),
            notification_token,
            sealed_request,
            interval_secs: poll_interval,
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
    if let Some(outgoing) = texting {
        outbound::delivery::deliver_text(&sealing, &tenancy, &context, outgoing).await;
    }

    uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({
        "auth_req_id": auth_req_id,
        "expires_in": asked.expiry.num_seconds(),
        "interval": i64::from(poll_interval),
    }))
}

fn drawn_request_id(provider: &dyn crypto::provider::CryptoProvider) -> Option<String> {
    let mut bytes = [0_u8; 32];
    provider.rand().fill(&mut bytes).ok()?;
    Some(data_encoding::BASE64URL_NOPAD.encode(&bytes))
}

/// Nobody the doorbell answers to: no sign-in on this realm, and no token its
/// account console obtained.
fn told_nobody_decides() -> HttpResponse {
    told(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "a sign-in on this realm, or its account console, decides here",
    )
}

/// The person behind a bearer token: one the realm's account console
/// obtained, admitted as the account API admits it.
async fn bearer_person(
    request: &HttpRequest,
    transaction: &UnitOfWork,
    tenant: &TenantContext,
    now: chrono::DateTime<Utc>,
) -> Result<String, HttpResponse> {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|held| held.to_str().ok())
        .and_then(|held| held.strip_prefix("Bearer "))
        .ok_or_else(told_nobody_decides)?;
    ciba::read_person_behind_bearer(transaction, tenant.clone(), bearer, now)
        .await
        .ok_or_else(told_nobody_decides)
}

/// The person asking: the account console's bearer token, or the browser's
/// own live login. The cookie is `SameSite=Lax` and the deciding body is
/// JSON, so a cross-site page can neither attach the one nor send the other;
/// what remains is the signed-in person on this realm's own pages, which is
/// who a doorbell is for.
async fn asking_person(
    request: &HttpRequest,
    transaction: &UnitOfWork,
    tenant: &TenantContext,
    now: chrono::DateTime<Utc>,
) -> Result<String, HttpResponse> {
    if request.headers().get("authorization").is_some() {
        return bearer_person(request, transaction, tenant, now).await;
    }
    let session_id = super::binding::read(request, super::binding::SSO_SESSION)
        .ok_or_else(told_nobody_decides)?;
    ciba::read_signed_in_person(transaction, &session_id, now)
        .await
        .map(|person| person.user_id)
        .ok_or_else(told_nobody_decides)
}

pub async fn pending(
    request: HttpRequest,
    realm: web::Path<String>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return answer_unavailable();
        }
        Err(_) => return told_nobody_decides(),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the realm could not be read",
            );
        }
    };
    let user_id = match asking_person(&request, &transaction, &context, now).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let Ok(standing) = ciba::read_pending_requests(&transaction, &user_id, now).await else {
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
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<Egress>,
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

    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return answer_unavailable();
        }
        Err(_) => return told_nobody_decides(),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => {
            return told(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the realm could not be read",
            );
        }
    };
    let user_id = match asking_person(&request, &transaction, &context, now).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let landed = ciba::decide_request(&transaction, &digest, &user_id, approved, now).await;
    match landed {
        Ok(Some(decided)) => {
            // Opened before the commit so a sealed id is never left behind
            // undeliverable, delivered after it so a ping never announces a
            // decision that rolled back.
            let ping = ping_of(&transaction, &sealing, &context, &decided).await;
            if transaction.commit().await.is_err() {
                return told(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "the realm could not be read",
                );
            }
            if let Some((endpoint, bearer, auth_req_id)) = ping {
                deliver_ping(endpoint, bearer, auth_req_id, **egress).await;
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(json!({ "decided": if approved { "approved" } else { "denied" } }))
        }
        // Somebody else's, already decided, expired, or never there: one face.
        Ok(None) => told(
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

/// What a ping needs, opened from the decided row: the client's registered
/// endpoint, the bearer it handed in, and the request id out of its seal.
pub(crate) async fn ping_of(
    transaction: &UnitOfWork,
    sealing: &Sealing,
    context: &store::tenancy::TenantContext,
    decided: &BackchannelRequestModel,
) -> Option<(String, String, String)> {
    if decided.delivery != "ping" {
        return None;
    }
    let bearer = decided.notification_token.clone()?;
    let sealed = decided.sealed_request.as_deref()?;
    let client = services::client::read_client(transaction, &decided.client_id)
        .await
        .ok()
        .flatten()?;
    let ciba::Delivery::Ping { endpoint } = ciba::delivery_of(&client)? else {
        return None;
    };
    let ring = store::keyring::load(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok()?;
    let opened = ring
        .open(&sealing.envelope, "ciba-ping", "request", sealed)
        .await
        .ok()?;
    let auth_req_id =
        String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()?;
    Some((endpoint, bearer, auth_req_id))
}

/// Tell the client its request is decided, §10.2: a POST bearing the token
/// it handed in, saying only which request. Fire and forget: the poll grant
/// stays the source of truth, so a lost ping costs latency, never
/// correctness.
pub(crate) async fn deliver_ping(
    endpoint: String,
    bearer: String,
    auth_req_id: String,
    egress: Egress,
) {
    // The endpoint is the client's own registration, so it is dialled under the
    // same policy as every other address a client supplies. A ping that cannot
    // be sent costs nothing: the client polls, which is the source of truth.
    if !may_dial(&endpoint, egress) {
        tracing::warn!("a ciba notification endpoint is not one this egress policy dials");
        return;
    }
    let _ = tokio::task::spawn_blocking(move || {
        let agent = outward_agent(egress, std::time::Duration::from_secs(5));
        let posted = agent
            .post(&endpoint)
            .header("authorization", &format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .send(serde_json::json!({ "auth_req_id": auth_req_id }).to_string());
        if let Err(why) = posted {
            tracing::warn!(%why, "a ping did not land; the client will poll");
        }
    })
    .await;
}

/// The doorbell page: what waits on the signed-in person, and the two
/// answers. Served in the browser's tongue; the listing itself is what
/// `bc-pending` says to this browser's session.
pub async fn doorbell(
    request: HttpRequest,
    realm: web::Path<String>,
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let tongues = super::page::tongues_of_realm(&tenancy, &realm).await;
    let tongue = tongues.negotiated(
        None,
        request
            .headers()
            .get("accept-language")
            .and_then(|value| value.to_str().ok()),
    );
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Language", tongue))
        .insert_header(("Vary", "Accept-Language"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(super::i18n::requests_page_in(tongue))
}

pub async fn doorbell_script() -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/javascript; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; base-uri 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(REQUESTS_SCRIPT)
}

const REQUESTS_SCRIPT: &str = include_str!("ui/requests.js");

/// The doorbell, texted: the words and the settings for one message telling
/// this person a request awaits them, or nothing when the realm cannot text,
/// the number is unproven, or a brake held it back. Counted where it is
/// decided, in the same transaction that opens the request.
async fn doorbell_text(
    transaction: &UnitOfWork,
    sealing: &Sealing,
    context: &store::tenancy::TenantContext,
    origin: &PublicOrigin,
    realm: Option<&models::entities::realm::RealmModel>,
    named: Option<&models::entities::user::UserModel>,
    now: chrono::DateTime<Utc>,
) -> Option<auth::messaging::OutgoingText> {
    let realm = realm?;
    let person = named?;
    let phone = person.phone_number.as_deref().unwrap_or("").trim();
    if phone.is_empty() || person.phone_number_verified != Some(true) || sealing.texter.is_none() {
        return None;
    }
    let settings = services::messaging::delivery::read_sms_settings(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await?;
    match auth::messaging::text_brakes(transaction, realm, &person.user_id, phone, now).await {
        Ok(None) => {}
        Ok(Some(_)) | Err(()) => return None,
    }
    auth::messaging::record_text(transaction, phone, now)
        .await
        .ok()?;

    let link = format!(
        "{}/realms/{}/protocol/openid-connect/requests",
        origin.as_str(),
        realm.name,
    );
    Some(auth::messaging::OutgoingText {
        settings,
        text: auth::messaging::Text {
            to: phone.to_owned(),
            body: auth::messaging::texted_link(
                realm,
                "ciba_doorbell",
                &link,
                auth::messaging::tongue_spoken_by(person),
            ),
        },
        about: auth::messaging::About {
            user_id: person.user_id.clone(),
            purpose: "ciba-doorbell".to_owned(),
        },
    })
}
