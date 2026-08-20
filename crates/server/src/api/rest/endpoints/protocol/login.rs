//! Answering a login a browser started.
//!
//! JSON, because the screens are an application of their own and this answers
//! them rather than rendering them. Not an endpoint any RFC specifies, so the
//! shape is this server's: the three outcomes a flow has, named.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use serde::Deserialize;
use services::login::authenticator::Answer;
use services::login::browser::{self, Step, Unanswerable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::binding;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// What the caller answers with.
///
/// Which login is being answered is not in here. It rides in a cookie, so a
/// caller cannot answer a login it merely learned the name of.
#[derive(Debug, Deserialize)]
pub struct Answered {
    pub username: Option<String>,
    pub password: Option<String>,
}

/// How long the login this opens lasts, matching what the flow writes.
const SSO_LIFESPAN: i64 = 36_000;

/// Run one step.
pub async fn answer(
    request: HttpRequest,
    realm: web::Path<String>,
    answered: Option<web::Json<Answered>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(answered) = answered else {
        return told(StatusCode::BAD_REQUEST, "unreadable", None);
    };
    // No cookie, no login. A body naming one would let anybody who read an
    // identifier off a log answer somebody else's sign-in.
    let Some(auth_session) = binding::read(&request, binding::AUTH_SESSION) else {
        return told(StatusCode::NOT_FOUND, "no-such-login", None);
    };
    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable", None);
    };
    // Resolved before anything is read, and answered the same way a login that
    // does not exist is: which realms a deployment holds is not something an
    // unauthenticated caller gets to enumerate.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(StatusCode::NOT_FOUND, "no-such-login", None);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable", None);
    };

    let step = browser::answer_step(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &auth_session,
        answered.username.as_deref(),
        answered
            .password
            .clone()
            .map(|secret| Answer::Password(SecretBox::new(Box::new(secret))))
            .as_ref(),
        now,
    )
    .await;

    match step {
        // The rows the answer wrote are what the next step reads, and on an
        // admission they are what the code names. Answering before committing
        // hands out a code whose login the redemption cannot find.
        Ok(step) => {
            if transaction.commit().await.is_err() {
                return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable", None);
            }
            match step {
                Step::Challenge { execution_id } => told(
                    StatusCode::OK,
                    "challenge",
                    Some(("execution", execution_id)),
                ),
                // The login in progress is over, so its cookie goes and the one
                // saying this browser is signed in takes its place. That second
                // cookie is what makes another client's `/authorize` something
                // other than a fresh sign-in.
                Step::Admitted {
                    redirect_to,
                    session_id,
                } => {
                    let mut response = HttpResponseBuilder::new(StatusCode::OK);
                    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
                    binding::set(
                        &mut response,
                        binding::SSO_SESSION,
                        &session_id,
                        &context.realm_id,
                        SSO_LIFESPAN,
                    );
                    uncached(&mut response).json(
                        serde_json::json!({ "status": "admitted", "redirect_to": redirect_to }),
                    )
                }
                Step::Refused => told(StatusCode::UNAUTHORIZED, "refused", None),
            }
        }
        Err(Unanswerable::NoSuchLogin) => told(StatusCode::NOT_FOUND, "no-such-login", None),
        Err(_) => told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable", None),
    }
}

/// One shape for every outcome. Never cached: a challenge and an admission both
/// name a login in progress, and a cache would answer the next caller with it.
fn told(status: StatusCode, status_name: &str, carried: Option<(&str, String)>) -> HttpResponse {
    let mut body = serde_json::json!({ "status": status_name });
    if let (Some((named, value)), Some(map)) = (carried, body.as_object_mut()) {
        map.insert(named.to_owned(), serde_json::Value::String(value));
    }
    uncached(&mut HttpResponseBuilder::new(status)).json(body)
}
