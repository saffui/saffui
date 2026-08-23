//! Answering a login a browser started.
//!
//! Two ways in, one flow behind them. JSON for the screens that are an
//! application of their own, answered in JSON. A form for the page this server
//! renders and for any browser that runs no script, answered the way a browser
//! understands: sent on. Not an endpoint any RFC specifies, so the shape is this
//! server's: the three outcomes a flow has, named.

use actix_web::http::StatusCode;
use actix_web::{Either, HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use serde::Deserialize;
use services::login::authenticator::Answer;
use services::login::browser::{self, Step, Unanswerable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::protocol::binding;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::mail::deliver;

/// What the caller answers with.
///
/// Which login is being answered is not in here. It rides in a cookie, so a
/// caller cannot answer a login it merely learned the name of.
#[derive(Debug, Deserialize)]
pub struct Answered {
    pub username: Option<String>,
    pub password: Option<String>,
    /// The digits from an authenticator app, as typed.
    pub totp: Option<String>,
    /// What a key handed back, as the JSON the browser produced.
    pub webauthn: Option<String>,
    /// The attestation for a key the realm told this user to enrol.
    pub webauthn_register: Option<String>,
    /// The code proving an authenticator app the realm told this user to set
    /// up was set up.
    pub totp_register: Option<String>,
    /// What a mailed link carried, as the page it landed on posted it.
    pub magic_link: Option<String>,
}

/// How the answer arrived, which is how the outcome is told.
#[derive(Clone, Copy)]
enum Spoken {
    Json,
    /// A form: every outcome is a place to go. The page shows what the
    /// fragment names, without a script and without this server rendering
    /// anything into it.
    Form,
}

/// How long the login this opens lasts, matching what the flow writes.
const SSO_LIFESPAN: i64 = 36_000;

/// Run one step.
pub async fn answer(
    request: HttpRequest,
    realm: web::Path<String>,
    answered: Option<Either<web::Json<Answered>, web::Form<Answered>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let (answered, spoken) = match answered {
        Some(Either::Left(json)) => (json.into_inner(), Spoken::Json),
        Some(Either::Right(form)) => (form.into_inner(), Spoken::Form),
        None => return told(StatusCode::BAD_REQUEST, "unreadable"),
    };
    let page = request.path().to_owned();
    let tell = |status: StatusCode, named: &str| match spoken {
        Spoken::Json => told(status, named),
        Spoken::Form => shown(&page, named),
    };

    // No cookie, no login. A body naming one would let anybody who read an
    // identifier off a log answer somebody else's sign-in.
    let Some(auth_session) = binding::read(&request, binding::AUTH_SESSION) else {
        return tell(StatusCode::NOT_FOUND, "no-such-login");
    };
    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    // Resolved before anything is read, and answered the same way a login that
    // does not exist is: which realms a deployment holds is not something an
    // unauthenticated caller gets to enumerate.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return tell(StatusCode::NOT_FOUND, "no-such-login");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    // A field left blank is a field not answered. A form posts every input it
    // has, and a step handed an empty code has been answered wrongly rather
    // than not yet.
    let filled = |field: &Option<String>| field.clone().filter(|value| !value.is_empty());
    let mut answers = Vec::new();
    if let Some(secret) = filled(&answered.password) {
        answers.push(Answer::Password(SecretBox::new(Box::new(secret))));
    }
    if let Some(typed) = filled(&answered.totp) {
        answers.push(Answer::Totp(typed));
    }
    if let Some(handed_back) = filled(&answered.webauthn) {
        answers.push(Answer::Webauthn(handed_back));
    }
    if let Some(followed) = filled(&answered.magic_link) {
        answers.push(Answer::MagicLink(secrecy::SecretBox::new(Box::new(
            followed,
        ))));
    }
    let attestation = filled(&answered.webauthn_register);
    let code = filled(&answered.totp_register);

    // A mailed step needs the realm's own key to open how it sends. Absent
    // where the realm holds no keyring, which is a realm nothing has mailed
    // from either.
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok();

    let step = browser::answer_step(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &origin,
        &auth_session,
        filled(&answered.username).as_deref(),
        // Everything the body carried. The flow runs every step against what it
        // was given, so a login resumed with a second factor still has to
        // satisfy the first, and each step takes the kind it understands.
        &answers,
        services::login::enrolment::Answers {
            attestation: attestation.as_deref(),
            code: code.as_deref(),
        },
        &read_provenance(&request),
        sealing.sender.is_some(),
        ring.as_ref().map(|ring| browser::Sealing {
            ring,
            envelope: &sealing.envelope,
        }),
        now,
    )
    .await;

    match step {
        // The rows the answer wrote are what the next step reads, and on an
        // admission they are what the code names. Answering before committing
        // hands out a code whose login the redemption cannot find.
        Ok(step) => {
            if transaction.commit().await.is_err() {
                return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
            match step {
                Step::Challenge {
                    execution_id,
                    asks,
                    sending,
                } => {
                    if let Some(outgoing) = sending {
                        deliver(&sealing, *outgoing).await;
                    }
                    match spoken {
                        Spoken::Json => {
                            let mut body = serde_json::json!({
                                "status": "challenge",
                                "execution": execution_id,
                            });
                            // Only when a step issued one. A password form is the
                            // caller's own and carries no server state, so a body
                            // claiming a challenge that is not there would have
                            // the caller wait for a device that was never asked.
                            if let (Some(asks), Some(map)) = (asks, body.as_object_mut()) {
                                map.insert("asks".to_owned(), asks);
                            }
                            uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(body)
                        }
                        // A key needs the script; a code needs only the field.
                        Spoken::Form => shown(
                            &page,
                            if asks.is_some() {
                                "key-needs-script"
                            } else {
                                "code"
                            },
                        ),
                    }
                }
                // The login in progress is over, so its cookie goes and the one
                // saying this browser is signed in takes its place. That second
                // cookie is what makes another client's `/authorize` something
                // other than a fresh sign-in.
                Step::Admitted {
                    redirect_to,
                    session_id,
                } => {
                    tracing::info!(session = %session_id, "login admitted");
                    let mut response = HttpResponseBuilder::new(match spoken {
                        Spoken::Json => StatusCode::OK,
                        Spoken::Form => StatusCode::SEE_OTHER,
                    });
                    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
                    binding::set(
                        &mut response,
                        binding::SSO_SESSION,
                        &session_id,
                        &context.realm_id,
                        SSO_LIFESPAN,
                    );
                    match spoken {
                        Spoken::Json => uncached(&mut response).json(
                            serde_json::json!({ "status": "admitted", "redirect_to": redirect_to }),
                        ),
                        Spoken::Form => uncached(&mut response)
                            .insert_header(("Location", redirect_to))
                            .finish(),
                    }
                }
                Step::Refused => {
                    tracing::warn!("login refused");
                    tell(StatusCode::UNAUTHORIZED, "refused")
                }
                // Over, and not admitted: the client hears why at its
                // redirect, and the browser carries it there. The login's
                // cookie goes; no session replaces it.
                Step::SentBack { redirect_to } => {
                    tracing::warn!(error = "login_required", "login sent back");
                    let mut response = HttpResponseBuilder::new(match spoken {
                        Spoken::Json => StatusCode::OK,
                        Spoken::Form => StatusCode::SEE_OTHER,
                    });
                    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
                    match spoken {
                        Spoken::Json => uncached(&mut response).json(
                            serde_json::json!({ "status": "sent_back", "redirect_to": redirect_to }),
                        ),
                        Spoken::Form => uncached(&mut response)
                            .insert_header(("Location", redirect_to))
                            .finish(),
                    }
                }
            }
        }
        Err(Unanswerable::NoSuchLogin) => {
            tracing::warn!("no such login");
            tell(StatusCode::NOT_FOUND, "no-such-login")
        }
        Err(_) => told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
    }
}

/// One shape for every outcome. Never cached: a challenge and an admission both
/// name a login in progress, and a cache would answer the next caller with it.
fn told(status: StatusCode, status_name: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .json(serde_json::json!({ "status": status_name }))
}

/// Back to the page, the outcome in the fragment. A fragment never reaches
/// this server again, so what the page shows is never something it was told
/// to show by a request.
fn shown(page: &str, named: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::SEE_OTHER))
        .insert_header(("Location", format!("{page}#{named}")))
        .finish()
}
