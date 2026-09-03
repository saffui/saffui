use actix_web::http::StatusCode;
use actix_web::{Either, HttpRequest, HttpResponse, HttpResponseBuilder, web};
use auth::login::authenticator::Answer;
use auth::login::browser::{self, Step, Unanswerable};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use serde::Deserialize;
use services::form_post;
use services::landing::{Landing, ResponseMode};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::mail::deliver;
use crate::api::rest::endpoints::protocol::{answering, binding};

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
    /// The person asked to sign in by key alone; the step answers with a
    /// challenge that names no credentials.
    pub webauthn_discover: Option<bool>,
    /// The attestation for a key the realm told this user to enrol.
    pub webauthn_register: Option<String>,
    /// The code proving an authenticator app the realm told this user to set
    /// up was set up.
    pub totp_register: Option<String>,
    /// One code off the printed sheet, answering a second factor.
    pub recovery_code: Option<String>,
    /// One code typed back off the sheet just shown, proving it was kept.
    pub recovery_codes_register: Option<String>,
    /// What a mailed link carried, as the page it landed on posted it.
    pub magic_link: Option<String>,
    /// The same, for a link confirming an address.
    pub verify_email: Option<String>,
    /// What the consent screen answered: `granted` or `refused`.
    pub consent: Option<String>,
    /// Which organization the chooser answered, by slug.
    pub organization: Option<String>,
    /// Whether the person ticked remember-me. Counted only where the realm
    /// says so; a body inventing it against a realm that does not is ignored.
    pub remember_me: Option<bool>,
}

/// How the answer arrived, which is how the outcome is told.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Spoken {
    Json,
    /// A form: every outcome is a place to go. The page shows what the
    /// fragment names, without a script and without this server rendering
    /// anything into it.
    Form,
}

/// How long the login this opens lasts, matching what the flow writes.
pub(crate) const SSO_LIFESPAN: i64 = 36_000;

/// How long the ticket that fetches a waiting response lasts. One navigation
/// and no longer: it stands for an authorization code.
const LANDING_SECONDS: i64 = 120;

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
    if let Some(typed) = filled(&answered.recovery_code) {
        answers.push(Answer::RecoveryCode(SecretBox::new(Box::new(typed))));
    }
    if let Some(handed_back) = filled(&answered.webauthn) {
        answers.push(Answer::Webauthn(handed_back));
    }
    if answered.webauthn_discover == Some(true) {
        answers.push(Answer::WebauthnAsk);
    }
    if let Some(followed) = filled(&answered.magic_link) {
        answers.push(Answer::MagicLink(secrecy::SecretBox::new(Box::new(
            followed,
        ))));
    }
    let attestation = filled(&answered.webauthn_register);
    let code = filled(&answered.totp_register);
    let kept = filled(&answered.recovery_codes_register);

    // The desktop ticket, when the realm answers that door and the browser
    // carried one. Reduced to a principal here, at the listener, so the flow
    // only ever sees who the exchange proved. A ticket that does not hold
    // becomes an answer that fails the step, rather than silence that would
    // re-challenge the same doomed exchange forever.
    let mut negotiated: Option<String> = None;
    if let Ok(Some(door)) = store::providers::brokering::spnego(&transaction).await
        && door.enabled != Some(false)
    {
        match services::negotiation::SpnegoSettings::parse(&door) {
            Err(why) => {
                tracing::warn!(%why, "the realm's ticket door no longer reads");
            }
            Ok(settings) => {
                if let Some(token) = negotiate_token(&request) {
                    let spn = settings.service_principal.clone();
                    let principal = web::block(move || crate::negotiate::accepted(&spn, &token))
                        .await
                        .map_err(|_| ())
                        .and_then(|held| {
                            held.map_err(|why| {
                                tracing::debug!(%why, "a ticket was refused at the door");
                            })
                        });
                    match principal {
                        Ok(named)
                            if named.rsplit('@').next() == Some(settings.kerberos_realm()) =>
                        {
                            let local = named.split('@').next().unwrap_or_default().to_owned();
                            negotiated = Some(local.clone());
                            answers.push(Answer::Negotiate(named));
                        }
                        Ok(named) => {
                            // A principal from another realm: nobody here.
                            tracing::debug!(principal = %named, "a foreign-realm ticket");
                            answers.push(Answer::Negotiate(String::new()));
                        }
                        Err(()) => {
                            answers.push(Answer::Negotiate(String::new()));
                        }
                    }
                }
            }
        }
    }

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

    let signing = ring.as_ref().map(|ring| services::grant::Signing {
        provider: sealing.provider.as_ref(),
        ring,
        envelope: &sealing.envelope,
    });

    // The realm's directories, first-asked first. A row that stopped
    // reading is skipped with a line for the operator: the plane refuses to
    // write one, so a broken row is a migration of trouble, and bricking
    // every login over it helps nobody.
    let rows = match store::providers::brokering::federations(&transaction).await {
        Ok(rows) => rows,
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
    };
    let mut federated = Vec::new();
    for held in &rows {
        if held.enabled == Some(false) {
            continue;
        }
        match services::federation::LdapSettings::parse(held) {
            Ok(settings) => federated.push((
                held.alias.clone(),
                crate::federation::directory_for(&transaction, &sealing, &context, held, settings)
                    .await,
            )),
            Err(why) => {
                tracing::warn!(%why, alias = held.alias, "a directory row no longer reads");
            }
        }
    }
    let federations: Vec<auth::login::directory::Named<'_>> = federated
        .iter()
        .map(|(alias, directory)| auth::login::directory::Named {
            alias,
            directory: directory as &dyn auth::login::directory::Directory,
        })
        .collect();

    let step = browser::answer_step(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &origin,
        &auth_session,
        // The ticket's name wins over a typed one: the exchange proved it,
        // and the step ties the two together anyway.
        negotiated
            .as_deref()
            .or(filled(&answered.username).as_deref()),
        // Everything the body carried. The flow runs every step against what it
        // was given, so a login resumed with a second factor still has to
        // satisfy the first, and each step takes the kind it understands.
        &answers,
        auth::login::enrolment::Answers {
            attestation: attestation.as_deref(),
            code: code.as_deref(),
            verified_address: answered.verify_email.as_deref(),
            kept: kept.as_deref(),
        },
        &read_provenance(&request),
        sealing.sender.is_some(),
        ring.as_ref().map(|ring| browser::Sealing {
            ring,
            envelope: &sealing.envelope,
        }),
        signing.as_ref(),
        // Anything other than the two words is no answer at all, so the
        // screen is shown again rather than read as one of them.
        match answered.consent.as_deref() {
            Some("granted") => Some(true),
            Some("refused") => Some(false),
            _ => None,
        },
        answered.remember_me.unwrap_or(false),
        answered.organization.as_deref(),
        &federations,
        now,
    )
    .await;

    match step {
        // The rows the answer wrote are what the next step reads, and on an
        // admission they are what the code names. Answering before committing
        // hands out a code whose login the redemption cannot find.
        Ok(step) => {
            // Where the browser goes, built inside the transaction the step ran
            // in: minting a code is a write, and one minted after the commit is
            // a code the redemption cannot find.
            let landed = match &step {
                Step::Admitted(admitted) => {
                    let signing = ring.as_ref().map(|ring| store::keyring::Signing {
                        provider: sealing.provider.as_ref(),
                        ring,
                        envelope: &sealing.envelope,
                    });
                    match services::minting::landed(
                        &transaction,
                        sealing.provider.as_ref(),
                        &context,
                        admitted,
                        signing.as_ref(),
                        &origin.issuer(&context.realm_id),
                        now,
                    )
                    .await
                    {
                        Ok(landing) => Some(landing),
                        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
                    }
                }
                Step::SentBack { error, login } => Some(services::minting::refused(
                    login,
                    error,
                    &origin.issuer(&context.realm_id),
                )),
                _ => None,
            };

            // A browser reading JSON cannot post the answer to the client: the
            // page it is on may only post to this server. It is handed a ticket
            // instead, written here so it commits with the code it stands for.
            let ticket = match landed.as_ref() {
                Some(landing)
                    if spoken == Spoken::Json && landing.mode == ResponseMode::FormPost =>
                {
                    match form_post::keep(&transaction, sealing.provider.as_ref(), landing, now)
                        .await
                    {
                        Ok(ticket) => Some(ticket),
                        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
                    }
                }
                _ => None,
            };
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
                        deliver(&sealing, &pool, &tenancy, &context, *outgoing).await;
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
                            // A negotiate step is asked for the way the
                            // protocol asks for it: a 401 naming the scheme,
                            // which is what makes a domain-joined browser
                            // attach its ticket to the retry. The body still
                            // says everything a scripted caller needs.
                            let status = match &asks {
                                Some(asks)
                                    if asks.get("mechanism").and_then(|held| held.as_str())
                                        == Some("negotiate") =>
                                {
                                    StatusCode::UNAUTHORIZED
                                }
                                _ => StatusCode::OK,
                            };
                            if let (Some(asks), Some(map)) = (asks, body.as_object_mut()) {
                                map.insert("asks".to_owned(), asks);
                            }
                            let mut builder = HttpResponseBuilder::new(status);
                            let answer = uncached(&mut builder);
                            if status == StatusCode::UNAUTHORIZED {
                                answer.insert_header(("WWW-Authenticate", "Negotiate"));
                            }
                            answer.json(body)
                        }
                        // A key needs the script; a code needs only the
                        // field; a link followed in the wrong browser needs
                        // to be told so rather than shown either.
                        Spoken::Form => shown(
                            &page,
                            match &asks {
                                Some(asks) if asks.get("wrong_browser").is_some() => {
                                    "wrong-browser"
                                }
                                Some(_) => "key-needs-script",
                                None => "code",
                            },
                        ),
                    }
                }
                // The login in progress is over, so its cookie goes and the one
                // saying this browser is signed in takes its place. That second
                // cookie is what makes another client's `/authorize` something
                // other than a fresh sign-in.
                Step::Admitted(admitted) => {
                    let session_id = admitted.session_id.clone();
                    let browser_state = admitted.browser_state.clone();
                    let remembered = admitted.remember_me;
                    let landing = landed.expect("an admission was landed above");
                    tracing::info!(session = %session_id, "login admitted");
                    let mut response = HttpResponseBuilder::new(match spoken {
                        Spoken::Json => StatusCode::OK,
                        Spoken::Form => StatusCode::SEE_OTHER,
                    });
                    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
                    // Remembered, the cookie survives the browser closing for
                    // as long as the session itself may live; otherwise it is
                    // the browser's session cookie and dies with the window.
                    binding::set(
                        &mut response,
                        binding::SSO_SESSION,
                        &session_id,
                        &context.realm_id,
                        remembered.then_some(SSO_LIFESPAN),
                    );
                    // §4.2: read by script in a frame the relying party loads,
                    // so it is set on terms the others are not.
                    if let Some(state) = &browser_state {
                        binding::set_browser_state(&mut response, state, &context.realm_id);
                    }
                    hand_over(&mut response, &context.realm_id, ticket.as_deref());
                    // An admission whose answer is a refusal, such as an
                    // organization the user does not hold, is said as what it
                    // is: the person signed in, and the client was told no.
                    let outcome = if landing.refuses() {
                        "sent_back"
                    } else {
                        "admitted"
                    };
                    told_landing(&mut response, spoken, outcome, &landing, &origin, &realm)
                }
                Step::Refused => {
                    tracing::warn!("login refused");
                    tell(StatusCode::UNAUTHORIZED, "refused")
                }
                // Nothing was tried, so the answer is not what is wrong. Said
                // plainly rather than as a refusal: a person told their
                // password is wrong will keep changing it.
                Step::Consent {
                    client_id,
                    client_name,
                    scopes,
                } => match spoken {
                    Spoken::Json => uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(
                        serde_json::json!({
                            "status": "consent",
                            "client_id": client_id,
                            "client_name": client_name,
                            "scopes": scopes,
                        }),
                    ),
                    Spoken::Form => shown(&page, "consent"),
                },
                Step::Organization { held } => match spoken {
                    Spoken::Json => uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(
                        serde_json::json!({
                            "status": "organization",
                            "organizations": held
                                .iter()
                                .map(|choice| serde_json::json!({
                                    "name": choice.name,
                                    "display_name": choice.display_name,
                                }))
                                .collect::<Vec<_>>(),
                        }),
                    ),
                    Spoken::Form => shown(&page, "choice-needs-script"),
                },
                Step::LockedOut { until } => {
                    tracing::warn!(until, "login locked out");
                    match spoken {
                        Spoken::Json => {
                            uncached(&mut HttpResponseBuilder::new(StatusCode::TOO_MANY_REQUESTS))
                                .json(serde_json::json!({ "status": "locked-out", "until": until }))
                        }
                        Spoken::Form => shown(&page, "locked-out"),
                    }
                }
                // Over, and not admitted: the client hears why at its
                // redirect, and the browser carries it there. The login's
                // cookie goes; no session replaces it.
                Step::SentBack { error, .. } => {
                    tracing::warn!(error, "login sent back");
                    let landing = landed.expect("a refusal was landed above");
                    let mut response = HttpResponseBuilder::new(match spoken {
                        Spoken::Json => StatusCode::OK,
                        Spoken::Form => StatusCode::SEE_OTHER,
                    });
                    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
                    hand_over(&mut response, &context.realm_id, ticket.as_deref());
                    told_landing(
                        &mut response,
                        spoken,
                        "sent_back",
                        &landing,
                        &origin,
                        &realm,
                    )
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

/// The outcome, the way the request asked to be answered.
///
/// A caller reading JSON is told where to post rather than where to go when the
/// mode is `form_post`: handing it a URL with the answer in the query is the
/// one thing that mode exists to prevent.
pub(crate) fn told_landing(
    response: &mut HttpResponseBuilder,
    spoken: Spoken,
    status: &str,
    landing: &Landing,
    origin: &PublicOrigin,
    realm: &str,
) -> HttpResponse {
    match (spoken, landing.mode) {
        (Spoken::Json, ResponseMode::Query | ResponseMode::Fragment) => uncached(response)
            .json(serde_json::json!({ "status": status, "redirect_to": landing.as_url() })),
        // `redirect_to` is this server, not the client: the response goes to
        // the client as a post, and the page that posts it is served there. A
        // caller that is not a browser still gets what it needs to post the
        // response itself.
        (Spoken::Json, ResponseMode::FormPost) => uncached(response).json(serde_json::json!({
            "status": status,
            "response_mode": landing.mode.as_str(),
            "redirect_to": format!(
                "{}/realms/{realm}/protocol/openid-connect/form-post",
                origin.as_str()
            ),
            "post_to": landing.redirect_uri,
            "parameters": landing
                .parameters
                .iter()
                .map(|(named, value)| ((*named).to_owned(), serde_json::json!(value)))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
        })),
        (Spoken::Form, _) => answering::onto(response, landing),
    }
}

/// Give the browser the ticket that fetches the response, and nothing else.
pub(crate) fn hand_over(response: &mut HttpResponseBuilder, realm_id: &str, ticket: Option<&str>) {
    if let Some(ticket) = ticket {
        binding::set(
            response,
            binding::LANDING,
            ticket,
            realm_id,
            Some(LANDING_SECONDS),
        );
    }
}

/// One shape for every outcome. Never cached: a challenge and an admission both
/// name a login in progress, and a cache would answer the next caller with it.
pub(crate) fn told(status: StatusCode, status_name: &str) -> HttpResponse {
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

/// The SPNEGO token the browser attached, when it attached one.
fn negotiate_token(request: &HttpRequest) -> Option<Vec<u8>> {
    let header = request
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let blob = header.strip_prefix("Negotiate ")?;
    data_encoding::BASE64.decode(blob.trim().as_bytes()).ok()
}
