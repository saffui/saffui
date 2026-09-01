use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::Egress;
use config::serving::{LoginUi, PublicOrigin};
use deadpool_postgres::Pool;
use serde::Deserialize;
use services::authorize::{self, Begun, Refusal, Requested};
use services::landing::{Landing, ResponseMode};
use services::response_type::ResponseType;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::{answering, binding, page};

/// How long the cookie naming a login in progress lasts. The row expires on its
/// own; this stops a browser offering a name that is already gone.
const LOGIN_LIFESPAN: i64 = 900;

/// What the query carries. Every field optional here so a missing one is a
/// refusal this endpoint decides how to deliver, rather than a 400 the extractor
/// wrote before the redirect was known to be trustworthy.
#[derive(Debug, Deserialize)]
pub struct Asked {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub dpop_jkt: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    /// How the client asked to be answered.
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub acr_values: Option<String>,
    /// OIDC Core §5.5, JSON as the client sent it.
    pub claims: Option<String>,
}

/// Begin a login, asked in the query.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn begin(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Query<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    login_ui: web::Data<LoginUi>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<Egress>,
) -> HttpResponse {
    let asked = asked.map(web::Query::into_inner);
    start(
        request, &realm, asked, &pool, &tenancy, &sealing, &login_ui, &origin, **egress,
    )
    .await
}

/// Begin a login, asked in a form. OIDC Core §3.1.2.1: both verbs, the same
/// parameters, and nothing a client can tell apart.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn begin_posted(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    login_ui: web::Data<LoginUi>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<Egress>,
) -> HttpResponse {
    let asked = asked.map(web::Form::into_inner);
    start(
        request, &realm, asked, &pool, &tenancy, &sealing, &login_ui, &origin, **egress,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
async fn start(
    request: HttpRequest,
    realm: &str,
    asked: Option<Asked>,
    pool: &Pool,
    tenancy: &Tenancy,
    sealing: &Sealing,
    login_ui: &LoginUi,
    origin: &PublicOrigin,
    egress: Egress,
) -> HttpResponse {
    let now = Utc::now();
    // What a refusal nobody can be sent to looks like: a page for a browser,
    // JSON for anything else.
    let shown = |error: &'static str, description: &str| shown(&request, error, description);
    let Ok(mut connection) = pool.get().await else {
        return shown("server_error", "the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, realm).await else {
        return shown("unauthorized_client", "no login can start here");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return shown("server_error", "the realm could not be read");
    };
    let Some(mut asked) = asked else {
        return shown("invalid_request", "the request could not be read");
    };

    // §6.2: a `request_uri` that is not a reference this server issued is one
    // the client hosts. Fetched here rather than inside, because reaching the
    // network is the transport's and the object then reads as an inline one.
    if let Some(uri) = asked
        .request_uri
        .as_deref()
        .filter(|named| !named.starts_with(services::pushed::HANDLE))
        .map(str::to_owned)
    {
        if authorize::hosted_request_object(&transaction, asked.client_id.as_deref(), &uri)
            .await
            .is_err()
        {
            return shown("invalid_request_uri", "no login can start here");
        }
        let Some(fetched) = super::hosted::fetch(uri, egress).await else {
            return shown(
                "invalid_request_uri",
                "the request object could not be read",
            );
        };
        asked.request = Some(fetched);
        asked.request_uri = None;
    }

    // Opened before the object is read, because a client that registered
    // encryption sends nothing this server can read until it is. Refused
    // rather than passed on: an object in the clear from such a client is one
    // anybody could have written.
    if let Some(raw) = asked.request.clone()
        && let Some(client_id) = asked.client_id.as_deref()
        && let Ok(Some(client)) = store::providers::clients::load(&transaction, client_id).await
        && client.request_object_encryption.is_some()
    {
        let Ok(ring) = store::keyring::load(
            &transaction,
            &sealing.envelope,
            &context.tenant,
            &context.realm_id,
        )
        .await
        else {
            return shown("invalid_request_object", "no login can start here");
        };
        match services::encryption::opened_request_object(
            &transaction,
            &ring,
            &sealing.envelope,
            &client,
            &raw,
        )
        .await
        {
            Ok(opened) => asked.request = Some(opened),
            Err(_) => {
                return shown(
                    "invalid_request_object",
                    "the request object could not be read",
                );
            }
        }
    }

    // A request object is verified against the client's keys, and a client
    // that publishes them elsewhere may have rotated since they were read.
    if asked.request.is_some()
        && let Some(client_id) = asked.client_id.as_deref()
    {
        super::hosted::refresh_client_keys(&transaction, client_id, egress, now).await;
    }

    // Loaded either way: what the request wants is read inside, and asking
    // first would be a second round trip on every login.
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

    let begun = authorize::begin(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &origin.issuer(realm),
        &Requested {
            response_type: asked.response_type.as_deref(),
            client_id: asked.client_id.as_deref(),
            redirect_uri: asked.redirect_uri.as_deref(),
            scope: asked.scope.as_deref(),
            state: asked.state.as_deref(),
            nonce: asked.nonce.as_deref(),
            code_challenge: asked.code_challenge.as_deref(),
            code_challenge_method: asked.code_challenge_method.as_deref(),
            dpop_jkt: asked.dpop_jkt.as_deref(),
            request: asked.request.as_deref(),
            request_uri: asked.request_uri.as_deref(),
            response_mode: asked.response_mode.as_deref(),
            prompt: asked.prompt.as_deref(),
            max_age: asked.max_age,
            acr_values: asked.acr_values.as_deref(),
            claims: asked.claims.as_deref(),
        },
        binding::read(&request, binding::SSO_SESSION).as_deref(),
        signing.as_ref(),
        now,
    )
    .await;

    match begun {
        // Nobody saw a screen, because somebody is already signed in here. The
        // commit is still first: the code has to exist before the browser is
        // sent somewhere to spend it.
        Ok(Begun::Admitted { landing }) => {
            if transaction.commit().await.is_err() {
                return shown("server_error", "the login could not be started");
            }
            answering::answer(&landing)
        }
        Ok(Begun::Authenticate { auth_session_id }) => {
            if transaction.commit().await.is_err() {
                return shown("server_error", "the login could not be started");
            }
            // The page a deployment named, or the one this server renders.
            let answering = login_ui
                .answering()
                .map(str::to_owned)
                .unwrap_or_else(|| page::location(origin, realm));
            // Nothing secret travels in the URL. The browser is told where to
            // answer, and which login it is answering rides in a cookie the
            // page cannot read and a cross-site request cannot attach.
            let mut response = HttpResponseBuilder::new(StatusCode::FOUND);
            binding::set(
                &mut response,
                binding::AUTH_SESSION,
                &auth_session_id,
                &context.realm_id,
                LOGIN_LIFESPAN,
            );
            uncached(&mut response)
                .insert_header(("Location", answering))
                .finish()
        }
        // Nothing was written, so nothing is committed. Rolling back is what
        // makes a refused start leave no half opened login behind.
        Err(Refusal::Unshowable(error)) => {
            noted_refusal(error, asked.client_id.as_deref(), "shown");
            shown(error, "no login can start here")
        }
        Err(Refusal::Redirect(error)) => {
            noted_refusal(error, asked.client_id.as_deref(), "sent");
            // The refusal travels the way the request asked, and a mode this
            // build does not know is one it cannot answer in: those are told
            // as a query, which is the mode a request naming none would get.
            answering::answer(
                &Landing::new(
                    asked.redirect_uri.as_deref().unwrap_or_default(),
                    refused_in(&asked),
                )
                .carrying("error", error)
                .carrying_any("state", asked.state.as_deref())
                // RFC 9207 again: a refusal is an answer, and a client must
                // be able to tell whose it is.
                .carrying("iss", origin.issuer(&context.realm_id)),
            )
        }
    }
}

/// How a refusal travels: the way the answer would have. A request whose
/// response was going in a fragment is refused in one, or a client reading
/// there never learns it was refused.
fn refused_in(asked: &Asked) -> ResponseMode {
    let named = asked.response_mode.as_deref().or_else(|| {
        ResponseType::read(asked.response_type.as_deref().unwrap_or_default())
            .map(ResponseType::default_mode)
    });
    ResponseMode::read(named).unwrap_or_default()
}

/// The refusal, on the record, with the client that asked and where the
/// answer went. The client id is the caller's, so it is cleaned first; nothing
/// else of the request is written, since the rest of it is what a log must
/// never hold.
fn noted_refusal(error: &str, client_id: Option<&str>, delivered: &str) {
    tracing::warn!(
        error,
        client_id = %commons::observability::sanitize_for_log(client_id.unwrap_or_default()),
        delivered,
        "authorization refused"
    );
}

/// A refusal the user sees. The client is not established, or the redirect is
/// not one this realm registered, so sending it onward is the open redirector.
///
/// Still RFC 6749 §4.1.2.1's shape and its code set: the party reading this is
/// not the client, but the codes are the vocabulary the endpoint has, and
/// inventing a second one here would be a second thing to learn.
/// A refusal with nowhere to go: no redirect was trustworthy, so whoever asked
/// is told where they stand. A browser gets a page, anything else the JSON.
fn shown(request: &HttpRequest, error: &'static str, description: &str) -> HttpResponse {
    if page::wants_page(request) {
        return page::notice(
            StatusCode::BAD_REQUEST,
            "Sign-in could not start",
            &format!(
                "<p class=\"told\">{}: {}</p><p>Go back to the application and try again.</p>",
                page::escaped(error),
                page::escaped(description),
            ),
        );
    }
    let mut response = HttpResponseBuilder::new(StatusCode::BAD_REQUEST);
    uncached(&mut response).json(serde_json::json!({
        "error": error,
        "error_description": description,
    }))
}
