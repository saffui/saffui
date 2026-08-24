use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use services::grant::Signing;
use services::logout::{self, EndedAt, Frame, Requested};
use store::keyring;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::backchannel;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::{binding, page};

/// What the request carried, by either verb. §2 allows both: a browser
/// arriving by link uses one, a form posting a hint too long for a URL the
/// other, and the page that asks the person answers by the second.
#[derive(Debug, Default, Deserialize)]
pub struct Asked {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub state: Option<String>,
    pub confirmed: Option<String>,
}

pub async fn end(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Query<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let asked = asked.map(web::Query::into_inner).unwrap_or_default();
    run(&request, &realm, asked, &pool, &tenancy, &sealing, &origin).await
}

pub async fn end_posted(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let asked = asked.map(web::Form::into_inner).unwrap_or_default();
    run(&request, &realm, asked, &pool, &tenancy, &sealing, &origin).await
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
async fn run(
    request: &HttpRequest,
    realm: &str,
    asked: Asked,
    pool: &Pool,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
) -> HttpResponse {
    let now = Utc::now();
    let told = |realm_id: &str, ended: EndedAt, frames: &[Frame]| {
        tell(request, realm_id, &asked, ended, frames)
    };

    let Ok(mut connection) = pool.get().await else {
        return told(realm, EndedAt::Nowhere, &[]);
    };
    // An unknown realm ends nothing and says so the same way. Which realms exist
    // is not a question this endpoint answers, and everyone links to it.
    let Ok(context) = resolve::realm_by_name(&connection, realm).await else {
        return told(realm, EndedAt::Nowhere, &[]);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(&context.realm_id, EndedAt::Nowhere, &[]);
    };
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return told(&context.realm_id, EndedAt::Nowhere, &[]);
    };

    let signed_in = binding::read(request, binding::SSO_SESSION);
    let ended = logout::end_session(
        &transaction,
        &keys,
        &Requested {
            id_token_hint: asked.id_token_hint.as_deref(),
            post_logout_redirect_uri: asked.post_logout_redirect_uri.as_deref(),
            client_id: asked.client_id.as_deref(),
            state: asked.state.as_deref(),
            confirmed: asked.confirmed.as_deref() == Some("yes"),
        },
        signed_in.as_deref(),
        now,
    )
    .await;

    // Minted while the login's record is still readable, delivered once the
    // ending is written: a client told of a logout that then failed to commit
    // would drop a session the user still holds.
    let mut notices = Vec::new();
    let mut frames = Vec::new();
    let ending = signed_in
        .as_deref()
        .filter(|named| !named.is_empty() && ended != EndedAt::Confirm);
    if let Some(session_id) = ending
        && let Ok(ring) = keyring::load(
            &transaction,
            &sealing.envelope,
            &context.tenant,
            &context.realm_id,
        )
        .await
    {
        let signing = Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        };
        notices = logout::notices_for(
            &transaction,
            &signing,
            &origin.issuer(realm),
            session_id,
            now,
        )
        .await;
    }
    if let Some(session_id) = ending {
        frames = logout::frames_for(&transaction, &origin.issuer(realm), session_id).await;
    }

    if transaction.commit().await.is_err() {
        return told(&context.realm_id, EndedAt::Nowhere, &[]);
    }
    backchannel::deliver(notices).await;
    told(&context.realm_id, ended, &frames)
}

/// What the browser is told. A page to a browser, JSON to anything else; the
/// cookies go whenever the login did, and stay while the person is still
/// being asked.
fn tell(
    request: &HttpRequest,
    realm_id: &str,
    asked: &Asked,
    ended: EndedAt,
    frames: &[Frame],
) -> HttpResponse {
    let as_page = page::wants_page(request);
    match ended {
        EndedAt::Confirm => {
            if as_page {
                return page::notice(StatusCode::OK, "Sign out?", &confirm_form(asked));
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                .json(json!({ "status": "confirm" }))
        }
        EndedAt::Redirect(landing) => {
            // Front-Channel Logout §3: the frames have to load before the
            // browser leaves, so a landing that has any is reached from the
            // page rather than by a redirect the browser follows at once.
            if !frames.is_empty() && as_page {
                let mut response = page::notice_with_frames(
                    StatusCode::OK,
                    "You are signed out",
                    &format!(
                        "{}<p class=\"told\"><a href=\"{}\">Continue</a></p>",
                        loading(frames),
                        page::escaped(&landing)
                    ),
                    Some(&landing),
                );
                forget_on(&mut response, realm_id);
                return response;
            }
            let mut response = HttpResponseBuilder::new(StatusCode::FOUND);
            forget(&mut response, realm_id);
            uncached(&mut response)
                .insert_header(("Location", landing))
                .finish()
        }
        EndedAt::Nowhere | EndedAt::Refused => {
            let refused = ended == EndedAt::Refused;
            if as_page {
                let mut response = signed_out(
                    "You are signed out",
                    if refused {
                        "<p class=\"told\">The application asked to send you to an address it \
                         never registered, so you stay here.</p>"
                    } else {
                        "<p class=\"told\">You can close this window.</p>"
                    },
                    frames,
                );
                forget_on(&mut response, realm_id);
                return response;
            }
            let mut response = HttpResponseBuilder::new(StatusCode::OK);
            forget(&mut response, realm_id);
            let mut body = json!({ "status": "logged-out" });
            if refused {
                body["redirect"] = json!("refused");
            }
            uncached(&mut response).json(body)
        }
    }
}

/// The page that says it is over, carrying whatever frames were asked for.
fn signed_out(title: &str, said: &str, frames: &[Frame]) -> HttpResponse {
    let inner = format!("{said}{}", loading(frames));
    if frames.is_empty() {
        page::notice(StatusCode::OK, title, &inner)
    } else {
        page::notice_with_frames(StatusCode::OK, title, &inner, None)
    }
}

/// One hidden frame per client that asked to be loaded at logout. Hidden
/// because the person is not meant to see another application's page here.
fn loading(frames: &[Frame]) -> String {
    frames
        .iter()
        .map(|frame| {
            format!(
                "<iframe src=\"{}\" title=\"{}\" hidden></iframe>",
                page::escaped(&frame.uri),
                page::escaped(&frame.client_id)
            )
        })
        .collect()
}

/// The question, carrying the request back so the answer ends the same
/// logout. A same-site post; the cookie it ends is withheld from any other.
fn confirm_form(asked: &Asked) -> String {
    let mut form = String::from(
        "<p class=\"told\">An application asked to sign you out.</p>\
         <form method=\"post\"><input type=\"hidden\" name=\"confirmed\" value=\"yes\">",
    );
    for (named, value) in [
        ("id_token_hint", &asked.id_token_hint),
        ("post_logout_redirect_uri", &asked.post_logout_redirect_uri),
        ("client_id", &asked.client_id),
        ("state", &asked.state),
    ] {
        if let Some(value) = value {
            form.push_str(&format!(
                "<input type=\"hidden\" name=\"{named}\" value=\"{}\">",
                page::escaped(value)
            ));
        }
    }
    form.push_str("<button type=\"submit\">Sign out</button></form>");
    form
}

fn forget(response: &mut HttpResponseBuilder, realm_id: &str) {
    binding::clear(response, binding::SSO_SESSION, realm_id);
    binding::clear(response, binding::AUTH_SESSION, realm_id);
    // What a relying party's iframe reads: gone is how it learns the login is.
    binding::clear_browser_state(response, realm_id);
}

/// The same, on a response already built.
fn forget_on(response: &mut HttpResponse, realm_id: &str) {
    let mut builder = HttpResponseBuilder::new(StatusCode::OK);
    forget(&mut builder, realm_id);
    let built = builder.finish();
    for cookie in built.cookies() {
        let _ = response.add_cookie(&cookie);
    }
}
