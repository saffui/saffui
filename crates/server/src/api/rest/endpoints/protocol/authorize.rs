//! Where a browser starts a login.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use serde::Deserialize;
use services::authorize::{self, Refusal, Requested};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;

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
}

/// Begin a login.
pub async fn begin(
    realm: web::Path<String>,
    asked: Option<web::Query<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return shown("the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return shown("no login can start here");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return shown("the realm could not be read");
    };
    let Some(asked) = asked else {
        return shown("the request could not be read");
    };

    let begun = authorize::begin(
        &transaction,
        sealing.provider.as_ref(),
        &Requested {
            response_type: asked.response_type.as_deref(),
            client_id: asked.client_id.as_deref(),
            redirect_uri: asked.redirect_uri.as_deref(),
            scope: asked.scope.as_deref(),
            state: asked.state.as_deref(),
            nonce: asked.nonce.as_deref(),
            code_challenge: asked.code_challenge.as_deref(),
            code_challenge_method: asked.code_challenge_method.as_deref(),
        },
        now,
    )
    .await;

    match begun {
        Ok(begun) => {
            if transaction.commit().await.is_err() {
                return shown("the login could not be started");
            }
            // The login carries its own identifier because there is no cookie to
            // carry it: a browser arriving at the next step names which login it
            // is in, and the row says everything else about it.
            redirect(&format!(
                "{}/realms/{}/protocol/openid-connect/login?auth_session={}",
                origin.as_str(),
                context.realm_id,
                begun.auth_session_id
            ))
        }
        // Nothing was written, so nothing is committed. Rolling back is what
        // makes a refused start leave no half opened login behind.
        Err(Refusal::Unshowable) => shown("no login can start here"),
        Err(Refusal::Redirect(error)) => sent(
            asked.redirect_uri.as_deref().unwrap_or_default(),
            error,
            asked.state.as_deref(),
        ),
    }
}

/// A refusal the user sees. The client is not established, or the redirect is
/// not one this realm registered, so sending it onward is the open redirector.
fn shown(why: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::BAD_REQUEST))
        .content_type("text/plain; charset=utf-8")
        .body(why.to_owned())
}

/// A refusal the client sees, at the redirect it registered.
fn sent(redirect_uri: &str, error: &str, state: Option<&str>) -> HttpResponse {
    let mut query = format!("error={}", encoded(error));
    if let Some(state) = state {
        query.push_str(&format!("&state={}", encoded(state)));
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    redirect(&format!("{redirect_uri}{separator}{query}"))
}

fn redirect(location: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::FOUND))
        .insert_header(("Location", location))
        .finish()
}

/// Percent encoding for what goes in a query. Written out rather than pulled in:
/// the alphabet is RFC 3986 §2.3 and everything else is escaped, which is the
/// safe direction when the value came from a caller.
fn encoded(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
