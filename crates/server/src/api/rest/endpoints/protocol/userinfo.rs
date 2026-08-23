//! What a client may learn about the person its token speaks for.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use services::userinfo::{self, Untold};
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// Tell what the token allows.
///
/// Both verbs, as OIDC Core §5.3.1 requires. A client that can only issue one of
/// them is one this endpoint would be unreachable from.
pub async fn tell(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Carried>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(bearer) = presented(&request, body.as_deref()) else {
        return challenged("a bearer token is required");
    };
    let Ok(mut connection) = pool.get().await else {
        return faulted();
    };
    // Answered as an unacceptable token, not as a missing realm: which realms
    // exist is not something a caller holding no valid token gets to map.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return challenged("the token presented is not one this realm accepts");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return faulted();
    };
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return faulted();
    };

    match userinfo::claims_for(&transaction, &keys, &bearer, now).await {
        Ok(claims) => {
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(Value::Object(claims))
        }
        Err(Untold::InvalidToken) => {
            tracing::warn!("userinfo refused");
            challenged("the token presented is not one this realm accepts")
        }
        Err(Untold::Unreadable) => faulted(),
    }
}

/// What a form body may carry, RFC 6750 §2.2.
#[derive(Debug, Deserialize)]
pub struct Carried {
    pub access_token: Option<String>,
}

/// The header, or the form field RFC 6750 §2.2 also allows, and never both.
/// The query form is deliberately not read: a token in a URL lands in logs
/// and history.
fn presented(request: &HttpRequest, body: Option<&Carried>) -> Option<String> {
    match (
        basic::bearer(request),
        body.and_then(|form| form.access_token.clone()),
    ) {
        (Some(header), None) => Some(header),
        (None, Some(field)) if !field.is_empty() => Some(field),
        // Two tokens is one more than a request may carry: §2 forbids it, and
        // picking one would let the other ride along unexamined.
        _ => None,
    }
}

/// RFC 6750 §3: a bearer failure carries a challenge saying what was wrong with
/// the credential, and nothing about who holds one.
fn challenged(description: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::UNAUTHORIZED))
        .insert_header((
            "WWW-Authenticate",
            format!(r#"Bearer error="invalid_token", error_description="{description}""#),
        ))
        .json(json!({
            "error": "invalid_token",
            "error_description": description,
        }))
}

fn faulted() -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
    .json(json!({
        "error": "server_error",
        "error_description": "the realm could not be read",
    }))
}
