//! Where a browser ends its login.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use models::entities::keys::KeyUse;
use serde::Deserialize;
use serde_json::json;
use services::logout::{self, EndedAt, Requested};
use store::providers::realm_keys;
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::binding;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// What the query carries. Every parameter is optional: RP-Initiated Logout §2
/// makes `id_token_hint` recommended and the rest optional, and a logout with
/// none of them is still a logout.
#[derive(Debug, Deserialize)]
pub struct Asked {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub state: Option<String>,
}

/// End the login.
///
/// Both verbs. §2 allows either, and a browser arriving by link uses one while a
/// form posting a hint too long for a URL uses the other.
pub async fn end(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Query<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let now = Utc::now();
    let asked = asked.map(web::Query::into_inner).unwrap_or(Asked {
        id_token_hint: None,
        post_logout_redirect_uri: None,
        client_id: None,
        state: None,
    });

    let Ok(mut connection) = pool.get().await else {
        return done(&realm, None);
    };
    // An unknown realm ends nothing and says so the same way. Which realms exist
    // is not a question this endpoint answers, and everyone links to it.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return done(&realm, None);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return done(&context.realm_id, None);
    };
    let Ok(keys) = realm_keys::published(&transaction, KeyUse::Sig).await else {
        return done(&context.realm_id, None);
    };

    let ended = logout::end_session(
        &transaction,
        &keys,
        &Requested {
            id_token_hint: asked.id_token_hint.as_deref(),
            post_logout_redirect_uri: asked.post_logout_redirect_uri.as_deref(),
            client_id: asked.client_id.as_deref(),
            state: asked.state.as_deref(),
        },
        binding::read(&request, binding::SSO_SESSION).as_deref(),
        now,
    )
    .await;

    // The cookie goes whether or not a row moved. A browser that keeps offering
    // a login the server has ended is a browser that looks signed in.
    if transaction.commit().await.is_err() {
        return done(&context.realm_id, None);
    }
    match ended {
        EndedAt::Nowhere => done(&context.realm_id, None),
        EndedAt::Redirect(landing) => done(&context.realm_id, Some(&landing)),
    }
}

/// One answer for every way of getting here, so nothing about whose login
/// existed is readable from the shape of the reply.
fn done(realm_id: &str, landing: Option<&str>) -> HttpResponse {
    let mut response = HttpResponseBuilder::new(match landing {
        Some(_) => StatusCode::FOUND,
        None => StatusCode::OK,
    });
    binding::clear(&mut response, binding::SSO_SESSION, realm_id);
    binding::clear(&mut response, binding::AUTH_SESSION, realm_id);
    match landing {
        Some(landing) => uncached(&mut response)
            .insert_header(("Location", landing))
            .finish(),
        None => uncached(&mut response).json(json!({ "status": "logged-out" })),
    }
}
