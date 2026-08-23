//! What a client reads to configure itself.
//!
//! Everything here is derived rather than written down. A document that names an
//! endpoint this build does not mount, or an algorithm the signer would refuse,
//! configures every client wrong at once and does it silently.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;
use crypto::provider::SignAlg;
use deadpool_postgres::Pool;
use models::entities::keys::KeyUse;
use serde_json::{Value, json};
use store::providers::{realm_keys, realms};
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::dto::uncached;

/// The realm's metadata, OpenID Connect Discovery §3.
pub async fn published(
    realm: web::Path<String>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let Ok(mut connection) = pool.get().await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused(StatusCode::NOT_FOUND);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(keys) = realm_keys::published(&transaction, KeyUse::Sig).await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // From the keys this realm actually holds, not from the build's catalogue. A
    // realm holding one EC key advertising RS256 sends every client that reads
    // it to a signature it will never see.
    let mut algorithms: Vec<String> = keys
        .iter()
        .filter_map(|key| match serde_json::to_value(key.algorithm) {
            Ok(Value::String(named)) => Some(named),
            _ => None,
        })
        .collect();
    algorithms.sort_unstable();
    algorithms.dedup();

    // What the realm calls its authentication levels, weakest first. A realm
    // mapping nothing omits this and the `acr` claim with it: an empty list
    // claims the server supports no authentication contexts at all.
    let mapped = realms::load(&transaction, &context.realm_id)
        .await
        .ok()
        .flatten()
        .and_then(|realm| realm.acr_loa_map)
        .filter(|map| !map.is_empty());
    let contexts: Vec<String> = mapped
        .as_ref()
        .map(|map| {
            map.values_by_level()
                .into_iter()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let issuer = origin.issuer(&context.realm_id);
    let protocol = format!("{issuer}/protocol/openid-connect");

    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Cache-Control", "public, max-age=300"))
        .json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{protocol}/auth"),
            "token_endpoint": format!("{protocol}/token"),
            "jwks_uri": format!("{protocol}/certs"),
            "userinfo_endpoint": format!("{protocol}/userinfo"),
            "end_session_endpoint": format!("{protocol}/logout"),
            "introspection_endpoint": format!("{protocol}/introspect"),
            "revocation_endpoint": format!("{protocol}/revoke"),
            "frontchannel_logout_supported": true,
            "frontchannel_logout_session_supported": true,
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            // Only what is mounted. `revocation_endpoint` and
            // `introspection_endpoint` are absent because they are, and naming
            // one would send a client to a 404 it reports as this realm being
            // broken.
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": algorithms,
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            // Introspection turns a stolen token into its claims, so never for
            // a client that keeps no secret; a revocation is a client's own to
            // ask, secret or not.
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            // S256 and nothing else. `plain` compares the verifier against a
            // challenge that travelled in the authorize request, and the
            // endpoint refuses it, so advertising it would be a lie a client
            // acts on.
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "phone",
                "address",
                "offline_access",
            ],
            "claims_supported": claims_named(!contexts.is_empty()),
            "acr_values_supported": contexts,
            // OIDC Core §6.1 is supported and §6.2 is not: an object a client
            // signs and sends is read, one this server would have to fetch is
            // refused. What a reference may name is therefore only what RFC
            // 9126 pushed here, never a URL.
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "require_request_uri_registration": false,
            "request_object_signing_alg_values_supported": SignAlg::ALL
                .iter()
                .map(|algorithm| algorithm.name())
                .collect::<Vec<_>>(),
            "pushed_authorization_request_endpoint": format!("{protocol}/par"),
            "require_pushed_authorization_requests": false,
            "claims_parameter_supported": true,
            "authorization_response_iss_parameter_supported": false,
        }))
}

/// What a token here may carry. `acr` only when the realm maps something, since
/// a claim advertised and never emitted is one a client waits for.
fn claims_named(maps_contexts: bool) -> Vec<&'static str> {
    let mut named = vec![
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "jti",
        "azp",
        "sid",
        "auth_time",
        "nonce",
        "preferred_username",
        "email",
        "email_verified",
        "phone_number",
        "phone_number_verified",
        "address",
    ];
    if maps_contexts {
        named.push("acr");
    }
    named
}

fn refused(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).json(json!({
        "error": "server_error",
        "error_description": "no metadata is published here",
    }))
}
