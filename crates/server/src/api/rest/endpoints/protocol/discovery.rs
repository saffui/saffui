use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;
use crypto::provider::SignAlg;
use deadpool_postgres::Pool;
use models::entities::keys::{JweAlgorithm, JweEncryption};
use models::entities::realm::ClientRegistration;
use serde_json::{Value, json};
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::dto::uncached;

/// How a client may prove it is itself, §9. One list, because one sequence
/// establishes the caller at every endpoint that has one, and three lists
/// would be three chances to say something the server does not do.
const AUTHENTICATED: [&str; 5] = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none",
];

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
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
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
    let held = services::realm::named(&transaction, &context.realm_id)
        .await
        .ok()
        .flatten();
    let registers = held
        .as_ref()
        .is_some_and(|realm| realm.client_registration != ClientRegistration::Disabled);
    let pushes_first = held
        .as_ref()
        .is_some_and(|realm| realm.require_pushed_authorization_requests);
    let mapped = held
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

    // Two literals rather than one. `json!` expands once per field, and a
    // single document of everything this provider states had reached what
    // the compiler will expand; split, a field added later fits without
    // anybody raising a limit to make room.
    let mut document = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{protocol}/auth"),
            "token_endpoint": format!("{protocol}/token"),
            "backchannel_authentication_endpoint": format!("{protocol}/bc-authorize"),
            "backchannel_token_delivery_modes_supported": ["poll", "ping"],
            "backchannel_user_code_parameter_supported": true,
            "jwks_uri": format!("{protocol}/certs"),
            "userinfo_endpoint": format!("{protocol}/userinfo"),
            "end_session_endpoint": format!("{protocol}/logout"),
            // Session Management 1.0 §2.1: where a relying party loads the
            // frame it asks about this login with.
            "check_session_iframe": format!("{protocol}/check-session"),
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
            "response_types_supported": [
                "code",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token",
            ],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "urn:openid:params:grant-type:ciba",
                "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": algorithms,
            "token_endpoint_auth_methods_supported": AUTHENTICATED,
            // What an assertion may be signed with. The shared-secret method
            // takes the HMAC family and the key method the rest, so the union
            // is what a client may register.
            "token_endpoint_auth_signing_alg_values_supported": [
                "HS256", "HS384", "HS512",
                "RS256", "RS384", "RS512",
                "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512",
                "EdDSA",
            ],
            // Introspection turns a stolen token into its claims, so never for
            // a client that keeps no secret; a revocation is a client's own to
            // ask, secret or not.
            // Everything but `none`: §2.1 of RFC 7662 has this endpoint tell
            // a caller about somebody else's token, so a caller that proved
            // nothing is refused rather than answered.
            "introspection_endpoint_auth_methods_supported": AUTHENTICATED
                .iter()
                .filter(|named| **named != "none")
                .collect::<Vec<_>>(),
            "revocation_endpoint_auth_methods_supported": AUTHENTICATED,
            // S256 and nothing else. `plain` compares the verifier against a
            // challenge that travelled in the authorize request, and the
            // endpoint refuses it, so advertising it would be a lie a client
            // acts on.
    });
    let rest = json!({
            "code_challenge_methods_supported": ["S256"],
            // From the set a realm is provisioned with, so a scope added
            // there is advertised and one never added is not.
            "scopes_supported": std::iter::once("openid")
                .chain(
                    services::provisioning::STANDARD_SCOPES
                        .iter()
                        .map(|(named, _, _)| *named),
                )
                .collect::<Vec<_>>(),
            "claims_supported": claims_named(!contexts.is_empty()),
            "acr_values_supported": contexts,
            // OIDC Core §6.1 is supported and §6.2 is not: an object a client
            // signs and sends is read, one this server would have to fetch is
            // refused. What a reference may name is therefore only what RFC
            // 9126 pushed here, never a URL.
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            // §6.2 leaves this optional. Required here: an endpoint that
            // fetches whatever a request names is a way to make this server
            // issue requests on somebody else's behalf.
            "require_request_uri_registration": true,
            // §5.3.2: what a client may register to be answered with, which
            // is every algorithm this build signs at.
            "userinfo_signing_alg_values_supported": SignAlg::ALL
                .iter()
                .map(|algorithm| algorithm.name())
                .collect::<Vec<_>>(),
            // §2 of the registration spec: what a client may register to be
            // encrypted to. Asymmetric only, because the key is one the client
            // published: a shared-secret family has no key here to use.
            //
            // The request object is among them too: that one travels the other
            // way, and the key to encrypt it to is in this realm's key set,
            // published under `use: "enc"`.
            "id_token_encryption_alg_values_supported": encryption_algorithms(),
            "id_token_encryption_enc_values_supported": encryption_methods(),
            "userinfo_encryption_alg_values_supported": encryption_algorithms(),
            "userinfo_encryption_enc_values_supported": encryption_methods(),
            // RFC 9449 §5.1: advertised so a client knows the mechanism is
            // here at all, and at which algorithms a proof will be read.
            "dpop_signing_alg_values_supported": services::dpop::SIGNING_ALGORITHMS,
            "request_object_encryption_alg_values_supported": encryption_algorithms(),
            "request_object_encryption_enc_values_supported": encryption_methods(),
            "request_object_signing_alg_values_supported": SignAlg::ALL
                .iter()
                .map(|algorithm| algorithm.name())
                .collect::<Vec<_>>(),
            "pushed_authorization_request_endpoint": format!("{protocol}/par"),
            "require_pushed_authorization_requests": pushes_first,
            "claims_parameter_supported": true,
            "authorization_response_iss_parameter_supported": true,
    });
    let named = document.as_object_mut().expect("a json object");
    named.extend(
        rest.as_object()
            .expect("a json object")
            .iter()
            .map(|(field, value)| (field.clone(), value.clone())),
    );
    // Named only where a realm answers it. A client sent to an endpoint that
    // is not there reports the realm as broken rather than as closed.
    if registers {
        document.as_object_mut().expect("a json object").insert(
            "registration_endpoint".to_owned(),
            Value::from(format!("{protocol}/register")),
        );
    }

    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Cache-Control", "public, max-age=300"))
        .json(document)
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

fn encryption_algorithms() -> Vec<&'static str> {
    JweAlgorithm::ALL
        .iter()
        .map(|algorithm| algorithm.as_str())
        .collect()
}

fn encryption_methods() -> Vec<&'static str> {
    JweEncryption::ALL
        .iter()
        .map(|method| method.as_str())
        .collect()
}
