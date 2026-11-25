use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{HttpResponse, delete, get, post, put, web};
use api::{CreatedClient, NewAuthMethod, NewClient, RotatedSecret};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::manage;
use saffui_core::clients::register::NewClient as WantedClient;
use saffui_core::clients::{AssertionAlgorithm, ClientAuthMethod};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::oidc::registration::end_registration_as_administrator;
use saffui_core::oidc::response::ResponseType;
use saffui_core::ports::crypto::SignatureAlgorithm;

use super::listing::{ListParameters, answer_page};
use super::views::show_client;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/clients",
    wrap = "RequireCapability(Capability::ClientRead)"
)]
pub async fn list_clients(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let listed = async {
        let (window, cut) = parameters.bound()?;
        let (clients, total) =
            manage::list_clients(&product, caller.scope, window, parameters.is_counted()).await?;
        Ok::<_, Failure>((window, cut, clients, total))
    }
    .await;
    match listed {
        Ok((window, cut, clients, total)) => answer_page(
            window,
            cut,
            clients.iter().map(show_client).collect(),
            total,
        ),
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/clients",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn create_client(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewClient>,
) -> HttpResponse {
    let created = async {
        let capabilities = wanted
            .capabilities
            .iter()
            .map(|name| Capability::parse(name).ok_or(Failure::new(ErrorCode::CapabilityUnknown)))
            .collect::<Result<Vec<_>, _>>()?;
        let id_token_algorithm = wanted
            .id_token_signed_response_alg
            .as_deref()
            .map(|name| {
                SignatureAlgorithm::parse(name).ok_or(Failure::new(ErrorCode::AlgorithmUnknown))
            })
            .transpose()?;
        let auth_method = wanted
            .token_endpoint_auth_method
            .as_deref()
            .map(|name| {
                ClientAuthMethod::parse(name).ok_or(Failure::new(ErrorCode::AuthMethodInvalid))
            })
            .transpose()?;
        let response_types = wanted
            .response_types
            .iter()
            .map(|named| {
                ResponseType::read(named).ok_or(Failure::new(ErrorCode::ResponseTypesInvalid))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let auth_signing_alg = wanted
            .token_endpoint_auth_signing_alg
            .as_deref()
            .map(|name| {
                AssertionAlgorithm::parse(name).ok_or(Failure::new(ErrorCode::AlgorithmUnknown))
            })
            .transpose()?;
        let client = WantedClient {
            client_id: &wanted.client_id,
            name: wanted.name.as_deref().unwrap_or(&wanted.client_id),
            scopes: &wanted.scopes,
            capabilities: &capabilities,
            redirect_uris: &wanted.redirect_uris,
            post_logout_redirect_uris: &wanted.post_logout_redirect_uris,
            response_types: &response_types,
            public: wanted.public,
            requires_consent: wanted.consent,
            id_token_signed_response_alg: id_token_algorithm,
            auth_method,
            jwks: wanted.jwks.as_ref(),
            jwks_uri: wanted.jwks_uri.as_deref(),
            auth_signing_alg,
            created_by: None,
        };
        manage::create_client(&product, &caller, client).await
    }
    .await;
    match created {
        Ok((client, secret)) => HttpResponse::Created()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(CreatedClient {
                client: show_client(&client),
                // The one showing of the secret: it is base64url text by construction.
                client_secret: secret
                    .map(|secret| String::from_utf8_lossy(secret.expose()).into_owned()),
            }),
        Err(failure) => render_failure(&failure),
    }
}

#[get(
    "/admin/v1/realms/{realm}/clients/{client_id}",
    wrap = "RequireCapability(Capability::ClientRead)"
)]
pub async fn read_client(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    match manage::find_client(&product, caller.scope, &client_id).await {
        Ok(client) => HttpResponse::Ok().json(show_client(&client)),
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/clients/{client_id}/secret",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn rotate_client_secret(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    match manage::rotate_client_secret(&product, &caller, &client_id).await {
        // The one showing of the new secret: it is base64url text by construction.
        Ok(secret) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(RotatedSecret {
                client_secret: String::from_utf8_lossy(secret.expose()).into_owned(),
            }),
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/clients/{client_id}/auth-method",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn change_client_auth_method(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    wanted: web::Json<NewAuthMethod>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    let changed = async {
        let method = ClientAuthMethod::parse(&wanted.token_endpoint_auth_method)
            .ok_or(Failure::new(ErrorCode::AuthMethodInvalid))?;
        manage::change_client_auth_method(&product, &caller, &client_id, method).await
    }
    .await;
    match changed {
        Ok(client) => HttpResponse::Ok().json(show_client(&client)),
        Err(failure) => render_failure(&failure),
    }
}

/// Ends the registration of a client that registered itself, as its own
/// token would: the client is disabled, and what it holds is taken back.
#[delete(
    "/admin/v1/realms/{realm}/clients/{client_id}/registration",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn end_registration(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    match end_registration_as_administrator(&product, &caller, &client_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
