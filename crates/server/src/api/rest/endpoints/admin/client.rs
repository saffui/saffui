use actix_web::{HttpResponse, get, post, web};
use api::{CreatedClient, NewClient};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::manage;
use saffui_core::clients::register::NewClient as WantedClient;
use saffui_core::error::{ErrorCode, Failure};

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
        let client = WantedClient {
            client_id: &wanted.client_id,
            name: wanted.name.as_deref().unwrap_or(&wanted.client_id),
            scopes: &wanted.scopes,
            capabilities: &capabilities,
            redirect_uris: &wanted.redirect_uris,
            post_logout_redirect_uris: &wanted.post_logout_redirect_uris,
            public: wanted.public,
            requires_consent: wanted.consent,
            created_by: None,
        };
        manage::create_client(&product, &caller, client).await
    }
    .await;
    match created {
        Ok((client, secret)) => HttpResponse::Created().json(CreatedClient {
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
