//! The settings of a realm, and the initial access tokens that let clients
//! register themselves when the realm asks for one.

use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{HttpResponse, delete, get, post, put, web};
use api::{CreatedInitialToken, InitialTokenView, NewInitialToken, NewRealmSettings};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::registration::{
    create_initial_access_token, delete_initial_access_token, list_initial_access_tokens,
};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::tenancy::settings::{
    RegistrationPolicy, WantedSettings, change_realm_settings, read_realm_settings,
};
use uuid::Uuid;

use super::listing::{ListParameters, answer_page};
use super::views::{show_initial_token, show_realm_settings};
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/settings",
    wrap = "RequireCapability(Capability::RealmRead)"
)]
pub async fn read_settings(caller: Caller, product: web::Data<Product>) -> HttpResponse {
    match read_realm_settings(&product, &caller).await {
        Ok(settings) => HttpResponse::Ok().json(show_realm_settings(&settings)),
        Err(failure) => render_failure(&failure),
    }
}

/// Writes the settings of registration whole: what is left out takes its
/// default, so that what is kept is what was sent.
#[put(
    "/admin/v1/realms/{realm}/settings/registration",
    wrap = "RequireCapability(Capability::RealmWrite)"
)]
pub async fn write_registration_settings(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewRealmSettings>,
) -> HttpResponse {
    let wanted = wanted.into_inner();
    let Some(registration) = RegistrationPolicy::parse(&wanted.registration) else {
        return render_failure(&Failure::new(ErrorCode::RealmSettingsInvalid));
    };
    let settings = WantedSettings {
        registration,
        registrable_scopes: wanted.registrable_scopes,
        max_registered_clients: wanted.max_registered_clients,
        max_redirect_uris: wanted.max_redirect_uris,
        max_daily_registrations: wanted.max_daily_registrations,
    };
    match change_realm_settings(&product, &caller, settings).await {
        Ok(settings) => HttpResponse::Ok().json(show_realm_settings(&settings)),
        Err(failure) => render_failure(&failure),
    }
}

#[get(
    "/admin/v1/realms/{realm}/initial-access-tokens",
    wrap = "RequireCapability(Capability::RealmWrite)"
)]
pub async fn list_initial_tokens(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let listed = async {
        let (window, cut) = parameters.bound()?;
        let tokens = list_initial_access_tokens(&product, &caller, window).await?;
        Ok::<_, Failure>((window, cut, tokens))
    }
    .await;
    match listed {
        Ok((window, cut, tokens)) => answer_page(
            window,
            cut,
            tokens
                .iter()
                .map(show_initial_token)
                .collect::<Vec<InitialTokenView>>(),
            None,
        ),
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/initial-access-tokens",
    wrap = "RequireCapability(Capability::RealmWrite)"
)]
pub async fn create_initial_token(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewInitialToken>,
) -> HttpResponse {
    match create_initial_access_token(&product, &caller, wanted.uses, wanted.expires_in).await {
        // The one showing of the token: it is base64url text by construction.
        Ok((made, token)) => HttpResponse::Created()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(CreatedInitialToken {
                view: show_initial_token(&made),
                initial_access_token: String::from_utf8_lossy(token.expose()).into_owned(),
            }),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/initial-access-tokens/{token}",
    wrap = "RequireCapability(Capability::RealmWrite)"
)]
pub async fn delete_initial_token(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, token) = path.into_inner();
    let Ok(token) = Uuid::parse_str(&token) else {
        return render_failure(&Failure::new(ErrorCode::InitialTokenNotFound));
    };
    match delete_initial_access_token(&product, &caller, token).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
