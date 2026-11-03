//! The authorization endpoint of a realm.

use actix_web::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::login::device::read_device_marks;
use saffui_core::login::session::SessionTicket;
use saffui_core::oidc::authorize::{
    Authorization, AuthorizationParameters, AuthorizationRefusal, begin_authorization,
};
use serde::Deserialize;

use crate::api::rest::endpoints::login::page::render_refusal;
use crate::extract::cookies::{
    is_served_over_tls, name_device_cookie, name_flow_cookie, name_session_cookie, read_cookie,
    write_cookie,
};
use crate::middleware::caller_address::read_caller_address;

/// How long the browser keeps the cookie of a pending sign-in: as long as
/// the request waits.
const FLOW_COOKIE_SECONDS: i64 = 600;

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    id_token_hint: Option<String>,
}

fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((LOCATION, location))
        .insert_header((CACHE_CONTROL, "no-store"))
        .finish()
}

#[get("/realms/{realm}/oauth2/authorize")]
pub async fn begin(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    query: web::Query<AuthorizeQuery>,
) -> HttpResponse {
    let secure = is_served_over_tls(&product);
    let ticket = read_cookie(&http, &name_session_cookie(&realm, secure))
        .and_then(|value| SessionTicket::parse(&value));
    let known_browsers = read_cookie(&http, &name_device_cookie(&realm, secure))
        .map(|value| read_device_marks(&value))
        .unwrap_or_default();
    let parameters = AuthorizationParameters {
        response_type: query.response_type.as_deref(),
        client_id: query.client_id.as_deref(),
        redirect_uri: query.redirect_uri.as_deref(),
        scope: query.scope.as_deref(),
        state: query.state.as_deref(),
        nonce: query.nonce.as_deref(),
        code_challenge: query.code_challenge.as_deref(),
        code_challenge_method: query.code_challenge_method.as_deref(),
        prompt: query.prompt.as_deref(),
        max_age: query.max_age.as_deref(),
        id_token_hint: query.id_token_hint.as_deref(),
        caller: read_caller_address(&product, &http),
        known_browsers: &known_browsers,
    };
    match begin_authorization(&product, &realm, parameters, ticket.as_ref()).await {
        // With a code or with an error, the browser goes back to a trusted address.
        Ok(Authorization::Granted { location })
        | Err(AuthorizationRefusal::Returned { location }) => redirect_to(&location),
        Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) => {
            let cookie = write_cookie(
                &name_flow_cookie(request, secure),
                &URL_SAFE_NO_PAD.encode(browser_secret.expose()),
                Some(FLOW_COOKIE_SECONDS),
                secure,
            );
            HttpResponse::SeeOther()
                .insert_header((LOCATION, format!("/realms/{realm}/login?request={request}")))
                .insert_header((CACHE_CONTROL, "no-store"))
                .insert_header((SET_COOKIE, cookie))
                .finish()
        }
        // Shown here and sent nowhere: the client or its address is not trusted.
        Err(AuthorizationRefusal::Shown(failure)) => render_refusal(&product, &failure),
    }
}
