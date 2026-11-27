//! The authorization endpoint of a realm.

use actix_web::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::device::read_device_marks;
use saffui_core::login::session::SessionTicket;
use saffui_core::oidc::authorize::{
    Authorization, AuthorizationParameters, AuthorizationRefusal, begin_authorization,
    write_authorization_query,
};
use saffui_core::secret::Secret;
use serde::Deserialize;
use uuid::Uuid;

use super::answer::send_answer_to_client;
use crate::api::rest::endpoints::login::page::{is_realm_label, render_refusal};
use crate::extract::cookies::{
    is_served_over_tls, name_device_cookie, name_flow_cookie, name_session_cookie, read_cookie,
    write_cookie,
};
use crate::middleware::caller_address::read_caller_address;

/// How long the browser keeps the cookie of a pending sign-in: as long as
/// the request waits.
const FLOW_COOKIE_SECONDS: i64 = 600;

/// What a request to the authorization endpoint carries, in a query or in a
/// form. A parameter named twice is refused; one not named here is passed over.
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
    response_mode: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    id_token_hint: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    claims: Option<String>,
}

impl AuthorizeQuery {
    /// Every parameter named, with no caller and no browser: those are read
    /// from the request that comes with the cookies.
    fn read_parameters(&self) -> AuthorizationParameters<'_> {
        AuthorizationParameters {
            response_type: self.response_type.as_deref(),
            client_id: self.client_id.as_deref(),
            redirect_uri: self.redirect_uri.as_deref(),
            scope: self.scope.as_deref(),
            state: self.state.as_deref(),
            nonce: self.nonce.as_deref(),
            code_challenge: self.code_challenge.as_deref(),
            code_challenge_method: self.code_challenge_method.as_deref(),
            response_mode: self.response_mode.as_deref(),
            prompt: self.prompt.as_deref(),
            max_age: self.max_age.as_deref(),
            id_token_hint: self.id_token_hint.as_deref(),
            request: self.request.as_deref(),
            request_uri: self.request_uri.as_deref(),
            claims: self.claims.as_deref(),
            caller: None,
            known_browsers: &[],
        }
    }
}

/// Sends the browser to a hosted page of the realm, `login` or `consent`,
/// with the cookie that binds the request to it.
fn send_to_page(
    realm: &str,
    page: &str,
    request: Uuid,
    browser_secret: &Secret,
    secure: bool,
) -> HttpResponse {
    let cookie = write_cookie(
        &name_flow_cookie(request, secure),
        &URL_SAFE_NO_PAD.encode(browser_secret.expose()),
        Some(FLOW_COOKIE_SECONDS),
        secure,
    );
    HttpResponse::SeeOther()
        .insert_header((
            LOCATION,
            format!("/realms/{realm}/{page}?request={request}"),
        ))
        .insert_header((CACHE_CONTROL, "no-store"))
        .insert_header((SET_COOKIE, cookie))
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
        caller: read_caller_address(&product, &http),
        known_browsers: &known_browsers,
        ..query.read_parameters()
    };
    match begin_authorization(&product, &realm, parameters, ticket.as_ref()).await {
        // With what it asked for or with an error, the browser goes back to
        // a trusted address, as the request asked.
        Ok(Authorization::Granted { response })
        | Err(AuthorizationRefusal::Returned { response }) => {
            send_answer_to_client(&product, HttpResponse::SeeOther(), &response)
        }
        Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) => send_to_page(&realm, "login", request, &browser_secret, secure),
        Ok(Authorization::ConsentRequired {
            request,
            browser_secret,
        }) => send_to_page(&realm, "consent", request, &browser_secret, secure),
        // Shown here and sent nowhere: the client or its address is not trusted.
        Err(AuthorizationRefusal::Shown(failure)) => render_refusal(&product, &failure),
    }
}

/// A request posted to the authorization endpoint, which it must take
/// (OpenID Connect Core 1.0, section 3.1.2.1), carried on to it in the
/// browser: the cookies of the person come with a navigation of its own,
/// never with a post another site makes. No cookie and no client is read,
/// nothing is kept, and the browser goes nowhere but the endpoint.
#[post("/realms/{realm}/oauth2/authorize")]
pub async fn relay_posted_authorization(
    product: web::Data<Product>,
    realm: web::Path<String>,
    form: web::Form<AuthorizeQuery>,
) -> HttpResponse {
    if !is_realm_label(&realm) {
        return render_refusal(&product, &Failure::new(ErrorCode::RealmNotFound));
    }
    let query = write_authorization_query(&form.read_parameters());
    HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/realms/{realm}/oauth2/authorize{query}")))
        .insert_header((CACHE_CONTROL, "no-store"))
        .finish()
}
