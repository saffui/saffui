//! The token endpoint of a realm.

use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{HttpRequest, HttpResponse, post, web};
use saffui_core::app::App as Product;
use saffui_core::error::ErrorCode;
use saffui_core::oidc::errors::OAuthFailure;
use saffui_core::oidc::token::{TokenRequest, grant_token};
use serde::Deserialize;

use crate::error::render_protocol_failure;
use crate::extract::client_credentials::{UnreadableIdentity, read_client_identity};

/// The largest form the token endpoint reads, in bytes.
const TOKEN_FORM_LIMIT: usize = 8 * 1024;

// No `Debug`: the form carries a secret.
#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// The limit of the form, and a refusal in the dialect of the protocol for a
/// form that is too large, malformed, or that repeats a parameter.
pub(crate) fn limit_form() -> web::FormConfig {
    web::FormConfig::default()
        .limit(TOKEN_FORM_LIMIT)
        .error_handler(|error, _request| {
            let refusal = render_protocol_failure(&ErrorCode::RequestInvalid.into(), false);
            actix_web::error::InternalError::from_response(error, refusal).into()
        })
}

#[post("/realms/{realm}/oauth2/token")]
pub async fn grant(
    product: web::Data<Product>,
    realm: web::Path<String>,
    request: HttpRequest,
    form: web::Form<TokenForm>,
) -> HttpResponse {
    let form = form.into_inner();
    let identity = match read_client_identity(&request, form.client_id, form.client_secret) {
        Ok(identity) => identity,
        Err(unreadable) => return refuse_unreadable_identity(&unreadable),
    };
    let asked_with_basic = identity.asked_with_basic;

    let granted = grant_token(
        &product,
        &realm,
        TokenRequest {
            grant_type: form.grant_type.as_deref(),
            scope: form.scope.as_deref(),
            client_id: identity.client_id.as_deref(),
            client_secret: identity.secret,
            code: form.code.as_deref(),
            redirect_uri: form.redirect_uri.as_deref(),
            code_verifier: form.code_verifier.as_deref(),
            refresh_token: form.refresh_token.as_deref(),
        },
    )
    .await;
    match granted {
        Ok(response) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .insert_header((PRAGMA, "no-cache"))
            .json(response),
        Err(failure) => refuse(&failure, asked_with_basic),
    }
}

fn refuse(failure: &OAuthFailure, asked_with_basic: bool) -> HttpResponse {
    render_protocol_failure(failure, asked_with_basic)
}

/// Refuses credentials that cannot be read, in the dialect of the protocol.
pub(crate) fn refuse_unreadable_identity(unreadable: &UnreadableIdentity) -> HttpResponse {
    match unreadable {
        UnreadableIdentity::TwoMethods => refuse(&ErrorCode::RequestInvalid.into(), true),
        UnreadableIdentity::UnusableHeader => {
            refuse(&ErrorCode::ClientAuthenticationFailed.into(), true)
        }
    }
}
