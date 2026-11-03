//! The token endpoint of a realm.

use actix_web::http::header::{CACHE_CONTROL, PRAGMA};
use actix_web::{HttpRequest, HttpResponse, post, web};
use saffui_core::app::App as Product;
use saffui_core::error::ErrorCode;
use saffui_core::oidc::errors::OAuthFailure;
use saffui_core::oidc::token::{TokenRequest, grant_token};
use saffui_core::secret::Secret;
use serde::Deserialize;

use crate::error::render_protocol_failure;
use crate::extract::client_credentials::{Presented, read_basic_header};

/// The largest form the token endpoint reads, in bytes.
const TOKEN_FORM_LIMIT: usize = 8 * 1024;

// No `Debug`: the form carries a secret.
#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
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
    let basic = read_basic_header(&request);
    let asked_with_basic = !matches!(basic, Presented::Nothing);

    // One method per request: the header, or the form, never the two.
    let in_form = form.client_secret.is_some();
    let (client_id, client_secret) = match basic {
        Presented::Credentials(_) | Presented::Unusable if in_form => {
            return refuse(&ErrorCode::RequestInvalid.into(), asked_with_basic);
        }
        Presented::Unusable => {
            return refuse(
                &ErrorCode::ClientAuthenticationFailed.into(),
                asked_with_basic,
            );
        }
        Presented::Credentials(credentials) => {
            (Some(credentials.client_id), Some(credentials.secret))
        }
        Presented::Nothing => (
            form.client_id,
            form.client_secret
                .map(|secret| Secret::new(secret.into_bytes())),
        ),
    };

    let granted = grant_token(
        &product,
        &realm,
        TokenRequest {
            grant_type: form.grant_type.as_deref(),
            scope: form.scope.as_deref(),
            client_id: client_id.as_deref(),
            client_secret,
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
