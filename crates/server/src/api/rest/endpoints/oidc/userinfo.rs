//! The userinfo endpoint. Its refusals are told in the challenge of the
//! Bearer scheme (RFC 6750), which is where a resource server tells them.

use actix_web::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use actix_web::{HttpRequest, HttpResponse, route, web};
use saffui_core::app::App as Product;
use saffui_core::error::ErrorCode;
use saffui_core::oidc::userinfo::read_user_info;

use crate::error::render_failure;
use crate::extract::bearer::read_bearer_token;

#[route("/realms/{realm}/oauth2/userinfo", method = "GET", method = "POST")]
pub async fn read(
    product: web::Data<Product>,
    realm: web::Path<String>,
    request: HttpRequest,
) -> HttpResponse {
    // A request that presents nothing is challenged, and told nothing else.
    let Some(token) = read_bearer_token(&request) else {
        return HttpResponse::Unauthorized()
            .insert_header((WWW_AUTHENTICATE, "Bearer"))
            .finish();
    };
    match read_user_info(&product, &realm, &token).await {
        Ok(told) => HttpResponse::Ok()
            .insert_header((CACHE_CONTROL, "no-store"))
            .json(told),
        Err(failure) if failure.code == ErrorCode::TokenInvalid => HttpResponse::Unauthorized()
            .insert_header((WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""))
            .finish(),
        Err(failure) if failure.code == ErrorCode::TokenScopeInsufficient => {
            HttpResponse::Forbidden()
                .insert_header((
                    WWW_AUTHENTICATE,
                    "Bearer error=\"insufficient_scope\", scope=\"openid\"",
                ))
                .finish()
        }
        Err(failure) => render_failure(&failure),
    }
}
