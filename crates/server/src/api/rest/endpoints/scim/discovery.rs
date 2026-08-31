use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;

use super::{answered, base_of};

pub async fn service_provider_config(
    request: HttpRequest,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    answered(
        StatusCode::OK,
        services::scim::service_provider_config(&base),
    )
}

pub async fn resource_types(
    request: HttpRequest,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    answered(StatusCode::OK, services::scim::resource_types(&base))
}

pub async fn schemas(
    request: HttpRequest,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    answered(StatusCode::OK, services::scim::schemas(&base))
}
