//! The mappers of a client: what its tokens say beyond their scopes.

use actix_web::{HttpResponse, delete, get, post, web};
use api::NewMapper;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::claims::manage::{self, create_mapper};
use saffui_core::claims::{self, ClaimTarget, MapperKind};
use saffui_core::error::{ErrorCode, Failure};
use uuid::Uuid;

use super::views::show_mapper;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/clients/{client}/mappers",
    wrap = "RequireCapability(Capability::ClientRead)"
)]
pub async fn list_mappers(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    match manage::list_mappers(&product, caller.scope, &client_id).await {
        Ok(mappers) => {
            let items: Vec<api::MapperView> = mappers.iter().map(show_mapper).collect();
            HttpResponse::Ok().json(serde_json::json!({ "items": items }))
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/clients/{client}/mappers",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn add_mapper(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    wanted: web::Json<NewMapper>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    let wanted = wanted.into_inner();
    let invalid = || render_failure(&Failure::new(ErrorCode::MapperInvalid));
    let Ok(kind) = serde_json::from_value::<MapperKind>(wanted.definition) else {
        return invalid();
    };
    let Some(targets) = wanted
        .targets
        .iter()
        .map(|name| ClaimTarget::parse(name))
        .collect::<Option<Vec<_>>>()
    else {
        return invalid();
    };
    let new = claims::NewMapper {
        name: &wanted.name,
        kind,
        claim: wanted.claim.as_deref(),
        targets: &targets,
        scope: wanted.scope.as_deref(),
    };
    match create_mapper(&product, &caller, &client_id, new).await {
        Ok(created) => HttpResponse::Created().json(show_mapper(&created)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/clients/{client}/mappers/{mapper}",
    wrap = "RequireCapability(Capability::ClientWrite)"
)]
pub async fn remove_mapper(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, client_id, mapper_id) = path.into_inner();
    // What is not written as an identifier names nothing.
    let Ok(mapper_id) = Uuid::parse_str(&mapper_id) else {
        return render_failure(&Failure::new(ErrorCode::MapperNotFound));
    };
    match manage::delete_mapper(&product, &caller, &client_id, mapper_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
