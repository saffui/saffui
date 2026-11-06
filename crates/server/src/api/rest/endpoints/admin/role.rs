//! The roles of a realm and of its clients.

use actix_web::{HttpResponse, delete, get, post, web};
use api::NewRole;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::roles;
use saffui_core::error::{ErrorCode, Failure};
use uuid::Uuid;

use super::listing::{ListParameters, answer_page};
use super::views::show_role;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/roles",
    wrap = "RequireCapability(Capability::RoleRead)"
)]
pub async fn list_roles(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let (window, cut) = match parameters.bound() {
        Ok(bounded) => bounded,
        Err(failure) => return render_failure(&failure),
    };
    match roles::list_roles(&product, caller.scope, window, parameters.is_counted()).await {
        Ok((listed, total)) => {
            answer_page(window, cut, listed.iter().map(show_role).collect(), total)
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/roles",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn create_role(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewRole>,
) -> HttpResponse {
    let wanted = roles::NewRole {
        name: &wanted.name,
        client_id: wanted.client_id.as_deref(),
        description: wanted.description.as_deref(),
    };
    match roles::create_role(&product, &caller, wanted).await {
        Ok(role) => HttpResponse::Created().json(show_role(&role)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/roles/{role}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn delete_role(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, role) = path.into_inner();
    // What is not written as an identifier names nothing.
    let Ok(role) = Uuid::parse_str(&role) else {
        return render_failure(&Failure::new(ErrorCode::RoleNotFound));
    };
    match roles::delete_role(&product, &caller, role).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
