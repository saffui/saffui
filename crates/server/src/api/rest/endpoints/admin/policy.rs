//! The policies of a client that guards resources.

use actix_web::{HttpResponse, delete, get, post, web};
use api::NewPolicy;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::policy::{self, Combine, Effect};
use saffui_core::error::{ErrorCode, Failure};
use uuid::Uuid;

use super::views::show_policy;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/clients/{client}/policies",
    wrap = "RequireCapability(Capability::PolicyRead)"
)]
pub async fn list_policies(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    match policy::list_policies(&product, caller.scope, &client_id).await {
        Ok(policies) => {
            let items: Vec<api::PolicyView> = policies.iter().map(show_policy).collect();
            HttpResponse::Ok().json(serde_json::json!({ "items": items }))
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/clients/{client}/policies",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn create_policy(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
    wanted: web::Json<NewPolicy>,
) -> HttpResponse {
    let (_realm, client_id) = path.into_inner();
    let invalid = || render_failure(&Failure::new(ErrorCode::PolicyInvalid));
    let Some(effect) = Effect::parse(&wanted.effect) else {
        return invalid();
    };
    let Some(combine) = Combine::parse(wanted.combine.as_deref().unwrap_or("all")) else {
        return invalid();
    };
    let new = policy::NewPolicy {
        client_id: &client_id,
        name: &wanted.name,
        resource_type: &wanted.resource_type,
        action: &wanted.action,
        effect,
        combine,
        conditions: &wanted.conditions,
    };
    match policy::create_policy(&product, &caller, new).await {
        Ok(created) => HttpResponse::Created().json(show_policy(&created)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/clients/{client}/policies/{policy}",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn delete_policy(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, client_id, policy_id) = path.into_inner();
    // What is not written as an identifier names nothing.
    let Ok(policy_id) = Uuid::parse_str(&policy_id) else {
        return render_failure(&Failure::new(ErrorCode::PolicyNotFound));
    };
    match policy::delete_policy(&product, &caller, &client_id, policy_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
