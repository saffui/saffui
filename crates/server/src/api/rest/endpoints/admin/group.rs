//! The groups of a realm: the roles they carry, and their members.

use actix_web::{HttpResponse, delete, get, post, put, web};
use api::NewGroup;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::grants::{self, GrantTerms, RoleHolder};
use saffui_core::authz::roles;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::instant::read_instant;
use uuid::Uuid;

use super::listing::{ListParameters, answer_page};
use super::views::{show_grant, show_group};
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

/// Reads the terms of a grant as the API writes them.
pub(super) fn read_terms(terms: &api::GrantTerms) -> Result<GrantTerms<'_>, Failure> {
    let read = |text: Option<&String>| match text {
        None => Ok(None),
        Some(text) => read_instant(text)
            .map(Some)
            .ok_or_else(|| Failure::new(ErrorCode::GrantPeriodInvalid)),
    };
    Ok(GrantTerms {
        valid_from: read(terms.valid_from.as_ref())?,
        valid_until: read(terms.valid_until.as_ref())?,
        reason: terms.reason.as_deref(),
    })
}

/// Reads two identifiers of a path. What is not written as one names
/// nothing, and is refused as the first that is not.
pub(super) fn read_identifiers(
    first: &str,
    second: &str,
    missing: (ErrorCode, ErrorCode),
) -> Result<(Uuid, Uuid), Failure> {
    let first = Uuid::parse_str(first).map_err(|_| Failure::new(missing.0))?;
    let second = Uuid::parse_str(second).map_err(|_| Failure::new(missing.1))?;
    Ok((first, second))
}

#[get(
    "/admin/v1/realms/{realm}/groups",
    wrap = "RequireCapability(Capability::RoleRead)"
)]
pub async fn list_groups(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let (window, cut) = match parameters.bound() {
        Ok(bounded) => bounded,
        Err(failure) => return render_failure(&failure),
    };
    match roles::list_groups(&product, caller.scope, window, parameters.is_counted()).await {
        Ok((listed, total)) => {
            answer_page(window, cut, listed.iter().map(show_group).collect(), total)
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/groups",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn create_group(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewGroup>,
) -> HttpResponse {
    let wanted = roles::NewGroup {
        name: &wanted.name,
        description: wanted.description.as_deref(),
    };
    match roles::create_group(&product, &caller, wanted).await {
        Ok(group) => HttpResponse::Created().json(show_group(&group)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/groups/{group}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn delete_group(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, group) = path.into_inner();
    let Ok(group) = Uuid::parse_str(&group) else {
        return render_failure(&Failure::new(ErrorCode::GroupNotFound));
    };
    match roles::delete_group(&product, &caller, group).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/groups/{group}/roles/{role}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn grant_group_role(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
    terms: web::Json<api::GrantTerms>,
) -> HttpResponse {
    let (_realm, group, role) = path.into_inner();
    let read = read_identifiers(
        &group,
        &role,
        (ErrorCode::GroupNotFound, ErrorCode::RoleNotFound),
    )
    .and_then(|identified| Ok((identified, read_terms(&terms)?)));
    let ((group, role), terms) = match read {
        Ok(read) => read,
        Err(failure) => return render_failure(&failure),
    };
    match grants::grant_role(&product, &caller, role, RoleHolder::Group(group), terms).await {
        Ok(grant) => HttpResponse::Ok().json(show_grant(&grant)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/groups/{group}/roles/{role}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn revoke_group_role(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, group, role) = path.into_inner();
    let missing = (ErrorCode::RoleGrantNotFound, ErrorCode::RoleGrantNotFound);
    let (group, role) = match read_identifiers(&group, &role, missing) {
        Ok(identified) => identified,
        Err(failure) => return render_failure(&failure),
    };
    match grants::revoke_role(&product, &caller, role, RoleHolder::Group(group)).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/groups/{group}/members/{person}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn add_group_member(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
    terms: web::Json<api::GrantTerms>,
) -> HttpResponse {
    let (_realm, group, person) = path.into_inner();
    let read = read_identifiers(
        &group,
        &person,
        (ErrorCode::GroupNotFound, ErrorCode::PersonNotFound),
    )
    .and_then(|identified| Ok((identified, read_terms(&terms)?)));
    let ((group, person), terms) = match read {
        Ok(read) => read,
        Err(failure) => return render_failure(&failure),
    };
    match grants::add_member(&product, &caller, group, person, terms).await {
        Ok(grant) => HttpResponse::Ok().json(show_grant(&grant)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/groups/{group}/members/{person}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn remove_group_member(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, group, person) = path.into_inner();
    let missing = (ErrorCode::MembershipNotFound, ErrorCode::MembershipNotFound);
    let (group, person) = match read_identifiers(&group, &person, missing) {
        Ok(identified) => identified,
        Err(failure) => return render_failure(&failure),
    };
    match grants::remove_member(&product, &caller, group, person).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
