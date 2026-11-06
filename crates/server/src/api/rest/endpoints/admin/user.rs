use actix_web::{HttpResponse, delete, get, post, put, web};
use api::NewUser;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::grants::{self, RoleHolder};
use saffui_core::directory::create::{NewPerson, create_person};
use saffui_core::directory::list::list_persons;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::enroll::{remove_security_keys, remove_totp, resume_codes};
use saffui_core::login::unlock::unlock_person;
use saffui_core::secret::Secret;

use super::group::{read_identifiers, read_terms};
use super::listing::{ListParameters, answer_page};
use super::views::{show_grant, show_held_role, show_user};
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/users",
    wrap = "RequireCapability(Capability::UserRead)"
)]
pub async fn list_users(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let listed = async {
        let (window, cut) = parameters.bound()?;
        let (persons, total) =
            list_persons(&product, caller.scope, window, parameters.is_counted()).await?;
        Ok::<_, Failure>((window, cut, persons, total))
    }
    .await;
    match listed {
        Ok((window, cut, persons, total)) => {
            answer_page(window, cut, persons.iter().map(show_user).collect(), total)
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/users",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn create_user(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewUser>,
) -> HttpResponse {
    let wanted = wanted.into_inner();
    let person = NewPerson {
        username: &wanted.username,
        email: wanted.email.as_deref(),
        display_name: wanted.display_name.as_deref(),
        password: wanted
            .password
            .map(|password| Secret::new(password.into_bytes())),
        created_by: Some(&caller.client.client_id),
    };
    match create_person(&product, caller.scope, person).await {
        Ok(person) => HttpResponse::Created().json(show_user(&person)),
        Err(failure) => render_failure(&failure),
    }
}

/// Gives back a name the brake locked. The name is in the path: it is the
/// one the person types.
#[post(
    "/admin/v1/realms/{realm}/users/{username}/unlock",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn unlock_user(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, username) = path.into_inner();
    match unlock_person(&product, caller.scope, &username, &caller.client.client_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

/// Takes the authenticator application of a person away: what a person who
/// lost their device asks an administrator for.
#[delete(
    "/admin/v1/realms/{realm}/users/{person}/authenticator",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn remove_authenticator(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, person) = path.into_inner();
    // What is not written as an identifier names nobody.
    let Ok(person) = uuid::Uuid::parse_str(&person) else {
        return render_failure(&Failure::new(ErrorCode::AuthenticatorNotFound));
    };
    match remove_totp(&product, &caller, person).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

/// Lets a person whose codes were suspended type them again.
#[delete(
    "/admin/v1/realms/{realm}/users/{person}/code-attempts",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn resume_person_codes(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, person) = path.into_inner();
    let Ok(person) = uuid::Uuid::parse_str(&person) else {
        return render_failure(&Failure::new(ErrorCode::PersonNotFound));
    };
    match resume_codes(&product, &caller, person).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

/// Takes every security key of a person away: what a person who lost a key
/// asks an administrator for.
#[delete(
    "/admin/v1/realms/{realm}/users/{person}/security-keys",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn remove_keys(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, person) = path.into_inner();
    // What is not written as an identifier names nobody.
    let Ok(person) = uuid::Uuid::parse_str(&person) else {
        return render_failure(&Failure::new(ErrorCode::SecurityKeyNotFound));
    };
    match remove_security_keys(&product, &caller, person).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

/// The roles a person holds now, and by which way.
#[get(
    "/admin/v1/realms/{realm}/users/{person}/roles",
    wrap = "RequireCapability(Capability::RoleRead)"
)]
pub async fn list_user_roles(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, person) = path.into_inner();
    let Ok(person) = uuid::Uuid::parse_str(&person) else {
        return render_failure(&Failure::new(ErrorCode::PersonNotFound));
    };
    match grants::list_held_roles(&product, caller.scope, person).await {
        Ok(held) => {
            let items: Vec<api::HeldRoleView> = held.iter().map(show_held_role).collect();
            HttpResponse::Ok().json(serde_json::json!({ "items": items }))
        }
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/users/{person}/roles/{role}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn grant_user_role(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
    terms: web::Json<api::GrantTerms>,
) -> HttpResponse {
    let (_realm, person, role) = path.into_inner();
    let read = read_identifiers(
        &person,
        &role,
        (ErrorCode::PersonNotFound, ErrorCode::RoleNotFound),
    )
    .and_then(|identified| Ok((identified, read_terms(&terms)?)));
    let ((person, role), terms) = match read {
        Ok(read) => read,
        Err(failure) => return render_failure(&failure),
    };
    match grants::grant_role(&product, &caller, role, RoleHolder::Person(person), terms).await {
        Ok(grant) => HttpResponse::Ok().json(show_grant(&grant)),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/users/{person}/roles/{role}",
    wrap = "RequireCapability(Capability::RoleWrite)"
)]
pub async fn revoke_user_role(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, person, role) = path.into_inner();
    let missing = (ErrorCode::RoleGrantNotFound, ErrorCode::RoleGrantNotFound);
    let (person, role) = match read_identifiers(&person, &role, missing) {
        Ok(identified) => identified,
        Err(failure) => return render_failure(&failure),
    };
    match grants::revoke_role(&product, &caller, role, RoleHolder::Person(person)).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
