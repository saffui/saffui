use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use secrecy::SecretBox;
use services::admin::users::{self as people, Spec, Uncreatable};
use store::query::list_query::{ListQuery, SortDirection};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::admin::dto::{PasswordSpec, UserBrief, UserSpec};
use crate::middleware::admin_guard::Admin;

pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    paging: web::Query<PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let query = ListQuery::new(window).sorted_by("user_name", SortDirection::Ascending);
    let found = people::list(&transaction, &query, paging.count.unwrap_or(false))
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(models::paging::Page {
        items: found
            .items
            .into_iter()
            .map(UserBrief::from)
            .collect::<Vec<_>>(),
        first: found.first,
        max: found.max,
        total: found.total,
    }))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found = people::get(&transaction, &user_id).await.map_err(refused)?;
    // The single read carries what the listing keeps to itself: the whole
    // attribute bag, and which identity providers this account is bound to.
    let attributes = found.attributes.clone();
    let links = store::providers::brokering::links_of(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    let mut answer = serde_json::to_value(UserBrief::from(found)).map_err(|_| internal())?;
    if let Some(held) = answer.as_object_mut() {
        held.insert(
            "attributes".to_owned(),
            serde_json::to_value(attributes).map_err(|_| internal())?,
        );
        held.insert(
            "identity_providers".to_owned(),
            serde_json::to_value(links).map_err(|_| internal())?,
        );
    }
    Ok(HttpResponse::Ok().json(answer))
}

/// Create a person, with what they first sign in with when it was given.
pub async fn create(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<UserSpec>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let user_name = asked
        .user_name
        .clone()
        .filter(|named| !named.is_empty())
        .ok_or_else(|| {
            ApiError::with_detail(ErrorCode::ValidationError, "user_name is required")
        })?;
    let spec = spec_of(&asked);

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let tenant = admin.context.tenant.tenant.clone();
    let by = admin.context.principal.id().to_owned();
    let user = people::create(&transaction, &tenant, &realm_id, &by, &user_name, &spec)
        .await
        .map_err(refused)?;
    if let Some(password) = asked.password.filter(|given| !given.is_empty()) {
        people::set_password(
            &transaction,
            sealing.provider.as_ref(),
            &tenant,
            &realm_id,
            &by,
            &user.user_id,
            &SecretBox::new(Box::new(password)),
        )
        .await
        .map_err(refused)?;
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(UserBrief::from(user)))
}

pub async fn update(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<UserSpec>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let spec = spec_of(&body.into_inner());
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let user = people::update(&transaction, &user_id, &spec)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(UserBrief::from(user)))
}

pub async fn set_password(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
    body: web::Json<PasswordSpec>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let password = body.into_inner().password;
    if password.is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "password is required",
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    people::set_password(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        &user_id,
        &SecretBox::new(Box::new(password)),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn remove(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    if !people::remove(&transaction, &user_id)
        .await
        .map_err(refused)?
    {
        return Err(ApiError::new(ErrorCode::UserNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn spec_of(asked: &UserSpec) -> Spec {
    Spec {
        email: asked.email.clone(),
        email_verified: asked.email_verified,
        enabled: asked.enabled,
        given_name: asked.given_name.clone(),
        family_name: asked.family_name.clone(),
        phone: asked.phone_number.clone(),
        required_actions: asked.required_actions.clone(),
        attributes: asked
            .attributes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
    }
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Uncreatable) -> ApiError {
    match why {
        Uncreatable::AlreadyExists => ApiError::new(ErrorCode::UserAlreadyExists),
        Uncreatable::NotFound => ApiError::new(ErrorCode::UserNotFound),
        Uncreatable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Uncreatable::Unwritable => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What is counted against this person, and whether they are refused now.
pub async fn lockout(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = people::lockout(&transaction, &user_id)
        .await
        .map_err(refused)?;
    let now = chrono::Utc::now().timestamp();
    Ok(HttpResponse::Ok().json(match held {
        Some(record) => serde_json::json!({
            "failures": record.num_failures,
            "locked": record.is_locked_at(now),
            "until": record.failed_login_not_before,
            "last_failure": record.last_failure,
            "last_address": record.last_ip_failure,
        }),
        None => serde_json::json!({ "failures": 0, "locked": false, "until": 0 }),
    }))
}

/// Lift a lockout and forget the count.
pub async fn lift_lockout(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    people::lift_lockout(&transaction, &user_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// What this server tried to send this person, and how it went.
pub async fn messages(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = store::providers::deliveries::of_user(&transaction, &user_id, 50)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "deliveries": held })))
}

/// What this person has agreed to give, and to whom.
pub async fn consents(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = store::providers::consents::of_user(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "consents": held
            .into_iter()
            .map(|one| serde_json::json!({
                "client_id": one.client_id,
                "scopes": one.scopes,
                "granted_at": one.granted_at,
            }))
            .collect::<Vec<_>>(),
    })))
}

/// Take one back.
///
/// The sessions it authorised are left alone. Taking back a permission and
/// ending what it permitted are two acts, and the second has its own route.
pub async fn withdraw_consent(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    if !store::providers::consents::withdraw(&transaction, &user_id, &client_id)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::UserNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Every role this user holds, directly or through a group: one answer, the
/// way a decision reads it.
pub async fn effective_roles(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    named_user(&transaction, &user_id).await?;
    let held = store::providers::roles::effective_roles(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "roles": held
            .iter()
            .map(|role| serde_json::json!({
                "role_id": role.role_id,
                "name": role.name,
                "display_name": role.display_name,
                "description": role.description,
                "client_id": role.client_id,
            }))
            .collect::<Vec<_>>(),
    })))
}

/// The groups this user belongs to, as the directory shows them.
pub async fn member_groups(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    named_user(&transaction, &user_id).await?;
    let mut groups = Vec::new();
    // Joined memberships only: each row here backs a remove control, and a
    // group reached through a parent has no membership row to remove.
    for group_id in store::providers::users::groups_of(&transaction, &user_id)
        .await
        .map_err(|_| internal())?
    {
        if let Ok(group) = services::admin::directory::get_group(&transaction, &group_id).await {
            groups.push(serde_json::json!({
                "group_id": group.group_id,
                "name": group.name,
                "display_name": group.display_name,
                "description": group.description,
            }));
        }
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({ "groups": groups })))
}

/// The organizations this user belongs to, as the directory shows them.
pub async fn member_organizations(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    named_user(&transaction, &user_id).await?;
    let mut organizations = Vec::new();
    for org_id in store::providers::organizations::of_member(&transaction, &user_id)
        .await
        .map_err(|_| internal())?
    {
        if let Ok(org) = services::admin::directory::get_organization(&transaction, &org_id).await {
            organizations.push(serde_json::json!({
                "org_id": org.org_id,
                "name": org.name,
                "display_name": org.display_name,
                "enabled": org.enabled,
            }));
        }
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({ "organizations": organizations })))
}

/// The user the path names, or the not-found the whole file answers with.
async fn named_user(
    transaction: &deadpool_postgres::Transaction<'_>,
    user_id: &str,
) -> Result<(), ApiError> {
    store::providers::users::load(transaction, user_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::UserNotFound))?;
    Ok(())
}
