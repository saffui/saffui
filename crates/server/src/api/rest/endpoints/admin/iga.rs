use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use serde::Deserialize;
use services::admin::iga::{self, Unruled};
use store::tenancy::Tenancy;

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

fn refuse(why: Unruled) -> ApiError {
    match why {
        Unruled::Invalid(said) => ApiError::with_detail(ErrorCode::ValidationError, said),
        Unruled::NoSuchUser => ApiError::new(ErrorCode::UserNotFound),
        Unruled::NoSuchRule => ApiError::new(ErrorCode::RoleNotFound),
        Unruled::Backend => internal(),
    }
}

pub async fn rules(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = iga::birthright_rules(&transaction).await.map_err(refuse)?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|rule| {
                serde_json::json!({
                    "rule_id": rule.rule_id,
                    "when_attribute": rule.when_attribute,
                    "when_value": rule.when_value,
                    "when_expr": rule.when_expr,
                    "roles": rule.roles,
                    "priority": rule.priority,
                    "enabled": rule.enabled,
                })
            })
            .collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AskedRule {
    pub when_attribute: Option<String>,
    #[serde(default)]
    pub when_value: String,
    /// A composed predicate; present, it is the whole condition.
    pub when_expr: Option<String>,
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub priority: i32,
    pub enabled: Option<bool>,
}

pub async fn put_rule(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedRule>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let asked = body.into_inner();
    let rule = iga::shaped_birthright_rule(
        &rule_id,
        asked.when_attribute.as_deref(),
        &asked.when_value,
        asked.when_expr.as_deref(),
        asked.roles,
        asked.priority,
        asked.enabled,
    )
    .map_err(refuse)?;

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    iga::keep_birthright_rule(&transaction, &rule, admin.context.principal.id())
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "rule_id": rule_id })))
}

#[derive(Debug, Deserialize)]
pub struct AskedGrant {
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    /// RFC 3339. Required: an end is the whole point of a grant written here
    /// rather than on the role directly.
    pub expires_at: Option<String>,
}

/// Grant a role for a while, by hand: the engine holds the end.
pub async fn put_grant(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<AskedGrant>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let refused =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());
    let user_id = asked
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| refused("user_id names who"))?;
    let role_id = asked
        .role_id
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| refused("role_id names what"))?;
    let expires_at = asked
        .expires_at
        .as_deref()
        .and_then(|held| chrono::DateTime::parse_from_rfc3339(held.trim()).ok())
        .map(|held| held.with_timezone(&chrono::Utc))
        .ok_or_else(|| refused("expires_at is an RFC 3339 instant: the end is the point"))?;

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let user_id = iga::grant_until(
        &transaction,
        user_id,
        role_id,
        admin.context.principal.id(),
        expires_at,
    )
    .await
    .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(serde_json::json!({
        "user_id": user_id,
        "role_id": role_id,
        "expires_at": expires_at.to_rfc3339(),
    })))
}

/// The ledger of one person: what the engine holds, from rules and hands.
pub async fn grants_of(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let user_id = super::users::named_user(&transaction, &user_id).await?;
    let held = iga::ledger_of(&transaction, &user_id)
        .await
        .map_err(refuse)?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|(role, rule, ends)| {
                serde_json::json!({
                    "role_id": role,
                    "rule_id": rule,
                    "expires_at": ends.map(|held| held.to_rfc3339()),
                })
            })
            .collect::<Vec<_>>(),
    ))
}

/// Take a hand-written grant back before its end.
pub async fn delete_grant(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, role_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let user_id = super::users::named_user(&transaction, &user_id).await?;
    iga::take_back_grant(&transaction, &user_id, &role_id)
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn delete_rule(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    iga::drop_birthright_rule(&transaction, &rule_id)
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Converge the whole realm now: the first fill after rules are written,
/// and the drift repair an audit reaches for.
pub async fn converge(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let (walked, told) = crate::lifecycle::converge_realm(&transaction)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "walked": walked,
        "granted": told.granted,
        "revoked": told.revoked,
        "sessions_closed": told.sessions_closed,
    })))
}

pub async fn sod_rules(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = iga::sod_rules(&transaction).await.map_err(refuse)?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|rule| {
                serde_json::json!({
                    "rule_id": rule.rule_id,
                    "roles": rule.roles,
                    "min_conflicting": rule.min_conflicting,
                    "enabled": rule.enabled,
                })
            })
            .collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AskedSodRule {
    pub roles: Option<Vec<String>>,
    /// Absent, the whole set is the threshold: holding every named role.
    pub min_conflicting: Option<i32>,
    pub enabled: Option<bool>,
}

pub async fn put_sod_rule(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedSodRule>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let asked = body.into_inner();
    let rule = iga::shaped_sod_rule(&rule_id, asked.roles, asked.min_conflicting, asked.enabled)
        .map_err(refuse)?;

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    iga::keep_sod_rule(&transaction, &rule, admin.context.principal.id())
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "rule_id": rule_id,
        "roles": rule.roles,
        "min_conflicting": rule.min_conflicting,
        "enabled": rule.enabled,
    })))
}

pub async fn delete_sod_rule(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    iga::drop_sod_rule(&transaction, &rule_id)
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Every toxic combination standing right now, weighed where it is read:
/// nothing here is stored, so nothing here can be stale. Excused ones are
/// listed too, marked; an auditor wants the excuse visible, not the fact
/// gone.
pub async fn sod_violations(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let found = iga::standing_violations(&transaction, chrono::Utc::now())
        .await
        .map_err(refuse)?;
    Ok(HttpResponse::Ok().json(
        found
            .iter()
            .map(|violation| {
                serde_json::json!({
                    "user_id": violation.user_id,
                    "user_name": violation.user_name,
                    "rule_id": violation.rule_id,
                    "roles": violation.roles,
                    "excused": violation.excused,
                })
            })
            .collect::<Vec<_>>(),
    ))
}

pub async fn sod_exceptions(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = iga::sod_exceptions(&transaction).await.map_err(refuse)?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|exception| {
                serde_json::json!({
                    "rule_id": exception.rule_id,
                    "user_id": exception.user_id,
                    "covered_roles": exception.covered_roles,
                    "justification": exception.justification,
                    "granted_by": exception.granted_by,
                    "valid_until": exception.valid_until.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AskedException {
    pub covered_roles: Option<Vec<String>>,
    pub justification: Option<String>,
    pub valid_until: Option<String>,
}

pub async fn put_sod_exception(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
    body: web::Json<AskedException>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id, user_id) = path.into_inner();
    let asked = body.into_inner();
    let refused =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());

    let justification = asked
        .justification
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .ok_or_else(|| refused("justification says why this pair of hands is allowed"))?;
    let valid_until = asked
        .valid_until
        .as_deref()
        .and_then(|spelled| chrono::DateTime::parse_from_rfc3339(spelled).ok())
        .map(|instant| instant.with_timezone(&chrono::Utc))
        .ok_or_else(|| refused("valid_until is an RFC 3339 instant: an exception ends"))?;
    if valid_until <= chrono::Utc::now() {
        return Err(refused("valid_until has already passed"));
    }

    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let (user_id, covered) = iga::keep_sod_exception(
        &transaction,
        &rule_id,
        &user_id,
        asked.covered_roles,
        justification,
        valid_until,
        admin.context.principal.id(),
    )
    .await
    .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "rule_id": rule_id,
        "user_id": user_id,
        "covered_roles": covered,
        "valid_until": valid_until.to_rfc3339(),
    })))
}

pub async fn delete_sod_exception(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id, user_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let user_id = super::users::named_user(&transaction, &user_id).await?;
    iga::drop_sod_exception(&transaction, &rule_id, &user_id)
        .await
        .map_err(refuse)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
