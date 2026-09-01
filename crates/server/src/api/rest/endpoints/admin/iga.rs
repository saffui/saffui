use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use store::providers::birthright::{self, BirthrightRule};
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

pub async fn rules(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = birthright::rules(&transaction)
        .await
        .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedRule>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let asked = body.into_inner();
    let when_expr = asked
        .when_expr
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .map(str::to_owned);
    if let Some(expr) = when_expr.as_deref()
        && !services::lifecycle::expr_parses(expr)
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "when_expr is name=value or name!=value terms joined by &&".to_owned(),
        ));
    }
    let when_attribute = match (
        when_expr.is_some(),
        asked
            .when_attribute
            .as_deref()
            .map(str::trim)
            .filter(|held| !held.is_empty()),
    ) {
        // The expression is the whole condition; the pair beside it is
        // decoration nothing reads, so it is refused rather than kept.
        (true, Some(_)) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "when_expr is the whole condition: drop when_attribute".to_owned(),
            ));
        }
        (true, None) => "*",
        (false, Some(named)) => named,
        (false, None) => {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "when_attribute names an attribute, or * for everybody".to_owned(),
            ));
        }
    };
    if when_expr.is_none() && when_attribute != "*" && asked.when_value.trim().is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "when_value names what the attribute must equal".to_owned(),
        ));
    }
    let Some(roles) = asked
        .roles
        .filter(|held| !held.is_empty() && held.iter().all(|role| !role.trim().is_empty()))
    else {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "roles names what the rule grants".to_owned(),
        ));
    };

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    for role in &roles {
        let held = store::providers::roles::load(&transaction, role)
            .await
            .map_err(|_| internal())?;
        if held.is_none() {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("no role answers to {role}"),
            ));
        }
    }
    let rule = BirthrightRule {
        rule_id: rule_id.clone(),
        when_attribute: when_attribute.to_owned(),
        when_value: asked.when_value.trim().to_owned(),
        when_expr,
        roles,
        priority: asked.priority,
        enabled: asked.enabled.unwrap_or(true),
    };
    birthright::keep_rule(&transaction, &rule, admin.context.principal.id())
        .await
        .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
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

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    if store::providers::users::load(&transaction, user_id)
        .await
        .map_err(|_| internal())?
        .is_none()
    {
        return Err(refused("no user answers to that name"));
    }
    if store::providers::roles::load(&transaction, role_id)
        .await
        .map_err(|_| internal())?
        .is_none()
    {
        return Err(refused("no role answers to that name"));
    }
    store::providers::roles::grant_to_user(&transaction, user_id, role_id)
        .await
        .map_err(|_| internal())?;
    birthright::record_timed_grant(
        &transaction,
        user_id,
        role_id,
        admin.context.principal.id(),
        expires_at,
    )
    .await
    .map_err(|_| internal())?;
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
    let held = birthright::ledger_of(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, role_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    store::providers::roles::revoke_from_user(&transaction, &user_id, &role_id)
        .await
        .map_err(|_| internal())?;
    birthright::erase_grant(&transaction, &user_id, &role_id)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn delete_rule(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let removed = birthright::drop_rule(&transaction, &rule_id)
        .await
        .map_err(|_| internal())?;
    if !removed {
        return Err(ApiError::new(ErrorCode::RoleNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Converge the whole realm now: the first fill after rules are written,
/// and the drift repair an audit reaches for.
pub async fn converge(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
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
