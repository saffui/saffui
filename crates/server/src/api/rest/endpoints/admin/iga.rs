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
    let Some(when_attribute) = asked
        .when_attribute
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
    else {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "when_attribute names an attribute, or * for everybody".to_owned(),
        ));
    };
    if when_attribute != "*" && asked.when_value.trim().is_empty() {
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
