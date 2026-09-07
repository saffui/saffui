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
    let user_id = &services::admin::users::identified(&transaction, user_id)
        .await
        .map(|held| held.user_id)
        .map_err(|_| refused("no user answers to that name"))?;
    if store::providers::roles::load(&transaction, role_id)
        .await
        .map_err(|_| internal())?
        .is_none()
    {
        return Err(refused("no role answers to that name"));
    }
    store::providers::sod::hold_person(&transaction, user_id)
        .await
        .map_err(|_| internal())?;
    store::providers::roles::grant_to_user(&transaction, user_id, role_id)
        .await
        .map_err(|_| internal())?;
    match services::sod::weigh(&transaction, user_id).await {
        Ok(()) => {}
        Err(services::sod::Toxic::Refused(said)) => {
            return Err(ApiError::with_detail(ErrorCode::ValidationError, said));
        }
        Err(services::sod::Toxic::Backend) => return Err(internal()),
    }
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
    let user_id = super::users::named_user(&transaction, &user_id).await?;
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
    let user_id = super::users::named_user(&transaction, &user_id).await?;
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

pub async fn sod_rules(
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
    let held = store::providers::sod::rules(&transaction)
        .await
        .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedSodRule>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id) = path.into_inner();
    let asked = body.into_inner();
    let refused =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());

    let roles: Vec<String> = asked
        .roles
        .unwrap_or_default()
        .iter()
        .map(|role| role.trim().to_owned())
        .filter(|role| !role.is_empty())
        .collect();
    if roles.len() < 2 {
        return Err(refused("a separation needs at least two roles to separate"));
    }
    if roles
        .iter()
        .enumerate()
        .any(|(at, role)| roles[..at].contains(role))
    {
        return Err(refused("each role is named once"));
    }
    let min_conflicting = asked.min_conflicting.unwrap_or(roles.len() as i32);
    if min_conflicting < 2 || min_conflicting as usize > roles.len() {
        return Err(refused(
            "min_conflicting is between 2 and the number of roles named",
        ));
    }

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    for role in &roles {
        if store::providers::roles::load(&transaction, role)
            .await
            .map_err(|_| internal())?
            .is_none()
        {
            return Err(refused(&format!("no role answers to {role}")));
        }
    }
    let rule = store::providers::sod::SodRule {
        rule_id: rule_id.clone(),
        roles,
        min_conflicting,
        enabled: asked.enabled.unwrap_or(true),
    };
    store::providers::sod::keep_rule(&transaction, &rule, admin.context.principal.id())
        .await
        .map_err(|_| internal())?;
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
    let removed = store::providers::sod::drop_rule(&transaction, &rule_id)
        .await
        .map_err(|_| internal())?;
    if !removed {
        return Err(ApiError::new(ErrorCode::RoleNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Every toxic combination standing right now, weighed where it is read:
/// nothing here is stored, so nothing here can be stale. Excused ones are
/// listed too, marked; an auditor wants the excuse visible, not the fact
/// gone.
pub async fn sod_violations(
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
    let rules = store::providers::sod::rules(&transaction)
        .await
        .map_err(|_| internal())?;
    let mut told = Vec::new();
    if rules.iter().any(|rule| rule.enabled) {
        let now = chrono::Utc::now();
        let mut first: i64 = 0;
        loop {
            let query = store::query::list_query::ListQuery::new(models::paging::Window {
                first,
                max: 200,
                clamped: false,
            });
            let page = store::providers::users::list(&transaction, &query, false)
                .await
                .map_err(|_| internal())?;
            if page.items.is_empty() {
                break;
            }
            first += page.items.len() as i64;
            for person in &page.items {
                let effective: Vec<String> =
                    store::providers::roles::effective_roles(&transaction, &person.user_id)
                        .await
                        .map_err(|_| internal())?
                        .into_iter()
                        .map(|role| role.role_id)
                        .collect();
                let reached = services::sod::offences(&rules, &effective);
                if reached.is_empty() {
                    continue;
                }
                let standing = store::providers::sod::exceptions_of(&transaction, &person.user_id)
                    .await
                    .map_err(|_| internal())?;
                for offence in reached {
                    told.push(serde_json::json!({
                        "user_id": person.user_id,
                        "user_name": person.user_name,
                        "rule_id": offence.rule_id,
                        "roles": offence.held,
                        "excused": services::sod::excused(&offence, &standing, now),
                    }));
                }
            }
        }
    }
    Ok(HttpResponse::Ok().json(told))
}

pub async fn sod_exceptions(
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
    let held = store::providers::sod::exceptions(&transaction)
        .await
        .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
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

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let rule = store::providers::sod::rules(&transaction)
        .await
        .map_err(|_| internal())?
        .into_iter()
        .find(|rule| rule.rule_id == rule_id)
        .ok_or_else(|| refused("no separation rule answers to that name"))?;
    let user_id = super::users::named_user(&transaction, &user_id).await?;

    let covered: Vec<String> = asked
        .covered_roles
        .unwrap_or_default()
        .iter()
        .map(|role| role.trim().to_owned())
        .filter(|role| !role.is_empty())
        .collect();
    if covered.iter().any(|role| !rule.roles.contains(role)) {
        return Err(refused("covered_roles only names roles the rule separates"));
    }
    if (covered.len() as i32) < rule.min_conflicting {
        return Err(refused(
            "covered_roles names a combination the rule would refuse: fewer roles than \
             min_conflicting excuse nothing",
        ));
    }

    store::providers::sod::keep_exception(
        &transaction,
        &store::providers::sod::SodException {
            rule_id: rule_id.clone(),
            user_id: user_id.clone(),
            covered_roles: covered.clone(),
            justification: justification.to_owned(),
            granted_by: admin.context.principal.id().to_owned(),
            valid_until,
        },
    )
    .await
    .map_err(|_| internal())?;
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
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, rule_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let user_id = super::users::named_user(&transaction, &user_id).await?;
    let removed = store::providers::sod::drop_exception(&transaction, &rule_id, &user_id)
        .await
        .map_err(|_| internal())?;
    if !removed {
        return Err(ApiError::new(ErrorCode::RoleNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
