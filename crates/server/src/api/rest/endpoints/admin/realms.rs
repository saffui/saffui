use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use models::entities::realm::{RealmCreateModel, RealmUpdateModel};
use models::paging::PagingParams;
use models::representation::RepresentationParams;
use services::provisioning;
use store::query::list_query::ListQuery;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::admin::dto::RealmBrief;
use crate::middleware::admin_guard::Admin;
use crate::middleware::admin_policy::AdminPolicy;

/// The realms of the tenant this token belongs to.
pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    paging: web::Query<PagingParams>,
) -> Result<HttpResponse, ApiError> {
    let window = paging
        .window()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest))?;

    let mut connection = pool.get().await.map_err(|_| internal())?;
    // Tenant wide: a realm listing is the one admin read that is not about one
    // realm, and the scope says so rather than a realm being borrowed for it.
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::tenant_wide(&admin.context.tenant.tenant),
        )
        .await
        .map_err(|_| internal())?;

    // One column is enough here and only here: the read is tenant wide and
    // `realm_name_unique_per_tenant` makes the name unique within it, so the
    // order is already total. A listing whose leading column can tie needs a
    // tiebreaker, or an offset window serves one row twice and another never.
    let query = ListQuery::new(window)
        .sorted_by("name", store::query::list_query::SortDirection::Ascending);
    let found = services::realm::listed(&transaction, &query, paging.count.unwrap_or(false))
        .await
        .map_err(|_| internal())?;

    Ok(HttpResponse::Ok().json(models::paging::Page {
        items: found.items.into_iter().map(brief).collect::<Vec<_>>(),
        first: found.first,
        max: found.max,
        total: found.total,
    }))
}

/// One realm.
pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    representation: web::Query<RepresentationParams>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let found = services::realm::named(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RealmNotFound))?;

    // The full representation carries the switches; the brief one does not, and
    // brief is what an unasked caller gets.
    if representation.wants_full() {
        Ok(HttpResponse::Ok().json(found))
    } else {
        Ok(HttpResponse::Ok().json(brief(found)))
    }
}

fn brief(realm: models::entities::realm::RealmModel) -> RealmBrief {
    RealmBrief {
        realm_id: realm.realm_id,
        name: realm.name,
        display_name: realm.display_name,
        enabled: realm.enabled,
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What a realm may be called: it becomes a path segment and the tail of an
/// issuer, so only characters that survive both are taken.
fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A realm, and everything it cannot work without.
///
/// Seeded the way `provision` seeds: the standard scopes, this deployment's
/// console client pointed at the console this server serves, a signing key
/// and the browser flow. A bare row would answer every login with an error
/// and every scope request with nothing, and nothing about it would say so.
///
/// Two transactions, because the row is written tenant wide and everything
/// inside the realm is written scoped to it, which is how row security is
/// told who is writing. A failure between the two leaves a realm that a
/// second create refuses; `provision` heals such a realm, and so does the
/// deployment's next start.
pub async fn create(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    policy: web::Data<AdminPolicy>,
    origin: web::Data<PublicOrigin>,
    sealing: web::Data<Sealing>,
    body: web::Json<RealmCreateModel>,
) -> Result<HttpResponse, ApiError> {
    let asked = body.into_inner();
    if !usable_name(&asked.name) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm name is 1 to 63 characters of a-z, A-Z, 0-9, - or _".to_owned(),
        ));
    }
    let tenant = admin.context.tenant.tenant.clone();
    let realm_id = asked.name.clone();
    let now = chrono::Utc::now().timestamp();

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(&tenant))
        .await
        .map_err(|_| internal())?;
    if store::providers::realms::load(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(ApiError::new(ErrorCode::RealmAlreadyExists));
    }
    let realm = asked.into_model(
        realm_id.clone(),
        models::auditable::AuditableModel::from_creator(
            tenant.clone(),
            admin.context.principal.id().to_owned(),
        ),
    );
    store::providers::realms::create(&transaction, &realm)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new(&tenant, &realm_id))
        .await
        .map_err(|_| internal())?;
    provisioning::provision_standard_scopes(&transaction, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    if let Some(console) = policy.parties.first() {
        provisioning::provision_admin_console(
            &transaction,
            &tenant,
            &realm_id,
            &provisioning::AdminConsole {
                client_id: console,
                scope: &policy.scope,
                redirect_uris: vec![format!("{}/console/login/return", origin.as_str())],
            },
        )
        .await
        .map_err(|_| internal())?;
    }
    provisioning::provision_signing_key(
        &transaction,
        sealing.provider.as_ref(),
        &sealing.envelope,
        &tenant,
        &realm_id,
        now,
    )
    .await
    .map_err(|_| internal())?;
    provisioning::provision_browser_flow(&transaction, &tenant, &realm_id)
        .await
        .map_err(|_| internal())?;
    provisioning::provision_levels(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    Ok(HttpResponse::Created().json(brief(realm)))
}

/// Take the realm away. The schema cascades, so everything keyed under it
/// goes with the row: users, clients, sessions, keys, the lot.
///
/// The realm this caller's own token was minted by is refused: deleting it
/// would take the admin plane down with it, and the person would learn that
/// from a broken console rather than an answer. Do it from another realm.
pub async fn delete(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    if admin.context.tenant.realm_id == realm_id {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm is not deleted from its own console: sign into another realm first".to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::delete(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Draw the secret protected client registration is opened with, and answer
/// it exactly once. Only the hash is kept.
pub async fn rotate_registration_secret(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let secret = services::registration::rotate_registration_secret(
        &transaction,
        sealing.provider.as_ref(),
        &realm_id,
    )
    .await
    .map_err(|_| ApiError::new(ErrorCode::RealmNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "registration_secret": secret })))
}

/// Take the registration secret away. Protected registration then admits
/// nobody until a new one is drawn.
pub async fn forget_registration_secret(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    services::registration::forget_registration_secret(&transaction, &realm_id)
        .await
        .map_err(|_| ApiError::new(ErrorCode::RealmNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Rewrite the realm's switches.
///
/// Absent fields stay as they are, so an edit that mentions one setting does
/// not reset the rest. The name and the identity are not writable here: the
/// issuer is built from them, and tokens outlive a rename.
pub async fn update(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<RealmUpdateModel>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let mut held = services::realm::named(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RealmNotFound))?;
    let asked = body.into_inner();
    // OTP bounds an authenticator app will actually honour: RFC 6238 speaks
    // 6 to 8 digits, and a period or window outside sanity is a lockout
    // being configured.
    if let Some(policy) = &asked.otp_policy {
        let sane = (6..=8).contains(&policy.digits)
            && (15..=300).contains(&policy.period)
            && policy.window <= 4;
        if !sane {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                "an otp policy wants 6 to 8 digits, a period of 15 to 300 seconds, \
                 and a window of at most 4 steps"
                    .to_owned(),
            ));
        }
    }
    // A binding is checked at the door, not at the first login it breaks:
    // the named flow must exist here and be one a login can start at.
    if let Some(alias) = asked
        .browser_flow
        .as_deref()
        .filter(|held| !held.is_empty())
    {
        let usable = store::providers::auth_flows::flow_by_alias(&transaction, alias)
            .await
            .map_err(|_| internal())?
            .is_some_and(|flow| flow.top_level == Some(true));
        if !usable {
            return Err(ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("no top-level flow is aliased {alias}"),
            ));
        }
    }
    asked.apply(&mut held);
    if !services::realm::reshape(&transaction, &held)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held))
}

/// The realm's theme tokens, for the console that edits them.
pub async fn theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    let held = store::providers::realms::theme_of(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held.unwrap_or(serde_json::Value::Null)))
}

/// Dress the realm. Refused whole on the first token the pages do not read
/// or the first value that could leave its declaration: the stylesheet is
/// executable enough that this door is the security boundary.
pub async fn set_theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    if let Err(why) = services::theme::css_of(&asked) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            why.to_owned(),
        ));
    }
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::set_theme(&transaction, &realm_id, Some(&asked))
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Back to the default look.
pub async fn clear_theme(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    if !store::providers::realms::set_theme(&transaction, &realm_id, None)
        .await
        .map_err(|_| internal())?
    {
        return Err(ApiError::new(ErrorCode::RealmNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
