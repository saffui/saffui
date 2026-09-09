use actix_web::{HttpResponse, web};
use chrono::Utc;
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::export::ExportedRealm;
use serde::Deserialize;
use services::admin::portability::{self, Unportable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// The realm as a document. Read whole inside one transaction, so no
/// section can come from a different state than another.
pub async fn export(
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
    let document = portability::export_realm(&transaction, &realm_id, Utc::now())
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(document))
}

/// Where the document lands: under its own name unless the caller says
/// another, which is how a realm is cloned beside its original.
#[derive(Deserialize)]
pub struct Landing {
    #[serde(rename = "as")]
    pub landed_as: Option<String>,
    /// Who will administer what lands.
    ///
    /// An export carries users and, by construction, no secrets, so a realm
    /// imported without this holds accounts that cannot answer for
    /// themselves and nobody can open it. Named here rather than read from
    /// the document, because the document was written elsewhere.
    pub administrator: Option<String>,
}

pub async fn import(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    landing: web::Query<Landing>,
    sealing: web::Data<Sealing>,
    ceiling: web::Data<config::serving::RealmCeiling>,
    body: web::Json<ExportedRealm>,
) -> Result<HttpResponse, ApiError> {
    let document = body.into_inner();
    let landing = landing.into_inner();
    let realm_id = landing
        .landed_as
        .unwrap_or_else(|| document.realm.realm_id.clone());
    if realm_id.trim().is_empty() {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a realm answers to a name",
        ));
    }
    let tenant = admin.context.tenant.tenant.clone();
    let mut connection = pool.get().await.map_err(|_| internal())?;

    // The ceiling first, tenant wide, before anything is written. An import
    // is a realm arriving like any other, and a door that skipped the count
    // would be the way past it.
    let counting = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(&tenant))
        .await
        .map_err(|_| internal())?;
    store::providers::tenants::hold_realms(&counting, &tenant)
        .await
        .map_err(|_| internal())?;
    let named = store::providers::tenants::load(&counting)
        .await
        .map_err(|_| internal())?
        .and_then(|held| held.limits)
        .and_then(|limits| limits.max_realms);
    if let Some(ceiling) = ceiling.against(named)
        && store::providers::tenants::count_realms(&counting)
            .await
            .map_err(|_| internal())?
            >= ceiling
    {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("this tenant holds the {ceiling} realms it is allowed"),
        ));
    }
    drop(counting);

    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;
    portability::import_realm(
        &transaction,
        &admin.context.tenant.tenant,
        &realm_id,
        document,
    )
    .await
    .map_err(refused)?;

    // The way in, when one was asked for. The account may have arrived with
    // the document; either way it leaves here with a drawn password and the
    // instruction to replace it.
    let opened = match landing.administrator.as_deref() {
        Some(user_name) if !user_name.trim().is_empty() => Some((
            user_name.to_owned(),
            services::provisioning::provision_first_administrator(
                &transaction,
                sealing.provider.as_ref(),
                &tenant,
                &realm_id,
                user_name,
                &format!("{user_name}@{realm_id}.invalid"),
            )
            .await
            .map_err(|_| internal())?,
        )),
        _ => None,
    };
    store::tenant_chain::append(
        &transaction,
        &serde_json::json!({
            "kind": "realm.imported",
            "occurred_at": chrono::Utc::now().timestamp() as f64,
            "realm": realm_id,
            "actor": admin.context.principal.id(),
            "actor_realm": admin.context.tenant.realm_id,
            "party": admin.context.presenter,
        }),
    )
    .await
    .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;

    let mut answer = serde_json::json!({ "realm_id": realm_id });
    if let Some((user_name, password)) = opened {
        answer["administrator"] = serde_json::json!({
            "user_name": user_name,
            "password": password,
        });
    }
    Ok(HttpResponse::Created().json(answer))
}

fn refused(why: Unportable) -> ApiError {
    match why {
        Unportable::NotFound => ApiError::new(ErrorCode::RealmNotFound),
        Unportable::AlreadyExists => ApiError::new(ErrorCode::RealmAlreadyExists),
        Unportable::Quarantined(what) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("policy {what} cannot be read, so the document would be missing it"),
        ),
        Unportable::Tangled(server) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("the policies of {server} do not resolve in document order"),
        ),
        Unportable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unportable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
