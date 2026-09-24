use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::entities::brokering::UserFederationMutationModel;
use services::admin::federation::{self, Unwritable};
use store::tenancy::Tenancy;

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

pub async fn list(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = federation::list(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let held = federation::get(&transaction, &alias)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn put(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
    body: web::Json<UserFederationMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let kept = federation::put(
        &transaction,
        &ring,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
        &alias,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(kept))
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    federation::delete(&transaction, &alias)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Mirror everybody the directory holds, now, once. The same walk the sync
/// makes, asked by an operator instead of a clock.
pub async fn import(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, alias) = path.into_inner();
    let context = within(&admin, &realm_id);
    let transaction = tenancy
        .begin(&context)
        .await
        .map_err(refuse_unopened_work)?;
    let held = services::admin::federation::directory_to_import(&transaction, &alias)
        .await
        .map_err(|why| match why {
            services::admin::federation::Unwritable::NotFound => {
                ApiError::new(ErrorCode::IdentityProviderNotFound)
            }
            services::admin::federation::Unwritable::Invalid(said) => {
                ApiError::with_detail(ErrorCode::ValidationError, said)
            }
            services::admin::federation::Unwritable::Backend => internal(),
        })?;
    let settings = services::federation::ldap::LdapSettings::parse(&held)
        .map_err(|why| ApiError::with_detail(ErrorCode::ValidationError, why.to_string()))?;
    let directory =
        outbound::directory::directory_for(&transaction, &sealing, &context, &held, settings).await;
    let told = services::federation::shadows::import_everyone(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &alias,
        &directory,
    )
    .await
    .map_err(|why| match why {
        services::federation::shadows::Unimported::Unwalked => ApiError::with_detail(
            ErrorCode::ValidationError,
            "the directory could not be walked".to_owned(),
        ),
        services::federation::shadows::Unimported::Unwritten => internal(),
    })?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "imported": told.imported,
        "refreshed": told.refreshed,
        "walked": told.walked,
    })))
}

fn refused(why: Unwritable) -> ApiError {
    match why {
        Unwritable::NotFound => ApiError::new(ErrorCode::IdentityProviderNotFound),
        Unwritable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unwritable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
