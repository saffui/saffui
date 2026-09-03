use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::client::ProtocolMapperMutationModel;
use services::admin::protocol_mappers::{self, Unwritable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

pub async fn list(
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
    let listed = protocol_mappers::mappers(&transaction)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(listed))
}

/// What the mappers would write for one grant, claim by claim with its
/// author. Mints nothing; the evaluation is issuance's own.
#[derive(serde::Deserialize)]
pub struct PreviewAsk {
    pub user_id: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

pub async fn preview(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<PreviewAsk>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let scope = asked.scope.unwrap_or_else(|| "openid".to_owned());
    let rows = services::mappers::preview(&transaction, &asked.client_id, &asked.user_id, &scope)
        .await
        .map_err(|()| ApiError::new(ErrorCode::UserNotFound))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "claims": rows, "scope": scope })))
}

pub async fn create(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<ProtocolMapperMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let made = protocol_mappers::create_mapper(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(made))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found = protocol_mappers::get_mapper(&transaction, &mapper_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(found))
}

pub async fn update(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<ProtocolMapperMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let rewritten = protocol_mappers::update_mapper(
        &transaction,
        &mapper_id,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(rewritten))
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    protocol_mappers::delete_mapper(&transaction, &mapper_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// The four owner-side handlers share one shape: two ids off the path, one
/// manager call, an empty answer.
macro_rules! carrying {
    ($list:ident, $attach:ident, $detach:ident, $list_call:ident, $attach_call:ident, $detach_call:ident) => {
        pub async fn $list(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let listed = protocol_mappers::$list_call(&transaction, &owner)
                .await
                .map_err(refused)?;
            Ok(HttpResponse::Ok().json(listed))
        }

        pub async fn $attach(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner, mapper_id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            protocol_mappers::$attach_call(&transaction, &owner, &mapper_id)
                .await
                .map_err(refused)?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }

        pub async fn $detach(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner, mapper_id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            protocol_mappers::$detach_call(&transaction, &owner, &mapper_id)
                .await
                .map_err(refused)?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }
    };
}

carrying!(
    of_scope,
    attach_to_scope,
    detach_from_scope,
    mappers_of_scope,
    attach_to_scope,
    detach_from_scope
);
carrying!(
    of_client,
    attach_to_client,
    detach_from_client,
    mappers_of_client,
    attach_to_client,
    detach_from_client
);

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Unwritable) -> ApiError {
    match why {
        Unwritable::NotFound => ApiError::new(ErrorCode::ProtocolMapperNotFound),
        Unwritable::NoSuchScope => ApiError::new(ErrorCode::ClientScopeNotFound),
        Unwritable::NoSuchClient => ApiError::new(ErrorCode::ClientNotFound),
        Unwritable::UnknownRule(known) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("no rule of this name runs here; one of: {known}"),
        ),
        Unwritable::StillHeld => ApiError::new(ErrorCode::StillGranted),
        Unwritable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
