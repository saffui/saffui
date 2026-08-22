//! The clients of a realm, over the admin plane.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use serde_json::json;
use services::admin::clients::{self as registry, Reshape, Secret, Spec, Unregistrable};
use store::query::list_query::{ListQuery, SortDirection};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::admin::dto::{ClientBrief, ClientSpec};
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
    let query = ListQuery::new(window).sorted_by("client_id", SortDirection::Ascending);
    let found = registry::list(&transaction, &query, paging.count.unwrap_or(false))
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(models::paging::Page {
        items: found
            .items
            .into_iter()
            .map(ClientBrief::from)
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
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found = registry::get(&transaction, &client_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(ClientBrief::from(found)))
}

/// Register a client. A confidential one is answered with its secret, this
/// once and never again.
pub async fn create(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<ClientSpec>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let client_id = asked
        .client_id
        .clone()
        .filter(|named| !named.is_empty())
        .ok_or_else(|| {
            ApiError::with_detail(ErrorCode::ValidationError, "client_id is required")
        })?;
    let spec = spec_of(&asked);

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let (client, secret) = registry::register(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        &client_id,
        &spec,
        Secret::Drawn,
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;

    let mut told = serde_json::to_value(ClientBrief::from(client)).map_err(|_| internal())?;
    if let (Some(secret), Some(map)) = (secret, told.as_object_mut()) {
        map.insert("client_secret".into(), json!(secret));
    }
    Ok(HttpResponse::Created().json(told))
}

pub async fn update(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<ClientSpec>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let reshape = Reshape {
        name: asked.name.clone(),
        redirect_uris: asked.redirect_uris.clone(),
        post_logout_redirect_uris: asked.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: asked.backchannel_logout_uri.clone().map(Some),
        frontchannel_logout_uri: asked.frontchannel_logout_uri.clone().map(Some),
    };
    let client = registry::update(&transaction, &client_id, &reshape)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(ClientBrief::from(client)))
}

pub async fn rotate_secret(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let secret = registry::rotate_secret(&transaction, sealing.provider.as_ref(), &client_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(json!({ "client_id": client_id, "client_secret": secret })))
}

pub async fn remove(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    if !registry::remove(&transaction, &client_id)
        .await
        .map_err(refused)?
    {
        return Err(ApiError::new(ErrorCode::ClientNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

fn spec_of(asked: &ClientSpec) -> Spec {
    Spec {
        name: asked.name.clone(),
        confidential: asked.confidential.unwrap_or(true),
        redirect_uris: asked.redirect_uris.clone().unwrap_or_default(),
        post_logout_redirect_uris: asked.post_logout_redirect_uris.clone().unwrap_or_default(),
        backchannel_logout_uri: asked.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: asked.frontchannel_logout_uri.clone(),
    }
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Unregistrable) -> ApiError {
    match why {
        Unregistrable::AlreadyExists => ApiError::new(ErrorCode::ClientAlreadyExists),
        Unregistrable::NotFound => ApiError::new(ErrorCode::ClientNotFound),
        Unregistrable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unregistrable::Unwritable => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
