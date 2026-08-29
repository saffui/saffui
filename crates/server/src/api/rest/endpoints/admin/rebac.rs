use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use services::rebac::{Unpublishable, Unwritable};
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

/// The schema as the realm shows it: the source and its lineage, never the
/// compiled half, which is the engine's shape and not an API.
pub async fn schema(
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
    let stored = store::providers::rebac::load_schema(&transaction)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RebacSchemaNotFound))?;
    Ok(HttpResponse::Ok().json(json!({
        "source": stored.source,
        "format": stored.format,
        "revision": stored.revision,
    })))
}

#[derive(Deserialize)]
pub struct SchemaBody {
    pub source: String,
}

/// Publish a schema: read, compiled and stored as one act, so the realm can
/// never show one schema and decide by another. What does not compile is
/// refused in the compiler's own words.
pub async fn publish(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<SchemaBody>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let source = body.into_inner().source;
    services::rebac::publish(&transaction, &source, Some(admin.context.principal.id()))
        .await
        .map_err(|why| match why {
            Unpublishable::Unreadable(said) => {
                ApiError::with_detail(ErrorCode::ValidationError, said.to_string())
            }
            Unpublishable::Faulty(said) => {
                ApiError::with_detail(ErrorCode::ValidationError, said.to_string())
            }
            Unpublishable::Unwritable => internal(),
        })?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(json!({ "source": source })))
}

/// One edge, both directions of writing. The subject may itself be a set:
/// `subject_relation` names the relation on it whose holders this edge
/// stands for.
#[derive(Deserialize)]
pub struct EdgeBody {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    #[serde(default)]
    pub subject_relation: String,
}

fn subject_of(edge: &EdgeBody) -> store::providers::rebac::Subject {
    store::providers::rebac::Subject {
        subject_type: edge.subject_type.clone(),
        subject_id: edge.subject_id.clone(),
        subject_relation: edge.subject_relation.clone(),
    }
}

fn refused_write(why: Unwritable) -> ApiError {
    match why {
        Unwritable::NoSchema => ApiError::new(ErrorCode::RebacSchemaNotFound),
        Unwritable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

pub async fn relate(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<EdgeBody>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let edge = body.into_inner();
    services::rebac::relate(
        &transaction,
        &edge.object_type,
        &edge.object_id,
        &edge.relation,
        &subject_of(&edge),
        Some(admin.context.principal.id()),
    )
    .await
    .map_err(refused_write)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn unrelate(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    body: web::Json<EdgeBody>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let edge = body.into_inner();
    let stood = services::rebac::unrelate(
        &transaction,
        &edge.object_type,
        &edge.object_id,
        &edge.relation,
        &subject_of(&edge),
    )
    .await
    .map_err(|_| internal())?;
    if !stood {
        return Err(ApiError::new(ErrorCode::RebacEdgeNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Deserialize)]
pub struct EdgeQuery {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
}

/// Who stands in one relation on one object, as written: direct subjects
/// and subject sets alike, without walking anything.
pub async fn subjects(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    asked: web::Query<EdgeQuery>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = store::providers::rebac::subjects(
        &transaction,
        &asked.object_type,
        &asked.object_id,
        &asked.relation,
        1000,
    )
    .await
    .map_err(|_| internal())?;
    let told: Vec<_> = held
        .into_iter()
        .map(|subject| {
            json!({
                "subject_type": subject.subject_type,
                "subject_id": subject.subject_id,
                "subject_relation": (!subject.subject_relation.is_empty())
                    .then_some(subject.subject_relation),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(told))
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
