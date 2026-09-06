use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::compliance::subject_request::{DsarKind, DsarRequest, Jurisdiction};
use serde::Deserialize;
use services::admin::compliance::{self, Lodging, Unactionable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// What the plane is asked to lodge.
#[derive(Debug, Deserialize)]
pub struct LodgeSpec {
    pub subject_identifier: String,
    /// One of the register's kinds; anything else is refused by name.
    pub kind: String,
    /// A jurisdiction code the register knows; `other` demands `due_at`.
    pub jurisdiction: String,
    /// Absolute epoch seconds. Required where the jurisdiction fixes no
    /// window, welcome where the controller's policy is tighter.
    pub due_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RefuseSpec {
    pub reason: String,
}

/// What a fulfilment may carry: the corrections a rectification applies,
/// or the client an objection names. Erasure and the copies take nothing.
#[derive(Debug, Default, Deserialize)]
pub struct FulfilSpec {
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub phone_number: Option<String>,
    pub client_id: Option<String>,
}

pub async fn lodge(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<LodgeSpec>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let kind: DsarKind = asked.kind.parse().map_err(|_| {
        ApiError::with_detail(
            ErrorCode::ValidationError,
            "kind is one of access, rectification, erasure, objection, portability".to_owned(),
        )
    })?;
    let jurisdiction: Jurisdiction = asked.jurisdiction.parse().map_err(|_| {
        ApiError::with_detail(
            ErrorCode::ValidationError,
            "jurisdiction is a code this register knows, or `other` with a due date".to_owned(),
        )
    })?;
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let lodged = compliance::lodge(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        Lodging {
            subject_identifier: asked.subject_identifier.trim(),
            kind,
            jurisdiction,
            due_at: asked.due_at,
        },
        chrono::Utc::now().timestamp(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(presentable(lodged)))
}

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
    let held = compliance::list(&transaction).await.map_err(refused)?;
    Ok(HttpResponse::Ok().json(held.into_iter().map(presentable).collect::<Vec<_>>()))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = compliance::get(&transaction, &request_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(presentable(held)))
}

pub async fn verify(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = compliance::verify(&transaction, &request_id, chrono::Utc::now().timestamp())
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(presentable(held)))
}

pub async fn refuse(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<RefuseSpec>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = compliance::refuse(
        &transaction,
        &request_id,
        body.reason.trim(),
        chrono::Utc::now().timestamp(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(presentable(held)))
}

/// Execute what a verified request asks and close it. Only erasure has an
/// execution today; the other kinds say so instead of pretending.
pub async fn fulfil(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: Option<web::Json<FulfilSpec>>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, request_id) = path.into_inner();
    let asked = body.map(web::Json::into_inner).unwrap_or_default();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let now = chrono::Utc::now().timestamp();
    let kind = compliance::get(&transaction, &request_id)
        .await
        .map_err(refused)?
        .kind;
    let answered = match kind {
        DsarKind::Erasure => {
            let held = compliance::fulfil_erasure(
                &transaction,
                &request_id,
                admin.context.principal.id(),
                now,
            )
            .await
            .map_err(refused)?;
            presentable(held)
        }
        // The copy rides this one answer and is never stored: producing a
        // second one is fulfilling again, which the lifecycle refuses.
        DsarKind::Access => {
            let (held, bundle) = compliance::fulfil_access(&transaction, &request_id, now)
                .await
                .map_err(refused)?;
            let mut told = presentable(held);
            told["bundle"] = bundle;
            told
        }
        DsarKind::Portability => {
            let (held, bundle) = compliance::fulfil_portability(&transaction, &request_id, now)
                .await
                .map_err(refused)?;
            let mut told = presentable(held);
            told["bundle"] = bundle;
            told
        }
        DsarKind::Rectification => {
            let held = compliance::fulfil_rectification(
                &transaction,
                &request_id,
                compliance::Corrections {
                    email: asked.email,
                    given_name: asked.given_name,
                    family_name: asked.family_name,
                    phone_number: asked.phone_number,
                },
                now,
            )
            .await
            .map_err(refused)?;
            presentable(held)
        }
        DsarKind::Objection => {
            let held = compliance::fulfil_objection(
                &transaction,
                &request_id,
                asked.client_id.as_deref(),
                now,
            )
            .await
            .map_err(refused)?;
            presentable(held)
        }
    };
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(answered))
}

/// The row as the plane answers it, the clock's provenance included: an
/// operator defending a deadline needs the citation, not only the number.
fn presentable(request: DsarRequest) -> serde_json::Value {
    let source = match request.jurisdiction.deadline_source() {
        models::compliance::subject_request::DeadlineSource::Statute(cited) => cited,
        models::compliance::subject_request::DeadlineSource::Unspecified(note) => note,
        models::compliance::subject_request::DeadlineSource::Unknown => "",
    };
    let mut told = serde_json::to_value(&request).expect("a request serialises");
    told["deadline_source"] = serde_json::Value::String(source.to_owned());
    told
}

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

fn refused(why: Unactionable) -> ApiError {
    match why {
        Unactionable::NotFound => ApiError::new(ErrorCode::SubjectRequestNotFound),
        Unactionable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unactionable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
