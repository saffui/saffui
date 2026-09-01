use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::paging::PagingParams;
use models::representation::RepresentationParams;
use store::query::list_query::ListQuery;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::rest::endpoints::admin::dto::RealmBrief;
use crate::middleware::admin_guard::Admin;

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
