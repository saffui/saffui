use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::authz::{GroupMutationModel, RoleMutationModel};
use models::entities::organization::OrganizationMutationModel;
use models::paging::PagingParams;
use services::admin::directory::{self, Unwritable};
use store::query::list_query::{ListQuery, SortDirection};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// The three entities share one file the way they share one manager: the
/// handlers differ only in which manager call answers, and the listing order.
/// `name` is unique per realm for each of them, so it orders totally on its
/// own.
macro_rules! crud {
    ($create:ident, $list:ident, $get:ident, $update:ident, $delete:ident,
     $mutation:ty, $create_call:ident, $list_call:ident, $get_call:ident,
     $update_call:ident, $delete_call:ident,
     $exists:ident, $missing:ident) => {
        pub async fn $create(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            sealing: web::Data<Sealing>,
            path: web::Path<String>,
            body: web::Json<$mutation>,
        ) -> Result<HttpResponse, ApiError> {
            let realm_id = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let made = directory::$create_call(
                &transaction,
                sealing.provider.as_ref(),
                &admin.context.tenant.tenant,
                &realm_id,
                admin.context.principal.id(),
                body.into_inner(),
            )
            .await
            .map_err(|why| refused(why, ErrorCode::$exists, ErrorCode::$missing))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::Created().json(made))
        }

        pub async fn $list(
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
            let query = ListQuery::new(window).sorted_by("name", SortDirection::Ascending);
            let found = directory::$list_call(&transaction, &query, paging.count.unwrap_or(false))
                .await
                .map_err(|why| refused(why, ErrorCode::$exists, ErrorCode::$missing))?;
            Ok(HttpResponse::Ok().json(found))
        }

        pub async fn $get(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let found = directory::$get_call(&transaction, &id)
                .await
                .map_err(|why| refused(why, ErrorCode::$exists, ErrorCode::$missing))?;
            Ok(HttpResponse::Ok().json(found))
        }

        pub async fn $update(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
            body: web::Json<$mutation>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let changed = directory::$update_call(
                &transaction,
                &id,
                admin.context.principal.id(),
                body.into_inner(),
            )
            .await
            .map_err(|why| refused(why, ErrorCode::$exists, ErrorCode::$missing))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::Ok().json(changed))
        }

        pub async fn $delete(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            directory::$delete_call(&transaction, &id)
                .await
                .map_err(|why| refused(why, ErrorCode::$exists, ErrorCode::$missing))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }
    };
}

crud!(
    create_role,
    list_roles,
    get_role,
    update_role,
    delete_role,
    RoleMutationModel,
    create_role,
    list_roles,
    get_role,
    update_role,
    delete_role,
    RoleAlreadyExists,
    RoleNotFound
);
crud!(
    create_group,
    list_groups,
    get_group,
    update_group,
    delete_group,
    GroupMutationModel,
    create_group,
    list_groups,
    get_group,
    update_group,
    delete_group,
    GroupAlreadyExists,
    GroupNotFound
);
crud!(
    create_organization,
    list_organizations,
    get_organization,
    update_organization,
    delete_organization,
    OrganizationMutationModel,
    create_organization,
    list_organizations,
    get_organization,
    update_organization,
    delete_organization,
    OrganizationAlreadyExists,
    OrganizationNotFound
);

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

/// One manager error, three vocabularies: the entity the route is about names
/// its own conflict and its own absence, so a group in conflict is not
/// reported as a role.
fn refused(why: Unwritable, exists: ErrorCode, missing: ErrorCode) -> ApiError {
    match why {
        Unwritable::AlreadyExists => ApiError::new(exists),
        Unwritable::NotFound => ApiError::new(missing),
        Unwritable::StillHeld => ApiError::new(ErrorCode::StillGranted),
        Unwritable::Invalid(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unwritable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
