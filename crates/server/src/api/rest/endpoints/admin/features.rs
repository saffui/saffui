use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::feature::{Feature, Reach, RealmWishes};
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::json;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::within;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What this build carries and what is on: the set the process was started
/// under. Read-only by nature; the compile half is link-time and the
/// runtime half was fixed at boot.
pub async fn list() -> Result<HttpResponse, ApiError> {
    let resolved = crate::api::config::features();
    let told: Vec<_> = Feature::ALL
        .iter()
        .map(|feature| {
            let spec = feature.spec();
            let status = resolved.status(*feature);
            json!({
                "slug": spec.slug,
                "lifecycle": format!("{:?}", spec.lifecycle).to_lowercase(),
                "reach": spec.reach.as_str(),
                "compiled": status.compiled,
                "enabled": status.enabled,
                "doc": spec.doc,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(told))
}

/// The same registry, said for one realm.
///
/// `enabled` is what this realm runs, which is the process's answer narrowed
/// by what the realm asked for. `asked` is the realm's own wish, absent where
/// it has never spoken, so an operator can tell "off because we turned it off"
/// from "off because this node was not started with it".
pub async fn list_for_realm(
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

    let held = store::providers::realm_features::read_wishes(&transaction)
        .await
        .map_err(|_| internal())?;

    let process = crate::api::config::features();
    let mut wishes = RealmWishes::none();
    for wish in &held {
        // A slug this build does not know is a realm carrying a name from
        // another one. It is kept in the table and ignored here rather than
        // failing the whole listing, which would leave an operator unable to
        // read their way out of it.
        wishes = wishes
            .clone()
            .with_wish(&wish.slug, wish.enabled)
            .unwrap_or(wishes);
    }
    let running = process.within_realm(&wishes);

    let told: Vec<_> = Feature::ALL
        .iter()
        .map(|feature| {
            let spec = feature.spec();
            let status = process.status(*feature);
            let wish = held.iter().find(|held| held.slug == spec.slug);
            json!({
                "slug": spec.slug,
                "lifecycle": format!("{:?}", spec.lifecycle).to_lowercase(),
                "reach": spec.reach.as_str(),
                "doc": spec.doc,
                "compiled": status.compiled,
                "in_process": status.enabled,
                "enabled": running.is_enabled(*feature),
                "asked": wish.map(|held| held.enabled),
                "changed_by": wish.map(|held| held.changed_by.clone()),
                "changed_at": wish.map(|held| held.changed_at),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(json!({ "items": told })))
}

#[derive(Deserialize)]
pub struct Wish {
    /// Absent returns the realm to whatever the process runs, which is not
    /// the same as asking for it to be off.
    pub enabled: Option<bool>,
}

/// Say what this realm wants of one capability.
///
/// Only a capability whose reach is the realm's may be named. The process's
/// own flags are refused here rather than stored and ignored, because a
/// setting that is kept and does nothing is how an operator comes to believe
/// something that is not so.
pub async fn set_wish(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    asked: web::Json<Wish>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, slug) = path.into_inner();
    let feature = Feature::by_slug(&slug).ok_or_else(|| {
        ApiError::with_detail(
            ErrorCode::ValidationError,
            "this build knows no such capability",
        )
    })?;
    if feature.spec().reach != Reach::Realm {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "this capability is the process's to set, not a realm's",
        ));
    }

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;

    match asked.enabled {
        Some(enabled) => {
            store::providers::realm_features::keep_wish(
                &transaction,
                feature.slug(),
                enabled,
                admin.context.principal.id(),
            )
            .await
            .map_err(|_| internal())?;
        }
        None => {
            store::providers::realm_features::forget_wish(&transaction, feature.slug())
                .await
                .map_err(|_| internal())?;
        }
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
