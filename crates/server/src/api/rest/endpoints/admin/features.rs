use actix_web::HttpResponse;
use commons::error::ErrorCode;
use commons::feature::{Feature, FeatureSet, locally_compiled};
use commons::http::ApiError;
use serde_json::json;

/// What this build carries and what is on: the registry, answered from the
/// crates that can see their own cfg. Read-only by nature: the gating is
/// compile-time, so there is nothing here a request could turn.
pub async fn list() -> Result<HttpResponse, ApiError> {
    let resolved = FeatureSet::resolve("", |feature| {
        crypto::compiled_features().contains(&feature.slug()) || locally_compiled(feature)
    })
    .map_err(|_| ApiError::new(ErrorCode::InternalError))?;

    let told: Vec<_> = Feature::ALL
        .iter()
        .map(|feature| {
            let spec = feature.spec();
            let status = resolved.status(*feature);
            json!({
                "slug": spec.slug,
                "lifecycle": format!("{:?}", spec.lifecycle).to_lowercase(),
                "compiled": status.compiled,
                "enabled": status.enabled,
                "doc": spec.doc,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(told))
}
