use actix_web::HttpResponse;
use commons::feature::Feature;
use commons::http::ApiError;
use serde_json::json;

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
                "compiled": status.compiled,
                "enabled": status.enabled,
                "doc": spec.doc,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(told))
}
