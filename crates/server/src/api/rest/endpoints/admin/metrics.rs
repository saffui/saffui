use actix_web::{HttpResponse, web};
use chrono::{Duration, Utc};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use serde::Deserialize;
use store::tenancy::Tenancy;

use crate::api::rest::endpoints::within;
use crate::middleware::admin_guard::Admin;

const DEFAULT_WINDOW_SECONDS: i64 = 86_400;
const MAX_WINDOW_SECONDS: i64 = 2_592_000;

#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    pub window_seconds: Option<i64>,
}

fn window_seconds(asked: &MetricsQuery) -> Result<i64, ApiError> {
    let seconds = asked.window_seconds.unwrap_or(DEFAULT_WINDOW_SECONDS);
    if seconds <= 0 {
        return Err(ApiError::new(ErrorCode::BadRequest));
    }
    Ok(seconds.min(MAX_WINDOW_SECONDS))
}

pub async fn read(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    query: web::Query<MetricsQuery>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let seconds = window_seconds(&query)?;
    let now = Utc::now();
    let since = now - Duration::seconds(seconds);
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;

    let decisions = store::providers::metrics::decisions(&transaction, since)
        .await
        .map_err(|_| internal())?;
    let logins = store::providers::metrics::logins(&transaction, since.timestamp())
        .await
        .map_err(|_| internal())?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "window_seconds": seconds,
        "since": since,
        "decisions": {
            "total": decisions.total,
            "permits": decisions.permits,
            "denials": decisions.denials,
            "indeterminate": decisions.indeterminate,
            "disagreements": decisions.disagreements,
            "average_duration_us": decisions.average_duration_us,
            "p95_duration_us": decisions.p95_duration_us,
        },
        "logins": {
            "total": logins.total,
            "signed_in": logins.signed_in,
            "sign_in_failed": logins.sign_in_failed,
            "signed_out": logins.signed_out,
            "sms_throttled": logins.sms_throttled,
        },
    })))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_has_a_bounded_default_and_refuses_zero() {
        assert_eq!(
            window_seconds(&MetricsQuery {
                window_seconds: None
            })
            .unwrap(),
            DEFAULT_WINDOW_SECONDS
        );
        assert_eq!(
            window_seconds(&MetricsQuery {
                window_seconds: Some(MAX_WINDOW_SECONDS + 1),
            })
            .unwrap(),
            MAX_WINDOW_SECONDS
        );
        let refused = window_seconds(&MetricsQuery {
            window_seconds: Some(0),
        })
        .unwrap_err();
        assert_eq!(
            actix_web::ResponseError::status_code(&refused),
            actix_web::http::StatusCode::BAD_REQUEST
        );
    }
}
