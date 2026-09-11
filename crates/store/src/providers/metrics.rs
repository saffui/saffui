use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionMetrics {
    pub total: i64,
    pub permits: i64,
    pub denials: i64,
    pub indeterminate: i64,
    pub disagreements: i64,
    pub average_duration_us: Option<f64>,
    pub p95_duration_us: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMetrics {
    pub total: i64,
    pub signed_in: i64,
    pub sign_in_failed: i64,
    pub signed_out: i64,
    pub sms_throttled: i64,
}

pub async fn decisions(
    transaction: &Transaction<'_>,
    since: DateTime<Utc>,
) -> StoreResult<DecisionMetrics> {
    let row = transaction
        .query_one(
            "SELECT count(*)::bigint AS total, \
                    count(*) FILTER (WHERE reported = 'permit')::bigint AS permits, \
                    count(*) FILTER (WHERE reported = 'deny')::bigint AS denials, \
                    count(*) FILTER (WHERE computed = 'indeterminate')::bigint AS indeterminate, \
                    count(*) FILTER (WHERE reported <> computed)::bigint AS disagreements, \
                    avg(duration_us)::double precision AS average_duration_us, \
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_us)::double precision \
                        AS p95_duration_us \
             FROM authz_decisions WHERE occurred_at >= $1",
            &[&since],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(DecisionMetrics {
        total: row.get("total"),
        permits: row.get("permits"),
        denials: row.get("denials"),
        indeterminate: row.get("indeterminate"),
        disagreements: row.get("disagreements"),
        average_duration_us: row.get("average_duration_us"),
        p95_duration_us: row.get("p95_duration_us"),
    })
}

pub async fn logins(transaction: &Transaction<'_>, since: i64) -> StoreResult<LoginMetrics> {
    let row = transaction
        .query_one(
            "SELECT count(*)::bigint AS total, \
                    count(*) FILTER (WHERE kind = 'signed_in')::bigint AS signed_in, \
                    count(*) FILTER (WHERE kind = 'sign_in_failed')::bigint AS sign_in_failed, \
                    count(*) FILTER (WHERE kind = 'signed_out')::bigint AS signed_out, \
                    count(*) FILTER (WHERE kind = 'sms_throttled')::bigint AS sms_throttled \
             FROM login_events WHERE recorded_at >= $1",
            &[&since],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(LoginMetrics {
        total: row.get("total"),
        signed_in: row.get("signed_in"),
        sign_in_failed: row.get("sign_in_failed"),
        signed_out: row.get("signed_out"),
        sms_throttled: row.get("sms_throttled"),
    })
}
