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
    /// How many of the window's decisions the p95 was read from.
    pub p95_sample: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMetrics {
    pub total: i64,
    pub signed_in: i64,
    pub sign_in_failed: i64,
    pub signed_out: i64,
    pub sms_throttled: i64,
}

/// The window's decisions, counted whole, with the p95 read from the
/// `p95_sample` most recent of them: a percentile sorts every row it reads, and
/// a month of a busy realm's decisions is a sort nobody should pay for a reading.
pub async fn decisions(
    transaction: &Transaction<'_>,
    since: DateTime<Utc>,
    p95_sample: i64,
) -> StoreResult<DecisionMetrics> {
    let row = transaction
        .query_one(
            "SELECT count(*)::bigint AS total, \
                    count(*) FILTER (WHERE reported = 'permit')::bigint AS permits, \
                    count(*) FILTER (WHERE reported = 'deny')::bigint AS denials, \
                    count(*) FILTER (WHERE computed = 'indeterminate')::bigint AS indeterminate, \
                    count(*) FILTER (WHERE reported <> computed)::bigint AS disagreements, \
                    avg(duration_us)::double precision AS average_duration_us, \
                    (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_us) \
                         FROM (SELECT duration_us FROM authz_decisions \
                               WHERE occurred_at >= $1 \
                               ORDER BY occurred_at DESC LIMIT $2) recent \
                    )::double precision AS p95_duration_us, \
                    least(count(*), $2)::bigint AS p95_sample \
             FROM authz_decisions WHERE occurred_at >= $1",
            &[&since, &p95_sample],
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
        p95_sample: row.get("p95_sample"),
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
