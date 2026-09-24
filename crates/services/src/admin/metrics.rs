//! What the console's metrics read: the decision journal and the sign-in log,
//! counted over a window.

use chrono::{DateTime, Utc};
use store::providers::events::metrics::{self, DecisionMetrics, LoginMetrics};
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the metrics could not be read")]
pub struct Uncounted;

/// The window's decisions, with the p95 read from the `p95_sample` most recent
/// of them, and the window's sign-ins.
pub async fn read_metrics(
    transaction: &UnitOfWork,
    since: DateTime<Utc>,
    p95_sample: i64,
) -> Result<(DecisionMetrics, LoginMetrics), Uncounted> {
    let decisions = metrics::decisions(transaction, since, p95_sample)
        .await
        .map_err(|_| Uncounted)?;
    let logins = metrics::logins(transaction, since.timestamp())
        .await
        .map_err(|_| Uncounted)?;
    Ok((decisions, logins))
}
