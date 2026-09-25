//! The logout notices a login owes the clients that took part in it, from the
//! moment it ends until each client has heard, or never will.

use chrono::{DateTime, Utc};

use crate::error::{StoreError, StoreResult};
use crate::providers::events::notices::Settled;
use crate::tenancy::UnitOfWork;

/// A notice owed, as a pass claims it.
#[derive(Debug, Clone)]
pub struct OwedNotice {
    pub session_id: String,
    pub client_id: String,
    pub user_id: String,
    /// Counting the attempt this claim makes.
    pub attempts: i32,
}

/// Every client of a login that registered where to be told, owed a notice.
/// Read off what the login's clients hold, so it runs before they go.
const OWED_FROM: &str = "INSERT INTO logout_notices (tenant, realm_id, session_id, client_id, user_id) \
     SELECT held.tenant, held.realm_id, held.user_session_id, held.client_id, held.user_id \
     FROM client_sessions held JOIN clients told USING (tenant, realm_id, client_id) \
     WHERE COALESCE(told.backchannel_logout_uri, '') <> ''";

/// Owe the clients of one login their notice.
pub async fn owe_for_login(transaction: &UnitOfWork, session_id: &str) -> StoreResult<()> {
    let statement = format!("{OWED_FROM} AND held.user_session_id = $1 ON CONFLICT DO NOTHING");
    transaction
        .execute(statement.as_str(), &[&session_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Owe the clients of every login this person holds their notice, but those of
/// the one spared.
pub async fn owe_for_logins_of(
    transaction: &UnitOfWork,
    user_id: &str,
    sparing: Option<&str>,
) -> StoreResult<()> {
    let statement = format!(
        "{OWED_FROM} AND held.user_id = $1 AND held.user_session_id IS DISTINCT FROM $2 \
         ON CONFLICT DO NOTHING"
    );
    transaction
        .execute(statement.as_str(), &[&user_id, &sparing])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Owe one client of one login its notice: its access taken back while the
/// login goes on.
pub async fn owe_for_client_of_login(
    transaction: &UnitOfWork,
    session_id: &str,
    client_id: &str,
) -> StoreResult<()> {
    let statement = format!(
        "{OWED_FROM} AND held.user_session_id = $1 AND held.client_id = $2 \
         ON CONFLICT DO NOTHING"
    );
    transaction
        .execute(statement.as_str(), &[&session_id, &client_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Owe the clients of every login of this realm their notice.
pub async fn owe_for_every_login(transaction: &UnitOfWork, realm_id: &str) -> StoreResult<()> {
    let statement = format!("{OWED_FROM} AND held.realm_id = $1 ON CONFLICT DO NOTHING");
    transaction
        .execute(statement.as_str(), &[&realm_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Claim up to `ceiling` notices that are due, oldest first, and push each one's
/// next attempt out by `backoff_seconds` for every attempt made. A claim is a
/// lease: another pass skips what this one holds, and a pass that dies leaves
/// the notice due again once the lease runs out.
pub async fn claim_due(
    transaction: &UnitOfWork,
    ceiling: i64,
    backoff_seconds: i64,
) -> StoreResult<Vec<OwedNotice>> {
    Ok(transaction
        .query(
            "WITH picked AS MATERIALIZED ( \
                 SELECT tenant, realm_id, session_id, client_id FROM logout_notices \
                 WHERE state = 'pending' AND next_attempt_at <= now() \
                 ORDER BY owed_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED) \
             UPDATE logout_notices held SET attempts = held.attempts + 1, \
                    next_attempt_at = now() + make_interval(secs => $2::float8 * (held.attempts + 1)) \
             FROM picked \
             WHERE held.tenant = picked.tenant AND held.realm_id = picked.realm_id \
               AND held.session_id = picked.session_id AND held.client_id = picked.client_id \
             RETURNING held.session_id, held.client_id, held.user_id, held.attempts",
            &[&ceiling, &(backoff_seconds as f64)],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| OwedNotice {
            session_id: row.get("session_id"),
            client_id: row.get("client_id"),
            user_id: row.get("user_id"),
            attempts: row.get("attempts"),
        })
        .collect())
}

/// Put a notice away as its last attempt decided.
pub async fn settle(
    transaction: &UnitOfWork,
    session_id: &str,
    client_id: &str,
    settled: Settled,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE logout_notices SET state = $3 WHERE session_id = $1 AND client_id = $2",
            &[&session_id, &client_id, &settled.as_str()],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take away the notices settled about logins that ended before `cutoff`, and
/// say how many went. A notice still pending is still owed.
pub async fn drop_settled_before(
    transaction: &UnitOfWork,
    cutoff: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM logout_notices WHERE state <> 'pending' AND owed_at < $1",
            &[&cutoff],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
