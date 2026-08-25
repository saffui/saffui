use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    pub user_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
}

/// What this person has agreed to give this client, if anything.
pub async fn held(
    transaction: &Transaction<'_>,
    user_id: &str,
    client_id: &str,
) -> StoreResult<Option<Consent>> {
    Ok(transaction
        .query_opt(
            "SELECT user_id, client_id, scopes, granted_at FROM user_consents \
             WHERE user_id = $1 AND client_id = $2",
            &[&user_id, &client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Everything this person has agreed to, for a page that shows it back.
pub async fn of_user(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<Vec<Consent>> {
    Ok(transaction
        .query(
            "SELECT user_id, client_id, scopes, granted_at FROM user_consents \
             WHERE user_id = $1 ORDER BY client_id",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

/// Record what was agreed to, replacing what was agreed before.
///
/// Replacing rather than adding: the row says what stands now, and a person
/// who agreed to less than last time has agreed to less.
pub async fn keep(
    transaction: &Transaction<'_>,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
    at: DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO user_consents (tenant, realm_id, user_id, client_id, scopes, granted_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4 \
             ON CONFLICT (tenant, realm_id, user_id, client_id) DO UPDATE \
                 SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at",
            &[&user_id, &client_id, &scopes, &at],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn withdraw(
    transaction: &Transaction<'_>,
    user_id: &str,
    client_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM user_consents WHERE user_id = $1 AND client_id = $2",
            &[&user_id, &client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read(row: tokio_postgres::Row) -> Consent {
    Consent {
        user_id: row.get("user_id"),
        client_id: row.get("client_id"),
        scopes: row.get("scopes"),
        granted_at: row.get("granted_at"),
    }
}
