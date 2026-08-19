//! A login while it is still happening, and what a realm counts against a user.

use deadpool_postgres::Transaction;
use models::sessions::login_failure::UserLoginFailure;
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// A login in progress, as it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSession {
    pub session_id: String,
    pub client_id: String,
    pub flow_id: String,
    /// Where the flow stands, and none before the first step runs.
    pub execution_id: Option<String>,
    /// Who this is, once a step has said so.
    pub user_id: Option<String>,
    pub redirect_uri: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub notes: Value,
}

/// Open a login.
pub async fn start(transaction: &Transaction<'_>, session: &AuthSession) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO auth_sessions \
                 (tenant, realm_id, session_id, client_id, flow_id, execution_id, user_id, \
                  redirect_uri, expires_at, notes) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &session.session_id,
                &session.client_id,
                &session.flow_id,
                &session.execution_id,
                &session.user_id,
                &session.redirect_uri,
                &session.expires_at,
                &session.notes,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A login in progress, if it is still in progress.
///
/// An expired one answers nothing rather than being handed back for a caller to
/// check, since every caller checking the same thing is every caller able to
/// forget.
pub async fn resume(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<AuthSession>> {
    Ok(transaction
        .query_opt(
            "SELECT session_id, client_id, flow_id, execution_id, user_id, redirect_uri, \
                    expires_at, notes \
             FROM auth_sessions WHERE session_id = $1 AND expires_at > now()",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_session))
}

/// Record what a step decided: who the user is, where the flow now stands, and
/// what the steps have to say to each other.
///
/// The notes are merged rather than replaced, so a step that writes one key does
/// not silently drop what another wrote.
pub async fn record_step(
    transaction: &Transaction<'_>,
    session_id: &str,
    user_id: Option<&str>,
    execution_id: Option<&str>,
    notes: &Value,
) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE auth_sessions \
             SET user_id = COALESCE($2, user_id), \
                 execution_id = COALESCE($3, execution_id), \
                 notes = notes || $4 \
             WHERE session_id = $1 AND expires_at > now()",
            &[&session_id, &user_id, &execution_id, notes],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Close a login, whether it succeeded or not.
pub async fn finish(transaction: &Transaction<'_>, session_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM auth_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Drop what stopped progressing.
pub async fn drop_expired(transaction: &Transaction<'_>) -> StoreResult<u64> {
    transaction
        .execute("DELETE FROM auth_sessions WHERE expires_at <= now()", &[])
        .await
        .map_err(|_| StoreError::Backend)
}

/// Count one failure and say what the count now stands at.
///
/// One statement. Reading the row and writing it back is two, and two attempts
/// failing at once then count as one: both read the same number and both write
/// the same successor. The window is computed here for the same reason.
pub async fn record_failure(
    transaction: &Transaction<'_>,
    user_id: &str,
    at: i64,
    ip_address: Option<&str>,
    lock_after: i64,
    lock_for_secs: i64,
) -> StoreResult<UserLoginFailure> {
    let row = transaction
        .query_one(
            "INSERT INTO user_login_failures \
                 (tenant, realm_id, user_id, num_failures, last_failure, last_ip_failure) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, 1, $2, $3 \
             ON CONFLICT (tenant, realm_id, user_id) DO UPDATE SET \
                 num_failures = user_login_failures.num_failures + 1, \
                 last_failure = EXCLUDED.last_failure, \
                 last_ip_failure = EXCLUDED.last_ip_failure, \
                 failed_login_not_before = CASE \
                     WHEN user_login_failures.num_failures + 1 >= $4 THEN $2 + $5 \
                     ELSE user_login_failures.failed_login_not_before \
                 END, \
                 updated_at = now() \
             RETURNING tenant, realm_id, user_id, num_failures, failed_login_not_before, \
                       last_failure, last_ip_failure",
            &[&user_id, &at, &ip_address, &lock_after, &lock_for_secs],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(read_failure(row))
}

/// What is counted against a user, if anything is.
pub async fn failures(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Option<UserLoginFailure>> {
    Ok(transaction
        .query_opt(
            "SELECT tenant, realm_id, user_id, num_failures, failed_login_not_before, \
                    last_failure, last_ip_failure \
             FROM user_login_failures WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_failure))
}

/// Clear the count, which a successful login does.
pub async fn clear_failures(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM user_login_failures WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_session(row: Row) -> AuthSession {
    AuthSession {
        session_id: row.get("session_id"),
        client_id: row.get("client_id"),
        flow_id: row.get("flow_id"),
        execution_id: row.get("execution_id"),
        user_id: row.get("user_id"),
        redirect_uri: row.get("redirect_uri"),
        expires_at: row.get("expires_at"),
        notes: row.get("notes"),
    }
}

/// The record carries no surrogate: the realm and the user are its identity, so
/// the model's identifier is built from them rather than stored beside them.
fn read_failure(row: Row) -> UserLoginFailure {
    let tenant: String = row.get("tenant");
    let realm_id: String = row.get("realm_id");
    let user_id: String = row.get("user_id");

    UserLoginFailure {
        failure_id: format!("{realm_id}:{user_id}"),
        tenant,
        realm_id,
        user_id,
        num_failures: row.get("num_failures"),
        failed_login_not_before: row.get("failed_login_not_before"),
        last_failure: row.get("last_failure"),
        last_ip_failure: row.get("last_ip_failure"),
    }
}
