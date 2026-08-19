//! What a login leaves behind, and the short lived things it hands out.

use deadpool_postgres::Transaction;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const SESSION_COLUMNS: &str = "tenant, realm_id, session_id, user_id, login_username, \
                               broker_session_id, broker_user_id, auth_method, ip_address, \
                               started_at, auth_time, loa, expiration, state, remember_me, \
                               last_session_refresh, is_offline, notes";

/// What a client got out of a login, without the token it refreshes with.
///
/// Reaching that is [`refresh_token`], so every place that holds one is a place
/// somebody wrote the call.
const CLIENT_SESSION_COLUMNS: &str = "tenant, realm_id, session_id, user_session_id, user_id, \
                                      client_id, auth_method, redirect_uri, started_at, \
                                      expiration, notes, current_refresh_token_use_count, offline";

/// Open a session.
pub async fn open(transaction: &Transaction<'_>, session: &UserSessionModel) -> StoreResult<()> {
    let notes = notes_json(session.notes.as_ref())?;
    let set = WriteSet::insert(vec![
        col("tenant", &session.tenant),
        col("realm_id", &session.realm_id),
        col("session_id", &session.session_id),
        col("user_id", &session.user_id),
        col("login_username", &session.login_username),
        col("broker_session_id", &session.broker_session_id),
        col("broker_user_id", &session.broker_user_id),
        col("auth_method", &session.auth_method),
        col("ip_address", &session.ip_address),
        col("started_at", &session.started_at),
        col("auth_time", &session.auth_time),
        col("loa", &session.loa),
        col("expiration", &session.expiration),
        col("state", &session.state),
        col("remember_me", &session.remember_me),
        col("last_session_refresh", &session.last_session_refresh),
        col("is_offline", &session.is_offline),
        col("notes", &notes),
    ]);

    transaction
        .execute(
            statement::insert("user_sessions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One session by identifier.
pub async fn load(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<UserSessionModel>> {
    let statement = format!("SELECT {SESSION_COLUMNS} FROM user_sessions WHERE session_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&session_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_session))
}

/// Every session a user holds, newest first.
pub async fn load_for_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<UserSessionModel>> {
    let statement = format!(
        "SELECT {SESSION_COLUMNS} FROM user_sessions WHERE user_id = $1 \
         ORDER BY started_at DESC, session_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_session)
        .collect())
}

/// Record that the user authenticated again, and how strongly.
///
/// The instant and the level move together. A level raised without the instant
/// attests to a strength reached at a time nothing recorded, and an instant
/// moved without the level says a step up happened that did not.
pub async fn record_authentication(
    transaction: &Transaction<'_>,
    session_id: &str,
    auth_time: i64,
    loa: Option<i32>,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![col("auth_time", &auth_time), col("loa", &loa)],
        vec![col("session_id", &session_id)],
    );

    let changed = transaction
        .execute(
            statement::update("user_sessions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Move a session to another state.
pub async fn set_state(
    transaction: &Transaction<'_>,
    session_id: &str,
    state: UserSessionState,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![col("state", &state)],
        vec![col("session_id", &session_id)],
    );

    let changed = transaction
        .execute(
            statement::update("user_sessions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// End a session, and everything a client got out of it.
pub async fn close(transaction: &Transaction<'_>, session_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM user_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record what a client got out of a login.
pub async fn open_client_session(
    transaction: &Transaction<'_>,
    session: &ClientSessionModel,
) -> StoreResult<()> {
    let notes = notes_json(session.notes.as_ref())?;
    let use_count = session.current_refresh_token_use_count.unwrap_or(0);
    let set = WriteSet::insert(vec![
        col("tenant", &session.tenant),
        col("realm_id", &session.realm_id),
        col("session_id", &session.session_id),
        col("user_session_id", &session.user_session_id),
        col("user_id", &session.user_id),
        col("client_id", &session.client_id),
        col("auth_method", &session.auth_method),
        col("redirect_uri", &session.redirect_uri),
        col("started_at", &session.started_at),
        col("expiration", &session.expiration),
        col("notes", &notes),
        col("current_refresh_token", &session.current_refresh_token),
        col("current_refresh_token_use_count", &use_count),
        col("offline", &session.offline),
    ]);

    transaction
        .execute(
            statement::insert("client_sessions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// What every client got out of one login.
pub async fn client_sessions_of(
    transaction: &Transaction<'_>,
    user_session_id: &str,
) -> StoreResult<Vec<ClientSessionModel>> {
    let statement = format!(
        "SELECT {CLIENT_SESSION_COLUMNS} FROM client_sessions WHERE user_session_id = $1 \
         ORDER BY client_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_session_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_client_session)
        .collect())
}

/// The token a client session refreshes with, and how many times it has been
/// presented.
///
/// Its own call, so reaching a bearer credential is deliberate. The count comes
/// with it because the two are only useful together: a token that matches and
/// has been presented before is a replay, and neither half says that alone.
pub async fn refresh_token(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<(String, i32)>> {
    Ok(transaction
        .query_opt(
            "SELECT current_refresh_token, current_refresh_token_use_count \
             FROM client_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| {
            row.get::<_, Option<String>>("current_refresh_token")
                .map(|token| (token, row.get("current_refresh_token_use_count")))
        }))
}

/// Count one more presentation of the current token.
///
/// Counts rather than flags. A flag says a token was reused and a count says how
/// far the reuse went, which is the difference between knowing something
/// happened and knowing what to revoke.
pub async fn count_refresh_use(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<i32>> {
    Ok(transaction
        .query_opt(
            "UPDATE client_sessions \
             SET current_refresh_token_use_count = current_refresh_token_use_count + 1 \
             WHERE session_id = $1 RETURNING current_refresh_token_use_count",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get(0)))
}

/// Put a new refresh token in place of the one presented.
///
/// A compare and swap rather than a write: the caller states which token it
/// believes is current, and the row moves only if that is still true. Two
/// refreshes racing on one session both read the same token and both mint a
/// successor, and a plain write would let the later one land, leaving a client
/// holding a token the row no longer names. Here one of them loses and is told
/// so, which is the difference between a rotation and a silent overwrite.
///
/// The count goes back to zero with the swap. It counts presentations of the
/// current token, so carrying it across a rotation would refuse a fresh token
/// for what its predecessor was used for.
pub async fn rotate_refresh_token(
    transaction: &Transaction<'_>,
    session_id: &str,
    expected: Option<&str>,
    replacement: &str,
) -> StoreResult<bool> {
    let swapped = transaction
        .execute(
            "UPDATE client_sessions \
             SET current_refresh_token = $3, current_refresh_token_use_count = 0 \
             WHERE session_id = $1 AND current_refresh_token IS NOT DISTINCT FROM $2",
            &[&session_id, &expected, &replacement],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(swapped > 0)
}

fn notes_json(
    notes: Option<&std::collections::HashMap<String, String>>,
) -> StoreResult<Option<serde_json::Value>> {
    notes
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn read_notes(row: &Row) -> Option<std::collections::HashMap<String, String>> {
    row.get::<_, Option<serde_json::Value>>("notes")
        .and_then(|value| serde_json::from_value(value).ok())
}

fn read_session(row: Row) -> UserSessionModel {
    UserSessionModel {
        notes: read_notes(&row),
        tenant: row.get("tenant"),
        session_id: row.get("session_id"),
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        login_username: row.get("login_username"),
        broker_session_id: row.get("broker_session_id"),
        broker_user_id: row.get("broker_user_id"),
        auth_method: row.get("auth_method"),
        ip_address: row.get("ip_address"),
        started_at: row.get("started_at"),
        auth_time: row.get("auth_time"),
        loa: row.get("loa"),
        expiration: row.get("expiration"),
        state: row.get("state"),
        remember_me: row.get("remember_me"),
        last_session_refresh: row.get("last_session_refresh"),
        is_offline: row.get("is_offline"),
    }
}

fn read_client_session(row: Row) -> ClientSessionModel {
    ClientSessionModel {
        notes: read_notes(&row),
        tenant: row.get("tenant"),
        session_id: row.get("session_id"),
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        user_session_id: row.get("user_session_id"),
        client_id: row.get("client_id"),
        auth_method: row.get("auth_method"),
        redirect_uri: row.get("redirect_uri"),
        started_at: row.get("started_at"),
        expiration: row.get("expiration"),
        // Never read here. Reaching a bearer credential is its own call.
        current_refresh_token: None,
        current_refresh_token_use_count: row.get("current_refresh_token_use_count"),
        offline: row.get("offline"),
    }
}
