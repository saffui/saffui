//! What a login leaves behind, and the short lived things it hands out.

use deadpool_postgres::Transaction;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

/// What presenting a refresh token turned out to be.
///
/// Four answers rather than a boolean, because a caller cannot reconstruct them
/// from one. A refusal that does not say whether the session is gone or the
/// token is stale gets reported as the wrong thing, and a rotation that does not
/// say whether it rotated cannot tell a lost race from a replay.
#[derive(Debug, Clone)]
pub enum Refreshed {
    /// It was the token this session held, and a successor is now in its place.
    Rotated { session: ClientSessionModel },
    /// It was the token this session held, the realm does not rotate, and this
    /// is how many times it has now been presented.
    Reused {
        session: ClientSessionModel,
        presentations: i32,
    },
    /// It is not the token this session holds. Either it was rotated away or it
    /// was never this session's.
    Replayed,
    /// There is no such client session.
    Unknown,
}

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
                                      expiration, notes, current_refresh_token_use_count, offline, \
                                      requested_claims";

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

/// Record what a client got out of a login, one row per login and client.
///
/// An upsert, because a client authorizing a second time under one login is
/// renewing what it already has. A second row would make "the session's current
/// refresh token" ambiguous, and the renewal that found the older one would read
/// as a replay.
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
        col("requested_claims", &session.requested_claims),
    ]);

    let statement = format!(
        "{} ON CONFLICT (tenant, realm_id, user_session_id, client_id) DO UPDATE \
            SET session_id = EXCLUDED.session_id, \
                auth_method = EXCLUDED.auth_method, \
                redirect_uri = EXCLUDED.redirect_uri, \
                started_at = EXCLUDED.started_at, \
                expiration = EXCLUDED.expiration, \
                notes = EXCLUDED.notes, \
                current_refresh_token = EXCLUDED.current_refresh_token, \
                current_refresh_token_use_count = EXCLUDED.current_refresh_token_use_count, \
                offline = EXCLUDED.offline, \
                requested_claims = EXCLUDED.requested_claims",
        statement::insert("client_sessions", &set)
    );

    transaction
        .execute(statement.as_str(), &set.params())
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

/// End what one client got out of a login, leaving the login and every other
/// client alone.
///
/// What reuse detection reaches for. The row is the anchor for the whole token
/// family, so removing it strands the successor and every access token minted
/// from the chain, and touches nothing another client holds.
pub async fn close_client_session(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM client_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Advance a client session's refresh token, and say what happened.
///
/// One statement, because the caller has no way to hold the row between two.
/// Reading the current token, comparing it, and writing a successor as three
/// calls means three snapshots, and under read committed a second refresh can
/// land between any two of them. Here the comparison is the write: two
/// refreshes racing both name the same token, the second waits on the row lock
/// and then re-reads it, finds a token that is no longer the one it named, and
/// is told so.
///
/// Nothing reads the stored token out. A caller presents what it holds and is
/// told what that is, so the credential never leaves the database, and there is
/// no call that hands one to something that then has to decide what to do with
/// it.
///
/// A successor rotates and resets the count. No successor means the realm does
/// not rotate, so the presentation is counted instead and the caller weighs it
/// against `refresh_token_max_reuse`.
///
/// The token a rotation replaced is kept, with the instant it was replaced, and
/// is accepted again while `grace_from` has not passed it. Without that window a
/// client firing two refreshes at once, or retrying after a response that never
/// arrived, is indistinguishable from an attacker replaying a stolen token, and
/// an ordinary double submit destroys the session. Outside the window the
/// mismatch is a replay again.
pub async fn advance_refresh_token(
    transaction: &Transaction<'_>,
    session_id: &str,
    presented: &str,
    successor: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
    grace_from: chrono::DateTime<chrono::Utc>,
) -> StoreResult<Refreshed> {
    let statement = format!(
        "UPDATE client_sessions \
            SET current_refresh_token = COALESCE($3, current_refresh_token), \
                previous_refresh_token = \
                    CASE WHEN $3 IS NULL THEN previous_refresh_token ELSE current_refresh_token END, \
                previous_rotated_at = \
                    CASE WHEN $3 IS NULL THEN previous_rotated_at ELSE $5 END, \
                current_refresh_token_use_count = \
                    CASE WHEN $3 IS NULL THEN current_refresh_token_use_count + 1 ELSE 0 END \
          WHERE session_id = $1 \
            AND (current_refresh_token = $2 \
                 OR (previous_refresh_token = $2 AND previous_rotated_at > $4)) \
      RETURNING {CLIENT_SESSION_COLUMNS}, current_refresh_token_use_count AS presentations"
    );

    if let Some(row) = transaction
        .query_opt(
            statement.as_str(),
            &[&session_id, &presented, &successor, &grace_from, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    {
        let presentations: i32 = row.get("presentations");
        let session = read_client_session(row);
        return Ok(match successor {
            Some(_) => Refreshed::Rotated { session },
            None => Refreshed::Reused {
                session,
                presentations,
            },
        });
    }

    // Only to name the refusal. Both answers withhold a token either way, and
    // asking after the fact cannot make a token that was refused accepted.
    let known = transaction
        .query_opt(
            "SELECT 1 FROM client_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .is_some();

    Ok(if known {
        Refreshed::Replayed
    } else {
        Refreshed::Unknown
    })
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
        requested_claims: row.get("requested_claims"),
    }
}

/// What one client asked for by name, in one login.
/// Whether this refresh token is the one the client session currently
/// anchors on. A rotated-out token is not current, however unexpired.
pub async fn refresh_is_current(
    transaction: &Transaction<'_>,
    user_session_id: &str,
    client_id: &str,
    token_id: &str,
) -> StoreResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM client_sessions \
             WHERE user_session_id = $1 AND client_id = $2 AND current_refresh_token = $3",
            &[&user_session_id, &client_id, &token_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .is_some())
}

/// Close the client session a token belongs to, which ends every renewal
/// descended from it.
pub async fn close_client_session_of(
    transaction: &Transaction<'_>,
    user_session_id: &str,
    client_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM client_sessions WHERE user_session_id = $1 AND client_id = $2",
            &[&user_session_id, &client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

pub async fn requested_claims_of(
    transaction: &Transaction<'_>,
    user_session_id: &str,
    client_id: &str,
) -> StoreResult<Option<serde_json::Value>> {
    Ok(transaction
        .query_opt(
            "SELECT requested_claims FROM client_sessions \
             WHERE user_session_id = $1 AND client_id = $2",
            &[&user_session_id, &client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| row.get("requested_claims")))
}
