use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::brokering::{SamlBrokerSession, SamlLoginRequest, SamlLogoutRequest};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// Open one SAML authentication request.
pub async fn open_login_request(
    transaction: &Transaction<'_>,
    request: &SamlLoginRequest,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO saml_login_requests \
                 (tenant, realm_id, request_id, provider_alias, auth_session, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[
                &request.request_id,
                &request.provider_alias,
                &request.auth_session,
                &request.expires_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend the authentication request a response answers, exactly once.
///
/// Keyed on the identifier and the provider both, the expiry part of the match:
/// a replay finds nothing, a request sent to one provider cannot be answered at
/// another's endpoint, and a stale one cannot be spent.
pub async fn consume_login_request(
    transaction: &Transaction<'_>,
    request_id: &str,
    alias: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<SamlLoginRequest>> {
    Ok(transaction
        .query_opt(
            "DELETE FROM saml_login_requests \
             WHERE request_id = $1 AND provider_alias = $2 AND expires_at > $3 \
             RETURNING request_id, provider_alias, auth_session, expires_at",
            &[&request_id, &alias, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_login_request))
}

/// Drop the authentication requests that ran out unanswered.
pub async fn drop_expired_login_requests(
    transaction: &Transaction<'_>,
    now: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM saml_login_requests WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// Open one logout request sent to a provider.
pub async fn open_logout_request(
    transaction: &Transaction<'_>,
    request: &SamlLogoutRequest,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO saml_logout_requests \
                 (tenant, realm_id, request_id, provider_alias, resume_to, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[
                &request.request_id,
                &request.provider_alias,
                &request.resume_to,
                &request.expires_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend the logout request a provider's answer names, exactly once, matched as
/// an authentication request is.
pub async fn consume_logout_request(
    transaction: &Transaction<'_>,
    request_id: &str,
    alias: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<SamlLogoutRequest>> {
    Ok(transaction
        .query_opt(
            "DELETE FROM saml_logout_requests \
             WHERE request_id = $1 AND provider_alias = $2 AND expires_at > $3 \
             RETURNING request_id, provider_alias, resume_to, expires_at",
            &[&request_id, &alias, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_logout_request))
}

/// Drop the logout requests no provider answered in time.
pub async fn drop_expired_logout_requests(
    transaction: &Transaction<'_>,
    now: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM saml_logout_requests WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// Keep what a provider named a login by, for as long as the login stands.
pub async fn record_broker_session(
    transaction: &Transaction<'_>,
    session: &SamlBrokerSession,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO saml_broker_sessions \
                 (tenant, realm_id, session_id, provider_alias, name_id, name_id_format, \
                  name_qualifier, sp_name_qualifier, session_index) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6, $7",
            &[
                &session.session_id,
                &session.provider_alias,
                &session.name_id,
                &session.name_id_format,
                &session.name_qualifier,
                &session.sp_name_qualifier,
                &session.session_index,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// What a provider named a login by, when a provider opened it.
pub async fn read_broker_session(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> StoreResult<Option<SamlBrokerSession>> {
    Ok(transaction
        .query_opt(
            "SELECT session_id, provider_alias, name_id, name_id_format, name_qualifier, \
                    sp_name_qualifier, session_index \
             FROM saml_broker_sessions WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_session))
}

/// The logins a provider's logout request names that still stand: by the provider
/// and the name identifier's value, among the sessions it lists when it lists any.
/// A login already ended is not found again, so its clients are not told twice.
///
/// Neither the format nor the qualifiers are matched, and a login the provider
/// gave no session index is taken whatever the request lists: a provider may
/// leave out at logout what it wrote at sign-in, and a logout that finds nothing
/// leaves standing a login the provider meant to end.
pub async fn find_named_sessions(
    transaction: &Transaction<'_>,
    alias: &str,
    name_id: &str,
    session_indexes: &[String],
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT named.session_id FROM saml_broker_sessions named \
             JOIN user_sessions standing \
               ON standing.tenant = named.tenant AND standing.realm_id = named.realm_id \
              AND standing.session_id = named.session_id \
             WHERE named.provider_alias = $1 AND named.name_id = $2 \
               AND standing.state = 'logged-in' \
               AND (cardinality($3::text[]) = 0 OR named.session_index IS NULL \
                    OR named.session_index = ANY($3)) \
             ORDER BY named.session_id",
            &[&alias, &name_id, &session_indexes],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("session_id"))
        .collect())
}

fn read_login_request(row: Row) -> SamlLoginRequest {
    SamlLoginRequest {
        request_id: row.get("request_id"),
        provider_alias: row.get("provider_alias"),
        auth_session: row.get("auth_session"),
        expires_at: row.get("expires_at"),
    }
}

fn read_logout_request(row: Row) -> SamlLogoutRequest {
    SamlLogoutRequest {
        request_id: row.get("request_id"),
        provider_alias: row.get("provider_alias"),
        resume_to: row.get("resume_to"),
        expires_at: row.get("expires_at"),
    }
}

fn read_session(row: Row) -> SamlBrokerSession {
    SamlBrokerSession {
        session_id: row.get("session_id"),
        provider_alias: row.get("provider_alias"),
        name_id: row.get("name_id"),
        name_id_format: row.get("name_id_format"),
        name_qualifier: row.get("name_qualifier"),
        sp_name_qualifier: row.get("sp_name_qualifier"),
        session_index: row.get("session_index"),
    }
}
