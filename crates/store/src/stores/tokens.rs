//! Refresh tokens.

use async_trait::async_trait;
use saffui_core::login::session::{SessionKind, SessionState};
use saffui_core::ports::storage::StorageError;
use saffui_core::tokens::store::{
    EndedFamily, RefreshStore, RefreshToken, RevokedFamilies, StoredRefreshToken,
};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::insert::Insert;
use crate::query::update::Update;
use crate::schema::refresh_tokens;
use crate::work::PgUnitOfWork;

/// Constant SQL: one statement finds the token and marks it. Of two uses of
/// one token, the second waits for the first, then matches no row. A token of
/// a family revoked while it was being written was never seen by the
/// revocation: the revoked tokens of its family refuse it.
const SPEND_TOKEN: &str = "
    UPDATE refresh_tokens AS token SET used_at = $5
    WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3 AND client_id = $4
      AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $5
      AND NOT EXISTS (
          SELECT 1 FROM refresh_tokens AS kin
          WHERE kin.tenant_id = $1 AND kin.realm_id = $2
            AND kin.family_id = token.family_id AND kin.revoked_at IS NOT NULL)
    RETURNING token_digest, family_id, client_id, person_id, session_id, scopes,
              issued_at, expires_at";

/// Constant SQL: a token reads as revoked from the first revocation in its
/// family, so that one written while it ran reads as it is spent.
const READ_TOKEN: &str = "
    SELECT token_digest, family_id, client_id, person_id, session_id, scopes,
           issued_at, expires_at, used_at,
           coalesce(revoked_at, (
               SELECT min(kin.revoked_at) FROM refresh_tokens AS kin
               WHERE kin.tenant_id = $1 AND kin.realm_id = $2
                 AND kin.family_id = token.family_id AND kin.revoked_at IS NOT NULL))
    FROM refresh_tokens AS token
    WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3";

/// Constant SQL: the session a family lives in is found by a live token of
/// it, and ended when it is offline: it lived for that grant alone.
const END_OFFLINE_SESSION_OF_FAMILY: &str = "
    UPDATE sessions SET state = $5
    WHERE tenant_id = $1 AND realm_id = $2 AND kind = $4 AND state = $6
      AND session_id = (
          SELECT session_id FROM refresh_tokens
          WHERE tenant_id = $1 AND realm_id = $2 AND family_id = $3 AND revoked_at IS NULL
          LIMIT 1)
    RETURNING session_id";

/// Constant SQL: one revoked token refuses its whole family, so only those
/// that could still be spent are written, with the latest. A rotation in
/// flight spends the latest while this waits on it, and the token it writes
/// is out of sight: the latest is written all the same, by its digest.
/// What the family told is summed up from its live tokens, read by their
/// index: they are read, and not written.
const REVOKE_FAMILY: &str = "
    WITH live AS (
        SELECT token_digest, issued_at, count(*) OVER () AS tokens,
               max(used_at) OVER () AS last_used_at
        FROM refresh_tokens
        WHERE tenant_id = $1 AND realm_id = $2 AND family_id = $3 AND revoked_at IS NULL
        ORDER BY issued_at DESC
        LIMIT 1),
    revoked AS (
        UPDATE refresh_tokens SET revoked_at = $4
        WHERE tenant_id = $1 AND realm_id = $2 AND family_id = $3 AND revoked_at IS NULL
          AND (used_at IS NULL OR token_digest = (SELECT token_digest FROM live))
          AND NOT EXISTS (
              SELECT 1 FROM refresh_tokens AS kin
              WHERE kin.tenant_id = $1 AND kin.realm_id = $2
                AND kin.family_id = $3 AND kin.revoked_at IS NOT NULL)
        RETURNING 1)
    SELECT tokens, issued_at, last_used_at FROM live WHERE EXISTS (SELECT 1 FROM revoked)";

/// Constant SQL: the offline sessions a client holds tokens in for a person,
/// found by the sessions of the person, each by an index. They end before
/// their tokens are revoked, as `end_grant` of the core ends one grant.
const END_OFFLINE_SESSIONS_OF_CLIENT: &str = "
    UPDATE sessions AS held SET state = $5
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND kind = $6 AND state = $7
      AND EXISTS (
          SELECT 1 FROM refresh_tokens AS token
          WHERE token.tenant_id = $1 AND token.realm_id = $2
            AND token.session_id = held.session_id AND token.client_id = $4)";

/// Constant SQL: the tokens of a person are reached through their sessions,
/// each by an index, and each family of the client is revoked as
/// `REVOKE_FAMILY` revokes one, in the same statement, which answers one row
/// however many families end. A family a revoked token refuses already is
/// left as it was.
const REVOKE_FAMILIES_OF_CLIENT: &str = "
    WITH latest AS (
        SELECT DISTINCT ON (family_id) token_digest
        FROM refresh_tokens
        WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND client_id = $4
          AND revoked_at IS NULL
          AND session_id = ANY (ARRAY(
              SELECT session_id FROM sessions
              WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3))
        ORDER BY family_id, issued_at DESC),
    revoked AS (
        UPDATE refresh_tokens AS token SET revoked_at = $5
        WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND client_id = $4
          AND revoked_at IS NULL
          AND session_id = ANY (ARRAY(
              SELECT session_id FROM sessions
              WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3))
          AND (used_at IS NULL OR token_digest IN (SELECT token_digest FROM latest))
          AND NOT EXISTS (
              SELECT 1 FROM refresh_tokens AS kin
              WHERE kin.tenant_id = $1 AND kin.realm_id = $2
                AND kin.family_id = token.family_id AND kin.revoked_at IS NOT NULL)
        RETURNING family_id),
    ended AS (SELECT DISTINCT family_id FROM revoked)
    SELECT (SELECT count(*) FROM ended), (SELECT count(*) FROM revoked),
           ARRAY(SELECT family_id FROM ended ORDER BY family_id LIMIT $6)";

/// Constant SQL, on the sessions alone: the offline sessions a client holds
/// tokens in for a person, newest first, past the `kept` first, end.
const END_OLDEST_OFFLINE_SESSIONS: &str = "
    UPDATE sessions SET state = $6
    WHERE tenant_id = $1 AND realm_id = $2 AND state = $8
      AND session_id = ANY (ARRAY(
          SELECT held.session_id FROM sessions AS held
          WHERE held.tenant_id = $1 AND held.realm_id = $2 AND held.person_id = $3
            AND held.kind = $7 AND held.state = $8 AND held.expires_at > $5
            AND EXISTS (
                SELECT 1 FROM refresh_tokens AS token
                WHERE token.tenant_id = $1 AND token.realm_id = $2
                  AND token.session_id = held.session_id AND token.client_id = $4)
          ORDER BY held.expires_at DESC, held.session_id
          OFFSET $9))
    RETURNING session_id";

/// Reads a token from the first eight columns of a row: what it is, then
/// what became of it follows.
fn read_token_row(row: &Row) -> RefreshToken {
    RefreshToken {
        token_digest: row.get(0),
        family: row.get(1),
        client_id: row.get(2),
        person: row.get(3),
        session: row.get(4),
        scopes: row.get(5),
        issued_at: row.get(6),
        expires_at: row.get(7),
    }
}

#[async_trait]
impl RefreshStore for PgUnitOfWork {
    async fn insert_refresh_token(&mut self, token: &RefreshToken) -> Result<(), StorageError> {
        let insert = Insert::into(
            refresh_tokens::TABLE,
            vec![
                col(refresh_tokens::TOKEN_DIGEST, &token.token_digest),
                col(refresh_tokens::FAMILY_ID, &token.family),
                col(refresh_tokens::CLIENT_ID, &token.client_id),
                col(refresh_tokens::PERSON_ID, &token.person),
                col(refresh_tokens::SESSION_ID, &token.session),
                col(refresh_tokens::SCOPES, &token.scopes),
                col(refresh_tokens::ISSUED_AT, &token.issued_at),
                col(refresh_tokens::EXPIRES_AT, &token.expires_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn spend_refresh_token(
        &mut self,
        token_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RefreshToken>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                SPEND_TOKEN,
                &[&tenant, &realm, &token_digest, &client_id, &now],
            )
            .await?;
        Ok(rows.first().map(read_token_row))
    }

    async fn read_refresh_token(
        &mut self,
        token_digest: &[u8],
    ) -> Result<Option<StoredRefreshToken>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(READ_TOKEN, &[&tenant, &realm, &token_digest])
            .await?;
        Ok(rows.first().map(|row| StoredRefreshToken {
            token: read_token_row(row),
            used_at: row.get(8),
            revoked_at: row.get(9),
        }))
    }

    async fn end_offline_session_of_family(
        &mut self,
        family: Uuid,
    ) -> Result<Option<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (offline, ended, active) = (
            SessionKind::Offline.name(),
            SessionState::Ended.name(),
            SessionState::Active.name(),
        );
        let rows = self
            .read_raw(
                END_OFFLINE_SESSION_OF_FAMILY,
                &[&tenant, &realm, &family, &offline, &ended, &active],
            )
            .await?;
        Ok(rows.first().map(|row| row.get(0)))
    }

    async fn revoke_refresh_family(
        &mut self,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<EndedFamily>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(REVOKE_FAMILY, &[&tenant, &realm, &family, &now])
            .await?;
        rows.first()
            .map(|row| {
                Ok(EndedFamily {
                    tokens: u64::try_from(row.get::<_, i64>(0))
                        .map_err(|_| StorageError::Failed)?,
                    last_issued_at: row.get(1),
                    last_used_at: row.get(2),
                })
            })
            .transpose()
    }

    async fn revoke_refresh_families_of_client(
        &mut self,
        person: Uuid,
        client_id: &str,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<RevokedFamilies, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (offline, ended, active) = (
            SessionKind::Offline.name(),
            SessionState::Ended.name(),
            SessionState::Active.name(),
        );
        let offline_sessions = self
            .execute_raw(
                END_OFFLINE_SESSIONS_OF_CLIENT,
                &[
                    &tenant, &realm, &person, &client_id, &ended, &offline, &active,
                ],
            )
            .await?;
        let rows = self
            .read_raw(
                REVOKE_FAMILIES_OF_CLIENT,
                &[&tenant, &realm, &person, &client_id, &now, &i64::from(most)],
            )
            .await?;
        let row = rows.first().ok_or(StorageError::Failed)?;
        let count = |column: usize| {
            u64::try_from(row.get::<_, i64>(column)).map_err(|_| StorageError::Failed)
        };
        Ok(RevokedFamilies {
            families: count(0)?,
            tokens: count(1)?,
            named: row.get(2),
            offline_sessions,
        })
    }

    async fn end_oldest_offline_sessions(
        &mut self,
        person: Uuid,
        client_id: &str,
        kept: u32,
        now: OffsetDateTime,
    ) -> Result<Vec<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (offline, ended, active) = (
            SessionKind::Offline.name(),
            SessionState::Ended.name(),
            SessionState::Active.name(),
        );
        let rows = self
            .read_raw(
                END_OLDEST_OFFLINE_SESSIONS,
                &[
                    &tenant,
                    &realm,
                    &person,
                    &client_id,
                    &now,
                    &ended,
                    &offline,
                    &active,
                    &i64::from(kept),
                ],
            )
            .await?;
        let mut ended: Vec<Uuid> = rows.iter().map(|row| row.get(0)).collect();
        ended.sort_unstable();
        Ok(ended)
    }

    async fn revoke_refresh_tokens_of_session(
        &mut self,
        session: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let update = Update::table(
            refresh_tokens::TABLE,
            vec![col(refresh_tokens::REVOKED_AT, &now)],
            Criteria::new()
                .where_equal(refresh_tokens::SESSION_ID, &session)
                .where_null(refresh_tokens::REVOKED_AT),
        )
        .build()
        .map_err(|_| StorageError::Failed)?;
        self.execute(&update).await
    }

    async fn revoke_refresh_tokens_of_sessions(
        &mut self,
        sessions: &[Uuid],
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(
            "UPDATE refresh_tokens SET revoked_at = $3
             WHERE tenant_id = $1 AND realm_id = $2
               AND session_id = ANY($4) AND revoked_at IS NULL",
            &[&tenant, &realm, &now, &sessions],
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use pgcore::migrate::EMBEDDED;
    use pgcore::testkit::TestDatabase;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{READ_TOKEN, REVOKE_FAMILY, SPEND_TOKEN};

    /// A realm whose families were revoked by the hundred, and one family
    /// that grew a thousand tokens long and never was: whether it was is read
    /// from the revoked tokens alone, not from the length of the family, and
    /// a revocation reads the live tokens alone.
    #[tokio::test]
    async fn whether_a_family_was_revoked_is_read_from_its_revoked_tokens_alone() {
        let database = TestDatabase::create(EMBEDDED).await;
        let mut owner = database
            .plan("saffui_owner")
            .connect_directly()
            .await
            .expect("a connection");
        let (tenant, realm) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let planting = owner.transaction().await.expect("a transaction");
        planting
            .batch_execute(&format!(
                "SELECT set_config('saffui.tenant', '{tenant}', true),
                        set_config('saffui.realm', '{realm}', true);
                 INSERT INTO tenants VALUES ('{tenant}', 'acme', now());
                 INSERT INTO realms VALUES ('{tenant}', '{realm}', 'acme', true, now());
                 INSERT INTO persons (tenant_id, realm_id, person_id, username, email_verified,
                                      enabled, created_at)
                     VALUES ('{tenant}', '{realm}', '{realm}', 'ada', false, true, now());
                 INSERT INTO sessions VALUES ('{tenant}', '{realm}', '{realm}', '{realm}', '\\x00',
                                              'active', now(), now() + interval '1 hour',
                                              '{{pwd}}', 'browser');
                 INSERT INTO refresh_tokens
                     SELECT '{tenant}', '{realm}', int4send(n), uuid_in(md5((n % 1000)::text)::cstring),
                            'webapp', '{realm}', '{realm}', '{{openid}}', now(),
                            now() + interval '1 hour', now(), now()
                     FROM generate_series(1, 5000) AS n;
                 INSERT INTO refresh_tokens
                     SELECT '{tenant}', '{realm}', int8send(n::bigint), '{tenant}', 'webapp', '{realm}',
                            '{realm}', '{{openid}}', now(), now() + interval '1 hour',
                            CASE WHEN n < 1000 THEN now() END, NULL
                     FROM generate_series(1, 1000) AS n;"
            ))
            .await
            .expect("the tokens of a realm");
        planting.commit().await.expect("a commit");
        owner
            .batch_execute("ANALYZE refresh_tokens")
            .await
            .expect("statistics");
        let digest = 1000_i64.to_be_bytes().to_vec();
        let explain = |statement: &str| format!("EXPLAIN {statement}");

        let spend = owner
            .query(
                &explain(SPEND_TOKEN),
                &[
                    &tenant,
                    &realm,
                    &digest,
                    &"webapp",
                    &OffsetDateTime::now_utc(),
                ],
            )
            .await
            .expect("the plan of a spending");
        let read = owner
            .query(&explain(READ_TOKEN), &[&tenant, &realm, &digest])
            .await
            .expect("the plan of a reading");
        let revoke = owner
            .query(
                &explain(REVOKE_FAMILY),
                &[&tenant, &realm, &tenant, &OffsetDateTime::now_utc()],
            )
            .await
            .expect("the plan of a revocation");

        for (statement, plan, index) in [
            ("spend", spend, "refresh_tokens_revoked_family"),
            ("read", read, "refresh_tokens_revoked_family"),
            ("revoke", revoke, "refresh_tokens_live_family"),
        ] {
            let plan: Vec<String> = plan.iter().map(|row| row.get(0)).collect();
            assert!(
                plan.iter().any(|line| line.contains(index)),
                "{statement} reads {index}: {plan:#?}"
            );
        }
    }
}
