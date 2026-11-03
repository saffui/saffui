//! Refresh tokens.

use async_trait::async_trait;
use saffui_core::ports::storage::StorageError;
use saffui_core::tokens::store::{RefreshStore, RefreshToken, StoredRefreshToken};
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::insert::Insert;
use crate::query::update::Update;
use crate::schema::refresh_tokens;
use crate::work::PgUnitOfWork;

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
        // Constant SQL: one statement finds the token and marks it. Of two
        // uses of one token, the second waits for the first, then matches no row.
        // A token of a family revoked while it was being written was never seen
        // by the revocation: the revoked tokens of its family refuse it.
        let rows = self
            .read_raw(
                "UPDATE refresh_tokens AS token SET used_at = $5
                 WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3 AND client_id = $4
                   AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $5
                   AND NOT EXISTS (
                       SELECT 1 FROM refresh_tokens AS kin
                       WHERE kin.tenant_id = $1 AND kin.realm_id = $2
                         AND kin.family_id = token.family_id AND kin.revoked_at IS NOT NULL)
                 RETURNING token_digest, family_id, client_id, person_id, session_id, scopes,
                           issued_at, expires_at",
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
        // Constant SQL: a token reads as revoked from the first revocation in
        // its family, so that one written while it ran reads as it is spent.
        let rows = self
            .read_raw(
                "SELECT token_digest, family_id, client_id, person_id, session_id, scopes,
                        issued_at, expires_at, used_at,
                        coalesce(revoked_at, (
                            SELECT min(kin.revoked_at) FROM refresh_tokens AS kin
                            WHERE kin.tenant_id = $1 AND kin.realm_id = $2
                              AND kin.family_id = token.family_id))
                 FROM refresh_tokens AS token
                 WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3",
                &[&tenant, &realm, &token_digest],
            )
            .await?;
        Ok(rows.first().map(|row| StoredRefreshToken {
            token: read_token_row(row),
            used_at: row.get(8),
            revoked_at: row.get(9),
        }))
    }

    async fn revoke_refresh_family(
        &mut self,
        family: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let update = Update::table(
            refresh_tokens::TABLE,
            vec![col(refresh_tokens::REVOKED_AT, &now)],
            Criteria::new()
                .where_equal(refresh_tokens::FAMILY_ID, &family)
                .where_null(refresh_tokens::REVOKED_AT),
        )
        .build()
        .map_err(|_| StorageError::Failed)?;
        self.execute(&update).await
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
}
