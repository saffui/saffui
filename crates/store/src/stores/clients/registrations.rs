//! What registration through the protocol keeps. Spending an initial
//! access token, and replacing or ending the token of a registration, are
//! constant SQL: each is one statement two requests cannot both win. An
//! ended registration stays until retention removes it with its client.

use async_trait::async_trait;
use saffui_core::clients::registration::InitialAccessToken;
use saffui_core::clients::store::{ListWindow, RegistrationCounts, RegistrationStore};
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::list_query::ListQuery;
use crate::query::select::SortDirection;
use crate::schema::{client_registrations, initial_access_tokens};
use crate::work::PgUnitOfWork;

/// What a list of initial access tokens reads: nothing of their digests.
const INITIAL_TOKEN: &[Column] = &[
    initial_access_tokens::TOKEN_ID,
    initial_access_tokens::USES_LEFT,
    initial_access_tokens::EXPIRES_AT,
    initial_access_tokens::CREATED_AT,
    initial_access_tokens::CREATED_BY,
];

/// Of two uses of the last use of a token, the second waits for the first,
/// then finds none left.
const SPEND_INITIAL_TOKEN: &str = "
    UPDATE initial_access_tokens SET uses_left = uses_left - 1
    WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3
      AND uses_left > 0 AND expires_at > $4
    RETURNING token_id";

/// The live tokens of the realm, taken until the commit, then counted by a
/// statement of its own. While one lives, two administrators count one
/// after the other: the second waits for the first, then counts the token
/// it made. With none, nothing is taken, and the bound is far.
const TAKE_LIVE_INITIAL_TOKENS: &str = "
    SELECT 1 FROM initial_access_tokens
    WHERE tenant_id = $1 AND realm_id = $2 AND uses_left > 0 AND expires_at > $3
    FOR NO KEY UPDATE";

const COUNT_LIVE_INITIAL_TOKENS: &str = "
    SELECT count(*) FROM initial_access_tokens
    WHERE tenant_id = $1 AND realm_id = $2 AND uses_left > 0 AND expires_at > $3";

/// The token of that digest, if it has a use left and has not expired.
const FIND_LIVE_INITIAL_TOKEN: &str = "
    SELECT token_id FROM initial_access_tokens
    WHERE tenant_id = $1 AND realm_id = $2 AND token_digest = $3
      AND uses_left > 0 AND expires_at > $4";

const DELETE_INITIAL_TOKEN: &str = "
    DELETE FROM initial_access_tokens
    WHERE tenant_id = $1 AND realm_id = $2 AND token_id = $3";

const MATCH_REGISTRATION: &str = "
    SELECT 1 FROM client_registrations
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND token_digest = $4";

/// Of two requests that present one token, the second waits for the first,
/// then finds the digest replaced.
const ROTATE_REGISTRATION: &str = "
    UPDATE client_registrations SET token_digest = $5
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND token_digest = $4";

/// An ended registration has no token: none presented matches it again.
const END_REGISTRATION: &str = "
    UPDATE client_registrations SET token_digest = NULL, ended_at = $5
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND token_digest = $4";

const END_REGISTRATION_AS_ADMINISTRATOR: &str = "
    UPDATE client_registrations SET token_digest = NULL, ended_at = $4
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND ended_at IS NULL";

/// Every client a registration made, ended or not, and those made since
/// `$3`, in one read of the index of the registrations of the realm.
const COUNT_REGISTRATIONS: &str = "
    SELECT count(*), count(*) FILTER (WHERE registered_at >= $3) FROM client_registrations
    WHERE tenant_id = $1 AND realm_id = $2";

/// The count a statement read in `column` of its one row.
fn read_count(rows: &[Row], column: usize) -> Result<u64, StorageError> {
    let counted: i64 = rows.first().ok_or(StorageError::Failed)?.get(column);
    u64::try_from(counted).map_err(|_| StorageError::Failed)
}

fn read_initial_token(row: &Row) -> Result<InitialAccessToken, StorageError> {
    let uses_left: i32 = row.get(1);
    Ok(InitialAccessToken {
        id: row.get(0),
        uses_left: u32::try_from(uses_left).map_err(|_| StorageError::Failed)?,
        expires_at: row.get(2),
        created_at: row.get(3),
        created_by: row.get(4),
    })
}

/// The newest first. The identifier breaks a tie: the order is total, so a
/// window neither repeats a row nor skips one.
fn order_initial_tokens(window: ListWindow) -> ListQuery {
    ListQuery::new(window)
        .sorted_by(initial_access_tokens::CREATED_AT, SortDirection::Descending)
        .sorted_by(initial_access_tokens::TOKEN_ID, SortDirection::Ascending)
}

#[async_trait]
impl RegistrationStore for PgUnitOfWork {
    async fn insert_initial_access_token(
        &mut self,
        token: &InitialAccessToken,
        token_digest: &[u8],
    ) -> Result<(), StorageError> {
        let uses_left = i32::try_from(token.uses_left).map_err(|_| StorageError::Failed)?;
        let insert = Insert::into(
            initial_access_tokens::TABLE,
            vec![
                col(initial_access_tokens::TOKEN_ID, &token.id),
                col(initial_access_tokens::TOKEN_DIGEST, &token_digest),
                col(initial_access_tokens::USES_LEFT, &uses_left),
                col(initial_access_tokens::EXPIRES_AT, &token.expires_at),
                col(initial_access_tokens::CREATED_AT, &token.created_at),
                col(initial_access_tokens::CREATED_BY, &token.created_by),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn count_live_initial_access_tokens(
        &mut self,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.read_raw(TAKE_LIVE_INITIAL_TOKENS, &[&tenant, &realm, &now])
            .await?;
        let rows = self
            .read_raw(COUNT_LIVE_INITIAL_TOKENS, &[&tenant, &realm, &now])
            .await?;
        read_count(&rows, 0)
    }

    async fn list_initial_access_tokens(
        &mut self,
        window: ListWindow,
    ) -> Result<Vec<InitialAccessToken>, StorageError> {
        let ordered = order_initial_tokens(window);
        let page = ordered.select(initial_access_tokens::TABLE, INITIAL_TOKEN);
        self.read_all(&page)
            .await?
            .iter()
            .map(read_initial_token)
            .collect()
    }

    async fn spend_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        Ok(self
            .read_raw(SPEND_INITIAL_TOKEN, &[&tenant, &realm, &token_digest, &now])
            .await?
            .first()
            .map(|row| row.get(0)))
    }

    async fn find_live_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        Ok(self
            .read_raw(
                FIND_LIVE_INITIAL_TOKEN,
                &[&tenant, &realm, &token_digest, &now],
            )
            .await?
            .first()
            .map(|row| row.get(0)))
    }

    async fn delete_initial_access_token(&mut self, token_id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(DELETE_INITIAL_TOKEN, &[&tenant, &realm, &token_id])
            .await?;
        Ok(removed == 1)
    }

    async fn insert_client_registration(
        &mut self,
        client_id: &str,
        token_digest: &[u8],
        registered_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let insert = Insert::into(
            client_registrations::TABLE,
            vec![
                col(client_registrations::CLIENT_ID, &client_id),
                col(client_registrations::TOKEN_DIGEST, &token_digest),
                col(client_registrations::REGISTERED_AT, &registered_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn matches_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let found = self
            .read_raw(
                MATCH_REGISTRATION,
                &[&tenant, &realm, &client_id, &presented_digest],
            )
            .await?;
        Ok(!found.is_empty())
    }

    async fn rotate_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        next_digest: &[u8],
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rotated = self
            .execute_raw(
                ROTATE_REGISTRATION,
                &[&tenant, &realm, &client_id, &presented_digest, &next_digest],
            )
            .await?;
        Ok(rotated == 1)
    }

    async fn end_client_registration(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let ended = self
            .execute_raw(
                END_REGISTRATION,
                &[&tenant, &realm, &client_id, &presented_digest, &now],
            )
            .await?;
        Ok(ended == 1)
    }

    async fn end_client_registration_as_administrator(
        &mut self,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let ended = self
            .execute_raw(
                END_REGISTRATION_AS_ADMINISTRATOR,
                &[&tenant, &realm, &client_id, &now],
            )
            .await?;
        Ok(ended == 1)
    }

    async fn count_registrations(
        &mut self,
        since: OffsetDateTime,
    ) -> Result<RegistrationCounts, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(COUNT_REGISTRATIONS, &[&tenant, &realm, &since])
            .await?;
        Ok(RegistrationCounts {
            registered: read_count(&rows, 0)?,
            since: read_count(&rows, 1)?,
        })
    }
}
