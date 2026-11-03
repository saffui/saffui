//! The authenticator applications of people, in constant SQL.

use async_trait::async_trait;
use saffui_core::login::store::{AuthenticatorStore, TotpAuthenticator, TotpUse};
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::work::PgUnitOfWork;

#[async_trait]
impl AuthenticatorStore for PgUnitOfWork {
    async fn write_pending_totp(
        &mut self,
        authenticator: &TotpAuthenticator,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement writes the secret, or replaces one that was never
        // confirmed. Over a confirmed authenticator it writes nothing.
        let written = self
            .execute_raw(
                "INSERT INTO totp_authenticators
                     (tenant_id, realm_id, person_id, sealed_secret, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (tenant_id, realm_id, person_id) DO UPDATE
                     SET sealed_secret = EXCLUDED.sealed_secret,
                         created_at = EXCLUDED.created_at,
                         last_step = NULL
                     WHERE totp_authenticators.confirmed_at IS NULL",
                &[
                    &tenant,
                    &realm,
                    &authenticator.person,
                    &authenticator.sealed_secret,
                    &authenticator.created_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn read_totp(&mut self, person: Uuid) -> Result<Option<TotpAuthenticator>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT sealed_secret, confirmed_at, last_step, created_at
                 FROM totp_authenticators
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3",
                &[&tenant, &realm, &person],
            )
            .await?;
        Ok(rows.first().map(|row| TotpAuthenticator {
            person,
            sealed_secret: row.get(0),
            confirmed_at: row.get(1),
            last_step: row.get(2),
            created_at: row.get(3),
        }))
    }

    async fn accept_totp_step(
        &mut self,
        person: Uuid,
        judged: &[u8],
        step: i64,
        used_for: TotpUse,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let confirming = used_for == TotpUse::Confirmation;
        // One statement compares the step to the last one, the secret to the
        // one the code was judged against and the state to the use, and
        // records the step. Of two uses of one code, the second waits for the
        // first, then matches no row; a secret replaced meanwhile matches none.
        let accepted = self
            .execute_raw(
                "UPDATE totp_authenticators
                 SET last_step = $4, confirmed_at = coalesce(confirmed_at, $5)
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                   AND sealed_secret = $6 AND (confirmed_at IS NULL) = $7
                   AND (last_step IS NULL OR last_step < $4)",
                &[&tenant, &realm, &person, &step, &now, &judged, &confirming],
            )
            .await?;
        Ok(accepted == 1)
    }

    async fn delete_totp(&mut self, person: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let deleted = self
            .execute_raw(
                "DELETE FROM totp_authenticators
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3",
                &[&tenant, &realm, &person],
            )
            .await?;
        Ok(deleted == 1)
    }

    async fn count_code_attempt(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
    ) -> Result<u32, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement counts and answers. The row stays locked until the
        // unit of work ends: a second attempt of the same person waits for
        // the first to be judged.
        let rows = self
            .read_raw(
                "INSERT INTO code_attempts (tenant_id, realm_id, person_id, attempts, last_at)
                 VALUES ($1, $2, $3, 1, $4)
                 ON CONFLICT (tenant_id, realm_id, person_id) DO UPDATE SET
                     attempts = least(code_attempts.attempts, 1000000) + 1,
                     last_at = EXCLUDED.last_at
                 RETURNING attempts",
                &[&tenant, &realm, &person, &now],
            )
            .await?;
        let attempts: i32 = rows.first().ok_or(StorageError::Failed)?.get(0);
        u32::try_from(attempts).map_err(|_| StorageError::Failed)
    }

    async fn clear_code_attempts(&mut self, person: Uuid) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(
            "DELETE FROM code_attempts
             WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3",
            &[&tenant, &realm, &person],
        )
        .await
        .map(|_| ())
    }

    async fn holds_second_factor(&mut self, person: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT EXISTS (SELECT 1 FROM totp_authenticators
                                WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                                  AND confirmed_at IS NOT NULL)
                        OR EXISTS (SELECT 1 FROM security_keys
                                   WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3)",
                &[&tenant, &realm, &person],
            )
            .await?;
        Ok(rows.first().ok_or(StorageError::Failed)?.get(0))
    }
}
