//! The security keys of people, and the enrollments they started, in
//! constant SQL.

use async_trait::async_trait;
use saffui_core::login::store::{SecurityKey, SecurityKeyStore};
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::work::PgUnitOfWork;

#[async_trait]
impl SecurityKeyStore for PgUnitOfWork {
    async fn insert_security_key(&mut self, key: &SecurityKey) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // A credential enrolled already, for anyone, writes nothing.
        let written = self
            .execute_raw(
                "INSERT INTO security_keys
                     (tenant_id, realm_id, credential_id, person_id, record, created_at, last_used_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (tenant_id, realm_id, credential_id) DO NOTHING",
                &[
                    &tenant,
                    &realm,
                    &key.credential_id,
                    &key.person,
                    &key.record,
                    &key.created_at,
                    &key.last_used_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn list_security_keys(&mut self, person: Uuid) -> Result<Vec<SecurityKey>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // The credential closes the order: two keys enrolled in one instant
        // are still listed the same way twice.
        let rows = self
            .read_raw(
                "SELECT credential_id, record, created_at, last_used_at FROM security_keys
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                 ORDER BY created_at, credential_id",
                &[&tenant, &realm, &person],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| SecurityKey {
                credential_id: row.get(0),
                person,
                record: row.get(1),
                created_at: row.get(2),
                last_used_at: row.get(3),
            })
            .collect())
    }

    async fn record_key_use(
        &mut self,
        judged: &SecurityKey,
        record: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let kept = record.unwrap_or(&judged.record);
        // One statement compares the key as it was read and replaces it. Of
        // two uses judged against one reading, the second waits for the
        // first, then matches no row: the first moved the instant of the last
        // use, if not the counter.
        let used = self
            .execute_raw(
                "UPDATE security_keys SET record = $6, last_used_at = $7
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                   AND credential_id = $4 AND record = $5
                   AND last_used_at IS NOT DISTINCT FROM $8",
                &[
                    &tenant,
                    &realm,
                    &judged.person,
                    &judged.credential_id,
                    &judged.record,
                    &kept,
                    &now,
                    &judged.last_used_at,
                ],
            )
            .await?;
        Ok(used == 1)
    }

    async fn delete_security_keys(&mut self, person: Uuid) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(
            "DELETE FROM security_keys WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3",
            &[&tenant, &realm, &person],
        )
        .await
    }

    async fn write_key_enrollment(
        &mut self,
        person: Uuid,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement keeps what was started, in place of what an earlier
        // start left.
        self.execute_raw(
            "INSERT INTO security_key_enrollments
                 (tenant_id, realm_id, person_id, state, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id, person_id) DO UPDATE
                 SET state = EXCLUDED.state, expires_at = EXCLUDED.expires_at",
            &[&tenant, &realm, &person, &state, &expires_at],
        )
        .await
        .map(|_| ())
    }

    async fn take_key_enrollment(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement finds what was started and removes it. Of two answers
        // to one challenge, the second finds no row.
        let rows = self
            .read_raw(
                "DELETE FROM security_key_enrollments
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND expires_at > $4
                 RETURNING state",
                &[&tenant, &realm, &person, &now],
            )
            .await?;
        Ok(rows.first().map(|row| row.get(0)))
    }
}
