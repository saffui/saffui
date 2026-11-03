//! The browsers a person signed in from, in constant SQL.

use async_trait::async_trait;
use saffui_core::login::store::{KnownBrowser, KnownBrowserStore};
use saffui_core::ports::storage::StorageError;
use uuid::Uuid;

use crate::work::PgUnitOfWork;

#[async_trait]
impl KnownBrowserStore for PgUnitOfWork {
    async fn remember_browser(
        &mut self,
        browser: &KnownBrowser,
        keep: u32,
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        // A browser kept for someone else keeps its owner: the condition of
        // the update leaves it as it was.
        self.execute_raw(
            "INSERT INTO known_browsers (tenant_id, realm_id, device_id, person_id, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id, device_id)
             DO UPDATE SET expires_at = EXCLUDED.expires_at
             WHERE known_browsers.person_id = EXCLUDED.person_id",
            &[
                &tenant,
                &realm,
                &browser.device,
                &browser.person,
                &browser.expires_at,
            ],
        )
        .await?;
        let keep = i64::from(keep);
        self.execute_raw(
            "DELETE FROM known_browsers
             WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
               AND device_id NOT IN (
                   SELECT device_id FROM known_browsers
                   WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                   ORDER BY expires_at DESC, device_id
                   LIMIT $4)",
            &[&tenant, &realm, &browser.person, &keep],
        )
        .await
        .map(|_| ())
    }

    async fn read_known_browser(
        &mut self,
        device: Uuid,
    ) -> Result<Option<KnownBrowser>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT person_id, expires_at FROM known_browsers
                 WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3",
                &[&tenant, &realm, &device],
            )
            .await?;
        Ok(rows.first().map(|row| KnownBrowser {
            device,
            person: row.get(0),
            expires_at: row.get(1),
        }))
    }
}
