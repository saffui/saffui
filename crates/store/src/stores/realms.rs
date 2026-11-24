use async_trait::async_trait;
use saffui_core::ports::storage::StorageError;
use saffui_core::tenancy::store::RealmStore;
use saffui_core::tenancy::{Realm, RealmId, RealmName, Tenant, TenantId};

use crate::query::bind::col;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::Select;
use crate::schema::{realm_settings, realms, tenants};
use crate::work::PgUnitOfWork;

const REALM: &[Column] = &[realms::NAME, realms::ENABLED, realms::CREATED_AT];

const SETTINGS: &[Column] = &[realm_settings::SETTINGS];

/// Constant SQL: the settings of the realm, and their row stays taken until
/// the commit. A realm without settings has no row to take: it is closed.
const READ_SETTINGS_FOR_UPDATE: &str = "
    SELECT settings FROM realm_settings
    WHERE tenant_id = $1 AND realm_id = $2
    FOR NO KEY UPDATE";

/// Constant SQL: the settings of the realm, and their row stays shared
/// until the commit: a writer waits, another reader that shares it does not.
const READ_SETTINGS_FOR_SHARE: &str = "
    SELECT settings FROM realm_settings
    WHERE tenant_id = $1 AND realm_id = $2
    FOR SHARE";

/// Constant SQL: one statement writes the first settings of a realm, or
/// replaces those it has.
const WRITE_SETTINGS: &str = "
    INSERT INTO realm_settings (tenant_id, realm_id, settings) VALUES ($1, $2, $3)
    ON CONFLICT (tenant_id, realm_id) DO UPDATE SET settings = EXCLUDED.settings";

#[async_trait]
impl RealmStore for PgUnitOfWork {
    async fn insert_tenant(&mut self, tenant: &Tenant) -> Result<(), StorageError> {
        // The key is written from the scope: a tenant other than the one this
        // unit of work is bound to is refused here, before row security is.
        if tenant.id != saffui_core::ports::storage::UnitOfWork::scope(self).tenant() {
            return Err(self.refuse_out_of_scope());
        }
        let insert = Insert::into(
            tenants::TABLE,
            vec![
                col(tenants::NAME, &tenant.name),
                col(tenants::CREATED_AT, &tenant.created_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn insert_realm(&mut self, realm: &Realm) -> Result<(), StorageError> {
        let scope = saffui_core::ports::storage::UnitOfWork::scope(self);
        if realm.tenant != scope.tenant() || realm.id != scope.realm() {
            return Err(self.refuse_out_of_scope());
        }
        let name = realm.name.as_str();
        let insert = Insert::into(
            realms::TABLE,
            vec![
                col(realms::NAME, &name),
                col(realms::ENABLED, &realm.enabled),
                col(realms::CREATED_AT, &realm.created_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_realm(&mut self) -> Result<Option<Realm>, StorageError> {
        let scope = saffui_core::ports::storage::UnitOfWork::scope(self);
        let select = Select::from(realms::TABLE, REALM).build();
        let Some(row) = self.read_one(&select).await? else {
            return Ok(None);
        };
        let name: String = row.get(0);
        Ok(Some(Realm {
            id: RealmId::from_uuid(scope.realm().as_uuid()),
            tenant: TenantId::from_uuid(scope.tenant().as_uuid()),
            // The schema holds the same grammar: a name that fails here was not written by it.
            name: RealmName::parse(&name).map_err(|_| StorageError::Failed)?,
            enabled: row.get(1),
            created_at: row.get(2),
        }))
    }

    async fn read_realm_settings(&mut self) -> Result<Option<serde_json::Value>, StorageError> {
        let select = Select::from(realm_settings::TABLE, SETTINGS).build();
        Ok(self.read_one(&select).await?.map(|row| row.get(0)))
    }

    async fn read_realm_settings_for_update(
        &mut self,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        Ok(self
            .read_raw(READ_SETTINGS_FOR_UPDATE, &[&tenant, &realm])
            .await?
            .first()
            .map(|row| row.get(0)))
    }

    async fn read_realm_settings_for_share(
        &mut self,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        Ok(self
            .read_raw(READ_SETTINGS_FOR_SHARE, &[&tenant, &realm])
            .await?
            .first()
            .map(|row| row.get(0)))
    }

    async fn write_realm_settings(
        &mut self,
        settings: &serde_json::Value,
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(WRITE_SETTINGS, &[&tenant, &realm, settings])
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::{READ_SETTINGS_FOR_SHARE, READ_SETTINGS_FOR_UPDATE};

    #[test]
    fn the_settings_are_read_and_taken_by_one_statement_inside_the_scope() {
        for (statement, lock) in [
            (READ_SETTINGS_FOR_UPDATE, "FOR NO KEY UPDATE"),
            (READ_SETTINGS_FOR_SHARE, "FOR SHARE"),
        ] {
            let written = statement.split_whitespace().collect::<Vec<_>>().join(" ");
            // The whole clause: the security of rows would hide a scope left out.
            assert_eq!(
                written,
                format!(
                    "SELECT settings FROM realm_settings \
                     WHERE tenant_id = $1 AND realm_id = $2 {lock}"
                )
            );
        }
    }
}
