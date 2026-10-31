use async_trait::async_trait;
use saffui_core::ports::storage::StorageError;
use saffui_core::tenancy::store::RealmStore;
use saffui_core::tenancy::{Realm, RealmId, RealmName, Tenant, TenantId};

use crate::query::bind::col;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::Select;
use crate::schema::{realms, tenants};
use crate::work::PgUnitOfWork;

const REALM: &[Column] = &[realms::NAME, realms::ENABLED, realms::CREATED_AT];

#[async_trait]
impl RealmStore for PgUnitOfWork {
    async fn insert_tenant(&mut self, tenant: &Tenant) -> Result<(), StorageError> {
        // The key is written from the scope: a tenant other than the one this
        // unit of work is bound to is refused here, before row security is.
        if tenant.id != saffui_core::ports::storage::UnitOfWork::scope(self).tenant() {
            return Err(StorageError::Failed);
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
            return Err(StorageError::Failed);
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
}
