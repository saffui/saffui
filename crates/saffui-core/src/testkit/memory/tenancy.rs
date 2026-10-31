use async_trait::async_trait;

use super::MemoryUnitOfWork;
use crate::ports::storage::StorageError;
use crate::tenancy::store::RealmStore;
use crate::tenancy::{Realm, Tenant};

impl MemoryUnitOfWork {
    fn keep_tenant(&mut self, tenant: &Tenant) -> Result<(), StorageError> {
        if tenant.id != self.scope.tenant()
            || self.working.tenants.contains_key(&tenant.id.as_uuid())
        {
            return Err(StorageError::Failed);
        }
        self.working
            .tenants
            .insert(tenant.id.as_uuid(), tenant.clone());
        Ok(())
    }

    fn keep_realm(&mut self, realm: &Realm) -> Result<(), StorageError> {
        let in_scope = realm.tenant == self.scope.tenant() && realm.id == self.scope.realm();
        if !in_scope
            || !self.working.tenants.contains_key(&realm.tenant.as_uuid())
            || self.working.realms.contains_key(&realm.id.as_uuid())
        {
            return Err(StorageError::Failed);
        }
        if self
            .working
            .realms
            .values()
            .any(|known| known.name == realm.name)
        {
            return Err(StorageError::Taken("realm name"));
        }
        self.working
            .realms
            .insert(realm.id.as_uuid(), realm.clone());
        Ok(())
    }
}

#[async_trait]
impl RealmStore for MemoryUnitOfWork {
    async fn insert_tenant(&mut self, tenant: &Tenant) -> Result<(), StorageError> {
        let outcome = self.keep_tenant(tenant);
        self.record_refusal(outcome)
    }

    async fn insert_realm(&mut self, realm: &Realm) -> Result<(), StorageError> {
        let outcome = self.keep_realm(realm);
        self.record_refusal(outcome)
    }

    async fn read_realm(&mut self) -> Result<Option<Realm>, StorageError> {
        Ok(self
            .working
            .realms
            .get(&self.scope.realm().as_uuid())
            .filter(|realm| realm.tenant == self.scope.tenant())
            .cloned())
    }
}
