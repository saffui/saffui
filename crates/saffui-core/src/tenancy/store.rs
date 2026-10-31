use async_trait::async_trait;

use super::{Realm, Tenant};
use crate::ports::storage::StorageError;

/// What the tenancy keeps. Every call reads and writes inside the scope of
/// the unit of work, whatever it is asked.
#[async_trait]
pub trait RealmStore {
    async fn insert_tenant(&mut self, tenant: &Tenant) -> Result<(), StorageError>;

    /// Fails with `Taken("realm name")` when the name designates a realm
    /// already, in any tenant.
    async fn insert_realm(&mut self, realm: &Realm) -> Result<(), StorageError>;

    /// The realm of the scope, if it exists.
    async fn read_realm(&mut self) -> Result<Option<Realm>, StorageError>;
}
