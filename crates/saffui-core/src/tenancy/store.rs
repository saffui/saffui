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

    /// The settings document of the realm as it is kept, unread: what it
    /// says is for the core to judge.
    async fn read_realm_settings(&mut self) -> Result<Option<serde_json::Value>, StorageError>;

    /// As `read_realm_settings`, and the row stays taken until the commit:
    /// a writer of the settings, or another registration, waits.
    async fn read_realm_settings_for_update(
        &mut self,
    ) -> Result<Option<serde_json::Value>, StorageError>;

    /// As `read_realm_settings`, and the row stays shared until the commit:
    /// a writer of the settings, or a registration, waits; another reader
    /// that shares it does not.
    async fn read_realm_settings_for_share(
        &mut self,
    ) -> Result<Option<serde_json::Value>, StorageError>;

    /// Replaces the settings document of the realm, or writes the first.
    async fn write_realm_settings(
        &mut self,
        settings: &serde_json::Value,
    ) -> Result<(), StorageError>;
}
