//! The storage double: the whole state in memory, behind one lock. A unit of
//! work copies the state and swaps its copy in when it commits, so that an
//! abandoned one leaves nothing.
//!
//! The double serializes nothing and enforces no row security: a property
//! held by SQL is proven on Postgres, never here.

mod tenancy;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use uuid::Uuid;

use super::clock::FixedClock;
use super::random::CountingRandom;
use crate::app::App;
use crate::ports::storage::{RealmLocation, Storage, StorageError, StorageUnavailable, UnitOfWork};
use crate::settings::{PublicOrigin, Settings};
use crate::tenancy::{Realm, RealmName, RealmScope, Tenant};

#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) tenants: HashMap<Uuid, Tenant>,
    pub(crate) realms: HashMap<Uuid, Realm>,
}

#[derive(Default)]
pub struct MemoryStorage {
    state: Arc<Mutex<State>>,
    outage: Mutex<Option<StorageUnavailable>>,
    probes: AtomicUsize,
    units_of_work: AtomicUsize,
}

pub struct MemoryUnitOfWork {
    scope: RealmScope,
    working: State,
    shared: Arc<Mutex<State>>,
    /// As on a database, a refused statement ends the transaction: nothing
    /// that follows is kept.
    failed: bool,
}

impl MemoryUnitOfWork {
    pub(crate) fn record_refusal<T>(
        &mut self,
        outcome: Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.failed |= outcome.is_err();
        outcome
    }
}

impl MemoryStorage {
    /// An application wired on doubles, and the storage double to steer it.
    ///
    /// # Panics
    ///
    /// Never: the origin it parses is a constant.
    #[must_use]
    pub fn wire() -> (App, Arc<Self>) {
        let storage = Arc::new(Self::default());
        let app = App {
            settings: Settings {
                public_origin: PublicOrigin::parse("https://id.example.test")
                    .expect("a well-formed origin"),
            },
            storage: storage.clone(),
            clock: Arc::new(FixedClock::default()),
            random: Arc::new(CountingRandom::default()),
        };
        (app, storage)
    }

    /// Makes the storage refuse everything with `reason`, as a database that is down.
    pub fn fail_with(&self, reason: StorageUnavailable) {
        *lock(&self.outage) = Some(reason);
    }

    #[must_use]
    pub fn count_probes(&self) -> usize {
        self.probes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn count_units_of_work(&self) -> usize {
        self.units_of_work.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn count_tenants(&self) -> usize {
        lock(&self.state).tenants.len()
    }

    #[must_use]
    pub fn count_realms(&self) -> usize {
        lock(&self.state).realms.len()
    }

    /// Disables the realm of that name, as an operator would.
    pub fn disable_realm(&self, name: &str) {
        for realm in lock(&self.state).realms.values_mut() {
            if realm.name.as_str() == name {
                realm.enabled = false;
            }
        }
    }

    fn check_reachable(&self) -> Result<(), StorageUnavailable> {
        match *lock(&self.outage) {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }
}

/// A test that panicked while holding the lock must not hide its own failure
/// behind a second panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn probe(&self) -> Result<(), StorageUnavailable> {
        self.probes.fetch_add(1, Ordering::Relaxed);
        self.check_reachable()
    }

    async fn locate_realm(&self, name: &RealmName) -> Result<Option<RealmLocation>, StorageError> {
        self.check_reachable()?;
        Ok(lock(&self.state)
            .realms
            .values()
            .find(|realm| realm.name == *name)
            .map(|realm| RealmLocation {
                tenant: realm.tenant,
                realm: realm.id,
                enabled: realm.enabled,
            }))
    }

    async fn begin(&self, scope: RealmScope) -> Result<Box<dyn UnitOfWork>, StorageError> {
        self.check_reachable()?;
        self.units_of_work.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(MemoryUnitOfWork {
            scope,
            working: lock(&self.state).clone(),
            shared: Arc::clone(&self.state),
            failed: false,
        }))
    }
}

#[async_trait]
impl UnitOfWork for MemoryUnitOfWork {
    fn scope(&self) -> RealmScope {
        self.scope
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        if self.failed {
            return Err(StorageError::Failed);
        }
        *lock(&self.shared) = self.working;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStorage;
    use crate::testkit::contract::check_tenancy_contract;
    use crate::testkit::drive::complete;

    #[test]
    fn the_double_passes_the_tenancy_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_tenancy_contract(&app));
    }
}
