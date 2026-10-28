//! The storage double: the whole state in memory, behind one lock.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;

use crate::app::App;
use crate::ports::storage::{Storage, StorageUnavailable};

#[derive(Default)]
pub struct MemoryStorage {
    probe_failure: Mutex<Option<StorageUnavailable>>,
    probes: AtomicUsize,
}

impl MemoryStorage {
    /// An application wired on doubles, and the storage double to steer it.
    #[must_use]
    pub fn wire() -> (App, Arc<Self>) {
        let storage = Arc::new(Self::default());
        let app = App {
            storage: storage.clone(),
        };
        (app, storage)
    }

    /// Makes every later probe fail with `reason`.
    pub fn fail_probes_with(&self, reason: StorageUnavailable) {
        *lock(&self.probe_failure) = Some(reason);
    }

    #[must_use]
    pub fn count_probes(&self) -> usize {
        self.probes.load(Ordering::Relaxed)
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
        match *lock(&self.probe_failure) {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }
}
