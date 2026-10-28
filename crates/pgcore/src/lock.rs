//! Session advisory locks. They coordinate work that must not run twice at
//! once. They are never a safety barrier: a lock is not replicated, so after
//! a failover two holders can exist.

use tokio_postgres::Client;

/// What `migrate` holds while it applies migrations.
pub const MIGRATION_LOCK: i64 = 0x7361_6666_7569_0001;

/// A session lock, and the connection whose session holds it. Dropping it
/// closes the connection, which releases the lock.
pub struct SessionLock {
    client: Client,
    key: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("another session holds the lock")]
    Held,
    #[error("the lock cannot be asked for")]
    Database(#[from] tokio_postgres::Error),
}

impl SessionLock {
    /// Takes the lock without waiting. The connection must be a direct one: a
    /// pooler in transaction mode would hand the session, and the lock, to
    /// someone else.
    ///
    /// # Errors
    ///
    /// Returns [`LockError::Held`] when another session holds it.
    pub async fn try_acquire(client: Client, key: i64) -> Result<Self, LockError> {
        let acquired: bool = client
            .query_one("SELECT pg_catalog.pg_try_advisory_lock($1)", &[&key])
            .await?
            .get(0);
        if acquired {
            Ok(Self { client, key })
        } else {
            Err(LockError::Held)
        }
    }

    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Releases the lock and gives the connection back.
    ///
    /// # Errors
    ///
    /// Returns the driver's error when the session is already gone.
    pub async fn release(self) -> Result<Client, tokio_postgres::Error> {
        self.client
            .execute("SELECT pg_catalog.pg_advisory_unlock($1)", &[&self.key])
            .await?;
        Ok(self.client)
    }
}
