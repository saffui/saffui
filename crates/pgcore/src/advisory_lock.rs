use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config};

use crate::tls::PgConnector;

/// Which lock. The advisory space is flat and shared by everything on the
/// server, so a namespace keeps one subsystem from waiting on another's.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AdvisoryLockKey {
    pub namespace: i32,
    pub id: i32,
}

impl AdvisoryLockKey {
    /// `0x5346` — ASCII "SF". Reserved for this workspace.
    pub const NAMESPACE: i32 = 0x5346;

    /// The one the migration runner holds, so a schema is applied by one
    /// process at a time whatever a deployment does.
    pub const MIGRATION_RUNNER: Self = Self::new(1);

    pub const fn new(id: i32) -> Self {
        Self {
            namespace: Self::NAMESPACE,
            id,
        }
    }

    /// A key outside the reserved namespace, for something that has to share
    /// the server with another application.
    pub const fn foreign(namespace: i32, id: i32) -> Self {
        Self { namespace, id }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdvisoryLockError {
    #[error("could not open a dedicated database connection")]
    Connect,
    #[error("the advisory-lock query failed")]
    Query,
}

/// A held lock, on a connection of its own.
pub struct AdvisoryLock {
    client: Client,
    key: AdvisoryLockKey,
    driver: Option<JoinHandle<()>>,
}

impl AdvisoryLock {
    /// Take the lock if it is free, and say so if it is not.
    pub async fn try_acquire(
        config: &Config,
        tls: &PgConnector,
        key: AdvisoryLockKey,
    ) -> Result<Option<Self>, AdvisoryLockError> {
        let (client, driver) = connect(config, tls).await?;

        let acquired: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock($1, $2)",
                &[&key.namespace, &key.id],
            )
            .await
            .map_err(|_| AdvisoryLockError::Query)?
            .get(0);

        if !acquired {
            // Nothing is held, so the session has no reason to stay open.
            driver.abort();
            return Ok(None);
        }

        Ok(Some(Self {
            client,
            key,
            driver: Some(driver),
        }))
    }

    /// Wait for the lock.
    pub async fn acquire(
        config: &Config,
        tls: &PgConnector,
        key: AdvisoryLockKey,
    ) -> Result<Self, AdvisoryLockError> {
        let (client, driver) = connect(config, tls).await?;

        client
            .execute(
                "SELECT pg_advisory_lock($1, $2)",
                &[&key.namespace, &key.id],
            )
            .await
            .map_err(|_| AdvisoryLockError::Query)?;

        Ok(Self {
            client,
            key,
            driver: Some(driver),
        })
    }

    pub fn key(&self) -> AdvisoryLockKey {
        self.key
    }

    /// Whether the session still exists. A dead one has already released the
    /// lock, whatever this side believes.
    pub async fn is_alive(&self) -> bool {
        self.client.simple_query("SELECT 1").await.is_ok()
    }

    /// Give the lock back and close the session.
    pub async fn release(mut self) -> Result<(), AdvisoryLockError> {
        let released = self
            .client
            .execute(
                "SELECT pg_advisory_unlock($1, $2)",
                &[&self.key.namespace, &self.key.id],
            )
            .await
            .map(|_| ())
            .map_err(|_| AdvisoryLockError::Query);

        // The session ends either way, which releases the lock even if the
        // query above did not get through.
        self.close();
        released
    }

    fn close(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

impl Drop for AdvisoryLock {
    /// The backstop. Ending the connection driver closes the session, and the
    /// server releases session-level locks when a session goes.
    fn drop(&mut self) {
        self.close();
    }
}

/// Open a connection outside the pool, under the shared policy.
///
/// Not a general-purpose helper: whoever calls it owns a backend for as long as
/// they hold the client.
pub async fn connect(
    config: &Config,
    tls: &PgConnector,
) -> Result<(Client, JoinHandle<()>), AdvisoryLockError> {
    let (client, connection) = tls
        .apply(config)
        .connect(tls.maker())
        .await
        .map_err(|_| AdvisoryLockError::Connect)?;

    // The driver has to be polled for the connection to work at all; it ends
    // when the client drops or the task is aborted.
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    Ok((client, driver))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the test database is.
    ///
    /// Absent, the tests below panic naming the variable rather than returning
    /// quietly: `--ignored` that passes without reaching a server proves
    /// nothing about locking.
    fn config() -> Config {
        std::env::var("SAFFUI_TEST_PG")
            .unwrap_or_else(|_| {
                panic!("these tests need a database: set SAFFUI_TEST_PG to a connection string")
            })
            .parse()
            .expect("SAFFUI_TEST_PG is a connection string")
    }

    /// Keys stay apart even when ids repeat, which is what the namespace is
    /// for: the advisory space is shared with everything else on the server.
    #[test]
    fn a_key_is_its_namespace_and_its_id() {
        assert_eq!(
            AdvisoryLockKey::MIGRATION_RUNNER.namespace,
            AdvisoryLockKey::NAMESPACE
        );
        assert_ne!(AdvisoryLockKey::new(1), AdvisoryLockKey::new(2));
        assert_ne!(
            AdvisoryLockKey::new(1),
            AdvisoryLockKey::foreign(0x4453, 1),
            "the same id in another namespace is another lock"
        );
    }

    /// One holder at a time, and the next one gets it once the first lets go.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn only_one_session_holds_it() {
        let (config, tls) = (config(), PgConnector::disabled());
        let key = AdvisoryLockKey::new(9001);

        let held = AdvisoryLock::try_acquire(&config, &tls, key)
            .await
            .unwrap()
            .expect("the lock was free");
        assert!(held.is_alive().await);

        // A second session cannot have it.
        assert!(
            AdvisoryLock::try_acquire(&config, &tls, key)
                .await
                .unwrap()
                .is_none(),
            "two sessions held one lock"
        );

        held.release().await.unwrap();

        // And now it is free again.
        let after = AdvisoryLock::try_acquire(&config, &tls, key).await.unwrap();
        assert!(after.is_some(), "the lock was not released");
    }

    /// Dropping the guard releases it, which is the path a panic takes.
    ///
    /// The explicit release is the one to prefer; this is the one that has to
    /// work when nothing got the chance to call it.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn dropping_the_guard_releases_it() {
        let (config, tls) = (config(), PgConnector::disabled());
        let key = AdvisoryLockKey::new(9002);

        {
            let _held = AdvisoryLock::try_acquire(&config, &tls, key)
                .await
                .unwrap()
                .unwrap();
            assert!(
                AdvisoryLock::try_acquire(&config, &tls, key)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        // The server releases on disconnect, which the driver's end triggers.
        for _ in 0..50 {
            if let Some(lock) = AdvisoryLock::try_acquire(&config, &tls, key).await.unwrap() {
                lock.release().await.unwrap();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        panic!("the lock was still held a second after its guard dropped");
    }

    /// Two different keys do not wait on each other.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn two_keys_do_not_contend() {
        let (config, tls) = (config(), PgConnector::disabled());

        let first = AdvisoryLock::try_acquire(&config, &tls, AdvisoryLockKey::new(9003))
            .await
            .unwrap()
            .unwrap();
        let second = AdvisoryLock::try_acquire(&config, &tls, AdvisoryLockKey::new(9004))
            .await
            .unwrap()
            .expect("a different key is a different lock");

        assert_eq!(first.key().id, 9003);
        assert_eq!(second.key().id, 9004);
    }

    /// Waiting for a lock returns once it is free.
    #[tokio::test]
    #[ignore = "needs a database (SAFFUI_TEST_PG)"]
    async fn waiting_gets_it_once_it_is_free() {
        let (config, tls) = (config(), PgConnector::disabled());
        let key = AdvisoryLockKey::new(9005);

        let held = AdvisoryLock::try_acquire(&config, &tls, key)
            .await
            .unwrap()
            .unwrap();

        let waiter = {
            let (config, tls) = (config.clone(), tls.clone());
            tokio::spawn(async move { AdvisoryLock::acquire(&config, &tls, key).await })
        };

        // Still waiting while the first holds it.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!waiter.is_finished(), "the waiter took a held lock");

        held.release().await.unwrap();

        let taken = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the waiter never woke")
            .unwrap()
            .unwrap();
        assert_eq!(taken.key(), key);
    }
}
