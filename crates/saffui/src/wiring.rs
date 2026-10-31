//! The composition root: the one file that knows every crate. It fills the
//! application once, by hand.

use std::sync::Arc;

use crypto::adapters::open_provider;
use crypto::adapters::random::ProviderRandom;
use deadpool_postgres::Pool;
use pgcore::connect::ConnectionPlan;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{BuildPoolError, PoolSettings, build_pool};
use pgcore::probe::describe_driver_error;
use pgcore::role::{PrivilegedRole, read_role_facts, refuse_privileged_role};
use saffui_core::app::App;
use saffui_core::ports::clock::Clock;
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::settings::Settings;
use store::PgStorage;
use time::OffsetDateTime;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

pub(crate) struct Wired {
    pub(crate) app: App,
    pool: Pool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WiringError {
    #[error("cannot reach the database: {0}")]
    Pool(#[from] BuildPoolError),
    #[error("the cryptographic library failed its self-test")]
    Library,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupRefusal {
    #[error("the database cannot serve: {0}")]
    Storage(#[from] StorageUnavailable),
    #[error("the role of the database link cannot be read")]
    RoleUnreadable,
    #[error(transparent)]
    Role(#[from] PrivilegedRole),
}

/// Wires the product on its database. No connection is opened yet.
pub(crate) fn wire_product(
    settings: Settings,
    database: &ConnectionPlan,
    pool: PoolSettings,
) -> Result<Wired, WiringError> {
    // Before anything draws: a library that fails its own vector draws nothing.
    let provider = open_provider().map_err(|_| WiringError::Library)?;
    let pool = build_pool(database, pool)?;
    let storage = PgStorage::new(pool.clone(), SchemaWindow::of_exactly(EMBEDDED));
    Ok(Wired {
        app: App {
            settings,
            storage: Arc::new(storage),
            clock: Arc::new(SystemClock),
            random: Arc::new(ProviderRandom::new(provider)),
        },
        pool,
    })
}

impl Wired {
    /// Refuses to serve from a database this binary cannot read, or under a
    /// role that row security does not bind.
    pub(crate) async fn refuse_unfit_database(&self) -> Result<(), StartupRefusal> {
        self.app.storage.probe().await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| StorageUnavailable::Unreachable)?;
        let facts = read_role_facts(&client).await.map_err(|error| {
            tracing::error!(
                cause = %describe_driver_error(&error),
                "the role of the database link cannot be read"
            );
            StartupRefusal::RoleUnreadable
        })?;
        refuse_privileged_role(&facts)?;
        Ok(())
    }
}
