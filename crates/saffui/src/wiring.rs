//! The composition root: the one file that knows every crate. It fills the
//! application once, by hand.

use std::sync::Arc;

use deadpool_postgres::Pool;
use pgcore::connect::ConnectionPlan;
use pgcore::migrate::EMBEDDED;
use pgcore::migrate::window::SchemaWindow;
use pgcore::pool::{BuildPoolError, PoolSettings, build_pool};
use pgcore::role::{PrivilegedRole, read_role_facts, refuse_privileged_role};
use saffui_core::app::App;
use saffui_core::ports::storage::StorageUnavailable;
use store::PgStorage;

pub(crate) struct Wired {
    pub(crate) app: App,
    pool: Pool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupRefusal {
    #[error("the database cannot serve: {0}")]
    Storage(#[from] StorageUnavailable),
    #[error(transparent)]
    Role(#[from] PrivilegedRole),
}

/// Wires the product on its database. No connection is opened yet.
pub(crate) fn wire_product(
    database: &ConnectionPlan,
    pool: PoolSettings,
) -> Result<Wired, BuildPoolError> {
    let pool = build_pool(database, pool)?;
    let storage = PgStorage::new(pool.clone(), SchemaWindow::of_exactly(EMBEDDED));
    Ok(Wired {
        app: App {
            storage: Arc::new(storage),
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
        let facts = read_role_facts(&**client)
            .await
            .map_err(|_| StorageUnavailable::Unreachable)?;
        refuse_privileged_role(&facts)?;
        Ok(())
    }
}
