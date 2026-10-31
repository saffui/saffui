//! The pool a serving node draws from: bounded in size and in wait, so that a
//! database that falls behind answers 503 quickly instead of queueing.

use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::connect::{ConnectionPlan, ConnectionPolicyError};

#[derive(Clone, Copy, Debug)]
pub struct PoolSettings {
    pub max_size: usize,
    /// How long a request waits for a connection before it gives up.
    pub wait_timeout: Duration,
    /// After how long the server ends a transaction nobody is driving.
    pub idle_in_transaction_timeout: Duration,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_size: 20,
            wait_timeout: Duration::from_secs(5),
            idle_in_transaction_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildPoolError {
    #[error(transparent)]
    Policy(#[from] ConnectionPolicyError),
    #[error("the pool settings cannot be used")]
    Settings,
}

/// Builds the pool. No connection is opened before the first one is asked for.
///
/// # Errors
///
/// Returns the policy error when the TLS settings cannot be loaded.
pub fn build_pool(plan: &ConnectionPlan, settings: PoolSettings) -> Result<Pool, BuildPoolError> {
    // Set on the pooled sessions only: a migration or a held lock legitimately
    // keeps a transaction open for longer.
    let plan = plan
        .clone()
        .with_session_setting(
            "idle_in_transaction_session_timeout",
            &settings.idle_in_transaction_timeout.as_millis().to_string(),
        )
        // Outside a unit of work, which sets a bound of its own, a lock waited
        // for longer than the pool waits for a connection gives it back.
        .with_session_setting(
            "lock_timeout",
            &settings.wait_timeout.as_millis().to_string(),
        )
        // The objects of the product live in public. A schema named after the
        // role would come first by default, and a temporary table last here.
        .with_session_setting("search_path", "public,pg_temp");
    // A unit of work rolls back when it is abandoned. This is the net under
    // it: a session never reaches its next borrower inside a transaction or
    // with a setting of the previous one.
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Custom("ROLLBACK; RESET ALL".to_string()),
    };
    let manager = match plan.build_tls_connector()? {
        None => Manager::from_config(plan.config, NoTls, manager_config),
        Some(connector) => Manager::from_config(plan.config, connector, manager_config),
    };
    Pool::builder(manager)
        .max_size(settings.max_size)
        .wait_timeout(Some(settings.wait_timeout))
        .create_timeout(Some(settings.wait_timeout))
        .recycle_timeout(Some(settings.wait_timeout))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|_| BuildPoolError::Settings)
}
