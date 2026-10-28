//! The link to Postgres. Nothing here knows a table of the product: the
//! migrations are carried as text and applied as text.

pub mod connect;
pub mod lock;
pub mod migrate;
pub mod pool;
pub mod probe;
pub mod role;

#[cfg(feature = "testkit")]
pub mod testkit;

/// The role every serving node connects as. Roles are global to a cluster, so
/// whoever provisions the cluster creates them and no migration does.
pub const APP_ROLE: &str = "saffui_app";

/// The role of the jobs that cross tenants. It bypasses row security.
pub const MAINTENANCE_ROLE: &str = "saffui_maintenance";
