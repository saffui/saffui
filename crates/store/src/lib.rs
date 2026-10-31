//! The storage port of the core, on Postgres. This crate executes: it
//! decides nothing and never commits on its own.

mod query;
mod schema;
mod stores;
mod work;

use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use pgcore::migrate::window::SchemaWindow;
use pgcore::probe::{
    ProbeFailure, classify_driver_error, classify_pool_error, describe_driver_error, probe_database,
};
use saffui_core::ports::storage::{
    RealmLocation, Storage, StorageError, StorageUnavailable, UnitOfWork,
};
use saffui_core::tenancy::{RealmId, RealmName, RealmScope, TenantId};

use crate::work::PgUnitOfWork;

/// How long a probe waits for a connection and for its answer. Short: a
/// probe that hangs tells the orchestrator nothing.
const PROBE_PATIENCE: Duration = Duration::from_secs(2);

pub struct PgStorage {
    pool: Pool,
    window: SchemaWindow,
}

impl PgStorage {
    #[must_use]
    pub fn new(pool: Pool, window: SchemaWindow) -> Self {
        Self { pool, window }
    }
}

pub(crate) fn translate_probe_failure(failure: ProbeFailure) -> StorageUnavailable {
    match failure {
        ProbeFailure::PoolExhausted => StorageUnavailable::PoolExhausted,
        ProbeFailure::TimedOut => StorageUnavailable::TimedOut,
        ProbeFailure::TlsFailed => StorageUnavailable::TlsFailed,
        ProbeFailure::Refused => StorageUnavailable::Refused,
        ProbeFailure::Unreachable => StorageUnavailable::Unreachable,
        ProbeFailure::SchemaBehind { .. } => StorageUnavailable::SchemaBehind,
        ProbeFailure::SchemaAhead { .. } => StorageUnavailable::SchemaAhead,
    }
}

#[async_trait]
impl Storage for PgStorage {
    async fn probe(&self) -> Result<(), StorageUnavailable> {
        probe_database(&self.pool, self.window, PROBE_PATIENCE)
            .await
            .map_err(translate_probe_failure)
    }

    async fn locate_realm(&self, name: &RealmName) -> Result<Option<RealmLocation>, StorageError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| translate_probe_failure(classify_pool_error(&error)))?;
        let located = async {
            let statement = client
                .prepare_cached(
                    "SELECT tenant_id, realm_id, enabled FROM public.saffui_locate_realm($1)",
                )
                .await?;
            client.query_opt(&statement, &[&name.as_str()]).await
        }
        .await
        .map_err(|error| {
            tracing::error!(
                cause = %describe_driver_error(&error),
                "the realm directory cannot be read"
            );
            translate_probe_failure(classify_driver_error(&error))
        })?;
        Ok(located.map(|row| RealmLocation {
            tenant: TenantId::from_uuid(row.get(0)),
            realm: RealmId::from_uuid(row.get(1)),
            enabled: row.get(2),
        }))
    }

    async fn begin(&self, scope: RealmScope) -> Result<Box<dyn UnitOfWork>, StorageError> {
        Ok(Box::new(PgUnitOfWork::open(&self.pool, scope).await?))
    }
}
