//! The history table. Its name is decided here, once.

use tokio_postgres::GenericClient;
use tokio_postgres::error::SqlState;

use super::Migration;
use super::plan::Fingerprint;
use crate::{APP_ROLE, MAINTENANCE_ROLE};

pub(crate) async fn create_history_table(
    client: &impl GenericClient,
) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version integer PRIMARY KEY,
                 name text NOT NULL,
                 checksum bytea NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT now()
             );
             GRANT SELECT ON schema_migrations TO {APP_ROLE}, {MAINTENANCE_ROLE};"
        ))
        .await
}

pub(crate) async fn read_applied(
    client: &impl GenericClient,
) -> Result<Vec<Fingerprint>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT version, checksum FROM schema_migrations ORDER BY version",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Fingerprint {
            version: row.get(0),
            checksum: row.get(1),
        })
        .collect())
}

/// The database computes the digests: this crate links no digest of its own.
pub(crate) async fn fingerprint_embedded(
    client: &impl GenericClient,
    migrations: &[Migration],
) -> Result<Vec<Fingerprint>, tokio_postgres::Error> {
    let versions: Vec<i32> = migrations
        .iter()
        .map(|migration| migration.version)
        .collect();
    let texts: Vec<&str> = migrations.iter().map(|migration| migration.sql).collect();
    let rows = client
        .query(
            "SELECT m.version, pg_catalog.sha256(pg_catalog.convert_to(m.body, 'UTF8'))
             FROM unnest($1::int4[], $2::text[]) AS m(version, body)
             ORDER BY m.version",
            &[&versions, &texts],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| Fingerprint {
            version: row.get(0),
            checksum: row.get(1),
        })
        .collect())
}

pub(crate) async fn record_applied(
    client: &impl GenericClient,
    migration: &Migration,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO schema_migrations (version, name, checksum)
             VALUES ($1, $2, pg_catalog.sha256(pg_catalog.convert_to($3, 'UTF8')))",
            &[&migration.version, &migration.name, &migration.sql],
        )
        .await?;
    Ok(())
}

/// The version of the schema: the last migration applied, 0 for a database
/// that never saw one.
///
/// # Errors
///
/// Returns the driver's error when the database cannot answer.
pub async fn read_schema_version(
    client: &impl GenericClient,
) -> Result<i32, tokio_postgres::Error> {
    match client
        .query_one(
            "SELECT COALESCE(max(version), 0) FROM schema_migrations",
            &[],
        )
        .await
    {
        Ok(row) => Ok(row.get(0)),
        Err(error) if error.code() == Some(&SqlState::UNDEFINED_TABLE) => Ok(0),
        Err(error) => Err(error),
    }
}
