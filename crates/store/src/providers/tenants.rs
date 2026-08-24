use deadpool_postgres::Transaction;
use models::entities::tenant::{TenantLimits, TenantModel, TenantState};

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant_id, display_name, state, limits, region, \
                       created_by, created_at, updated_by, updated_at, version";

/// Record a tenant.
///
/// Which tenant is decided by the transaction, so a model naming another is
/// refused by the rules rather than written. Nothing here commits.
pub async fn create(transaction: &Transaction<'_>, tenant: &TenantModel) -> StoreResult<()> {
    let limits = limits_json(tenant.limits.as_ref())?;
    let set = WriteSet::insert(vec![
        col("tenant_id", &tenant.tenant_id),
        col("display_name", &tenant.display_name),
        col("state", &tenant.state),
        col("limits", &limits),
        col("region", &tenant.region),
    ]);

    transaction
        .execute(statement::insert("tenants", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The tenant this transaction is for, if it exists.
///
/// Another tenant's row is invisible under the rules, so this answers nothing
/// rather than answering theirs.
pub async fn load(transaction: &Transaction<'_>) -> StoreResult<Option<TenantModel>> {
    let statement = format!("SELECT {COLUMNS} FROM tenants");
    let row = transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?;

    row.map(|row| {
        Ok(TenantModel {
            tenant_id: row.get("tenant_id"),
            display_name: row.get("display_name"),
            state: row.get("state"),
            limits: parse_limits(row.get("limits"))?,
            region: row.get("region"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_by: row.get("updated_by"),
            updated_at: row.get("updated_at"),
            version: row.get("version"),
        })
    })
    .transpose()
}

/// Whether this transaction's tenant is registered.
pub async fn exists(transaction: &Transaction<'_>) -> StoreResult<bool> {
    let found: i64 = transaction
        .query_one("SELECT count(*) FROM tenants", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

/// Move a tenant to another state, and say whether there was one to move.
///
/// The version is bumped by the statement rather than written from the model. A
/// number carried in would be a second opinion about a row the writer last read
/// some time ago.
pub async fn set_state(
    transaction: &Transaction<'_>,
    state: TenantState,
    actor: &str,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![col("state", &state), col("updated_by", &actor)],
        vec![],
    );
    // The stamp and the version are the statement's own, never the model's: a
    // number carried in would be a second opinion about a row the writer last
    // read some time ago.
    let statement = format!(
        "{}, updated_at = now(), version = version + 1",
        statement::update("tenants", &set)
    );

    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// How many realms this tenant has, for a check against its own ceiling.
pub async fn count_realms(transaction: &Transaction<'_>) -> StoreResult<i64> {
    Ok(transaction
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

fn limits_json(limits: Option<&TenantLimits>) -> StoreResult<Option<serde_json::Value>> {
    limits
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn parse_limits(value: Option<serde_json::Value>) -> StoreResult<Option<TenantLimits>> {
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}
