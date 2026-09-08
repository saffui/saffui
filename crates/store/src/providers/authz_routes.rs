use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

#[derive(Debug, Clone)]
pub struct AuthzRoute {
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub server_id: String,
    pub resource: String,
    pub scope: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
}

const COLUMNS: &str =
    "route_id, method, path, server_id, resource, scope, action, priority, enabled";

/// Every route of the realm, in the order they are asked in.
pub async fn routes(transaction: &Transaction<'_>) -> StoreResult<Vec<AuthzRoute>> {
    let statement =
        format!("SELECT {COLUMNS} FROM authz_routes ORDER BY priority ASC, route_id ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

pub async fn keep(transaction: &Transaction<'_>, route: &AuthzRoute, by: &str) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO authz_routes \
                 (tenant, realm_id, route_id, method, path, server_id, resource, scope, \
                  action, priority, enabled, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
             ON CONFLICT (tenant, realm_id, route_id) DO UPDATE \
                 SET method = EXCLUDED.method, \
                     path = EXCLUDED.path, \
                     server_id = EXCLUDED.server_id, \
                     resource = EXCLUDED.resource, \
                     scope = EXCLUDED.scope, \
                     action = EXCLUDED.action, \
                     priority = EXCLUDED.priority, \
                     enabled = EXCLUDED.enabled, \
                     updated_by = EXCLUDED.created_by, \
                     updated_at = now(), \
                     version = authz_routes.version + 1",
            &[
                &route.route_id,
                &route.method,
                &route.path,
                &route.server_id,
                &route.resource,
                &route.scope,
                &route.action,
                &route.priority,
                &route.enabled,
                &by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn drop_route(transaction: &Transaction<'_>, route_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM authz_routes WHERE route_id = $1", &[&route_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read(row: Row) -> AuthzRoute {
    AuthzRoute {
        route_id: row.get("route_id"),
        method: row.get("method"),
        path: row.get("path"),
        server_id: row.get("server_id"),
        resource: row.get("resource"),
        scope: row.get("scope"),
        action: row.get("action"),
        priority: row.get("priority"),
        enabled: row.get("enabled"),
    }
}
