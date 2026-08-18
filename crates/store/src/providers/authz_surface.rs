//! What a protected application exposes, and the verbs declared on it.
//!
//! The scopes here are not the ones a client asks for at login. Those say what
//! a token may carry; these say what may be done to a resource, and an
//! application declares them for itself.
//!
//! A resource never leaves this module with its scopes unloaded. The model
//! keeps "declares none" apart from "not loaded" because a decision has to tell
//! them apart, and a read that sometimes filled the field and sometimes did not
//! would make which one it is a question about the call site.

use std::collections::HashMap;

use deadpool_postgres::Transaction;
use models::entities::attributes::AttributesMap;
use models::entities::authz::{ResourceModel, ResourceServerModel, ScopeModel};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const SERVER_COLUMNS: &str = "tenant, realm_id, server_id, enforcement_mode, decision_strategy, \
                              remote_resource_management, user_managed_access, created_by, \
                              created_at, updated_by, updated_at, version";

const RESOURCE_COLUMNS: &str = "tenant, realm_id, resource_id, server_id, name, display_name, \
                                description, resource_uris, resource_type, resource_owner, \
                                user_managed_access, configs, created_by, created_at, \
                                updated_by, updated_at, version";

const SCOPE_COLUMNS: &str = "tenant, realm_id, scope_id, server_id, name, display_name, \
                             description, created_by, created_at, updated_by, updated_at, version";

/// Give a client a surface.
///
/// The identifier is the client's, so there is no name to record here: what the
/// application is called is the client's answer, and a copy would be a second
/// one.
pub async fn create_server(
    transaction: &Transaction<'_>,
    server: &ResourceServerModel,
) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &server.metadata.tenant),
        col("realm_id", &server.realm_id),
        col("server_id", &server.server_id),
        col("enforcement_mode", &server.enforcement_mode),
        col("decision_strategy", &server.decision_strategy),
        col(
            "remote_resource_management",
            &server.remote_resource_management,
        ),
        col("user_managed_access", &server.user_managed_access),
        col("created_by", &server.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("resource_servers", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One protected application of this realm.
pub async fn load_server(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> StoreResult<Option<ResourceServerModel>> {
    let statement = format!("SELECT {SERVER_COLUMNS} FROM resource_servers WHERE server_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&server_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_server))
}

/// How much a server's decisions are allowed to refuse, and how answers combine.
///
/// The mode is what a permissive rollout changes, so it is settable without
/// rewriting the surface underneath it.
pub async fn set_server_mode(
    transaction: &Transaction<'_>,
    server: &ResourceServerModel,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![
            col("enforcement_mode", &server.enforcement_mode),
            col("decision_strategy", &server.decision_strategy),
            col("updated_by", &server.metadata.updated_by),
        ],
        vec![col("server_id", &server.server_id)],
    );

    // The stamp and the version are the statement's, not the caller's.
    let statement = statement::update("resource_servers", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );

    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Take the surface away, and say whether there was one.
///
/// The client stays. Removing a surface stops an application being protected;
/// removing the client is a different act with a different blast radius.
pub async fn delete_server(transaction: &Transaction<'_>, server_id: &str) -> StoreResult<bool> {
    // The aggregation edges first. A policy something is conditioned on cannot
    // be deleted from under it, and the cascade below reaches the two ends of an
    // edge in whichever order it finds them.
    crate::providers::authz_policies::unbind_server(transaction, server_id).await?;

    let removed = transaction
        .execute(
            "DELETE FROM resource_servers WHERE server_id = $1",
            &[&server_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record something the application protects.
///
/// Its scopes are not written here. They are declared through their own
/// operation, so creating a resource cannot quietly widen what is meaningful on
/// it.
pub async fn create_resource(
    transaction: &Transaction<'_>,
    resource: &ResourceModel,
) -> StoreResult<()> {
    let configs = resource
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    let set = WriteSet::insert(vec![
        col("tenant", &resource.metadata.tenant),
        col("realm_id", &resource.realm_id),
        col("resource_id", &resource.resource_id),
        col("server_id", &resource.server_id),
        col("name", &resource.name),
        col("display_name", &resource.display_name),
        col("description", &resource.description),
        col("resource_uris", &resource.resource_uris),
        col("resource_type", &resource.resource_type),
        col("resource_owner", &resource.resource_owner),
        col("user_managed_access", &resource.user_managed_access),
        col("configs", &configs),
        col("created_by", &resource.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("resources", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One resource, with the verbs it declares.
pub async fn load_resource(
    transaction: &Transaction<'_>,
    resource_id: &str,
) -> StoreResult<Option<ResourceModel>> {
    let statement = format!("SELECT {RESOURCE_COLUMNS} FROM resources WHERE resource_id = $1");
    let Some(row) = transaction
        .query_opt(statement.as_str(), &[&resource_id])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let mut declared = declared_scopes(transaction, &[resource_id.to_owned()]).await?;
    let scopes = declared.remove(resource_id).unwrap_or_default();
    Ok(Some(read_resource(row, scopes)))
}

/// Everything one application protects.
pub async fn resources_of_server(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> StoreResult<Vec<ResourceModel>> {
    let statement =
        format!("SELECT {RESOURCE_COLUMNS} FROM resources WHERE server_id = $1 ORDER BY name ASC");
    with_scopes(
        transaction,
        transaction
            .query(statement.as_str(), &[&server_id])
            .await
            .map_err(|_| StoreError::Backend)?,
    )
    .await
}

/// Everything of one type that an application protects.
///
/// What a permission naming a type applies to. A permission that named a type
/// nothing answers to applies to nothing, which is a permission that cannot
/// grant, never one that grants everywhere.
pub async fn resources_of_type(
    transaction: &Transaction<'_>,
    server_id: &str,
    resource_type: &str,
) -> StoreResult<Vec<ResourceModel>> {
    let statement = format!(
        "SELECT {RESOURCE_COLUMNS} FROM resources \
         WHERE server_id = $1 AND resource_type = $2 ORDER BY name ASC"
    );
    with_scopes(
        transaction,
        transaction
            .query(statement.as_str(), &[&server_id, &resource_type])
            .await
            .map_err(|_| StoreError::Backend)?,
    )
    .await
}

/// Remove a resource, and say whether there was one to remove.
pub async fn delete_resource(
    transaction: &Transaction<'_>,
    resource_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM resources WHERE resource_id = $1",
            &[&resource_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record a verb the application knows.
pub async fn create_scope(transaction: &Transaction<'_>, scope: &ScopeModel) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &scope.metadata.tenant),
        col("realm_id", &scope.realm_id),
        col("scope_id", &scope.scope_id),
        col("server_id", &scope.server_id),
        col("name", &scope.name),
        col("display_name", &scope.display_name),
        col("description", &scope.description),
        col("created_by", &scope.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("scopes", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One verb of this realm.
pub async fn load_scope(
    transaction: &Transaction<'_>,
    scope_id: &str,
) -> StoreResult<Option<ScopeModel>> {
    let statement = format!("SELECT {SCOPE_COLUMNS} FROM scopes WHERE scope_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&scope_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_scope))
}

/// Every verb one application knows.
pub async fn scopes_of_server(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> StoreResult<Vec<ScopeModel>> {
    let statement =
        format!("SELECT {SCOPE_COLUMNS} FROM scopes WHERE server_id = $1 ORDER BY name ASC");
    Ok(transaction
        .query(statement.as_str(), &[&server_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_scope)
        .collect())
}

/// Remove a verb, and say whether there was one to remove.
pub async fn delete_scope(transaction: &Transaction<'_>, scope_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM scopes WHERE scope_id = $1", &[&scope_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Say that a verb is meaningful on a resource.
///
/// Declaring twice declares once. A caller reconciling a set of verbs would
/// otherwise have to know which it had already declared, and reading that from
/// a failure is reading it from an error message.
pub async fn declare_scope(
    transaction: &Transaction<'_>,
    server_id: &str,
    resource_id: &str,
    scope_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO resource_scopes \
                 (tenant, realm_id, server_id, resource_id, scope_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT DO NOTHING",
            &[&server_id, &resource_id, &scope_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take a verb back off a resource, and say whether it declared it.
pub async fn undeclare_scope(
    transaction: &Transaction<'_>,
    resource_id: &str,
    scope_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM resource_scopes WHERE resource_id = $1 AND scope_id = $2",
            &[&resource_id, &scope_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Attach the declared verbs to resources already read.
async fn with_scopes(
    transaction: &Transaction<'_>,
    rows: Vec<Row>,
) -> StoreResult<Vec<ResourceModel>> {
    let ids: Vec<String> = rows.iter().map(|row| row.get("resource_id")).collect();
    let mut declared = declared_scopes(transaction, &ids).await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let id: String = row.get("resource_id");
            let scopes = declared.remove(&id).unwrap_or_default();
            read_resource(row, scopes)
        })
        .collect())
}

/// The verbs each of these resources declares.
///
/// One statement whatever the count, so listing a server's surface does not
/// grow a query per resource. A resource with no row here declares none, which
/// is why the caller defaults to the empty list and never to "unknown".
async fn declared_scopes(
    transaction: &Transaction<'_>,
    resource_ids: &[String],
) -> StoreResult<HashMap<String, Vec<String>>> {
    let mut declared: HashMap<String, Vec<String>> = HashMap::new();
    if resource_ids.is_empty() {
        return Ok(declared);
    }

    let rows = transaction
        .query(
            "SELECT resource_id, scope_id FROM resource_scopes \
             WHERE resource_id = ANY($1) ORDER BY scope_id ASC",
            &[&resource_ids],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    for row in rows {
        declared
            .entry(row.get("resource_id"))
            .or_default()
            .push(row.get("scope_id"));
    }
    Ok(declared)
}

fn read_server(row: Row) -> ResourceServerModel {
    ResourceServerModel {
        server_id: row.get("server_id"),
        realm_id: row.get("realm_id"),
        enforcement_mode: row.get("enforcement_mode"),
        decision_strategy: row.get("decision_strategy"),
        remote_resource_management: row.get("remote_resource_management"),
        user_managed_access: row.get("user_managed_access"),
        metadata: audit(&row),
    }
}

/// Read a resource, with the verbs it declares.
///
/// The scopes are a parameter rather than a field left to fill in afterwards:
/// there is no way to build one of these without having asked what it declares.
fn read_resource(row: Row, scopes: Vec<String>) -> ResourceModel {
    ResourceModel {
        resource_id: row.get("resource_id"),
        server_id: row.get("server_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        resource_uris: row.get("resource_uris"),
        resource_type: row.get("resource_type"),
        resource_owner: row.get("resource_owner"),
        user_managed_access: row.get("user_managed_access"),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value::<AttributesMap>(value).ok()),
        scopes: Some(scopes),
        metadata: audit(&row),
    }
}

fn read_scope(row: Row) -> ScopeModel {
    ScopeModel {
        scope_id: row.get("scope_id"),
        server_id: row.get("server_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        metadata: audit(&row),
    }
}

fn audit(row: &Row) -> models::auditable::AuditableModel {
    models::auditable::AuditableModel {
        tenant: row.get("tenant"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
    }
}
