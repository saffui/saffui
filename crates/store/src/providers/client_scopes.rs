use deadpool_postgres::Transaction;
use models::entities::client::{ClientScopeModel, Protocol, ProtocolMapperModel};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const SCOPE_COLUMNS: &str = "tenant, realm_id, client_scope_id, name, description, protocol, \
                             default_scope, configs, created_by, created_at, updated_by, \
                             updated_at, version";

const MAPPER_COLUMNS: &str = "tenant, realm_id, mapper_id, name, protocol, mapper_type, \
                              configs, created_by, created_at, updated_by, updated_at, version";

/// Record a scope.
pub async fn create_scope(
    transaction: &Transaction<'_>,
    scope: &ClientScopeModel,
) -> StoreResult<()> {
    let configs = json(&scope.configs)?;
    let default_scope = scope.default_scope.unwrap_or(false);
    let set = WriteSet::insert(vec![
        col("tenant", &scope.metadata.tenant),
        col("realm_id", &scope.realm_id),
        col("client_scope_id", &scope.client_scope_id),
        col("name", &scope.name),
        col("description", &scope.description),
        col("protocol", &scope.protocol),
        col("default_scope", &default_scope),
        col("configs", &configs),
        col("created_by", &scope.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("client_scopes", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One scope of this realm.
pub async fn load_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
) -> StoreResult<Option<ClientScopeModel>> {
    let statement = format!("SELECT {SCOPE_COLUMNS} FROM client_scopes WHERE client_scope_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&client_scope_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_scope))
}

/// The scopes a new client of this realm is given without anyone attaching
/// them.
///
/// Ordered by name, which is also the order of the index enforcing one scope
/// per name, so removing the clause changes nothing observable. Stated anyway,
/// since the index exists for uniqueness and could be replaced by one that does
/// not sort this way.
pub async fn default_scopes(
    transaction: &Transaction<'_>,
    protocol: Protocol,
) -> StoreResult<Vec<ClientScopeModel>> {
    let statement = format!(
        "SELECT {SCOPE_COLUMNS} FROM client_scopes \
         WHERE default_scope AND protocol = $1 ORDER BY name ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&protocol])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_scope)
        .collect())
}

/// Record a mapper.
pub async fn create_mapper(
    transaction: &Transaction<'_>,
    mapper: &ProtocolMapperModel,
) -> StoreResult<()> {
    let configs = json(&mapper.configs)?;
    let set = WriteSet::insert(vec![
        col("tenant", &mapper.metadata.tenant),
        col("realm_id", &mapper.realm_id),
        col("mapper_id", &mapper.mapper_id),
        col("name", &mapper.name),
        col("protocol", &mapper.protocol),
        col("mapper_type", &mapper.mapper_type),
        col("configs", &configs),
        col("created_by", &mapper.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("protocol_mappers", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Give a client a scope, or leave the attachment as it stands.
pub async fn attach_scope(
    transaction: &Transaction<'_>,
    client_id: &str,
    client_scope_id: &str,
    optional: bool,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO clients_client_scopes \
                 (tenant, realm_id, client_id, client_scope_id, optional) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT (tenant, realm_id, client_id, client_scope_id) \
             DO UPDATE SET optional = EXCLUDED.optional",
            &[&client_id, &client_scope_id, &optional],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take a scope away from a client, and say whether it had it.
pub async fn detach_scope(
    transaction: &Transaction<'_>,
    client_id: &str,
    client_scope_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM clients_client_scopes WHERE client_id = $1 AND client_scope_id = $2",
            &[&client_id, &client_scope_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Attach a mapper to a scope.
pub async fn attach_mapper_to_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
    mapper_id: &str,
) -> StoreResult<()> {
    attach(
        transaction,
        "client_scopes_protocol_mappers",
        "client_scope_id",
        "mapper_id",
        client_scope_id,
        mapper_id,
    )
    .await
}

/// Attach a mapper to a client, bypassing scopes.
pub async fn attach_mapper_to_client(
    transaction: &Transaction<'_>,
    client_id: &str,
    mapper_id: &str,
) -> StoreResult<()> {
    attach(
        transaction,
        "clients_protocol_mappers",
        "client_id",
        "mapper_id",
        client_id,
        mapper_id,
    )
    .await
}

/// Say that holding a scope grants a role.
pub async fn attach_role_to_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
    role_id: &str,
) -> StoreResult<()> {
    attach(
        transaction,
        "client_scopes_roles",
        "client_scope_id",
        "role_id",
        client_scope_id,
        role_id,
    )
    .await
}

/// The scopes a client holds.
///
/// The optional ones are included and marked, because whether a scope applies
/// depends on what the request asked for, and that decision does not belong to
/// a query.
pub async fn scopes_of_client(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Vec<(ClientScopeModel, bool)>> {
    let columns = SCOPE_COLUMNS
        .split(", ")
        .map(|column| format!("s.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let statement = format!(
        "SELECT {columns}, a.optional FROM client_scopes s \
         JOIN clients_client_scopes a USING (tenant, realm_id, client_scope_id) \
         WHERE a.client_id = $1 ORDER BY s.name ASC"
    );

    Ok(transaction
        .query(statement.as_str(), &[&client_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| {
            let optional: bool = row.get("optional");
            (read_scope(row), optional)
        })
        .collect())
}

/// Every mapper that applies to a client: attached to it, or reached through a
/// scope it holds.
///
/// One query rather than one per scope. A mapper reached through two scopes is
/// one rule, and the membership test is what makes it one: adding a DISTINCT on
/// top would be a second mechanism for the same property, and a test could then
/// only ever exercise whichever ran first.
pub async fn mappers_for_client(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Vec<ProtocolMapperModel>> {
    let columns = MAPPER_COLUMNS
        .split(", ")
        .map(|column| format!("m.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let statement = format!(
        "SELECT {columns} FROM protocol_mappers m \
         WHERE m.mapper_id IN ( \
             SELECT mapper_id FROM clients_protocol_mappers WHERE client_id = $1 \
             UNION ALL \
             SELECT sm.mapper_id FROM client_scopes_protocol_mappers sm \
             JOIN clients_client_scopes a USING (tenant, realm_id, client_scope_id) \
             WHERE a.client_id = $1 \
         ) ORDER BY m.name ASC"
    );

    Ok(transaction
        .query(statement.as_str(), &[&client_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_mapper)
        .collect())
}

/// The roles a scope grants.
///
/// Ordered by identifier, which happens to be the order the primary key index
/// returns them in. The clause states the intent and a mutation removing it is
/// not observable here, which is worth knowing rather than assuming a test
/// covers it.
pub async fn roles_of_scope(
    transaction: &Transaction<'_>,
    client_scope_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT role_id FROM client_scopes_roles \
             WHERE client_scope_id = $1 ORDER BY role_id ASC",
            &[&client_scope_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("role_id"))
        .collect())
}

/// The shared attachment, since all four are the same statement over different
/// names and a second copy of it drifts a column at a time.
async fn attach(
    transaction: &Transaction<'_>,
    table: &str,
    left: &str,
    right: &str,
    left_value: &str,
    right_value: &str,
) -> StoreResult<()> {
    let statement = format!(
        "INSERT INTO {table} (tenant, realm_id, {left}, {right}) \
         SELECT current_setting('saffui.current_tenant', true), \
                current_setting('saffui.current_realm', true), $1, $2 \
         ON CONFLICT DO NOTHING"
    );
    transaction
        .execute(statement.as_str(), &[&left_value, &right_value])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

fn json(
    configs: &Option<models::entities::attributes::AttributesMap>,
) -> StoreResult<Option<serde_json::Value>> {
    configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn read_scope(row: Row) -> ClientScopeModel {
    ClientScopeModel {
        client_scope_id: row.get("client_scope_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        description: row.get("description"),
        protocol: row.get::<_, Protocol>("protocol"),
        default_scope: Some(row.get("default_scope")),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value(value).ok()),
        metadata: audit(&row),
    }
}

fn read_mapper(row: Row) -> ProtocolMapperModel {
    ProtocolMapperModel {
        mapper_id: row.get("mapper_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        protocol: row.get::<_, Protocol>("protocol"),
        mapper_type: row.get("mapper_type"),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value(value).ok()),
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
