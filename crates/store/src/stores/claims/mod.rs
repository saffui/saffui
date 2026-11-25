//! The mappers of the clients and the attributes of the people, in constant
//! SQL.

use async_trait::async_trait;
use saffui_core::authz::capability::Capability;
use saffui_core::claims::store::ClaimStore;
use saffui_core::claims::{ClaimTarget, LockedClient, Mapper, MapperKind};
use saffui_core::ports::storage::StorageError;
use serde_json::{Map, Value};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::work::PgUnitOfWork;

/// Constant SQL: the row stays locked until the commit. The key of a client
/// never changes.
const LOCK_CLIENT: &str = "
    SELECT scopes, capabilities FROM clients
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
    FOR NO KEY UPDATE";

/// Constant SQL: a name the client holds already writes nothing.
const INSERT_MAPPER: &str = "
    INSERT INTO client_mappers (tenant_id, realm_id, mapper_id, client_id, name, definition,
        claim, targets, scope, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT ON CONSTRAINT client_mappers_name_taken DO NOTHING";

/// Constant SQL: a name is unique for a client, and its collation is bytes.
/// A client keeps fifty at most, counted under the lock of its row.
const LIST_MAPPERS: &str = "
    SELECT mapper_id, client_id, name, definition, claim, targets, scope, created_at
    FROM client_mappers
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
    ORDER BY name";

const DELETE_MAPPER: &str = "
    DELETE FROM client_mappers
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND mapper_id = $4";

const READ_ATTRIBUTES: &str = "
    SELECT attributes FROM persons
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3";

/// Constant SQL: as `READ_ATTRIBUTES`, and the row stays locked until the
/// commit. The key of a person never changes.
const LOCK_ATTRIBUTES: &str = "
    SELECT attributes FROM persons
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
    FOR NO KEY UPDATE";

const WRITE_ATTRIBUTES: &str = "
    UPDATE persons SET attributes = $4
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3";

/// Reads a mapper from a row. A kind or a target this version does not know
/// is a failure: a token never leaves a mapper out unsaid.
fn read_mapper_row(row: &Row) -> Result<Mapper, StorageError> {
    let definition: Value = row.try_get(3).map_err(|_| StorageError::Failed)?;
    let targets: Vec<String> = row.get(5);
    Ok(Mapper {
        id: row.get(0),
        client_id: row.get(1),
        name: row.get(2),
        kind: serde_json::from_value::<MapperKind>(definition).map_err(|_| StorageError::Failed)?,
        claim: row.get(4),
        targets: targets
            .iter()
            .map(|name| ClaimTarget::parse(name).ok_or(StorageError::Failed))
            .collect::<Result<_, _>>()?,
        scope: row.get(6),
        created_at: row.get(7),
    })
}

/// Reads the attributes of a person from the first row, if there is one.
fn read_attributes_row(rows: &[Row]) -> Result<Option<Map<String, Value>>, StorageError> {
    rows.first()
        .map(|row| match row.try_get::<_, Value>(0) {
            Ok(Value::Object(attributes)) => Ok(attributes),
            _ => Err(StorageError::Failed),
        })
        .transpose()
}

#[async_trait]
impl ClaimStore for PgUnitOfWork {
    async fn lock_client(&mut self, client_id: &str) -> Result<Option<LockedClient>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let taken = self
            .read_raw(LOCK_CLIENT, &[&tenant, &realm, &client_id])
            .await?;
        let Some(row) = taken.first() else {
            return Ok(None);
        };
        let capabilities: Vec<String> = row.get(1);
        Ok(Some(LockedClient {
            scopes: row.get(0),
            // The schema holds the same list: a name unknown here was not
            // written by this binary.
            capabilities: capabilities
                .iter()
                .map(|name| Capability::parse(name).ok_or(StorageError::Failed))
                .collect::<Result<_, _>>()?,
        }))
    }

    async fn insert_mapper(&mut self, mapper: &Mapper) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let definition = serde_json::to_value(&mapper.kind).map_err(|_| StorageError::Failed)?;
        let targets: Vec<&str> = mapper.targets.iter().map(|target| target.name()).collect();
        let written = self
            .execute_raw(
                INSERT_MAPPER,
                &[
                    &tenant,
                    &realm,
                    &mapper.id,
                    &mapper.client_id,
                    &mapper.name,
                    &definition,
                    &mapper.claim,
                    &targets,
                    &mapper.scope,
                    &mapper.created_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn list_mappers(&mut self, client_id: &str) -> Result<Vec<Mapper>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(LIST_MAPPERS, &[&tenant, &realm, &client_id])
            .await?;
        rows.iter().map(read_mapper_row).collect()
    }

    async fn delete_mapper(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(DELETE_MAPPER, &[&tenant, &realm, &client_id, &id])
            .await?;
        Ok(removed == 1)
    }

    async fn read_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(READ_ATTRIBUTES, &[&tenant, &realm, &person])
            .await?;
        read_attributes_row(&rows)
    }

    async fn lock_person_attributes(
        &mut self,
        person: Uuid,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(LOCK_ATTRIBUTES, &[&tenant, &realm, &person])
            .await?;
        read_attributes_row(&rows)
    }

    async fn write_person_attributes(
        &mut self,
        person: Uuid,
        attributes: &Map<String, Value>,
    ) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        let document = Value::Object(attributes.clone());
        let written = self
            .execute_raw(WRITE_ATTRIBUTES, &[&tenant, &realm, &person, &document])
            .await?;
        if written == 1 {
            Ok(())
        } else {
            Err(self.refuse_out_of_scope())
        }
    }
}
