//! The policies of the clients that guard resources, in constant SQL.

use async_trait::async_trait;
use saffui_core::authz::policy::{Combine, Effect, Policy};
use saffui_core::authz::store::PolicyStore;
use saffui_core::ports::storage::StorageError;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::work::PgUnitOfWork;

/// Reads a policy from a row. An effect or a combination the table admits
/// but this version does not know is a failure, never a guess.
fn read_policy_row(row: &Row) -> Result<Policy, StorageError> {
    let effect: String = row.get(5);
    let combine: String = row.get(6);
    Ok(Policy {
        id: row.get(0),
        client_id: row.get(1),
        name: row.get(2),
        resource_type: row.get(3),
        action: row.get(4),
        effect: Effect::parse(&effect).ok_or(StorageError::Failed)?,
        combine: Combine::parse(&combine).ok_or(StorageError::Failed)?,
        conditions: row.try_get(7).map_err(|_| StorageError::Failed)?,
        created_at: row.get(8),
    })
}

impl PgUnitOfWork {
    /// Takes the row of the definitions of the realm, made with the realm, by
    /// a statement that locks it, and returns what it read. A realm without
    /// the row is refused, never let through unlocked.
    async fn take_definitions_row(&mut self, statement: &str) -> Result<Row, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let mut taken = self.read_raw(statement, &[&tenant, &realm]).await?;
        let row = taken.pop().filter(|_| taken.is_empty());
        row.ok_or_else(|| {
            tracing::error!("a realm has no row of the definitions of its authorization");
            StorageError::Failed
        })
    }
}

#[async_trait]
impl PolicyStore for PgUnitOfWork {
    async fn insert_policy(&mut self, policy: &Policy) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (effect, combine) = (policy.effect.name(), policy.combine.name());
        // A name the client holds already writes nothing.
        let written = self
            .execute_raw(
                "INSERT INTO authz_policies (tenant_id, realm_id, policy_id, client_id, name,
                     resource_type, action, effect, combine, conditions, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT ON CONSTRAINT authz_policies_name_taken DO NOTHING",
                &[
                    &tenant,
                    &realm,
                    &policy.id,
                    &policy.client_id,
                    &policy.name,
                    &policy.resource_type,
                    &policy.action,
                    &effect,
                    &combine,
                    &policy.conditions,
                    &policy.created_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn list_policies(&mut self, client_id: &str) -> Result<Vec<Policy>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // A name is unique for a client: the order is total.
        let rows = self
            .read_raw(
                "SELECT policy_id, client_id, name, resource_type, action, effect, combine,
                        conditions, created_at
                 FROM authz_policies
                 WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
                 ORDER BY name",
                &[&tenant, &realm, &client_id],
            )
            .await?;
        rows.iter().map(read_policy_row).collect()
    }

    async fn list_applicable_policies(
        &mut self,
        client_id: &str,
        resource_type: &str,
        action: &str,
    ) -> Result<Vec<Policy>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT policy_id, client_id, name, resource_type, action, effect, combine,
                        conditions, created_at
                 FROM authz_policies
                 WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
                   AND resource_type = $4 AND action = $5
                 ORDER BY name",
                &[&tenant, &realm, &client_id, &resource_type, &action],
            )
            .await?;
        rows.iter().map(read_policy_row).collect()
    }

    async fn count_policies(&mut self, client_id: &str, most: u32) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let most = i64::from(most);
        let rows = self
            .read_raw(
                "SELECT count(*) FROM (
                     SELECT 1 FROM authz_policies
                     WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
                     LIMIT $4
                 ) counted",
                &[&tenant, &realm, &client_id, &most],
            )
            .await?;
        let kept: i64 = rows.first().ok_or(StorageError::Failed)?.get(0);
        u64::try_from(kept).map_err(|_| StorageError::Failed)
    }

    async fn delete_policy(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM authz_policies
                 WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND policy_id = $4",
                &[&tenant, &realm, &client_id, &id],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn lock_definitions(&mut self) -> Result<(), StorageError> {
        self.take_definitions_row(
            "SELECT 1 FROM authz_definitions WHERE tenant_id = $1 AND realm_id = $2 FOR UPDATE",
        )
        .await
        .map(|_| ())
    }

    async fn lock_definitions_and_read_schema(
        &mut self,
    ) -> Result<Option<serde_json::Value>, StorageError> {
        // The function sets the shorter wait for its own statements alone.
        let taken = self
            .take_definitions_row("SELECT compiled FROM saffui_take_definitions_to_relate($1, $2)")
            .await?;
        taken.try_get(0).map_err(|_| StorageError::Failed)
    }

    async fn has_policy_for_types(&mut self, types: &[String]) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT EXISTS (SELECT 1 FROM authz_policies
                     WHERE tenant_id = $1 AND realm_id = $2 AND resource_type = ANY($3))",
                &[&tenant, &realm, &types],
            )
            .await?;
        rows.first()
            .map(|row| row.get(0))
            .ok_or(StorageError::Failed)
    }

    async fn is_named_by_policy(
        &mut self,
        condition: &str,
        id: Uuid,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let id = id.to_string();
        // A condition is one member of the array of its policy: containment
        // finds it, whatever the other conditions are.
        let rows = self
            .read_raw(
                "SELECT EXISTS (SELECT 1 FROM authz_policies
                     WHERE tenant_id = $1 AND realm_id = $2
                       AND conditions @> jsonb_build_array(jsonb_build_object($3::text, $4::text)))",
                &[&tenant, &realm, &condition, &id],
            )
            .await?;
        rows.first()
            .map(|row| row.get(0))
            .ok_or(StorageError::Failed)
    }
}
