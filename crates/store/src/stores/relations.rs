//! The schema of relations of a realm, and the relations it keeps, in
//! constant SQL.

use async_trait::async_trait;
use saffui_core::authz::relations::{
    AdmittedRelation, ObjectRef, RelationTuple, StoredSchema, SubjectRef,
};
use saffui_core::authz::store::RelationStore;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;

use crate::work::PgUnitOfWork;

/// The subject a row names. An empty member is the subject itself.
fn write_member(subject: &SubjectRef) -> &str {
    subject.member.as_deref().unwrap_or("")
}

#[async_trait]
impl RelationStore for PgUnitOfWork {
    async fn write_relation_schema(&mut self, schema: &StoredSchema) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement keeps the schema of the realm, in place of the one before.
        self.execute_raw(
            "INSERT INTO relation_schemas (tenant_id, realm_id, source, compiled, written_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id) DO UPDATE
                 SET source = EXCLUDED.source, compiled = EXCLUDED.compiled,
                     written_at = EXCLUDED.written_at",
            &[
                &tenant,
                &realm,
                &schema.source,
                &schema.compiled,
                &schema.written_at,
            ],
        )
        .await
        .map(|_| ())
    }

    async fn read_relation_schema(&mut self) -> Result<Option<StoredSchema>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT source, compiled, written_at FROM relation_schemas
                 WHERE tenant_id = $1 AND realm_id = $2",
                &[&tenant, &realm],
            )
            .await?;
        // A compiled form the driver cannot read is a failure, never a panic.
        rows.first()
            .map(|row| {
                Ok(StoredSchema {
                    source: row.get(0),
                    compiled: row.try_get(1).map_err(|_| StorageError::Failed)?,
                    written_at: row.get(2),
                })
            })
            .transpose()
    }

    async fn insert_relation(
        &mut self,
        tuple: &RelationTuple,
        written_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Kept twice, a relation is kept once, and the count says which time it was.
        let kept = self
            .execute_raw(
                "INSERT INTO relation_tuples (tenant_id, realm_id, object_type, object_id,
                     relation, subject_type, subject_id, subject_member, written_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT DO NOTHING",
                &[
                    &tenant,
                    &realm,
                    &tuple.object.object_type,
                    &tuple.object.object_id,
                    &tuple.relation,
                    &tuple.subject.object.object_type,
                    &tuple.subject.object.object_id,
                    &write_member(&tuple.subject),
                    &written_at,
                ],
            )
            .await?;
        Ok(kept == 1)
    }

    async fn delete_relation(&mut self, tuple: &RelationTuple) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM relation_tuples
                 WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3 AND object_id = $4
                   AND relation = $5 AND subject_type = $6 AND subject_id = $7
                   AND subject_member = $8",
                &[
                    &tenant,
                    &realm,
                    &tuple.object.object_type,
                    &tuple.object.object_id,
                    &tuple.relation,
                    &tuple.subject.object.object_type,
                    &tuple.subject.object.object_id,
                    &write_member(&tuple.subject),
                ],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn delete_relations_not_admitted(
        &mut self,
        admitted: &[AdmittedRelation],
    ) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let object_types: Vec<&str> = admitted
            .iter()
            .map(|one| one.object_type.as_str())
            .collect();
        let relations: Vec<&str> = admitted.iter().map(|one| one.relation.as_str()).collect();
        let subject_types: Vec<&str> = admitted
            .iter()
            .map(|one| one.subject.object_type.as_str())
            .collect();
        let members: Vec<&str> = admitted
            .iter()
            .map(|one| one.subject.member.as_deref().unwrap_or(""))
            .collect();
        // What the schema admits, as rows: a kept relation none of them names goes.
        self.execute_raw(
            "DELETE FROM relation_tuples kept
             WHERE kept.tenant_id = $1 AND kept.realm_id = $2
               AND NOT EXISTS (
                   SELECT 1 FROM unnest($3::text[], $4::text[], $5::text[], $6::text[])
                       AS admitted (object_type, relation, subject_type, subject_member)
                   WHERE admitted.object_type = kept.object_type
                     AND admitted.relation = kept.relation
                     AND admitted.subject_type = kept.subject_type
                     AND admitted.subject_member = kept.subject_member
               )",
            &[
                &tenant,
                &realm,
                &object_types,
                &relations,
                &subject_types,
                &members,
            ],
        )
        .await
    }

    async fn insert_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
        written_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let kept = self
            .execute_raw(
                "INSERT INTO relation_guards (tenant_id, realm_id, object_type, client_id, written_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                &[&tenant, &realm, &object_type, &client_id, &written_at],
            )
            .await?;
        Ok(kept == 1)
    }

    async fn delete_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM relation_guards
                 WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3 AND client_id = $4",
                &[&tenant, &realm, &object_type, &client_id],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn is_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT EXISTS (SELECT 1 FROM relation_guards
                     WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3 AND client_id = $4)",
                &[&tenant, &realm, &object_type, &client_id],
            )
            .await?;
        rows.first()
            .map(|row| row.get(0))
            .ok_or(StorageError::Failed)
    }

    async fn list_relation_guards(
        &mut self,
        object_type: &str,
        most: u32,
    ) -> Result<Vec<String>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let most = i64::from(most);
        let rows = self
            .read_raw(
                "SELECT client_id FROM relation_guards
                 WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3
                 ORDER BY client_id COLLATE \"C\"
                 LIMIT $4",
                &[&tenant, &realm, &object_type, &most],
            )
            .await?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    async fn list_relation_subjects(
        &mut self,
        object: &ObjectRef,
        relation: &str,
        limit: u32,
    ) -> Result<Vec<SubjectRef>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let limit = i64::from(limit);
        let rows = self
            .read_raw(
                "SELECT subject_type, subject_id, subject_member FROM relation_tuples
                 WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3 AND object_id = $4
                   AND relation = $5
                 ORDER BY subject_type, subject_id, subject_member
                 LIMIT $6",
                &[
                    &tenant,
                    &realm,
                    &object.object_type,
                    &object.object_id,
                    &relation,
                    &limit,
                ],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| {
                let member: String = row.get(2);
                SubjectRef {
                    object: ObjectRef {
                        object_type: row.get(0),
                        object_id: row.get(1),
                    },
                    member: (!member.is_empty()).then_some(member),
                }
            })
            .collect())
    }
}
