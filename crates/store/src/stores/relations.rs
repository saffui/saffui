//! The schema of relations of a realm, and the relations it keeps, in
//! constant SQL.

use async_trait::async_trait;
use saffui_core::authz::relations::{
    AdmittedRelation, GuardedSchema, ObjectRef, RelationAdmission, RelationTuple, StoredSchema,
    SubjectRef,
};
use saffui_core::authz::store::RelationStore;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;

use crate::work::PgUnitOfWork;

/// The subject a row names. An empty member is the subject itself.
fn write_member(subject: &SubjectRef) -> &str {
    subject.member.as_deref().unwrap_or("")
}

/// Removes the relations of some kinds, $3 to $6 their four columns. The key
/// is entered once for each type and relation they name, so a relation is
/// read once whatever the number of its kinds, and `IS TRUE` keeps the kinds
/// a filter. Planned for any values, `= ANY` on both columns reads the whole
/// realm: each array counts as ten values, the two as a hundred descents.
const DELETE_RELATIONS_OF_KINDS: &str = "DELETE FROM relation_tuples kept
     USING (SELECT DISTINCT * FROM unnest($3::text[], $4::text[])) AS named (object_type, relation)
     WHERE kept.tenant_id = $1 AND kept.realm_id = $2
       AND kept.object_type = named.object_type AND kept.relation = named.relation
       AND ((kept.object_type, kept.relation, kept.subject_type, kept.subject_member) IN (
           SELECT * FROM unnest($3::text[], $4::text[], $5::text[], $6::text[]))) IS TRUE";

/// Kinds of relations as four columns, for `unnest`: type of object,
/// relation, type of subject, member.
fn split_kinds(kinds: &[AdmittedRelation]) -> [Vec<&str>; 4] {
    let mut columns: [Vec<&str>; 4] = Default::default();
    for kind in kinds {
        columns[0].push(&kind.object_type);
        columns[1].push(&kind.relation);
        columns[2].push(&kind.subject.object_type);
        columns[3].push(kind.subject.member.as_deref().unwrap_or(""));
    }
    columns
}

#[async_trait]
impl RelationStore for PgUnitOfWork {
    async fn write_relation_schema(
        &mut self,
        schema: &StoredSchema,
        admitted: &[AdmittedRelation],
    ) -> Result<(), StorageError> {
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
        .await?;
        // Its kinds in place of those before, in two statements: within one,
        // the insert would meet the rows the removal has yet to take.
        self.execute_raw(
            "DELETE FROM relation_kinds WHERE tenant_id = $1 AND realm_id = $2",
            &[&tenant, &realm],
        )
        .await?;
        let [object_types, relations, subject_types, members] = split_kinds(admitted);
        self.execute_raw(
            "INSERT INTO relation_kinds (tenant_id, realm_id, object_type, relation, subject_type,
                 subject_member)
             SELECT $1::uuid, $2::uuid, *
             FROM unnest($3::text[], $4::text[], $5::text[], $6::text[])",
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

    async fn read_guarded_schema(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<Option<GuardedSchema>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT compiled, EXISTS (SELECT 1 FROM relation_guards
                     WHERE tenant_id = $1 AND realm_id = $2 AND object_type = $3
                       AND client_id = $4)
                 FROM relation_schemas
                 WHERE tenant_id = $1 AND realm_id = $2",
                &[&tenant, &realm, &object_type, &client_id],
            )
            .await?;
        rows.first()
            .map(|row| {
                Ok(GuardedSchema {
                    compiled: row.try_get(0).map_err(|_| StorageError::Failed)?,
                    guarded: row.get(1),
                })
            })
            .transpose()
    }

    async fn admit_relation(
        &mut self,
        tuple: &RelationTuple,
    ) -> Result<RelationAdmission, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT saffui_admit_relation($1, $2, $3, $4, $5, $6, $7, $8)",
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
        // An answer this version does not know is a failure, never a guess.
        match rows.first().and_then(|row| row.try_get::<_, &str>(0).ok()) {
            Some("refused") => Ok(RelationAdmission::Refused),
            Some("kept") => Ok(RelationAdmission::Kept),
            Some("taken") => Ok(RelationAdmission::Taken),
            _ => Err(StorageError::Failed),
        }
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
        let [object_types, relations, subject_types, members] = split_kinds(admitted);
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

    async fn delete_relations_of_kinds(
        &mut self,
        kinds: &[AdmittedRelation],
    ) -> Result<u64, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let [object_types, relations, subject_types, members] = split_kinds(kinds);
        self.execute_raw(
            DELETE_RELATIONS_OF_KINDS,
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

#[cfg(test)]
mod tests {
    use pgcore::migrate::EMBEDDED;
    use pgcore::testkit::TestDatabase;

    use super::DELETE_RELATIONS_OF_KINDS;

    /// A hundred realms of three types, each of three kinds, and in the realm
    /// swept tens of thousands of relations of other types, or of other
    /// relations of its types. A sweep of the three kinds of one type and of
    /// one kind of another, planned for any values, enters the key once for
    /// each of the three types and relations it names, and reads nothing else.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario, read from top to bottom"
    )]
    async fn a_sweep_reads_the_relations_it_names_once_whatever_the_number_of_their_kinds() {
        let database = TestDatabase::create(EMBEDDED).await;
        let owner = database
            .plan("saffui_owner")
            .connect_directly()
            .await
            .expect("a connection");
        let (tenant, realm) = (
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        );
        owner
            .batch_execute(&format!(
                "BEGIN;
                 SELECT set_config('saffui.tenant', '{tenant}', true);
                 INSERT INTO tenants VALUES ('{tenant}', 'acme', now());
                 DO $$
                 DECLARE planted uuid;
                 BEGIN
                     FOR i IN 2..101 LOOP
                         planted := ('00000000-0000-0000-0000-' || lpad(i::text, 12, '0'))::uuid;
                         PERFORM set_config('saffui.realm', planted::text, true);
                         INSERT INTO realms VALUES ('{tenant}', planted, 'realm-' || i, true, now());
                         INSERT INTO relation_tuples
                         SELECT '{tenant}', planted, object_type, 'o' || n, relation, subject_type,
                                'u' || n, member, now()
                         FROM generate_series(1, 25) n,
                              unnest(ARRAY['document', 'folder', 'team']) object_type,
                              (VALUES ('owner', 'user', ''), ('reader', 'user', ''),
                                      ('reader', 'team', 'member')) kind (relation, subject_type, member);
                     END LOOP;
                     -- Of types the sweep does not name, or of relations it does not.
                     PERFORM set_config('saffui.realm', '{realm}', true);
                     INSERT INTO relation_tuples
                     SELECT '{tenant}', '{realm}', object_type, 'x' || n, relation, 'user', 'u' || n,
                            '', now()
                     FROM generate_series(1, 2500) n,
                          unnest(ARRAY['document', 'folder', 'invoice', 'printer', 'ticket']) object_type,
                          unnest(ARRAY['approver', 'editor', 'owner', 'reader']) relation
                     WHERE (object_type IN ('document', 'folder')) = (relation IN ('approver', 'editor'));
                 END $$;
                 COMMIT;
                 ANALYZE relation_tuples;"
            ))
            .await
            .expect("the relations of a hundred realms");

        owner
            .batch_execute(&format!(
                "BEGIN;
                 SELECT set_config('saffui.tenant', '{tenant}', true),
                        set_config('saffui.realm', '{realm}', true);
                 SET LOCAL plan_cache_mode = force_generic_plan;
                 PREPARE sweep (uuid, uuid, text[], text[], text[], text[]) AS
                     {DELETE_RELATIONS_OF_KINDS}"
            ))
            .await
            .expect("a sweep, planned for any values");
        let plan = owner
            .query(
                &format!(
                    "EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF, SUMMARY OFF) EXECUTE sweep (
                         '{tenant}', '{realm}',
                         ARRAY['document', 'document', 'document', 'folder'],
                         ARRAY['owner', 'reader', 'reader', 'owner'],
                         ARRAY['user', 'user', 'team', 'user'],
                         ARRAY['', '', 'member', ''])"
                ),
                &[],
            )
            .await
            .expect("the plan of the sweep");
        owner.batch_execute("ROLLBACK").await.expect("a rollback");

        let plan: Vec<String> = plan.iter().map(|row| row.get(0)).collect();
        assert!(
            plan.iter()
                .any(|line| line.contains("(actual rows=100 loops=1)")),
            "the hundred relations of the four kinds are found: {plan:#?}"
        );
        for line in plan
            .iter()
            .filter(|line| line.contains("Scan") && line.contains(" on relation_tuples"))
        {
            assert!(
                line.contains("Index Scan") && line.contains(" loops=3)"),
                "{line}: {plan:#?}"
            );
        }
        assert!(
            plan.iter().any(|line| line.contains("Index Cond:")
                && line.contains("(object_type = ")
                && line.contains("(relation = ")),
            "the key bounds the read to the types and relations named: {plan:#?}"
        );
        assert!(
            !plan.iter().any(|line| line.contains("Rows Removed")),
            "nothing else is read: {plan:#?}"
        );
        // The relation before the object in the key: else the plan reads the
        // same, but each scan walks every object of its type (312 pages, not 28).
        let pages: u32 = plan
            .iter()
            .skip_while(|line| !line.contains("Index Scan"))
            .find_map(|line| line.trim().strip_prefix("Buffers: shared "))
            .map(|counts| {
                counts
                    .split(' ')
                    .filter_map(|count| count.split_once('=')?.1.parse::<u32>().ok())
                    .sum()
            })
            .expect("the pages the scan read");
        assert!(pages < 100, "{pages} pages read: {plan:#?}");
        assert!(
            plan.iter().any(|line| line.contains("hashed SubPlan")),
            "the kinds are a filter, each relation read once: {plan:#?}"
        );
    }

    /// The table refuses a compiled form past twice what the product writes,
    /// whoever writes it, and keeps one at that bound.
    #[tokio::test]
    async fn a_compiled_form_past_its_bound_is_refused_by_the_table() {
        use tokio_postgres::error::SqlState;

        let database = TestDatabase::create(EMBEDDED).await;
        let owner = database
            .plan("saffui_owner")
            .connect_directly()
            .await
            .expect("a connection");
        let (tenant, realm) = (
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        );
        let scoped = format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{tenant}', true),
                    set_config('saffui.realm', '{realm}', true);"
        );
        owner
            .batch_execute(&format!(
                "{scoped}
                 INSERT INTO tenants VALUES ('{tenant}', 'acme', now());
                 INSERT INTO realms VALUES ('{tenant}', '{realm}', 'acme', true, now());
                 COMMIT"
            ))
            .await
            .expect("a realm");
        // What jsonb writes around the padding: `{"pad": "", "version": 1}`.
        let bound = 2 * saffui_core::authz::relations::schema::SCHEMA_COMPILED_MAX_BYTES;
        let around = r#"{"pad": "", "version": 1}"#.len();
        let write = |padding: usize| {
            let scoped = scoped.clone();
            let owner = &owner;
            async move {
                owner.batch_execute(&scoped).await.expect("a scope");
                let written = owner
                    .query_one(
                        "INSERT INTO relation_schemas
                         VALUES ($1::text::uuid, $2::text::uuid, '',
                                 jsonb_build_object('version', 1, 'pad', repeat('x', $3)), now())
                         RETURNING octet_length(compiled::text)",
                        &[&tenant, &realm, &i32::try_from(padding).expect("a padding")],
                    )
                    .await
                    .map(|row| row.get::<_, i32>(0));
                owner.batch_execute("ROLLBACK").await.expect("a rollback");
                written
            }
        };

        let at_bound = write(bound - around).await.expect("a form at the bound");
        assert_eq!(usize::try_from(at_bound).expect("a length"), bound);
        let refused = write(bound - around + 1).await.expect_err("a form past it");
        assert_eq!(refused.code(), Some(&SqlState::CHECK_VIOLATION));
    }
}
