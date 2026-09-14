use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

/// A realm's relationship schema, as written and as compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSchema {
    /// The shape the compiled half is in, so a build meeting a number it does
    /// not know refuses rather than reading the document as a shape it is not.
    pub format: i32,
    pub revision: i32,
    pub source: String,
    pub compiled: serde_json::Value,
}

/// One end of an edge: who or what stands in a relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub subject_type: String,
    pub subject_id: String,
    /// Empty for a subject named directly, otherwise the relation on that
    /// subject whose holders this edge stands for.
    pub subject_relation: String,
}

/// Record a realm's schema, replacing whatever it had.
///
/// Both halves together. Writing the source without the compiled form would
/// leave a realm deciding by the previous one while showing the new one.
pub async fn put_schema(
    transaction: &Transaction<'_>,
    schema: &StoredSchema,
    actor: Option<&str>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO rebac_schemas \
                 (tenant, realm_id, format, revision, source, compiled, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5 \
             ON CONFLICT (tenant, realm_id) DO UPDATE SET \
                 format = excluded.format, \
                 revision = rebac_schemas.revision + 1, \
                 source = excluded.source, \
                 compiled = excluded.compiled, \
                 updated_by = excluded.created_by, \
                 updated_at = now(), \
                 version = rebac_schemas.version + 1",
            &[
                &schema.format,
                &schema.revision,
                &schema.source,
                &schema.compiled,
                &actor,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// This realm's schema, if it has one.
pub async fn load_schema(transaction: &Transaction<'_>) -> StoreResult<Option<StoredSchema>> {
    Ok(transaction
        .query_opt(
            "SELECT format, revision, source, compiled FROM rebac_schemas",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| StoredSchema {
            format: row.get("format"),
            revision: row.get("revision"),
            source: row.get("source"),
            compiled: row.get("compiled"),
        }))
}

/// Record an edge, as a row and nothing more.
///
/// Nothing here reads the schema, because this layer cannot: the compiled form
/// belongs to the crate that decides by it. What that means for a caller is
/// that this writes edges the schema does not describe, which are stored, never
/// matched, and a grant somebody thought they made and did not.
///
/// The door edges should come in by is `services::rebac::relate`, which asks
/// the schema first. This one is for a caller replaying edges that were already
/// validated, an import being the case that exists.
///
/// Writing one twice writes it once.
pub async fn relate(
    transaction: &Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject: &Subject,
    actor: Option<&str>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO rebac_tuples \
                 (tenant, realm_id, object_type, object_id, relation, \
                  subject_type, subject_id, subject_relation, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6, $7 \
             ON CONFLICT DO NOTHING",
            &[
                &object_type,
                &object_id,
                &relation,
                &subject.subject_type,
                &subject.subject_id,
                &subject.subject_relation,
                &actor,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Remove an edge, and say whether there was one.
pub async fn unrelate(
    transaction: &Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject: &Subject,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM rebac_tuples \
             WHERE object_type = $1 AND object_id = $2 AND relation = $3 \
               AND subject_type = $4 AND subject_id = $5 AND subject_relation = $6",
            &[
                &object_type,
                &object_id,
                &relation,
                &subject.subject_type,
                &subject.subject_id,
                &subject.subject_relation,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Delete every edge naming this entity, as the subject or as the object, and
/// say how many went.
pub async fn unrelate_everything_naming(
    transaction: &Transaction<'_>,
    entity_type: &str,
    entity_id: &str,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM rebac_tuples \
             WHERE (subject_type = $1 AND subject_id = $2) \
                OR (object_type = $1 AND object_id = $2)",
            &[&entity_type, &entity_id],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

/// Who stands in one relation to one object.
///
/// Ordered, because a walk that short circuits on the first answer spends a
/// different amount of its budget depending on the order rows come back in, and
/// a budget that runs out is an error: unordered, the same question on the same
/// edges answers on one run and fails on the next.
///
/// One more than asked for is read, so a caller can tell a relation that fits
/// inside its ceiling from one that was cut off at it.
pub async fn subjects(
    transaction: &Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    limit: i64,
) -> StoreResult<Vec<Subject>> {
    Ok(transaction
        .query(
            "SELECT subject_type, subject_id, subject_relation FROM rebac_tuples \
             WHERE object_type = $1 AND object_id = $2 AND relation = $3 \
             ORDER BY subject_type ASC, subject_id ASC, subject_relation ASC \
             LIMIT $4",
            &[&object_type, &object_id, &relation, &(limit + 1)],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_subject)
        .collect())
}

/// The same edges, as far as they grant.
///
/// An edge on a resource whose sharing is closed, by the resource or by its
/// server, grants nothing and is left out here. It stays written, and grants
/// again once sharing reopens. Every edge on that resource is left out, since a
/// share is a row like any other; [`subjects`] still lists them all.
pub async fn granting_subjects(
    transaction: &Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    limit: i64,
) -> StoreResult<Vec<Subject>> {
    Ok(transaction
        .query(
            "SELECT t.subject_type, t.subject_id, t.subject_relation FROM rebac_tuples t \
             WHERE t.object_type = $1 AND t.object_id = $2 AND t.relation = $3 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM resources r \
                   JOIN resource_servers s \
                     ON s.tenant = r.tenant AND s.realm_id = r.realm_id \
                    AND s.server_id = r.server_id \
                   WHERE r.tenant = t.tenant AND r.realm_id = t.realm_id \
                     AND r.resource_type = t.object_type AND r.resource_id = t.object_id \
                     AND NOT (r.user_managed_access AND s.user_managed_access)) \
             ORDER BY t.subject_type ASC, t.subject_id ASC, t.subject_relation ASC \
             LIMIT $4",
            &[&object_type, &object_id, &relation, &(limit + 1)],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_subject)
        .collect())
}

fn read_subject(row: Row) -> Subject {
    Subject {
        subject_type: row.get("subject_type"),
        subject_id: row.get("subject_id"),
        subject_relation: row.get("subject_relation"),
    }
}

/// One edge as written: an object, a relation, and who stands in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject: Subject,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// What a listing of edges is narrowed to. Every part is optional, and every
/// part given has to hold.
#[derive(Debug, Default, Clone, Copy)]
pub struct TupleFilter<'a> {
    pub object_type: Option<&'a str>,
    pub relation: Option<&'a str>,
    pub subject_type: Option<&'a str>,
    pub subject_id: Option<&'a str>,
}

/// The realm's edges a page at a time, in the order the key keeps them.
///
/// Read as written and never walked: a listing says what stands, the engine
/// says what follows from it.
pub async fn tuples(
    transaction: &Transaction<'_>,
    filter: TupleFilter<'_>,
    first: i64,
    max: i64,
) -> StoreResult<Vec<Tuple>> {
    Ok(transaction
        .query(
            "SELECT object_type, object_id, relation, subject_type, subject_id, \
                    subject_relation, created_at \
             FROM rebac_tuples \
             WHERE ($1::text IS NULL OR object_type = $1) \
               AND ($2::text IS NULL OR relation = $2) \
               AND ($3::text IS NULL OR subject_type = $3) \
               AND ($4::text IS NULL OR subject_id = $4) \
             ORDER BY object_type, object_id, relation, subject_type, subject_id, \
                      subject_relation \
             OFFSET $5 LIMIT $6",
            &[
                &filter.object_type,
                &filter.relation,
                &filter.subject_type,
                &filter.subject_id,
                &first,
                &max,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| Tuple {
            object_type: row.get("object_type"),
            object_id: row.get("object_id"),
            relation: row.get("relation"),
            created_at: row.get("created_at"),
            subject: read_subject(row),
        })
        .collect())
}
