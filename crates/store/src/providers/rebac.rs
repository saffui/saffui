//! The edges of a realm, and the schema that says which of them mean anything.

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

/// Record an edge. Writing one twice writes it once.
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

fn read_subject(row: Row) -> Subject {
    Subject {
        subject_type: row.get("subject_type"),
        subject_id: row.get("subject_id"),
        subject_relation: row.get("subject_relation"),
    }
}
