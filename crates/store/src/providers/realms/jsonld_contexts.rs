use models::entities::jsonld_contexts::JsonLdContext;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

const COLUMNS: &str = "context_id, url, digest, octet_length(document) AS octets, read_at, \
                       created_by, created_at";

/// Pin a context with the document read for it. One already pinned in the
/// realm is refused by the schema, and said to be so.
pub async fn pin(
    transaction: &UnitOfWork,
    context: &JsonLdContext,
    document: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO realm_jsonld_contexts \
                 (tenant, realm_id, context_id, url, document, digest, read_at, created_by, \
                  created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7",
            &[
                &context.context_id,
                &context.url,
                &document,
                &context.digest,
                &context.read_at,
                &context.created_by,
                &context.created_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Every context the realm pins, oldest first, without the documents.
pub async fn list(transaction: &UnitOfWork) -> StoreResult<Vec<JsonLdContext>> {
    let statement =
        format!("SELECT {COLUMNS} FROM realm_jsonld_contexts ORDER BY created_at, context_id");
    let rows = transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows.into_iter().map(read).collect())
}

/// One context the realm pins, without its document.
pub async fn load(
    transaction: &UnitOfWork,
    context_id: &str,
) -> StoreResult<Option<JsonLdContext>> {
    let statement = format!("SELECT {COLUMNS} FROM realm_jsonld_contexts WHERE context_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&context_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Every pinned document, by the URL documents name it with: what a
/// presentation is read under, beside the contexts built in.
pub async fn documents(transaction: &UnitOfWork) -> StoreResult<Vec<(String, String)>> {
    let rows = transaction
        .query("SELECT url, document FROM realm_jsonld_contexts", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get("url"), row.get("document")))
        .collect())
}

/// Keep the document read for a context again, and say whether it was there.
pub async fn replace_document(
    transaction: &UnitOfWork,
    context_id: &str,
    document: &str,
    digest: &str,
    read_at: &chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let rewritten = transaction
        .execute(
            "UPDATE realm_jsonld_contexts SET document = $2, digest = $3, read_at = $4 \
             WHERE context_id = $1",
            &[&context_id, &document, &digest, read_at],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(rewritten > 0)
}

/// Which lock a realm's contexts are counted under.
const PINNING: i32 = 0x4A53_4C44;

/// Wait for whoever else is pinning a context in this realm.
///
/// Transaction scoped, so it is released at commit and never rides a pooled
/// backend to the next caller. Counting and then pinning without it lets two
/// pins one below the bound both read a count that passes.
pub async fn hold_pins(transaction: &UnitOfWork) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_tenant', true) || ':' \
                          || current_setting('saffui.current_realm', true)))",
            &[&PINNING],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// How many contexts the realm pins.
pub async fn count(transaction: &UnitOfWork) -> StoreResult<i64> {
    Ok(transaction
        .query_one("SELECT count(*) FROM realm_jsonld_contexts", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// Unpin one context, and say whether there was one.
pub async fn forget(transaction: &UnitOfWork, context_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM realm_jsonld_contexts WHERE context_id = $1",
            &[&context_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read(row: Row) -> JsonLdContext {
    JsonLdContext {
        context_id: row.get("context_id"),
        url: row.get("url"),
        digest: row.get("digest"),
        octets: row.get("octets"),
        read_at: row.get("read_at"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    }
}
