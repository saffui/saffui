use models::entities::credential_issuers::CredentialIssuer;
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

/// Name an issuer. One already named in the realm is refused by the schema,
/// and said to be so.
pub async fn name(transaction: &UnitOfWork, issuer: &CredentialIssuer) -> StoreResult<()> {
    let keys = Value::Array(issuer.keys.clone());
    transaction
        .execute(
            "INSERT INTO realm_credential_issuers \
                 (tenant, realm_id, issuer_id, name, issuer, keys, read_from, read_at, \
                  created_by, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &issuer.issuer_id,
                &issuer.name,
                &issuer.issuer,
                &keys,
                &issuer.read_from,
                &issuer.read_at,
                &issuer.created_by,
                &issuer.created_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Every issuer the realm names, oldest first.
pub async fn list(transaction: &UnitOfWork) -> StoreResult<Vec<CredentialIssuer>> {
    let rows = transaction
        .query(
            "SELECT issuer_id, name, issuer, keys, read_from, read_at, created_by, created_at \
             FROM realm_credential_issuers ORDER BY created_at, issuer_id",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    rows.into_iter().map(read).collect()
}

/// One issuer the realm names.
pub async fn load(
    transaction: &UnitOfWork,
    issuer_id: &str,
) -> StoreResult<Option<CredentialIssuer>> {
    transaction
        .query_opt(
            "SELECT issuer_id, name, issuer, keys, read_from, read_at, created_by, created_at \
             FROM realm_credential_issuers WHERE issuer_id = $1",
            &[&issuer_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read)
        .transpose()
}

/// Keep the keys read from an issuer again, and say whether it was there.
pub async fn replace_keys(
    transaction: &UnitOfWork,
    issuer_id: &str,
    keys: &[Value],
    read_from: &str,
    read_at: &chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let keys = Value::Array(keys.to_vec());
    let rewritten = transaction
        .execute(
            "UPDATE realm_credential_issuers SET keys = $2, read_from = $3, read_at = $4 \
             WHERE issuer_id = $1",
            &[&issuer_id, &keys, &read_from, read_at],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(rewritten > 0)
}

/// Which lock a realm's issuers are counted under.
const NAMING: i32 = 0x4953_5355;

/// Wait for whoever else is naming an issuer in this realm.
///
/// Transaction scoped, so it is released at commit and never rides a pooled
/// backend to the next caller. Counting and then naming without it lets two
/// names one below the bound both read a count that passes.
pub async fn hold_names(transaction: &UnitOfWork) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_tenant', true) || ':' \
                          || current_setting('saffui.current_realm', true)))",
            &[&NAMING],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// How many issuers the realm names.
pub async fn count(transaction: &UnitOfWork) -> StoreResult<i64> {
    Ok(transaction
        .query_one("SELECT count(*) FROM realm_credential_issuers", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// Stop naming one issuer, and say whether there was one.
pub async fn forget(transaction: &UnitOfWork, issuer_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM realm_credential_issuers WHERE issuer_id = $1",
            &[&issuer_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read(row: Row) -> StoreResult<CredentialIssuer> {
    let Value::Array(keys) = row.get::<_, Value>("keys") else {
        return Err(StoreError::Backend);
    };
    Ok(CredentialIssuer {
        issuer_id: row.get("issuer_id"),
        name: row.get("name"),
        issuer: row.get("issuer"),
        keys,
        read_from: row.get("read_from"),
        read_at: row.get("read_at"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    })
}
