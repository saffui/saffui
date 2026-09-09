use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

/// Where an entry landed.
pub struct Appended {
    pub seq: i64,
    pub hash: Vec<u8>,
}

/// Record what happened *to* a realm.
///
/// The tenant is taken from the settings inside the function, never from the
/// entry, so an entry cannot name a chain other than the one in scope. The
/// chain starts itself on the first entry: a tenant has no provisioning moment
/// where a realm has one, and the first realm to come or go is as good a start
/// as any.
pub async fn append(transaction: &Transaction<'_>, entry: &Value) -> StoreResult<Appended> {
    let row = transaction
        .query_one("SELECT seq, hash FROM tenant_append($1)", &[entry])
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(Appended {
        seq: row.get("seq"),
        hash: row.get("hash"),
    })
}

pub struct TenantEntry {
    pub seq: i64,
    pub envelope: Value,
    pub hash: Vec<u8>,
}

/// Read the chain, newest first.
///
/// There is no grant behind this for the served plane: `saffui_app` may
/// execute the appender and select nothing, so this answers only to a
/// connection holding the owner's credentials. That is the whole point of the
/// table living above realms rather than inside one.
///
/// The tenant is named in the statement rather than left to row security. The
/// reader here is the one connection that may be a superuser, and a superuser
/// bypasses row security whatever `FORCE` says, so a caller asking for one
/// tenant would quietly be shown every one of them.
pub async fn list_entries(
    transaction: &Transaction<'_>,
    tenant: &str,
    first: i64,
    max: i64,
) -> StoreResult<Vec<TenantEntry>> {
    let rows = transaction
        .query(
            "SELECT seq, envelope, hash FROM tenant_events WHERE tenant = $1 \
             ORDER BY seq DESC OFFSET $2 LIMIT $3",
            &[&tenant, &first, &max],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(rows
        .into_iter()
        .map(|row| TenantEntry {
            seq: row.get("seq"),
            envelope: row.get("envelope"),
            hash: row.get("hash"),
        })
        .collect())
}

/// Walk every link from the stored bytes and say where it first breaks.
///
/// The preimage is the previous hash, the sequence as eight big endian bytes,
/// then the canonical text of the envelope, which is what the function hashed.
pub async fn verify(
    transaction: &Transaction<'_>,
    tenant: &str,
    digest: &dyn DigestProvider,
) -> StoreResult<Option<i64>> {
    let rows = transaction
        .query(
            "SELECT seq, envelope::text AS text, prev_hash, hash FROM tenant_events \
             WHERE tenant = $1 ORDER BY seq ASC",
            &[&tenant],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    let mut expected: Option<Vec<u8>> = None;
    for row in rows {
        let seq: i64 = row.get("seq");
        let text: String = row.get("text");
        let prev: Vec<u8> = row.get("prev_hash");
        let held: Vec<u8> = row.get("hash");
        if let Some(carried) = &expected
            && carried != &prev
        {
            return Ok(Some(seq));
        }
        let mut preimage = prev.clone();
        preimage.extend_from_slice(&seq.to_be_bytes());
        preimage.extend_from_slice(text.as_bytes());
        let recomputed = digest
            .hash(HashAlg::Sha256, &preimage)
            .map_err(|_| StoreError::Backend)?;
        if recomputed != held {
            return Ok(Some(seq));
        }
        expected = Some(held);
    }
    Ok(None)
}
