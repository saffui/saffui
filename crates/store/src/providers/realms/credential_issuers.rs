use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use serde_json::Value;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

const COLUMNS: &str = "issuer_id, name, issuer, trusted_by, keys, read_from, read_at, \
                       credential_types, \
                       ARRAY(SELECT anchor_id FROM realm_credential_issuer_anchors AS linked \
                             WHERE linked.issuer_id = named.issuer_id \
                             ORDER BY anchor_id) AS anchors, \
                       created_by, created_at";

/// Name an issuer, with the authorities it is trusted through when the realm
/// trusts it by certificate. One already named in the realm, or an authority
/// the realm does not trust, is refused by the schema and said to be so.
pub async fn name(transaction: &UnitOfWork, issuer: &CredentialIssuer) -> StoreResult<()> {
    let (trusted_by, keys, read_from, read_at, credential_types, anchors) = match &issuer.trust {
        IssuerTrust::Metadata {
            keys,
            read_from,
            read_at,
        } => (
            "metadata",
            Value::Array(keys.clone()),
            Some(read_from.as_str()),
            Some(*read_at),
            None,
            &[][..],
        ),
        IssuerTrust::Certificate {
            anchors,
            credential_types,
        } => (
            "certificate",
            Value::Array(Vec::new()),
            None,
            None,
            Some(serde_json::to_value(credential_types).map_err(|_| StoreError::Backend)?),
            anchors.as_slice(),
        ),
    };
    transaction
        .execute(
            "INSERT INTO realm_credential_issuers \
                 (tenant, realm_id, issuer_id, name, issuer, trusted_by, keys, read_from, \
                  read_at, credential_types, created_by, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10",
            &[
                &issuer.issuer_id,
                &issuer.name,
                &issuer.issuer,
                &trusted_by,
                &keys,
                &read_from,
                &read_at,
                &credential_types,
                &issuer.created_by,
                &issuer.created_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    link_anchors(transaction, &issuer.issuer_id, anchors).await
}

async fn link_anchors(
    transaction: &UnitOfWork,
    issuer_id: &str,
    anchors: &[String],
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO realm_credential_issuer_anchors (tenant, realm_id, issuer_id, anchor_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, unnest($2::text[])",
            &[&issuer_id, &anchors],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Every issuer the realm names, oldest first.
pub async fn list(transaction: &UnitOfWork) -> StoreResult<Vec<CredentialIssuer>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM realm_credential_issuers AS named \
         ORDER BY created_at, issuer_id"
    );
    let rows = transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    rows.into_iter().map(read).collect()
}

/// One issuer the realm names.
pub async fn load(
    transaction: &UnitOfWork,
    issuer_id: &str,
) -> StoreResult<Option<CredentialIssuer>> {
    let statement =
        format!("SELECT {COLUMNS} FROM realm_credential_issuers AS named WHERE issuer_id = $1");
    transaction
        .query_opt(statement.as_str(), &[&issuer_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read)
        .transpose()
}

/// The issuer the realm names by this identifier, as credentials carry it.
pub async fn by_issuer(
    transaction: &UnitOfWork,
    issuer: &str,
) -> StoreResult<Option<CredentialIssuer>> {
    let statement =
        format!("SELECT {COLUMNS} FROM realm_credential_issuers AS named WHERE issuer = $1");
    transaction
        .query_opt(statement.as_str(), &[&issuer])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read)
        .transpose()
}

/// The certificates of the authorities an issuer is trusted through, DER.
pub async fn anchor_certificates(
    transaction: &UnitOfWork,
    issuer_id: &str,
) -> StoreResult<Vec<Vec<u8>>> {
    let rows = transaction
        .query(
            "SELECT anchor.certificate FROM realm_credential_issuer_anchors AS linked \
             JOIN realm_trust_anchors AS anchor \
               ON anchor.tenant = linked.tenant AND anchor.realm_id = linked.realm_id \
              AND anchor.anchor_id = linked.anchor_id \
             WHERE linked.issuer_id = $1 ORDER BY anchor.anchor_id",
            &[&issuer_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows.into_iter().map(|row| row.get(0)).collect())
}

/// Replace the authorities and the types of an issuer the realm trusts by
/// certificate, and say whether it names one by this identifier.
pub async fn replace_certificate_trust(
    transaction: &UnitOfWork,
    issuer_id: &str,
    anchors: &[String],
    credential_types: &[String],
) -> StoreResult<bool> {
    let credential_types =
        serde_json::to_value(credential_types).map_err(|_| StoreError::Backend)?;
    let rewritten = transaction
        .execute(
            "UPDATE realm_credential_issuers SET credential_types = $2 \
             WHERE issuer_id = $1 AND trusted_by = 'certificate'",
            &[&issuer_id, &credential_types],
        )
        .await
        .map_err(refuse_broken_rule)?;
    if rewritten == 0 {
        return Ok(false);
    }
    transaction
        .execute(
            "DELETE FROM realm_credential_issuer_anchors WHERE issuer_id = $1",
            &[&issuer_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    link_anchors(transaction, issuer_id, anchors).await?;
    Ok(true)
}

/// Keep the keys read from an issuer the realm trusts by its metadata again,
/// and say whether it names one by this identifier.
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
             WHERE issuer_id = $1 AND trusted_by = 'metadata'",
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
    let trust = match row.get::<_, String>("trusted_by").as_str() {
        "metadata" => {
            let Value::Array(keys) = row.get::<_, Value>("keys") else {
                return Err(StoreError::Backend);
            };
            IssuerTrust::Metadata {
                keys,
                read_from: row
                    .get::<_, Option<String>>("read_from")
                    .ok_or(StoreError::Backend)?,
                read_at: row
                    .get::<_, Option<chrono::DateTime<chrono::Utc>>>("read_at")
                    .ok_or(StoreError::Backend)?,
            }
        }
        "certificate" => IssuerTrust::Certificate {
            anchors: row.get("anchors"),
            credential_types: row
                .get::<_, Option<Value>>("credential_types")
                .and_then(|types| serde_json::from_value(types).ok())
                .ok_or(StoreError::Backend)?,
        },
        _ => return Err(StoreError::Backend),
    };
    Ok(CredentialIssuer {
        issuer_id: row.get("issuer_id"),
        name: row.get("name"),
        issuer: row.get("issuer"),
        trust,
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    })
}
