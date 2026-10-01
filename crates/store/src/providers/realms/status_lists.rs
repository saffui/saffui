//! The status lists a realm's credentials cite, as the scheduled pass read
//! them: one status read at a time by a presentation, each list claimed by one
//! reader when it is due.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::error::{StoreError, StoreResult};
use crate::tenancy::UnitOfWork;

/// A list as a citation finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedList {
    /// What was kept of the list, when a reading ever was.
    pub reading: Option<HeldReading>,
    /// Whether the last reading tried was not kept.
    pub failed: bool,
    pub cited_at: DateTime<Utc>,
}

/// What is kept of a list that was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldReading {
    pub usable_until: DateTime<Utc>,
    /// How many bytes the statuses take.
    pub octets: i32,
    pub bits: Option<i16>,
    pub purposes: Option<Vec<String>>,
    /// The byte holding the status cited, when the list reaches that far.
    pub byte: Option<u8>,
}

/// The list one credential cites, and the status it cites in it, located by
/// the bits each status takes in the list.
pub async fn read_cited(
    transaction: &UnitOfWork,
    issuer_id: &str,
    uri: &str,
    format: &str,
    index: i64,
) -> StoreResult<Option<CitedList>> {
    let row = transaction
        .query_opt(
            "SELECT usable_until, octet_length(statuses) AS octets, bits, purposes, cited_at, \
                    failure IS NOT NULL AS failed, \
                    substring(statuses \
                              FROM (($4::bigint * coalesce(bits, 1)) / 8 + 1)::int FOR 1) AS held \
             FROM credential_status_lists \
             WHERE issuer_id = $1 AND uri = $2 AND format = $3",
            &[&issuer_id, &uri, &format, &index],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.map(|row| {
        let usable_until: Option<DateTime<Utc>> = row.get("usable_until");
        let held: Option<Vec<u8>> = row.get("held");
        CitedList {
            reading: usable_until.map(|usable_until| HeldReading {
                usable_until,
                octets: row.get::<_, Option<i32>>("octets").unwrap_or_default(),
                bits: row.get("bits"),
                purposes: row.get("purposes"),
                byte: held.and_then(|held| held.first().copied()),
            }),
            failed: row.get("failed"),
            cited_at: row.get("cited_at"),
        }
    }))
}

/// Write down a list no credential cited before, due to be read at once.
/// False when the realm already keeps `most` lists and this is not one of them.
pub async fn write_down(
    transaction: &UnitOfWork,
    issuer_id: &str,
    uri: &str,
    format: &str,
    now: &DateTime<Utc>,
    most: i64,
) -> StoreResult<bool> {
    let written = transaction
        .execute(
            "INSERT INTO credential_status_lists \
                 (tenant, realm_id, issuer_id, uri, format, due_at, cited_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $4 \
             WHERE (SELECT count(*) FROM credential_status_lists) < $5 \
             ON CONFLICT DO NOTHING",
            &[&issuer_id, &uri, &format, now, &most],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if written > 0 {
        return Ok(true);
    }
    // Nothing written: another citation wrote it first, or there is no room.
    Ok(transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM credential_status_lists \
                            WHERE issuer_id = $1 AND uri = $2 AND format = $3)",
            &[&issuer_id, &uri, &format],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// Say a credential cited the list now.
pub async fn note_cited(
    transaction: &UnitOfWork,
    issuer_id: &str,
    uri: &str,
    format: &str,
    now: &DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE credential_status_lists SET cited_at = $4 \
             WHERE issuer_id = $1 AND uri = $2 AND format = $3",
            &[&issuer_id, &uri, &format, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A list the pass reads now, with the issuer whose keys must have signed it.
#[derive(Debug, Clone, PartialEq)]
pub struct DueList {
    pub issuer_id: String,
    pub uri: String,
    pub format: String,
    /// The issuer as its credentials name it.
    pub issuer: String,
    pub signers: ListSigners,
    /// When the issuer wrote the reading kept, if it said.
    pub issued_at: Option<DateTime<Utc>>,
}

/// What a list must be signed under, as the realm trusts its issuer.
#[derive(Debug, Clone, PartialEq)]
pub enum ListSigners {
    /// The issuer's keys, as the realm read them.
    Keys(Vec<Value>),
    /// A certificate one of these authorities issued, DER.
    Anchors(Vec<Vec<u8>>),
}

/// Claim at most `most` lists that are due, putting each off until `again_at`
/// so no other reader takes it meanwhile; a reading kept puts it off further.
pub async fn claim_due(
    transaction: &UnitOfWork,
    now: &DateTime<Utc>,
    again_at: &DateTime<Utc>,
    most: i64,
) -> StoreResult<Vec<DueList>> {
    let rows = transaction
        .query(
            "UPDATE credential_status_lists AS list SET due_at = $2 \
             FROM realm_credential_issuers AS named \
             WHERE named.tenant = list.tenant AND named.realm_id = list.realm_id \
               AND named.issuer_id = list.issuer_id \
               AND (list.issuer_id, list.uri, list.format) IN ( \
                   SELECT issuer_id, uri, format FROM credential_status_lists \
                   WHERE due_at <= $1 ORDER BY due_at LIMIT $3 FOR UPDATE SKIP LOCKED) \
             RETURNING list.issuer_id, list.uri, list.format, named.issuer, named.keys, \
                       named.trusted_by, list.issued_at, \
                       ARRAY(SELECT anchor.certificate \
                             FROM realm_credential_issuer_anchors AS linked \
                             JOIN realm_trust_anchors AS anchor \
                               ON anchor.tenant = linked.tenant \
                              AND anchor.realm_id = linked.realm_id \
                              AND anchor.anchor_id = linked.anchor_id \
                             WHERE linked.issuer_id = list.issuer_id \
                             ORDER BY anchor.anchor_id) AS anchors",
            &[now, again_at, &most],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    rows.into_iter()
        .map(|row| {
            let signers = match row.get::<_, String>("trusted_by").as_str() {
                "metadata" => {
                    let Value::Array(keys) = row.get::<_, Value>("keys") else {
                        return Err(StoreError::Backend);
                    };
                    ListSigners::Keys(keys)
                }
                "certificate" => ListSigners::Anchors(row.get("anchors")),
                _ => return Err(StoreError::Backend),
            };
            Ok(DueList {
                issuer_id: row.get("issuer_id"),
                uri: row.get("uri"),
                format: row.get("format"),
                issuer: row.get("issuer"),
                signers,
                issued_at: row.get("issued_at"),
            })
        })
        .collect()
}

/// A reading of a list, verified and expanded.
pub struct KeptReading<'a> {
    pub issuer_id: &'a str,
    pub uri: &'a str,
    pub format: &'a str,
    pub statuses: &'a [u8],
    pub bits: Option<i16>,
    pub purposes: Option<&'a [String]>,
    pub issued_at: Option<DateTime<Utc>>,
    pub read_at: DateTime<Utc>,
    pub usable_until: DateTime<Utc>,
    pub due_at: DateTime<Utc>,
}

/// Keep a reading in place of the one kept, unless the issuer wrote the kept
/// one later: an older writing served again would undo a revocation. Says
/// whether it was kept.
pub async fn keep_reading(
    transaction: &UnitOfWork,
    reading: &KeptReading<'_>,
) -> StoreResult<bool> {
    let kept = transaction
        .execute(
            "UPDATE credential_status_lists \
             SET statuses = $4, bits = $5, purposes = $6, issued_at = $7, read_at = $8, \
                 usable_until = $9, due_at = $10, failure = NULL \
             WHERE issuer_id = $1 AND uri = $2 AND format = $3 \
               AND (issued_at IS NULL OR $7::timestamptz IS NULL OR issued_at <= $7)",
            &[
                &reading.issuer_id,
                &reading.uri,
                &reading.format,
                &reading.statuses,
                &reading.bits,
                &reading.purposes,
                &reading.issued_at,
                &reading.read_at,
                &reading.usable_until,
                &reading.due_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(kept > 0)
}

/// Say why a reading was not kept. What was kept before stays, until it may
/// no longer be relied on.
pub async fn note_unread(
    transaction: &UnitOfWork,
    issuer_id: &str,
    uri: &str,
    format: &str,
    failure: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE credential_status_lists SET failure = $4 \
             WHERE issuer_id = $1 AND uri = $2 AND format = $3",
            &[&issuer_id, &uri, &format, &failure],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Forget the lists no credential cited since `cited_before`.
pub async fn drop_uncited(
    transaction: &UnitOfWork,
    cited_before: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM credential_status_lists WHERE cited_at < $1",
            &[&cited_before],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
