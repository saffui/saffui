//! The certificate revocation lists the chains of a realm's credentials name,
//! as the scheduled pass read them: a presentation looks one serial up, each
//! list is claimed by one reader when it is due.

use chrono::{DateTime, Utc};

use crate::error::{StoreError, StoreResult};
use crate::tenancy::UnitOfWork;

/// Where a list is kept: the issuer whose credentials' chains name it, its
/// address, and the authority whose certificates it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListPlace<'a> {
    pub issuer_id: &'a str,
    pub uri: &'a str,
    /// SHA-256 of the authority's certificate, lowercase hex.
    pub authority_digest: &'a str,
}

/// A list as a certificate naming it finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedList {
    /// Until when what was kept may be relied on, when a reading ever was.
    pub usable_until: Option<DateTime<Utc>>,
    /// Whether the last reading tried was not kept.
    pub failed: bool,
    /// Whether what was kept revokes the serial looked up.
    pub revokes: bool,
    pub cited_at: DateTime<Utc>,
}

/// The list one certificate names, and whether what is kept of it revokes the
/// certificate's serial.
pub async fn read_named(
    transaction: &UnitOfWork,
    place: &ListPlace<'_>,
    serial: &[u8],
) -> StoreResult<Option<NamedList>> {
    let row = transaction
        .query_opt(
            "SELECT list.usable_until, list.cited_at, list.failure IS NOT NULL AS failed, \
                    EXISTS (SELECT 1 FROM certificate_revocations AS revoked \
                            WHERE revoked.issuer_id = list.issuer_id \
                              AND revoked.uri = list.uri \
                              AND revoked.authority_digest = list.authority_digest \
                              AND revoked.serial = $4) AS revokes \
             FROM certificate_revocation_lists AS list \
             WHERE list.issuer_id = $1 AND list.uri = $2 AND list.authority_digest = $3",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &serial,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.map(|row| NamedList {
        usable_until: row.get("usable_until"),
        failed: row.get("failed"),
        revokes: row.get("revokes"),
        cited_at: row.get("cited_at"),
    }))
}

/// Write down a list no certificate named before, due to be read at once, with
/// the authority it is read under. False when the realm already keeps `most`
/// lists and this is not one of them.
pub async fn write_down(
    transaction: &UnitOfWork,
    place: &ListPlace<'_>,
    authority: &[u8],
    now: &DateTime<Utc>,
    most: i64,
) -> StoreResult<bool> {
    let written = transaction
        .execute(
            "INSERT INTO certificate_revocation_lists \
                 (tenant, realm_id, issuer_id, uri, authority_digest, authority, due_at, \
                  cited_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $5 \
             WHERE (SELECT count(*) FROM certificate_revocation_lists) < $6 \
             ON CONFLICT DO NOTHING",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &authority,
                now,
                &most,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if written > 0 {
        return Ok(true);
    }
    // Nothing written: another certificate wrote it first, or there is no room.
    Ok(transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM certificate_revocation_lists \
                            WHERE issuer_id = $1 AND uri = $2 AND authority_digest = $3)",
            &[&place.issuer_id, &place.uri, &place.authority_digest],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// Say a certificate named the list now.
pub async fn note_cited(
    transaction: &UnitOfWork,
    place: &ListPlace<'_>,
    now: &DateTime<Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE certificate_revocation_lists SET cited_at = $4 \
             WHERE issuer_id = $1 AND uri = $2 AND authority_digest = $3",
            &[&place.issuer_id, &place.uri, &place.authority_digest, now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// A list the pass reads now, with the authority it is read under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueRevocationList {
    pub issuer_id: String,
    pub uri: String,
    pub authority_digest: String,
    /// The authority's certificate, DER.
    pub authority: Vec<u8>,
    /// When the authority issued the reading kept, if one is.
    pub issued_at: Option<DateTime<Utc>>,
}

impl DueRevocationList {
    pub fn place(&self) -> ListPlace<'_> {
        ListPlace {
            issuer_id: &self.issuer_id,
            uri: &self.uri,
            authority_digest: &self.authority_digest,
        }
    }
}

/// Claim at most `most` lists that are due, putting each off until `again_at`
/// so no other reader takes it meanwhile; a reading kept puts it off further.
pub async fn claim_due(
    transaction: &UnitOfWork,
    now: &DateTime<Utc>,
    again_at: &DateTime<Utc>,
    most: i64,
) -> StoreResult<Vec<DueRevocationList>> {
    let rows = transaction
        .query(
            "UPDATE certificate_revocation_lists SET due_at = $2 \
             WHERE (issuer_id, uri, authority_digest) IN ( \
                 SELECT issuer_id, uri, authority_digest FROM certificate_revocation_lists \
                 WHERE due_at <= $1 ORDER BY due_at LIMIT $3 FOR UPDATE SKIP LOCKED) \
             RETURNING issuer_id, uri, authority_digest, authority, issued_at",
            &[now, again_at, &most],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows
        .into_iter()
        .map(|row| DueRevocationList {
            issuer_id: row.get("issuer_id"),
            uri: row.get("uri"),
            authority_digest: row.get("authority_digest"),
            authority: row.get("authority"),
            issued_at: row.get("issued_at"),
        })
        .collect())
}

/// A reading of a list, verified under its authority.
pub struct KeptRevocations<'a> {
    pub place: ListPlace<'a>,
    /// The serials it revokes, each a magnitude in big-endian bytes.
    pub revoked: &'a [Vec<u8>],
    pub issued_at: DateTime<Utc>,
    pub read_at: DateTime<Utc>,
    pub usable_until: DateTime<Utc>,
    pub due_at: DateTime<Utc>,
}

/// Keep a reading in place of the one kept, unless the authority issued the
/// kept one later: an older list served again would undo a revocation. Says
/// whether it was kept.
pub async fn keep_reading(
    transaction: &UnitOfWork,
    reading: &KeptRevocations<'_>,
) -> StoreResult<bool> {
    let place = &reading.place;
    let kept = transaction
        .execute(
            "UPDATE certificate_revocation_lists \
             SET issued_at = $4, read_at = $5, usable_until = $6, due_at = $7, failure = NULL \
             WHERE issuer_id = $1 AND uri = $2 AND authority_digest = $3 \
               AND (issued_at IS NULL OR issued_at <= $4)",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &reading.issued_at,
                &reading.read_at,
                &reading.usable_until,
                &reading.due_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if kept == 0 {
        return Ok(false);
    }
    // A serial still revoked is left as it is: a list read again unchanged
    // writes nothing.
    transaction
        .execute(
            "DELETE FROM certificate_revocations AS revoked \
             WHERE revoked.issuer_id = $1 AND revoked.uri = $2 \
               AND revoked.authority_digest = $3 \
               AND NOT EXISTS (SELECT 1 FROM unnest($4::bytea[]) AS listed (serial) \
                               WHERE listed.serial = revoked.serial)",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &reading.revoked,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "INSERT INTO certificate_revocations \
                 (tenant, realm_id, issuer_id, uri, authority_digest, serial) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, serial \
             FROM unnest($4::bytea[]) AS serial \
             ON CONFLICT DO NOTHING",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &reading.revoked,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(true)
}

/// Say why a reading was not kept. What was kept before stays, until it may
/// no longer be relied on.
pub async fn note_unread(
    transaction: &UnitOfWork,
    place: &ListPlace<'_>,
    failure: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE certificate_revocation_lists SET failure = $4 \
             WHERE issuer_id = $1 AND uri = $2 AND authority_digest = $3",
            &[
                &place.issuer_id,
                &place.uri,
                &place.authority_digest,
                &failure,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Forget the lists no certificate named since `cited_before`, and what they
/// revoked.
pub async fn drop_uncited(
    transaction: &UnitOfWork,
    cited_before: DateTime<Utc>,
) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM certificate_revocation_lists WHERE cited_at < $1",
            &[&cited_before],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
