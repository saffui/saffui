//! Failed attempts from one address, a minute at a time.
//!
//! Keyed by the address and by a name digest, empty for the address's own
//! count. What the counts mean, and when they turn an address away, is the
//! throttle's to say (`auth::login::throttle`); this only keeps them.

use crate::error::{StoreError, StoreResult};
use crate::tenancy::UnitOfWork;

/// How much time one count covers, in seconds.
pub const MINUTE: i64 = 60;

/// One minute of failures under one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    /// Empty for the address's own count, otherwise the digest of a name.
    pub named: String,
    /// When the minute began, in seconds since the epoch.
    pub minute: i64,
    pub failures: i32,
}

/// What was counted against this address under these keys, in the minutes
/// that began after `since`, oldest first.
pub async fn counted_since(
    transaction: &UnitOfWork,
    source: &str,
    named: &[&str],
    since: i64,
) -> StoreResult<Vec<Counted>> {
    let rows = transaction
        .query(
            "SELECT named, minute, failures FROM source_failures \
             WHERE tenant = current_setting('saffui.current_tenant', true) \
               AND realm_id = current_setting('saffui.current_realm', true) \
               AND source = $1 AND named = ANY($2::text[]) AND minute > $3::bigint \
             ORDER BY minute",
            &[&source, &named, &since],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(rows
        .iter()
        .map(|row| Counted {
            named: row.get(0),
            minute: row.get(1),
            failures: row.get(2),
        })
        .collect())
}

/// Count one failure under each of these keys, in the minute that began at
/// `minute`. One statement, so the keys of one attempt are never half counted.
pub async fn record(
    transaction: &UnitOfWork,
    source: &str,
    named: &[&str],
    minute: i64,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO source_failures (tenant, realm_id, source, named, minute, failures) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, named, $3::bigint, 1 \
             FROM unnest($2::text[]) AS named \
             ON CONFLICT (tenant, realm_id, source, named, minute) \
             DO UPDATE SET failures = source_failures.failures + 1",
            &[&source, &named, &minute],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Drop the minutes this realm's window no longer reaches, and say how many
/// went. A name digest is kept no longer than it can still count.
pub async fn drop_stale(transaction: &UnitOfWork, now: i64) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM source_failures \
             WHERE tenant = current_setting('saffui.current_tenant', true) \
               AND realm_id = current_setting('saffui.current_realm', true) \
               AND minute <= $1::bigint - $2::bigint - COALESCE( \
                   (SELECT source_window_seconds FROM realms \
                    WHERE tenant = current_setting('saffui.current_tenant', true) \
                      AND realm_id = current_setting('saffui.current_realm', true)), \
                   86400)",
            &[&now, &MINUTE],
        )
        .await
        .map_err(|_| StoreError::Backend)
}
