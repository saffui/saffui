use deadpool_postgres::Transaction;
use models::compliance::breach::{BreachRecord, BreachSeverity, BreachStatus};
use models::compliance::subject_request::{DsarKind, DsarRequest, DsarStatus, Jurisdiction};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

const COLUMNS: &str = "request_id, tenant, realm_id, user_id, subject_identifier, kind, \
                       stage, outcome, reason, jurisdiction, received_at, due_at, \
                       verified_at, closed_at";

/// Keep a freshly lodged request.
pub async fn lodge(transaction: &Transaction<'_>, request: &DsarRequest) -> StoreResult<()> {
    let (stage, outcome, reason) = status_columns(&request.status);
    transaction
        .execute(
            "INSERT INTO subject_requests \
             (request_id, tenant, realm_id, user_id, subject_identifier, kind, \
              stage, outcome, reason, jurisdiction, received_at, due_at, \
              verified_at, closed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            &[
                &request.request_id,
                &request.tenant,
                &request.realm_id,
                &request.user_id,
                &request.subject_identifier,
                &request.kind.as_str(),
                &stage,
                &outcome,
                &reason,
                &request.jurisdiction.as_str(),
                &request.received_at,
                &request.due_at,
                &request.verified_at,
                &request.closed_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn load(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> StoreResult<Option<DsarRequest>> {
    let statement = format!("SELECT {COLUMNS} FROM subject_requests WHERE request_id = $1");
    transaction
        .query_opt(statement.as_str(), &[&request_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read)
        .transpose()
}

/// The realm's register, the open requests first and the tightest clock on
/// top: the order an operator works it in.
pub async fn list(transaction: &Transaction<'_>) -> StoreResult<Vec<DsarRequest>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM subject_requests \
         ORDER BY (closed_at IS NOT NULL), due_at, request_id"
    );
    transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect()
}

/// Write a request back whole, as its lifecycle moved it.
pub async fn save(transaction: &Transaction<'_>, request: &DsarRequest) -> StoreResult<bool> {
    let (stage, outcome, reason) = status_columns(&request.status);
    let written = transaction
        .execute(
            "UPDATE subject_requests SET user_id = $2, stage = $3, outcome = $4, \
             reason = $5, verified_at = $6, closed_at = $7 WHERE request_id = $1",
            &[
                &request.request_id,
                &request.user_id,
                &stage,
                &outcome,
                &reason,
                &request.verified_at,
                &request.closed_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(written > 0)
}

fn status_columns(status: &DsarStatus) -> (&'static str, Option<String>, Option<String>) {
    match status {
        DsarStatus::Received => ("received", None, None),
        DsarStatus::Verified => ("verified", None, None),
        DsarStatus::Fulfilled { outcome } => ("fulfilled", Some(outcome.clone()), None),
        DsarStatus::Refused { reason } => ("refused", None, Some(reason.clone())),
    }
}

fn read(row: Row) -> StoreResult<DsarRequest> {
    let stage: String = row.get("stage");
    let outcome: Option<String> = row.get("outcome");
    let reason: Option<String> = row.get("reason");
    // A closed row missing what closed it does not become a bare status: the
    // model refuses to represent it, and so does this read.
    let status = match stage.as_str() {
        "received" => DsarStatus::Received,
        "verified" => DsarStatus::Verified,
        "fulfilled" => DsarStatus::Fulfilled {
            outcome: outcome.ok_or(StoreError::Backend)?,
        },
        "refused" => DsarStatus::Refused {
            reason: reason.ok_or(StoreError::Backend)?,
        },
        _ => return Err(StoreError::Backend),
    };
    let kind: String = row.get("kind");
    let jurisdiction: String = row.get("jurisdiction");
    Ok(DsarRequest {
        request_id: row.get("request_id"),
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        subject_identifier: row.get("subject_identifier"),
        kind: kind.parse::<DsarKind>().map_err(|_| StoreError::Backend)?,
        status,
        jurisdiction: jurisdiction
            .parse::<Jurisdiction>()
            .map_err(|_| StoreError::Backend)?,
        received_at: row.get("received_at"),
        due_at: row.get("due_at"),
        verified_at: row.get("verified_at"),
        closed_at: row.get("closed_at"),
    })
}

const BREACH_COLUMNS: &str = "breach_id, tenant, realm_id, description, data_categories, \
                              subjects_affected, severity, status, jurisdiction, occurred_at, \
                              discovered_at, notify_by, notified_at, notified_to, filed_by";

/// Keep a freshly discovered breach, with the jurisdiction its filing draft
/// will be shaped for.
pub async fn record_breach(
    transaction: &Transaction<'_>,
    breach: &BreachRecord,
    jurisdiction: Jurisdiction,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO breaches \
             (breach_id, tenant, realm_id, description, data_categories, \
              subjects_affected, severity, status, jurisdiction, occurred_at, \
              discovered_at, notify_by, notified_at, notified_to, filed_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
            &[
                &breach.breach_id,
                &breach.tenant,
                &breach.realm_id,
                &breach.description,
                &breach.data_categories,
                &breach.subjects_affected,
                &breach.severity.as_str(),
                &breach.status.as_str(),
                &jurisdiction.as_str(),
                &breach.occurred_at,
                &breach.discovered_at,
                &breach.notify_by,
                &breach.notified_at,
                &breach.notified_to,
                &breach.filed_by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn load_breach(
    transaction: &Transaction<'_>,
    breach_id: &str,
) -> StoreResult<Option<(BreachRecord, Jurisdiction)>> {
    let statement = format!("SELECT {BREACH_COLUMNS} FROM breaches WHERE breach_id = $1");
    transaction
        .query_opt(statement.as_str(), &[&breach_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_breach)
        .transpose()
}

/// The register, the ticking clocks first: what awaits a filing on top,
/// tightest deadline leading.
pub async fn list_breaches(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<(BreachRecord, Jurisdiction)>> {
    let statement = format!(
        "SELECT {BREACH_COLUMNS} FROM breaches \
         ORDER BY (status IN ('closed', 'not-notifiable')), \
                  notify_by NULLS LAST, discovered_at, breach_id"
    );
    transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_breach)
        .collect()
}

/// Write a breach back whole, as its handling moved it.
pub async fn save_breach(
    transaction: &Transaction<'_>,
    breach: &BreachRecord,
) -> StoreResult<bool> {
    let written = transaction
        .execute(
            "UPDATE breaches SET subjects_affected = $2, severity = $3, status = $4, \
             notified_at = $5, notified_to = $6, filed_by = $7 WHERE breach_id = $1",
            &[
                &breach.breach_id,
                &breach.subjects_affected,
                &breach.severity.as_str(),
                &breach.status.as_str(),
                &breach.notified_at,
                &breach.notified_to,
                &breach.filed_by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(written > 0)
}

fn read_breach(row: Row) -> StoreResult<(BreachRecord, Jurisdiction)> {
    let severity: String = row.get("severity");
    let status: String = row.get("status");
    let jurisdiction: String = row.get("jurisdiction");
    Ok((
        BreachRecord {
            breach_id: row.get("breach_id"),
            tenant: row.get("tenant"),
            realm_id: row.get("realm_id"),
            description: row.get("description"),
            data_categories: row.get("data_categories"),
            subjects_affected: row.get("subjects_affected"),
            severity: severity
                .parse::<BreachSeverity>()
                .map_err(|_| StoreError::Backend)?,
            status: status
                .parse::<BreachStatus>()
                .map_err(|_| StoreError::Backend)?,
            occurred_at: row.get("occurred_at"),
            discovered_at: row.get("discovered_at"),
            notify_by: row.get("notify_by"),
            notified_at: row.get("notified_at"),
            notified_to: row.get("notified_to"),
            filed_by: row.get("filed_by"),
        },
        jurisdiction
            .parse::<Jurisdiction>()
            .map_err(|_| StoreError::Backend)?,
    ))
}

/// The consents granted inside a period, oldest first, capped, with the
/// period's true total beside them so a cut section says it was cut.
pub async fn consents_granted_in_period(
    transaction: &Transaction<'_>,
    from: i64,
    to: i64,
    cap: i64,
) -> StoreResult<(Vec<(String, String, Vec<String>, i64)>, u64)> {
    let rows = transaction
        .query(
            "SELECT user_id, client_id, scopes, extract(epoch FROM granted_at)::bigint AS at \
             FROM user_consents \
             WHERE extract(epoch FROM granted_at) BETWEEN $1::bigint AND $2::bigint \
             ORDER BY granted_at, user_id LIMIT $3",
            &[&from, &to, &cap],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let total: i64 = transaction
        .query_one(
            "SELECT count(*) FROM user_consents \
             WHERE extract(epoch FROM granted_at) BETWEEN $1::bigint AND $2::bigint",
            &[&from, &to],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok((
        rows.iter()
            .map(|row| {
                (
                    row.get("user_id"),
                    row.get("client_id"),
                    row.get("scopes"),
                    row.get("at"),
                )
            })
            .collect(),
        total as u64,
    ))
}

/// The accounts created inside a period, capped the same way. Identifiers
/// and instants only: a pack for a regulator carries no addresses.
pub async fn registrations_in_period(
    transaction: &Transaction<'_>,
    from: i64,
    to: i64,
    cap: i64,
) -> StoreResult<(Vec<(String, i64)>, u64)> {
    let rows = transaction
        .query(
            "SELECT user_id, extract(epoch FROM created_at)::bigint AS at FROM users \
             WHERE extract(epoch FROM created_at) BETWEEN $1::bigint AND $2::bigint \
             ORDER BY created_at, user_id LIMIT $3",
            &[&from, &to, &cap],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let total: i64 = transaction
        .query_one(
            "SELECT count(*) FROM users \
             WHERE extract(epoch FROM created_at) BETWEEN $1::bigint AND $2::bigint",
            &[&from, &to],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok((
        rows.iter()
            .map(|row| (row.get("user_id"), row.get("at")))
            .collect(),
        total as u64,
    ))
}
