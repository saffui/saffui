use deadpool_postgres::Transaction;
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
