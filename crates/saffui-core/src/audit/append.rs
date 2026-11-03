use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use super::EventKind;
use super::canonical::canonicalize;
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::storage::UnitOfWork;

/// Appends an event to the chain of the realm, inside the unit of work that
/// makes the change. Every immutable field is in the envelope, the instant
/// included, and the envelope is what gets hashed.
///
/// # Errors
///
/// Returns the storage failure, or [`ErrorCode::Internal`] for a payload that
/// has no canonical form.
pub async fn record_event(
    app: &App,
    work: &mut dyn UnitOfWork,
    kind: EventKind,
    payload: Value,
) -> Result<(), Failure> {
    let scope = work.scope();
    let instant = app.now().format(&Rfc3339).map_err(|_| {
        Failure::with_detail(ErrorCode::Internal, "an instant that cannot be written")
    })?;
    let envelope = json!({
        "id": mint_id(app)?.to_string(),
        "tenant_id": scope.tenant().as_uuid().to_string(),
        "realm_id": scope.realm().as_uuid().to_string(),
        "kind": kind.name(),
        "ts": instant,
        "payload": payload,
    });
    let bytes = canonicalize(&envelope)
        .map_err(|error| Failure::with_detail(ErrorCode::Internal, error.to_string()))?;
    work.append_audit_event(&bytes).await?;
    Ok(())
}
