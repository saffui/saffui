//! What the evaluator reads, gathered from the storage before it runs.

use serde_json::Map;
use time::OffsetDateTime;

use super::rules::{ClaimGrant, needs_attributes, needs_roles};
use super::{ClaimInputs, ClaimTarget};
use crate::authz::grants::{name_client_held_for, read_held_roles};
use crate::error::Failure;
use crate::ports::storage::UnitOfWork;

/// Reads what writing `targets` for a grant needs: the mappers of its
/// client, and of its person the attributes and the roles held at `now`,
/// each only when a scope or a mapper that applies says them.
///
/// # Errors
///
/// Returns [`crate::error::ErrorCode::HeldTooMany`] for a person who holds
/// roles by more ways than are read, or the storage failure.
pub async fn gather_claim_inputs(
    work: &mut dyn UnitOfWork,
    grant: &ClaimGrant<'_>,
    targets: &[ClaimTarget],
    now: OffsetDateTime,
) -> Result<ClaimInputs, Failure> {
    let mappers = work.list_mappers(grant.client_id).await?;
    let Some(person) = grant.person else {
        return Ok(ClaimInputs {
            mappers,
            ..ClaimInputs::default()
        });
    };
    let attributes = if needs_attributes(&mappers, grant.scopes, targets) {
        work.read_person_attributes(person.id)
            .await?
            .unwrap_or_default()
    } else {
        Map::new()
    };
    let held = if needs_roles(&mappers, grant.scopes, targets) {
        read_held_roles(work, person.id, now)
            .await
            .map_err(|failure| name_client_held_for(failure, grant.client_id))?
    } else {
        Vec::new()
    };
    Ok(ClaimInputs {
        mappers,
        attributes,
        held,
    })
}
