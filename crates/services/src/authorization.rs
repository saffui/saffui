//! What a caller may do on the admin plane.

use deadpool_postgres::Transaction;
use models::entities::authz::AdminAction;
use store::providers::{organizations, roles};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("what this caller may do could not be read")]
pub struct Unreadable;

/// Everything this subject may do, from the roles it holds and from the ones
/// the organization it is acting within gives it.
///
/// Both, because an organization's roles are held within it and not by the
/// person outright: reading only the first answers for the wrong scope, and
/// reading only the second loses everything a person holds on their own.
pub async fn admin_actions(
    transaction: &Transaction<'_>,
    subject: &str,
    within_organization: Option<&str>,
) -> Result<Vec<AdminAction>, Unreadable> {
    let mut held = roles::effective_roles(transaction, subject)
        .await
        .map_err(|_| Unreadable)?;

    if let Some(org_id) = within_organization {
        held.extend(
            organizations::roles_of_member(transaction, org_id, subject)
                .await
                .map_err(|_| Unreadable)?,
        );
    }

    Ok(held
        .into_iter()
        .filter_map(|role| role.admin_actions)
        .flatten()
        .collect())
}
