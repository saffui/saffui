use deadpool_postgres::Transaction;
use store::providers::{organizations, users};

/// The organization a login acts within, once resolved: its id and the name
/// the tokens will speak, which is the display name when one was given and
/// the slug otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acting {
    pub org_id: String,
    pub org_name: String,
}

/// Why no organization was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unresolved {
    /// The request cannot proceed as asked: a named organization that does not
    /// exist, is disabled, or does not hold the user; or several memberships
    /// and nothing that picks one. All of them answer alike, because telling
    /// them apart tells whoever asked which organizations exist.
    #[error("access_denied")]
    Refused,
    #[error("the store could not answer")]
    Unreadable,
}

/// Which organization this login is for, if any.
///
/// A named organization must exist, be enabled and hold the user, or the
/// request is refused rather than quietly downgraded: the client pinned a
/// context and a token without it would be an answer to a different question.
/// With nothing named, the user's memberships decide: none means a realm-level
/// login, exactly one selects itself, and among several only a verified mail
/// domain that names one of them can choose. A sole membership whose
/// organization row is gone or disabled degrades to a realm-level login,
/// because a dangling membership must not lock the user out.
pub async fn resolve_organization(
    transaction: &Transaction<'_>,
    user_id: &str,
    asked: Option<&str>,
) -> Result<Option<Acting>, Unresolved> {
    if let Some(slug) = asked.map(str::trim).filter(|held| !held.is_empty()) {
        let org = organizations::load_by_name(transaction, slug)
            .await
            .map_err(|_| Unresolved::Unreadable)?
            .filter(|org| org.enabled)
            .ok_or(Unresolved::Refused)?;
        let member = organizations::of_member(transaction, user_id)
            .await
            .map_err(|_| Unresolved::Unreadable)?
            .contains(&org.org_id);
        if !member {
            return Err(Unresolved::Refused);
        }
        return Ok(Some(acting_from(org)));
    }

    let memberships = organizations::of_member(transaction, user_id)
        .await
        .map_err(|_| Unresolved::Unreadable)?;
    match memberships.as_slice() {
        [] => Ok(None),
        [only] => Ok(organizations::load(transaction, only)
            .await
            .map_err(|_| Unresolved::Unreadable)?
            .filter(|org| org.enabled)
            .map(acting_from)),
        _ => {
            // Several memberships and no pin: only the user's verified mail
            // domain may pick, and only an organization they belong to. The
            // domain join already admits none but verified domains.
            let user = users::load(transaction, user_id)
                .await
                .map_err(|_| Unresolved::Unreadable)?
                .ok_or(Unresolved::Refused)?;
            let domain = user
                .email_verified
                .unwrap_or(false)
                .then(|| user.email.rsplit('@').next())
                .flatten()
                .filter(|held| !held.is_empty());
            let Some(domain) = domain else {
                return Err(Unresolved::Refused);
            };
            let discovered = organizations::by_domain(transaction, domain)
                .await
                .map_err(|_| Unresolved::Unreadable)?
                .filter(|org| org.enabled)
                .filter(|org| memberships.contains(&org.org_id));
            discovered
                .map(acting_from)
                .ok_or(Unresolved::Refused)
                .map(Some)
        }
    }
}

fn acting_from(org: models::entities::organization::OrganizationModel) -> Acting {
    Acting {
        org_name: if org.display_name.is_empty() {
            org.name.clone()
        } else {
            org.display_name.clone()
        },
        org_id: org.org_id,
    }
}

/// Whether the user belongs to the organization a token claims, for the paths
/// that re-stamp an old claim rather than resolve a fresh one. Fails closed:
/// an unreadable store reads as "no", which drops the claim rather than
/// carrying a stale one.
pub async fn still_a_member(transaction: &Transaction<'_>, org_id: &str, user_id: &str) -> bool {
    organizations::of_member(transaction, user_id)
        .await
        .map(|held| held.iter().any(|org| org == org_id))
        .unwrap_or(false)
}
