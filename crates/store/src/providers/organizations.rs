use deadpool_postgres::Transaction;
use models::entities::organization::{
    OrgMembershipType, OrganizationDomain, OrganizationMemberModel, OrganizationModel,
};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const ORG_COLUMNS: &str = "tenant, realm_id, org_id, name, display_name, description, enabled, \
                           redirect_url, attributes, created_by, created_at, updated_by, \
                           updated_at, version";

const MEMBER_COLUMNS: &str = "tenant, realm_id, org_id, user_id, membership_type, joined_at, \
                              created_by, created_at, updated_by, updated_at, version";

/// Record an organization.
///
/// Its domains are not written here. A claim is proven before it routes
/// anything, and a create that carried its own domains would let a caller take
/// delivery of mail addresses it does not own.
pub async fn create(transaction: &Transaction<'_>, org: &OrganizationModel) -> StoreResult<()> {
    let attributes = org
        .attributes
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    let set = WriteSet::insert(vec![
        col("tenant", &org.metadata.tenant),
        col("realm_id", &org.realm_id),
        col("org_id", &org.org_id),
        col("name", &org.name),
        col("display_name", &org.display_name),
        col("description", &org.description),
        col("enabled", &org.enabled),
        col("redirect_url", &org.redirect_url),
        col("attributes", &attributes),
        col("created_by", &org.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("organizations", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One organization by the name a caller spelled, which the realm holds
/// unique.
pub async fn load_by_name(
    transaction: &Transaction<'_>,
    name: &str,
) -> StoreResult<Option<OrganizationModel>> {
    let statement = format!("SELECT {ORG_COLUMNS} FROM organizations WHERE name = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&name])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_org))
}

/// One page of this realm's organizations, without their domains.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<OrganizationModel>> {
    let rows = transaction
        .query(
            query.select(ORG_COLUMNS, "organizations").as_str(),
            &query.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("organizations").as_str(), &query.params())
                .await
                .map_err(|_| StoreError::Backend)?
                .get::<_, i64>(0),
        )
    } else {
        None
    };
    Ok(Page::new(
        rows.into_iter().map(read_org).collect(),
        query.window(),
        total,
    ))
}

/// Rewrite what an organization says about itself. The identity stays, and so
/// do its members and domains.
pub async fn update(transaction: &Transaction<'_>, org: &OrganizationModel) -> StoreResult<bool> {
    let attributes = org
        .attributes
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    let set = WriteSet::update(
        vec![
            col("name", &org.name),
            col("display_name", &org.display_name),
            col("description", &org.description),
            col("enabled", &org.enabled),
            col("redirect_url", &org.redirect_url),
            col("attributes", &attributes),
            col("updated_by", &org.metadata.updated_by),
        ],
        vec![col("org_id", &org.org_id)],
    );

    // The stamp and the version are the statement's, not the caller's.
    let statement = statement::update("organizations", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );
    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// One organization of this realm, without its domains.
pub async fn load(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> StoreResult<Option<OrganizationModel>> {
    let statement = format!("SELECT {ORG_COLUMNS} FROM organizations WHERE org_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&org_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_org))
}

/// Remove an organization, and say whether there was one to remove.
pub async fn delete(transaction: &Transaction<'_>, org_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM organizations WHERE org_id = $1", &[&org_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Claim a mail domain for an organization, with the challenge that proves it.
///
/// The claim is refused if another organization of this realm already holds the
/// domain, since discovery reads one row per domain and two claims would make
/// the answer depend on which was found first.
///
/// The challenge is the caller's to generate and to publish. This records it.
pub async fn claim_domain(
    transaction: &Transaction<'_>,
    org_id: &str,
    domain: &str,
    challenge: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO organization_domains \
                 (tenant, realm_id, org_id, domain, challenge) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3",
            &[&org_id, &domain, &challenge],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Mark a claim proven, and say whether there was one to prove.
///
/// The challenge goes with it. A challenge that outlived its proof is a value
/// still published somewhere that would pass a check already passed.
pub async fn verify_domain(transaction: &Transaction<'_>, domain: &str) -> StoreResult<bool> {
    let proven = transaction
        .execute(
            "UPDATE organization_domains SET verified_at = now(), challenge = NULL \
             WHERE domain = $1 AND verified_at IS NULL",
            &[&domain],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(proven > 0)
}

/// The challenge a pending claim waits on, if it is still pending.
pub async fn pending_challenge(
    transaction: &Transaction<'_>,
    domain: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT challenge FROM organization_domains WHERE domain = $1",
            &[&domain],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| row.get("challenge")))
}

/// Every domain an organization claims, proven or not.
pub async fn domains(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> StoreResult<Vec<OrganizationDomain>> {
    let rows = transaction
        .query(
            "SELECT domain, verified_at FROM organization_domains \
             WHERE org_id = $1 ORDER BY domain ASC",
            &[&org_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(rows.iter().map(read_domain).collect())
}

/// The organization a mail domain routes to.
///
/// Only a proven claim routes anything. An unproven one is someone saying they
/// own a domain, and honouring it would hand that domain's users to whoever
/// asked first.
pub async fn by_domain(
    transaction: &Transaction<'_>,
    domain: &str,
) -> StoreResult<Option<OrganizationModel>> {
    // Qualified, because the claims carry a creator and a creation time of their
    // own and an unqualified list would ask for whichever the planner picked.
    let columns = ORG_COLUMNS
        .split(", ")
        .map(|column| format!("o.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let statement = format!(
        "SELECT {columns} FROM organizations o \
         JOIN organization_domains d USING (tenant, realm_id, org_id) \
         WHERE d.domain = $1 AND d.verified_at IS NOT NULL"
    );
    Ok(transaction
        .query_opt(statement.as_str(), &[&domain])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_org))
}

/// Add a user to an organization, or correct how they belong.
///
/// A membership that is already there keeps the day it started. Only the way
/// they belong is corrected, because a user provisioned by a broker who is
/// later invited by hand did not join twice.
pub async fn add_member(
    transaction: &Transaction<'_>,
    member: &OrganizationMemberModel,
) -> StoreResult<()> {
    let mut columns = vec![
        col("tenant", &member.metadata.tenant),
        col("realm_id", &member.realm_id),
        col("org_id", &member.org_id),
        col("user_id", &member.user_id),
        col("membership_type", &member.membership_type),
        col("created_by", &member.metadata.created_by),
    ];
    // Given when an import restores a membership, so the day it started is the
    // day it started and not the day it was imported.
    if member.joined_at.is_some() {
        columns.push(col("joined_at", &member.joined_at));
    }
    let set = WriteSet::insert(columns);

    let statement = format!(
        "{} ON CONFLICT (tenant, realm_id, org_id, user_id) \
         DO UPDATE SET membership_type = EXCLUDED.membership_type, updated_at = now()",
        statement::insert("organization_members", &set)
    );
    transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Remove a membership, and say whether there was one to remove.
pub async fn remove_member(
    transaction: &Transaction<'_>,
    org_id: &str,
    user_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2",
            &[&org_id, &user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Who belongs to an organization, with the roles each holds in it.
pub async fn members(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> StoreResult<Vec<OrganizationMemberModel>> {
    let statement = format!(
        "SELECT {MEMBER_COLUMNS}, \
                COALESCE(( \
                    SELECT array_agg(r.role_id ORDER BY r.role_id) \
                    FROM organization_members_roles r \
                    WHERE r.tenant = m.tenant AND r.realm_id = m.realm_id \
                      AND r.org_id = m.org_id AND r.user_id = m.user_id \
                ), '{{}}') AS roles \
         FROM organization_members m WHERE org_id = $1 ORDER BY user_id ASC"
    );
    let rows = transaction
        .query(statement.as_str(), &[&org_id])
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(rows.into_iter().map(read_member).collect())
}

/// The organizations a subject belongs to, by identifier.
///
/// The reverse of `members`, on the index that exists for it. A decision reads
/// this to place a caller, so a subject in no organization comes back empty,
/// which the caller reads as a realm level principal rather than as an unknown.
/// Ordered by identifier so the answer does not depend on insertion order.
pub async fn of_member(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT org_id FROM organization_members WHERE user_id = $1 ORDER BY org_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("org_id"))
        .collect())
}

/// Grant a realm role to a member, inside one organization.
///
/// Granting twice grants once: the row is keyed by everything it joins.
pub async fn grant_role(
    transaction: &Transaction<'_>,
    org_id: &str,
    user_id: &str,
    role_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO organization_members_roles \
                 (tenant, realm_id, org_id, user_id, role_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT DO NOTHING",
            &[&org_id, &user_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The roles a member holds inside one organization.
///
/// Read on its own and never folded into the roles a subject holds across the
/// realm, because folding them is what would destroy the confinement. A role
/// granted within one organization is held there; counted realm wide it would
/// answer for every other organization too, and for the realm itself, which is
/// the grant nobody wrote.
pub async fn roles_of_member(
    transaction: &Transaction<'_>,
    org_id: &str,
    user_id: &str,
) -> StoreResult<Vec<models::entities::authz::RoleModel>> {
    let columns = super::roles::ROLE_COLUMNS;
    let statement = format!(
        "SELECT {columns} FROM roles \
         WHERE role_id IN ( \
             SELECT role_id FROM organization_members_roles \
             WHERE org_id = $1 AND user_id = $2 \
         ) ORDER BY name ASC"
    );

    Ok(transaction
        .query(statement.as_str(), &[&org_id, &user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(super::roles::read_role)
        .collect())
}

fn read_org(row: Row) -> OrganizationModel {
    OrganizationModel {
        org_id: row.get("org_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        enabled: row.get("enabled"),
        domains: Vec::new(),
        redirect_url: row.get("redirect_url"),
        attributes: row
            .get::<_, Option<serde_json::Value>>("attributes")
            .and_then(|value| serde_json::from_value(value).ok()),
        metadata: audit(&row),
    }
}

/// A claim is verified when it has a time, and there is nothing else to read.
fn read_domain(row: &Row) -> OrganizationDomain {
    OrganizationDomain {
        name: row.get("domain"),
        verified: row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("verified_at")
            .is_some(),
    }
}

fn read_member(row: Row) -> OrganizationMemberModel {
    OrganizationMemberModel {
        realm_id: row.get("realm_id"),
        org_id: row.get("org_id"),
        user_id: row.get("user_id"),
        membership_type: row.get::<_, OrgMembershipType>("membership_type"),
        roles: row.get::<_, Vec<String>>("roles"),
        joined_at: row.get("joined_at"),
        metadata: audit(&row),
    }
}

fn audit(row: &Row) -> models::auditable::AuditableModel {
    models::auditable::AuditableModel {
        tenant: row.get("tenant"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
    }
}

/// The organization's stored theme, worn by the hosted pages after the
/// realm's own; absent is the realm's look.
pub async fn theme_of(
    transaction: &Transaction<'_>,
    org_id: &str,
) -> StoreResult<Option<serde_json::Value>> {
    let row = transaction
        .query_opt(
            "SELECT theme FROM organizations WHERE org_id = $1",
            &[&org_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.and_then(|row| row.get("theme")))
}

/// Dress or undress the organization; absent is the realm's look.
pub async fn set_theme(
    transaction: &Transaction<'_>,
    org_id: &str,
    theme: Option<&serde_json::Value>,
) -> StoreResult<bool> {
    let touched = transaction
        .execute(
            "UPDATE organizations SET theme = $2 WHERE org_id = $1",
            &[&org_id, &theme],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(touched > 0)
}
