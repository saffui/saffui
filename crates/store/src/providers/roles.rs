use deadpool_postgres::Transaction;
use models::entities::authz::{AdminAction, GroupModel, RoleModel};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

pub(crate) const ROLE_COLUMNS: &str = "tenant, realm_id, role_id, name, display_name, description, \
                            client_id, admin_actions, created_by, created_at, \
                            updated_by, updated_at, version";

const GROUP_COLUMNS: &str = "tenant, realm_id, group_id, name, display_name, description, \
                             is_default, parent_id, created_by, created_at, updated_by, \
                             updated_at, version";

/// One role by the name a caller spelled, which the realm holds unique.
pub async fn load_by_name(
    transaction: &Transaction<'_>,
    name: &str,
) -> StoreResult<Option<RoleModel>> {
    let statement = format!("SELECT {ROLE_COLUMNS} FROM roles WHERE name = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&name])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_role))
}

/// The same for a group.
pub async fn load_group_by_name(
    transaction: &Transaction<'_>,
    name: &str,
) -> StoreResult<Option<GroupModel>> {
    let statement = format!("SELECT {GROUP_COLUMNS} FROM groups WHERE name = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&name])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_group))
}

/// One page of this realm's roles.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<RoleModel>> {
    let rows = transaction
        .query(
            query.select(ROLE_COLUMNS, "roles").as_str(),
            &query.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("roles").as_str(), &query.params())
                .await
                .map_err(|_| StoreError::Backend)?
                .get::<_, i64>(0),
        )
    } else {
        None
    };
    Ok(Page::new(
        rows.into_iter().map(read_role).collect(),
        query.window(),
        total,
    ))
}

/// One page of this realm's groups.
pub async fn list_groups(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<GroupModel>> {
    let rows = transaction
        .query(
            query.select(GROUP_COLUMNS, "groups").as_str(),
            &query.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("groups").as_str(), &query.params())
                .await
                .map_err(|_| StoreError::Backend)?
                .get::<_, i64>(0),
        )
    } else {
        None
    };
    Ok(Page::new(
        rows.into_iter().map(read_group).collect(),
        query.window(),
        total,
    ))
}

/// Rewrite what a role says about itself. The identity stays; a rename is not
/// a new role, and everything granted keeps meaning what it meant.
pub async fn update(transaction: &Transaction<'_>, role: &RoleModel) -> StoreResult<bool> {
    let permissions = role
        .admin_actions
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    let set = WriteSet::update(
        vec![
            col("name", &role.name),
            col("display_name", &role.display_name),
            col("description", &role.description),
            col("admin_actions", &permissions),
            col("updated_by", &role.metadata.updated_by),
        ],
        vec![col("role_id", &role.role_id)],
    );

    // The stamp and the version are the statement's, not the caller's.
    let statement = statement::update("roles", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );
    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// The same for a group.
pub async fn update_group(transaction: &Transaction<'_>, group: &GroupModel) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![
            col("name", &group.name),
            col("display_name", &group.display_name),
            col("description", &group.description),
            col("is_default", &group.is_default),
            col("parent_id", &group.parent_id),
            col("updated_by", &group.metadata.updated_by),
        ],
        vec![col("group_id", &group.group_id)],
    );
    let statement = statement::update("groups", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );
    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Whether anything still holds this role: a user, a group, or a policy.
///
/// Asked before a deletion, because the joins cascade: the rows naming the
/// role would go with it, and every holder would silently lose an entitlement
/// rather than the deletion being told no.
pub async fn role_still_held(transaction: &Transaction<'_>, role_id: &str) -> StoreResult<bool> {
    let row = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM users_roles WHERE role_id = $1)                  OR EXISTS(SELECT 1 FROM groups_roles WHERE role_id = $1)                  OR EXISTS(SELECT 1 FROM policies_roles WHERE role_id = $1)",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get::<_, bool>(0))
}

/// Whether anybody is still in this group.
pub async fn group_still_held(transaction: &Transaction<'_>, group_id: &str) -> StoreResult<bool> {
    let row = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM users_groups WHERE group_id = $1)                  OR EXISTS(SELECT 1 FROM groups_roles WHERE group_id = $1) \
                 OR EXISTS(SELECT 1 FROM policies_groups WHERE group_id = $1)",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get::<_, bool>(0))
}

/// Whether any group sits under this one.
pub async fn has_children(transaction: &Transaction<'_>, group_id: &str) -> StoreResult<bool> {
    let row = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM groups WHERE parent_id = $1)",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get::<_, bool>(0))
}

/// Take a group away.
pub async fn delete_group(transaction: &Transaction<'_>, group_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM groups WHERE group_id = $1", &[&group_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record a role.
pub async fn create(transaction: &Transaction<'_>, role: &RoleModel) -> StoreResult<()> {
    let permissions = role
        .admin_actions
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    // Bound to a local, since the write set borrows what it is given.
    let is_client_role = role.is_client_role();
    let set = WriteSet::insert(vec![
        col("tenant", &role.metadata.tenant),
        col("realm_id", &role.realm_id),
        col("role_id", &role.role_id),
        col("name", &role.name),
        col("display_name", &role.display_name),
        col("description", &role.description),
        // Both columns are written from the one field, and a check keeps them
        // from disagreeing.
        col("is_client_role", &is_client_role),
        col("client_id", &role.client_id),
        col("admin_actions", &permissions),
        col("created_by", &role.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("roles", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One role of this realm.
pub async fn load(transaction: &Transaction<'_>, role_id: &str) -> StoreResult<Option<RoleModel>> {
    let statement = format!("SELECT {ROLE_COLUMNS} FROM roles WHERE role_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&role_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_role))
}

/// Remove a role, and say whether there was one to remove.
pub async fn delete(transaction: &Transaction<'_>, role_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM roles WHERE role_id = $1", &[&role_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Record a group.
pub async fn create_group(transaction: &Transaction<'_>, group: &GroupModel) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &group.metadata.tenant),
        col("realm_id", &group.realm_id),
        col("group_id", &group.group_id),
        col("name", &group.name),
        col("display_name", &group.display_name),
        col("description", &group.description),
        col("is_default", &group.is_default),
        col("parent_id", &group.parent_id),
        col("created_by", &group.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("groups", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One group of this realm.
pub async fn load_group(
    transaction: &Transaction<'_>,
    group_id: &str,
) -> StoreResult<Option<GroupModel>> {
    let statement = format!("SELECT {GROUP_COLUMNS} FROM groups WHERE group_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&group_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_group))
}

/// The groups a new user joins without anyone adding them.
pub async fn default_groups(transaction: &Transaction<'_>) -> StoreResult<Vec<GroupModel>> {
    let statement =
        format!("SELECT {GROUP_COLUMNS} FROM groups WHERE is_default ORDER BY name ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_group)
        .collect())
}

/// Put a fresh account into every group the realm marked default.
///
/// One door for every way a person comes to exist, an administrator's POST,
/// a federation shadow, a SCIM push, so birthright membership does not
/// depend on which door was used.
pub async fn join_default_groups(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<()> {
    for group in default_groups(transaction).await? {
        add_to_group(transaction, user_id, &group.group_id).await?;
    }
    Ok(())
}

/// Grant a role to a user.
///
/// Granting twice is not an error and not a second grant. A caller reconciling a
/// set of grants would otherwise have to know which it already made, and
/// deciding that from a failure is deciding it from an error message.
pub async fn grant_to_user(
    transaction: &Transaction<'_>,
    user_id: &str,
    role_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO users_roles (tenant, realm_id, user_id, role_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2 \
             ON CONFLICT DO NOTHING",
            &[&user_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take a role back from a user, and say whether they held it.
pub async fn revoke_from_user(
    transaction: &Transaction<'_>,
    user_id: &str,
    role_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM users_roles WHERE user_id = $1 AND role_id = $2",
            &[&user_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Put a user in a group.
pub async fn add_to_group(
    transaction: &Transaction<'_>,
    user_id: &str,
    group_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO users_groups (tenant, realm_id, user_id, group_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2 \
             ON CONFLICT DO NOTHING",
            &[&user_id, &group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take a person out of a group.
pub async fn remove_from_group(
    transaction: &Transaction<'_>,
    user_id: &str,
    group_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM users_groups WHERE user_id = $1 AND group_id = $2",
            &[&user_id, &group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Take a role back from a group. Everyone in the group stops holding it at
/// once, which is what granting through a group means.
pub async fn revoke_from_group(
    transaction: &Transaction<'_>,
    group_id: &str,
    role_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM groups_roles WHERE group_id = $1 AND role_id = $2",
            &[&group_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Who holds this role directly, and through which groups.
///
/// Both lists, because an administrator refused a deletion with "still
/// granted" needs to see whom to revoke from, and a holder through a group is
/// revoked at the group, not at the person.
pub async fn holders_of(
    transaction: &Transaction<'_>,
    role_id: &str,
) -> StoreResult<(Vec<String>, Vec<String>)> {
    let direct = transaction
        .query(
            "SELECT user_id FROM users_roles WHERE role_id = $1 ORDER BY user_id ASC",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("user_id"))
        .collect();
    let through_groups = transaction
        .query(
            "SELECT group_id FROM groups_roles WHERE role_id = $1 ORDER BY group_id ASC",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("group_id"))
        .collect();
    Ok((direct, through_groups))
}

/// Who is in this group, and which roles it grants them.
pub async fn group_membership(
    transaction: &Transaction<'_>,
    group_id: &str,
) -> StoreResult<(Vec<String>, Vec<String>)> {
    let people = transaction
        .query(
            "SELECT user_id FROM users_groups WHERE group_id = $1 ORDER BY user_id ASC",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("user_id"))
        .collect();
    let roles = transaction
        .query(
            "SELECT role_id FROM groups_roles WHERE group_id = $1 ORDER BY role_id ASC",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("role_id"))
        .collect();
    Ok((people, roles))
}

/// Grant a role to a group.
pub async fn grant_to_group(
    transaction: &Transaction<'_>,
    group_id: &str,
    role_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO groups_roles (tenant, realm_id, group_id, role_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2 \
             ON CONFLICT DO NOTHING",
            &[&group_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Every role a user holds, directly or through a group they belong to.
///
/// One answer rather than two lists to combine. A caller that read the direct
/// grants and the group ones separately would have to union them, and a role
/// held both ways would appear twice or be dropped depending on how carefully.
pub async fn effective_roles(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<RoleModel>> {
    // The membership test is what removes a duplicate: a role reached by both
    // routes is still one role in the set. `DISTINCT` on top would be a second
    // mechanism for one property, and a test could then only ever exercise
    // whichever of the two runs first.
    // The walk up `parent_id` is what makes a sub-group mean something: its
    // members stand in every group above it, so those groups' roles are
    // theirs too. `UNION` in the walk, so a malformed chain terminates.
    let statement = format!(
        "WITH RECURSIVE standing AS ( \
             SELECT g.group_id, g.parent_id FROM groups g \
             JOIN users_groups ug ON ug.group_id = g.group_id \
             WHERE ug.user_id = $1 \
             UNION \
             SELECT g.group_id, g.parent_id FROM groups g \
             JOIN standing s ON g.group_id = s.parent_id \
         ) \
         SELECT {ROLE_COLUMNS} FROM roles \
         WHERE role_id IN ( \
             SELECT role_id FROM users_roles WHERE user_id = $1 \
             UNION ALL \
             SELECT gr.role_id FROM groups_roles gr \
             JOIN standing s ON s.group_id = gr.group_id \
         ) ORDER BY name ASC"
    );

    Ok(transaction
        .query(statement.as_str(), &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_role)
        .collect())
}

/// The groups a subject stands in, by identifier: the ones joined, and every
/// group above those, since standing in a sub-group is standing in the whole.
/// Ordered by identifier so two reads of one membership answer in one order,
/// which a decision that records what it saw depends on.
pub async fn groups_of(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE standing AS ( \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN users_groups ug ON ug.group_id = g.group_id \
                 WHERE ug.user_id = $1 \
                 UNION \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN standing s ON g.group_id = s.parent_id \
             ) \
             SELECT group_id FROM standing ORDER BY group_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("group_id"))
        .collect())
}

pub(crate) fn read_role(row: Row) -> RoleModel {
    RoleModel {
        role_id: row.get("role_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        description: row.get("description"),
        display_name: row.get("display_name"),
        client_id: row.get("client_id"),
        admin_actions: row
            .get::<_, Option<serde_json::Value>>("admin_actions")
            .and_then(|value| serde_json::from_value::<Vec<AdminAction>>(value).ok()),
        metadata: audit(&row),
    }
}

fn read_group(row: Row) -> GroupModel {
    GroupModel {
        group_id: row.get("group_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        is_default: row.get("is_default"),
        parent_id: row.get("parent_id"),
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
