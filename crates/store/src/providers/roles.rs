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
    lock_role_composites(transaction).await?;
    let row = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM users_roles WHERE role_id = $1)                  OR EXISTS(SELECT 1 FROM groups_roles WHERE role_id = $1)                  OR EXISTS(SELECT 1 FROM policies_roles WHERE role_id = $1)                  OR EXISTS(SELECT 1 FROM role_composites WHERE parent_role_id = $1 OR child_role_id = $1)",
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

/// Serialize graph changes within one realm. Cycle checks must observe a
/// stable graph, including when two requests add different edges concurrently.
pub async fn lock_role_composites(transaction: &Transaction<'_>) -> StoreResult<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended(\
             current_setting('saffui.current_tenant', true) || ':' || \
             current_setting('saffui.current_realm', true), 0))",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Roles directly contained by a composite role.
pub async fn composite_children(
    transaction: &Transaction<'_>,
    parent_role_id: &str,
) -> StoreResult<Vec<RoleModel>> {
    // Read through the edge's identifiers rather than joined to it: both tables
    // carry the realm's columns, and a join makes every one of them ambiguous.
    let statement = format!(
        "SELECT {ROLE_COLUMNS} FROM roles \
         WHERE role_id IN (SELECT child_role_id FROM role_composites WHERE parent_role_id = $1) \
         ORDER BY name ASC, role_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&parent_role_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_role)
        .collect())
}

/// Whether the child already reaches the parent through composite edges.
pub async fn composite_reaches(
    transaction: &Transaction<'_>,
    child_role_id: &str,
    parent_role_id: &str,
) -> StoreResult<bool> {
    let row = transaction
        .query_one(
            "WITH RECURSIVE descendants(role_id) AS ( \
                 SELECT child_role_id FROM role_composites \
                 WHERE parent_role_id = $1 \
                 UNION \
                 SELECT composites.child_role_id \
                 FROM role_composites composites \
                 JOIN descendants ON descendants.role_id = composites.parent_role_id \
             ) \
             SELECT EXISTS(SELECT 1 FROM descendants WHERE role_id = $2)",
            &[&child_role_id, &parent_role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get(0))
}

/// Add a composite edge. Repeating the same edge is idempotent.
pub async fn add_composite(
    transaction: &Transaction<'_>,
    parent_role_id: &str,
    child_role_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO role_composites \
             (tenant, realm_id, parent_role_id, child_role_id) \
             VALUES (current_setting('saffui.current_tenant', true), \
                     current_setting('saffui.current_realm', true), $1, $2) \
             ON CONFLICT DO NOTHING",
            &[&parent_role_id, &child_role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Remove a composite edge, and say whether there was one.
pub async fn remove_composite(
    transaction: &Transaction<'_>,
    parent_role_id: &str,
    child_role_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM role_composites \
             WHERE parent_role_id = $1 AND child_role_id = $2",
            &[&parent_role_id, &child_role_id],
        )
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

/// Direct holders with the stable identifier and the name shown to people.
pub async fn named_holders_of(
    transaction: &Transaction<'_>,
    role_id: &str,
) -> StoreResult<(Vec<(String, String)>, Vec<(String, String)>)> {
    let direct = transaction
        .query(
            "SELECT users.user_id, users.user_name FROM users_roles \
             JOIN users ON users.user_id = users_roles.user_id \
             WHERE users_roles.role_id = $1 ORDER BY users.user_name ASC, users.user_id ASC",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| (row.get("user_id"), row.get("user_name")))
        .collect();
    let through_groups = transaction
        .query(
            "SELECT groups.group_id, groups.name FROM groups_roles \
             JOIN groups ON groups.group_id = groups_roles.group_id \
             WHERE groups_roles.role_id = $1 ORDER BY groups.name ASC, groups.group_id ASC",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| (row.get("group_id"), row.get("name")))
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
         , granted(role_id) AS ( \
             SELECT role_id FROM users_roles WHERE user_id = $1 \
             UNION \
             SELECT gr.role_id FROM groups_roles gr \
             JOIN standing s ON s.group_id = gr.group_id \
         ) \
         , effective(role_id) AS ( \
             SELECT role_id FROM granted \
             UNION \
             SELECT composites.child_role_id FROM role_composites composites \
             JOIN effective ON effective.role_id = composites.parent_role_id \
         ) \
         SELECT {ROLE_COLUMNS} FROM roles \
         WHERE role_id IN (SELECT role_id FROM effective) ORDER BY name ASC"
    );

    Ok(transaction
        .query(statement.as_str(), &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_role)
        .collect())
}

/// Everyone standing in this group, directly or through a group below it: the
/// people a role given to the group reaches, and a new parent above it.
pub async fn members_at_or_below(
    transaction: &Transaction<'_>,
    group_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE below(group_id) AS ( \
                 SELECT $1::text \
                 UNION \
                 SELECT g.group_id FROM groups g JOIN below b ON g.parent_id = b.group_id \
             ) \
             SELECT DISTINCT user_id FROM users_groups \
             WHERE group_id IN (SELECT group_id FROM below) ORDER BY user_id",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// Everyone who holds this role, however they came to: granted it, standing in
/// a group that carries it, or holding a role it is placed under. The mirror of
/// `effective_roles`, read from the role's side.
pub async fn holders_of_role(
    transaction: &Transaction<'_>,
    role_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE above(role_id) AS ( \
                 SELECT $1::text \
                 UNION \
                 SELECT c.parent_role_id FROM role_composites c \
                 JOIN above a ON c.child_role_id = a.role_id \
             ) \
             , carrying(group_id) AS ( \
                 SELECT group_id FROM groups_roles \
                 WHERE role_id IN (SELECT role_id FROM above) \
                 UNION \
                 SELECT g.group_id FROM groups g JOIN carrying c ON g.parent_id = c.group_id \
             ) \
             SELECT user_id FROM users_roles WHERE role_id IN (SELECT role_id FROM above) \
             UNION \
             SELECT user_id FROM users_groups WHERE group_id IN (SELECT group_id FROM carrying) \
             ORDER BY user_id",
            &[&role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// These roles and every role placed below them: what somebody handed them
/// comes to hold.
pub async fn roles_reached_from(
    transaction: &Transaction<'_>,
    starting: &[String],
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE reached(role_id) AS ( \
                 SELECT unnest($1::text[]) \
                 UNION \
                 SELECT c.child_role_id FROM role_composites c \
                 JOIN reached r ON c.parent_role_id = r.role_id \
             ) \
             SELECT role_id FROM reached ORDER BY role_id",
            &[&starting],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// The roles the default groups carry, with those of every group above them:
/// what each newcomer holds through the groups they are seated in at birth.
pub async fn roles_of_default_groups(transaction: &Transaction<'_>) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE above(group_id, parent_id) AS ( \
                 SELECT group_id, parent_id FROM groups WHERE is_default \
                 UNION \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN above a ON g.group_id = a.parent_id \
             ) \
             SELECT DISTINCT role_id FROM groups_roles \
             WHERE group_id IN (SELECT group_id FROM above) ORDER BY role_id",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// The roles carried by this group and by every group above it: what anyone
/// standing in it holds through its groups.
pub async fn roles_carried_at_or_above(
    transaction: &Transaction<'_>,
    group_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE above(group_id, parent_id) AS ( \
                 SELECT group_id, parent_id FROM groups WHERE group_id = $1 \
                 UNION \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN above a ON g.group_id = a.parent_id \
             ) \
             SELECT DISTINCT role_id FROM groups_roles \
             WHERE group_id IN (SELECT group_id FROM above) ORDER BY role_id",
            &[&group_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get(0))
        .collect())
}

/// The role grants written against this person and no one else: the direct
/// edges, without what a group confers. A review that offers to pull an
/// edge has to name the edge it can pull.
pub async fn direct_roles_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT role_id FROM users_roles WHERE user_id = $1 ORDER BY role_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("role_id"))
        .collect())
}

/// The groups this person was put in, without the ones above them: joining
/// is the edge, standing in the parent is the consequence.
pub async fn groups_joined_by(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT group_id FROM users_groups WHERE user_id = $1 ORDER BY group_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("group_id"))
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
