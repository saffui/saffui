//! Named grants, and the sets of users they are given to together.

use deadpool_postgres::Transaction;
use models::entities::authz::{AdminAction, GroupModel, RoleModel};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const ROLE_COLUMNS: &str = "tenant, realm_id, role_id, name, display_name, description, \
                            is_client_role, admin_permissions, created_by, created_at, \
                            updated_by, updated_at, version";

const GROUP_COLUMNS: &str = "tenant, realm_id, group_id, name, display_name, description, \
                             is_default, created_by, created_at, updated_by, updated_at, version";

/// Record a role.
pub async fn create(transaction: &Transaction<'_>, role: &RoleModel) -> StoreResult<()> {
    let permissions = role
        .admin_permissions
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    let set = WriteSet::insert(vec![
        col("tenant", &role.metadata.tenant),
        col("realm_id", &role.realm_id),
        col("role_id", &role.role_id),
        col("name", &role.name),
        col("display_name", &role.display_name),
        col("description", &role.description),
        col("is_client_role", &role.is_client_role),
        col("admin_permissions", &permissions),
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
    let statement = format!(
        "SELECT {ROLE_COLUMNS} FROM roles \
         WHERE role_id IN ( \
             SELECT role_id FROM users_roles WHERE user_id = $1 \
             UNION ALL \
             SELECT gr.role_id FROM groups_roles gr \
             JOIN users_groups ug ON ug.group_id = gr.group_id \
             WHERE ug.user_id = $1 \
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

fn read_role(row: Row) -> RoleModel {
    RoleModel {
        role_id: row.get("role_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        description: row.get("description"),
        display_name: row.get("display_name"),
        is_client_role: row.get("is_client_role"),
        admin_permissions: row
            .get::<_, Option<serde_json::Value>>("admin_permissions")
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
