//! Roles, groups and who holds them. A name taken, a grant given again, a
//! removal, the roles held, and a read of several identifiers at once are
//! answered in constant SQL, the builder having no `= ANY` criterion; a read
//! of one and a page go through the builder.

use async_trait::async_trait;
use saffui_core::authz::grants::{HeldRole, Membership, RoleGrant, RoleHolder};
use saffui_core::authz::roles::{Group, Role};
use saffui_core::authz::store::RoleStore;
use saffui_core::clients::store::ListWindow;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::list_query::ListQuery;
use crate::query::select::{Select, SortDirection};
use crate::schema::{groups, roles};
use crate::work::PgUnitOfWork;

const ROLE: &[Column] = &[
    roles::ROLE_ID,
    roles::CLIENT_ID,
    roles::NAME,
    roles::DESCRIPTION,
    roles::CREATED_AT,
];

const GROUP: &[Column] = &[
    groups::GROUP_ID,
    groups::NAME,
    groups::DESCRIPTION,
    groups::CREATED_AT,
];

fn read_role_row(row: &Row) -> Role {
    Role {
        id: row.get(0),
        client_id: row.get(1),
        name: row.get(2),
        description: row.get(3),
        created_at: row.get(4),
    }
}

fn read_group_row(row: &Row) -> Group {
    Group {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        created_at: row.get(3),
    }
}

impl PgUnitOfWork {
    async fn read_total(
        &mut self,
        total: &crate::query::bind::Built<'_>,
    ) -> Result<u64, StorageError> {
        let counted: i64 = self
            .read_one(total)
            .await?
            .ok_or(StorageError::Failed)?
            .get(0);
        u64::try_from(counted).map_err(|_| StorageError::Failed)
    }
}

#[async_trait]
impl RoleStore for PgUnitOfWork {
    async fn insert_role(&mut self, role: &Role) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // A name the realm, or the client, holds already writes nothing.
        let written = self
            .execute_raw(
                "INSERT INTO roles
                     (tenant_id, realm_id, role_id, client_id, name, description, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT ON CONSTRAINT roles_name_taken DO NOTHING",
                &[
                    &tenant,
                    &realm,
                    &role.id,
                    &role.client_id,
                    &role.name,
                    &role.description,
                    &role.created_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn read_role(&mut self, id: Uuid) -> Result<Option<Role>, StorageError> {
        let select = Select::from(roles::TABLE, ROLE)
            .filter(Criteria::new().where_equal(roles::ROLE_ID, &id))
            .build();
        Ok(self.read_one(&select).await?.as_ref().map(read_role_row))
    }

    async fn read_roles(&mut self, ids: &[Uuid]) -> Result<Vec<Role>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT role_id, client_id, name, description, created_at FROM roles
                 WHERE tenant_id = $1 AND realm_id = $2 AND role_id = ANY($3)",
                &[&tenant, &realm, &ids],
            )
            .await?;
        Ok(rows.iter().map(read_role_row).collect())
    }

    async fn list_roles(&mut self, window: ListWindow) -> Result<Vec<Role>, StorageError> {
        // A name is unique per client only: the identifier closes the order.
        let query = ListQuery::new(window)
            .sorted_by(roles::NAME, SortDirection::Ascending)
            .sorted_by(roles::ROLE_ID, SortDirection::Ascending);
        let page = query.select(roles::TABLE, ROLE);
        Ok(self
            .read_all(&page)
            .await?
            .iter()
            .map(read_role_row)
            .collect())
    }

    async fn count_roles(&mut self) -> Result<u64, StorageError> {
        self.read_total(&ListQuery::count(roles::TABLE)).await
    }

    async fn delete_role(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM roles WHERE tenant_id = $1 AND realm_id = $2 AND role_id = $3",
                &[&tenant, &realm, &id],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn insert_group(&mut self, group: &Group) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let written = self
            .execute_raw(
                "INSERT INTO groups (tenant_id, realm_id, group_id, name, description, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT ON CONSTRAINT groups_name_taken DO NOTHING",
                &[
                    &tenant,
                    &realm,
                    &group.id,
                    &group.name,
                    &group.description,
                    &group.created_at,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn read_group(&mut self, id: Uuid) -> Result<Option<Group>, StorageError> {
        let select = Select::from(groups::TABLE, GROUP)
            .filter(Criteria::new().where_equal(groups::GROUP_ID, &id))
            .build();
        Ok(self.read_one(&select).await?.as_ref().map(read_group_row))
    }

    async fn read_groups(&mut self, ids: &[Uuid]) -> Result<Vec<Group>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(
                "SELECT group_id, name, description, created_at FROM groups
                 WHERE tenant_id = $1 AND realm_id = $2 AND group_id = ANY($3)",
                &[&tenant, &realm, &ids],
            )
            .await?;
        Ok(rows.iter().map(read_group_row).collect())
    }

    async fn list_groups(&mut self, window: ListWindow) -> Result<Vec<Group>, StorageError> {
        // The name is unique in the realm: the order is total.
        let query = ListQuery::new(window).sorted_by(groups::NAME, SortDirection::Ascending);
        let page = query.select(groups::TABLE, GROUP);
        Ok(self
            .read_all(&page)
            .await?
            .iter()
            .map(read_group_row)
            .collect())
    }

    async fn count_groups(&mut self) -> Result<u64, StorageError> {
        self.read_total(&ListQuery::count(groups::TABLE)).await
    }

    async fn delete_group(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM groups WHERE tenant_id = $1 AND realm_id = $2 AND group_id = $3",
                &[&tenant, &realm, &id],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn write_role_grant(&mut self, given: &RoleGrant) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        let grant = &given.grant;
        // One statement keeps the grant, or replaces the one the holder had
        // of that role.
        let (statement, holder) = match given.holder {
            RoleHolder::Person(person) => (
                "INSERT INTO person_roles (tenant_id, realm_id, person_id, role_id,
                     valid_from, valid_until, granted_by, reason, granted_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (tenant_id, realm_id, person_id, role_id) DO UPDATE
                     SET valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                         granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason,
                         granted_at = EXCLUDED.granted_at",
                person,
            ),
            RoleHolder::Group(group) => (
                "INSERT INTO group_roles (tenant_id, realm_id, group_id, role_id,
                     valid_from, valid_until, granted_by, reason, granted_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (tenant_id, realm_id, group_id, role_id) DO UPDATE
                     SET valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                         granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason,
                         granted_at = EXCLUDED.granted_at",
                group,
            ),
        };
        self.execute_raw(
            statement,
            &[
                &tenant,
                &realm,
                &holder,
                &given.role,
                &grant.valid_from,
                &grant.valid_until,
                &grant.granted_by,
                &grant.reason,
                &grant.granted_at,
            ],
        )
        .await
        .map(|_| ())
    }

    async fn delete_role_grant(
        &mut self,
        role: Uuid,
        holder: RoleHolder,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (statement, holder) = match holder {
            RoleHolder::Person(person) => (
                "DELETE FROM person_roles
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND role_id = $4",
                person,
            ),
            RoleHolder::Group(group) => (
                "DELETE FROM group_roles
                 WHERE tenant_id = $1 AND realm_id = $2 AND group_id = $3 AND role_id = $4",
                group,
            ),
        };
        let removed = self
            .execute_raw(statement, &[&tenant, &realm, &holder, &role])
            .await?;
        Ok(removed == 1)
    }

    async fn write_membership(&mut self, membership: &Membership) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        let grant = &membership.grant;
        // One statement keeps the membership, or replaces the one the person
        // had of that group.
        self.execute_raw(
            "INSERT INTO group_members (tenant_id, realm_id, group_id, person_id,
                 valid_from, valid_until, granted_by, reason, granted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, realm_id, group_id, person_id) DO UPDATE
                 SET valid_from = EXCLUDED.valid_from, valid_until = EXCLUDED.valid_until,
                     granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason,
                     granted_at = EXCLUDED.granted_at",
            &[
                &tenant,
                &realm,
                &membership.group,
                &membership.person,
                &grant.valid_from,
                &grant.valid_until,
                &grant.granted_by,
                &grant.reason,
                &grant.granted_at,
            ],
        )
        .await
        .map(|_| ())
    }

    async fn delete_membership(&mut self, group: Uuid, person: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(
                "DELETE FROM group_members
                 WHERE tenant_id = $1 AND realm_id = $2 AND group_id = $3 AND person_id = $4",
                &[&tenant, &realm, &group, &person],
            )
            .await?;
        Ok(removed == 1)
    }

    async fn list_held_roles(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<HeldRole>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let most = i64::from(most);
        // Both ways in one statement, each filtered on the instant of the
        // question. `least` skips an absent end: a way ends with the first
        // grant on it that has one. Cut before it is ordered: past `most` the
        // core refuses whichever ways were read, and no more than `most` are sorted.
        let rows = self
            .read_raw(
                "SELECT role_id, client_id, name, through, until FROM (
                     SELECT r.role_id, r.client_id, r.name, NULL::uuid AS through,
                            g.valid_until AS until
                     FROM person_roles g
                     JOIN roles r ON r.tenant_id = g.tenant_id AND r.realm_id = g.realm_id
                         AND r.role_id = g.role_id
                     WHERE g.tenant_id = $1 AND g.realm_id = $2 AND g.person_id = $3
                       AND g.valid_from <= $4 AND (g.valid_until IS NULL OR g.valid_until > $4)
                     UNION ALL
                     SELECT r.role_id, r.client_id, r.name, m.group_id,
                            least(m.valid_until, g.valid_until)
                     FROM group_members m
                     JOIN group_roles g ON g.tenant_id = m.tenant_id AND g.realm_id = m.realm_id
                         AND g.group_id = m.group_id
                     JOIN roles r ON r.tenant_id = g.tenant_id AND r.realm_id = g.realm_id
                         AND r.role_id = g.role_id
                     WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.person_id = $3
                       AND m.valid_from <= $4 AND (m.valid_until IS NULL OR m.valid_until > $4)
                       AND g.valid_from <= $4 AND (g.valid_until IS NULL OR g.valid_until > $4)
                 ) held
                 LIMIT $5",
                &[&tenant, &realm, &person, &now, &most],
            )
            .await?;
        let mut held: Vec<HeldRole> = rows
            .iter()
            .map(|row| HeldRole {
                role: row.get(0),
                client_id: row.get(1),
                name: row.get(2),
                through: row.get(3),
                until: row.get(4),
            })
            .collect();
        // Byte for byte, as the collation "C" orders the names; an absent
        // client, then an absent group, first.
        held.sort_by(|left, right| {
            (&left.name, &left.client_id, left.through).cmp(&(
                &right.name,
                &right.client_id,
                right.through,
            ))
        });
        Ok(held)
    }

    async fn list_member_groups(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let most = i64::from(most);
        // The bounds of a membership are compared to the instant of the
        // question, as for the roles.
        let rows = self
            .read_raw(
                "SELECT group_id FROM group_members
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                   AND valid_from <= $4 AND (valid_until IS NULL OR valid_until > $4)
                 ORDER BY group_id
                 LIMIT $5",
                &[&tenant, &realm, &person, &now, &most],
            )
            .await?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }
}
