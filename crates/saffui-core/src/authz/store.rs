use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::grants::{HeldRole, Membership, RoleGrant, RoleHolder};
use super::policy::Policy;
use super::relations::{
    AdmittedRelation, GuardedSchema, ObjectRef, RelationAdmission, RelationTuple, StoredSchema,
    SubjectRef,
};
use super::roles::{Group, Role};
use crate::clients::store::ListWindow;
use crate::ports::storage::StorageError;

#[async_trait]
pub trait RoleStore {
    /// Keeps a role. Answers false, and keeps nothing, when the realm, or the
    /// client of the role, has a role of that name already.
    async fn insert_role(&mut self, role: &Role) -> Result<bool, StorageError>;

    async fn read_role(&mut self, id: Uuid) -> Result<Option<Role>, StorageError>;

    /// The roles of these identifiers the realm has, in one read.
    async fn read_roles(&mut self, ids: &[Uuid]) -> Result<Vec<Role>, StorageError>;

    /// The roles of the realm and of its clients by name, within the window.
    async fn list_roles(&mut self, window: ListWindow) -> Result<Vec<Role>, StorageError>;

    async fn count_roles(&mut self) -> Result<u64, StorageError>;

    /// Removes a role and every grant of it. Answers whether there was one.
    async fn delete_role(&mut self, id: Uuid) -> Result<bool, StorageError>;

    /// Keeps a group. Answers false, and keeps nothing, when the realm has a
    /// group of that name already.
    async fn insert_group(&mut self, group: &Group) -> Result<bool, StorageError>;

    async fn read_group(&mut self, id: Uuid) -> Result<Option<Group>, StorageError>;

    /// The groups of these identifiers the realm has, in one read.
    async fn read_groups(&mut self, ids: &[Uuid]) -> Result<Vec<Group>, StorageError>;

    /// The groups of the realm by name, within the window.
    async fn list_groups(&mut self, window: ListWindow) -> Result<Vec<Group>, StorageError>;

    async fn count_groups(&mut self) -> Result<u64, StorageError>;

    /// Removes a group, its memberships and the grants it held. Answers
    /// whether there was one.
    async fn delete_group(&mut self, id: Uuid) -> Result<bool, StorageError>;

    /// Keeps a grant, in place of the one its holder had of that role.
    async fn write_role_grant(&mut self, grant: &RoleGrant) -> Result<(), StorageError>;

    /// Removes the grant of a role to a holder. Answers whether there was one.
    async fn delete_role_grant(
        &mut self,
        role: Uuid,
        holder: RoleHolder,
    ) -> Result<bool, StorageError>;

    /// Keeps a membership, in place of the one the person had of that group.
    async fn write_membership(&mut self, membership: &Membership) -> Result<(), StorageError>;

    /// Removes a person from a group. Answers whether they were a member.
    async fn delete_membership(&mut self, group: Uuid, person: Uuid) -> Result<bool, StorageError>;

    /// The roles a person holds at `now`, once per way: granted to them, or
    /// through each group they are a member of. A way stands when every
    /// grant on it does, and lasts until the first of them ends. `most` at
    /// most, whichever ones when there are more, ordered by name, then
    /// client, then group, a role of the realm and a direct grant first.
    async fn list_held_roles(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<HeldRole>, StorageError>;

    /// The groups a person is a member of at `now`, ordered, `most` at most.
    async fn list_member_groups(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<Uuid>, StorageError>;
}

#[async_trait]
pub trait RelationStore {
    /// Keeps the schema of the realm, in place of the one before, and the
    /// kinds of relations it admits, in place of theirs.
    async fn write_relation_schema(
        &mut self,
        schema: &StoredSchema,
        admitted: &[AdmittedRelation],
    ) -> Result<(), StorageError>;

    async fn read_relation_schema(&mut self) -> Result<Option<StoredSchema>, StorageError>;

    /// The compiled form of the schema of the realm, without its source, and
    /// whether a client guards a type, in one read.
    async fn read_guarded_schema(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<Option<GuardedSchema>, StorageError>;

    /// Reads, without the definitions, whether the schema admits the kind of a
    /// relation and whether the realm keeps it. A new one of a kind admitted
    /// takes them, behind any holder, writer of relations or not, a second at
    /// most per lock awaited, about two at worst, then reads the kind again.
    async fn admit_relation(
        &mut self,
        tuple: &RelationTuple,
    ) -> Result<RelationAdmission, StorageError>;

    /// Keeps a relation. Answers `false` when it was kept already.
    async fn insert_relation(
        &mut self,
        tuple: &RelationTuple,
        written_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Removes a relation. Answers whether there was one.
    async fn delete_relation(&mut self, tuple: &RelationTuple) -> Result<bool, StorageError>;

    /// Removes every relation kept that none of `admitted` names. Returns how
    /// many went.
    async fn delete_relations_not_admitted(
        &mut self,
        admitted: &[AdmittedRelation],
    ) -> Result<u64, StorageError>;

    /// Removes every relation kept that one of `kinds` names, and no other.
    /// Returns how many went.
    async fn delete_relations_of_kinds(
        &mut self,
        kinds: &[AdmittedRelation],
    ) -> Result<u64, StorageError>;

    /// Keeps a client as a guard of a type. Answers `false` when it was one.
    async fn insert_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
        written_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Removes a guard of a type. Answers whether there was one.
    async fn delete_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<bool, StorageError>;

    /// The clients that guard a type, by identifier, `most` at most.
    async fn list_relation_guards(
        &mut self,
        object_type: &str,
        most: u32,
    ) -> Result<Vec<String>, StorageError>;

    /// The subjects a relation of an object names, at most `limit` of them,
    /// in the order of their names.
    async fn list_relation_subjects(
        &mut self,
        object: &ObjectRef,
        relation: &str,
        limit: u32,
    ) -> Result<Vec<SubjectRef>, StorageError>;
}

#[async_trait]
pub trait PolicyStore {
    /// Keeps a policy. Answers false, and keeps nothing, when the client has
    /// a policy of that name already.
    async fn insert_policy(&mut self, policy: &Policy) -> Result<bool, StorageError>;

    /// The policies of a client, by name.
    async fn list_policies(&mut self, client_id: &str) -> Result<Vec<Policy>, StorageError>;

    /// The policies of a client for one action on one type of resource, by name.
    async fn list_applicable_policies(
        &mut self,
        client_id: &str,
        resource_type: &str,
        action: &str,
    ) -> Result<Vec<Policy>, StorageError>;

    /// How many policies a client has, counted to `most` and no further.
    async fn count_policies(&mut self, client_id: &str, most: u32) -> Result<u64, StorageError>;

    /// Removes a policy of a client. Answers whether there was one.
    async fn delete_policy(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError>;

    /// Holds, until the unit of work ends, the definitions of the realm, its
    /// policies, its schema of relations, its roles and its groups: any other
    /// unit of work that holds them waits, in the order they came.
    async fn lock_definitions(&mut self) -> Result<(), StorageError>;

    /// Whether a policy of any client of the realm guards one of these types.
    async fn has_policy_for_types(&mut self, types: &[String]) -> Result<bool, StorageError>;

    /// Whether a condition of a policy of the realm names this identifier, as
    /// `{"role": id}` or `{"group": id}` does.
    async fn is_named_by_policy(&mut self, condition: &str, id: Uuid)
    -> Result<bool, StorageError>;
}
