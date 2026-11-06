use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::authz::grants::{HeldRole, Membership, RoleGrant, RoleHolder};
use crate::authz::policy::Policy;
use crate::authz::relations::{
    AdmittedRelation, GuardedSchema, ObjectRef, RelationAdmission, RelationTuple, StoredSchema,
    SubjectRef,
};
use crate::authz::roles::{Group, Role};
use crate::authz::store::{PolicyStore, RelationStore, RoleStore};
use crate::clients::store::ListWindow;
use crate::ports::storage::StorageError;

/// The rows of one realm, in a map of every realm.
fn read_realm<T>(rows: &HashMap<Uuid, Vec<T>>, realm: Uuid) -> &[T] {
    rows.get(&realm).map_or(&[], Vec::as_slice)
}

fn cut_window<T>(rows: Vec<T>, window: ListWindow) -> Vec<T> {
    rows.into_iter()
        .skip(usize::try_from(window.first).unwrap_or(usize::MAX))
        .take(usize::try_from(window.max).unwrap_or(usize::MAX))
        .collect()
}

fn count<T>(rows: &[T]) -> Result<u64, StorageError> {
    u64::try_from(rows.len()).map_err(|_| StorageError::Failed)
}

/// Whether a relation kept is of one of these kinds.
fn is_of_kinds(tuple: &RelationTuple, kinds: &[AdmittedRelation]) -> bool {
    kinds.iter().any(|kind| {
        kind.object_type == tuple.object.object_type
            && kind.relation == tuple.relation
            && kind.subject.object_type == tuple.subject.object.object_type
            && kind.subject.member == tuple.subject.member
    })
}

impl MemoryUnitOfWork {
    fn realm(&self) -> Uuid {
        self.scope.realm().as_uuid()
    }
}

#[async_trait]
impl RoleStore for MemoryUnitOfWork {
    async fn insert_role(&mut self, role: &Role) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let roles = self.working.roles.entry(realm).or_default();
        if roles
            .iter()
            .any(|known| known.client_id == role.client_id && known.name == role.name)
        {
            return Ok(false);
        }
        roles.push(role.clone());
        Ok(true)
    }

    async fn read_role(&mut self, id: Uuid) -> Result<Option<Role>, StorageError> {
        Ok(read_realm(&self.working.roles, self.realm())
            .iter()
            .find(|role| role.id == id)
            .cloned())
    }

    async fn read_roles(&mut self, ids: &[Uuid]) -> Result<Vec<Role>, StorageError> {
        Ok(read_realm(&self.working.roles, self.realm())
            .iter()
            .filter(|role| ids.contains(&role.id))
            .cloned()
            .collect())
    }

    async fn list_roles(&mut self, window: ListWindow) -> Result<Vec<Role>, StorageError> {
        let mut roles = read_realm(&self.working.roles, self.realm()).to_vec();
        roles.sort_by(|left, right| (&left.name, left.id).cmp(&(&right.name, right.id)));
        Ok(cut_window(roles, window))
    }

    async fn count_roles(&mut self) -> Result<u64, StorageError> {
        count(read_realm(&self.working.roles, self.realm()))
    }

    async fn delete_role(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let roles = self.working.roles.entry(realm).or_default();
        let before = roles.len();
        roles.retain(|role| role.id != id);
        let removed = roles.len() < before;
        if removed {
            self.working
                .role_grants
                .entry(realm)
                .or_default()
                .retain(|grant| grant.role != id);
        }
        Ok(removed)
    }

    async fn insert_group(&mut self, group: &Group) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let groups = self.working.groups.entry(realm).or_default();
        if groups.iter().any(|known| known.name == group.name) {
            return Ok(false);
        }
        groups.push(group.clone());
        Ok(true)
    }

    async fn read_group(&mut self, id: Uuid) -> Result<Option<Group>, StorageError> {
        Ok(read_realm(&self.working.groups, self.realm())
            .iter()
            .find(|group| group.id == id)
            .cloned())
    }

    async fn read_groups(&mut self, ids: &[Uuid]) -> Result<Vec<Group>, StorageError> {
        Ok(read_realm(&self.working.groups, self.realm())
            .iter()
            .filter(|group| ids.contains(&group.id))
            .cloned()
            .collect())
    }

    async fn list_groups(&mut self, window: ListWindow) -> Result<Vec<Group>, StorageError> {
        let mut groups = read_realm(&self.working.groups, self.realm()).to_vec();
        groups.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(cut_window(groups, window))
    }

    async fn count_groups(&mut self) -> Result<u64, StorageError> {
        count(read_realm(&self.working.groups, self.realm()))
    }

    async fn delete_group(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let groups = self.working.groups.entry(realm).or_default();
        let before = groups.len();
        groups.retain(|group| group.id != id);
        let removed = groups.len() < before;
        if removed {
            self.working
                .role_grants
                .entry(realm)
                .or_default()
                .retain(|grant| grant.holder != RoleHolder::Group(id));
            self.working
                .memberships
                .entry(realm)
                .or_default()
                .retain(|membership| membership.group != id);
        }
        Ok(removed)
    }

    async fn write_role_grant(&mut self, grant: &RoleGrant) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let grants = self.working.role_grants.entry(realm).or_default();
        grants.retain(|known| (known.role, known.holder) != (grant.role, grant.holder));
        grants.push(grant.clone());
        Ok(())
    }

    async fn delete_role_grant(
        &mut self,
        role: Uuid,
        holder: RoleHolder,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let grants = self.working.role_grants.entry(realm).or_default();
        let before = grants.len();
        grants.retain(|known| (known.role, known.holder) != (role, holder));
        Ok(grants.len() < before)
    }

    async fn write_membership(&mut self, membership: &Membership) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let memberships = self.working.memberships.entry(realm).or_default();
        memberships
            .retain(|known| (known.group, known.person) != (membership.group, membership.person));
        memberships.push(membership.clone());
        Ok(())
    }

    async fn delete_membership(&mut self, group: Uuid, person: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let memberships = self.working.memberships.entry(realm).or_default();
        let before = memberships.len();
        memberships.retain(|known| (known.group, known.person) != (group, person));
        Ok(memberships.len() < before)
    }

    async fn list_held_roles(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<HeldRole>, StorageError> {
        let realm = self.realm();
        let roles = read_realm(&self.working.roles, realm);
        let grants = read_realm(&self.working.role_grants, realm);
        let memberships = read_realm(&self.working.memberships, realm);
        let describe = |grant: &RoleGrant, through: Option<Uuid>, until: Option<OffsetDateTime>| {
            roles
                .iter()
                .find(|role| role.id == grant.role)
                .map(|role| HeldRole {
                    role: role.id,
                    client_id: role.client_id.clone(),
                    name: role.name.clone(),
                    through,
                    until,
                })
        };
        let mut held: Vec<HeldRole> = grants
            .iter()
            .filter(|grant| {
                grant.holder == RoleHolder::Person(person) && grant.grant.stands_at(now)
            })
            .filter_map(|grant| describe(grant, None, grant.grant.valid_until))
            .collect();
        for membership in memberships
            .iter()
            .filter(|membership| membership.person == person && membership.grant.stands_at(now))
        {
            for grant in grants.iter().filter(|grant| {
                grant.holder == RoleHolder::Group(membership.group) && grant.grant.stands_at(now)
            }) {
                // The first end on the way, as `least` reads it: none is no end.
                let until = match (membership.grant.valid_until, grant.grant.valid_until) {
                    (Some(one), Some(other)) => Some(one.min(other)),
                    (one, other) => one.or(other),
                };
                held.extend(describe(grant, Some(membership.group), until));
            }
        }
        held.sort_by(|left, right| {
            (&left.name, &left.client_id, left.through).cmp(&(
                &right.name,
                &right.client_id,
                right.through,
            ))
        });
        held.truncate(usize::try_from(most).unwrap_or(usize::MAX));
        Ok(held)
    }

    async fn list_member_groups(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
        most: u32,
    ) -> Result<Vec<Uuid>, StorageError> {
        let mut groups: Vec<Uuid> = read_realm(&self.working.memberships, self.realm())
            .iter()
            .filter(|membership| membership.person == person && membership.grant.stands_at(now))
            .map(|membership| membership.group)
            .collect();
        groups.sort();
        groups.truncate(usize::try_from(most).unwrap_or(usize::MAX));
        Ok(groups)
    }
}

#[async_trait]
impl RelationStore for MemoryUnitOfWork {
    async fn write_relation_schema(
        &mut self,
        schema: &StoredSchema,
        admitted: &[AdmittedRelation],
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        self.working.relation_schemas.insert(realm, schema.clone());
        self.working.relation_kinds.insert(realm, admitted.to_vec());
        Ok(())
    }

    async fn read_relation_schema(&mut self) -> Result<Option<StoredSchema>, StorageError> {
        Ok(self.working.relation_schemas.get(&self.realm()).cloned())
    }

    async fn read_guarded_schema(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<Option<GuardedSchema>, StorageError> {
        let realm = self.realm();
        let guarded = read_realm(&self.working.relation_guards, realm).iter().any(
            |(known_type, known_client)| known_type == object_type && known_client == client_id,
        );
        Ok(self
            .working
            .relation_schemas
            .get(&realm)
            .map(|stored| GuardedSchema {
                compiled: stored.compiled.clone(),
                guarded,
            }))
    }

    async fn admit_relation(
        &mut self,
        tuple: &RelationTuple,
    ) -> Result<RelationAdmission, StorageError> {
        // One unit of work at a time: the definitions are never held by another.
        let realm = self.realm();
        let admitted = read_realm(&self.working.relation_kinds, realm);
        Ok(if !is_of_kinds(tuple, admitted) {
            RelationAdmission::Refused
        } else if read_realm(&self.working.relations, realm).contains(tuple) {
            RelationAdmission::Kept
        } else {
            RelationAdmission::Taken
        })
    }

    async fn insert_relation(
        &mut self,
        tuple: &RelationTuple,
        _written_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let kept = self.working.relations.entry(realm).or_default();
        if kept.contains(tuple) {
            return Ok(false);
        }
        kept.push(tuple.clone());
        Ok(true)
    }

    async fn delete_relation(&mut self, tuple: &RelationTuple) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let kept = self.working.relations.entry(realm).or_default();
        let before = kept.len();
        kept.retain(|known| known != tuple);
        Ok(kept.len() < before)
    }

    async fn delete_relations_not_admitted(
        &mut self,
        admitted: &[AdmittedRelation],
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let kept = self.working.relations.entry(realm).or_default();
        let before = kept.len();
        kept.retain(|tuple| is_of_kinds(tuple, admitted));
        u64::try_from(before - kept.len()).map_err(|_| StorageError::Failed)
    }

    async fn delete_relations_of_kinds(
        &mut self,
        kinds: &[AdmittedRelation],
    ) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let kept = self.working.relations.entry(realm).or_default();
        let before = kept.len();
        kept.retain(|tuple| !is_of_kinds(tuple, kinds));
        u64::try_from(before - kept.len()).map_err(|_| StorageError::Failed)
    }

    async fn insert_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
        _written_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let guards = self.working.relation_guards.entry(realm).or_default();
        let guard = (object_type.to_owned(), client_id.to_owned());
        if guards.contains(&guard) {
            return Ok(false);
        }
        guards.push(guard);
        Ok(true)
    }

    async fn delete_relation_guard(
        &mut self,
        object_type: &str,
        client_id: &str,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let guards = self.working.relation_guards.entry(realm).or_default();
        let before = guards.len();
        guards.retain(|(known_type, known_client)| {
            !(known_type == object_type && known_client == client_id)
        });
        Ok(guards.len() < before)
    }

    async fn list_relation_guards(
        &mut self,
        object_type: &str,
        most: u32,
    ) -> Result<Vec<String>, StorageError> {
        let mut clients: Vec<String> = read_realm(&self.working.relation_guards, self.realm())
            .iter()
            .filter(|(known_type, _)| known_type == object_type)
            .map(|(_, client)| client.clone())
            .collect();
        clients.sort();
        clients.truncate(usize::try_from(most).unwrap_or(usize::MAX));
        Ok(clients)
    }

    async fn list_relation_subjects(
        &mut self,
        object: &ObjectRef,
        relation: &str,
        limit: u32,
    ) -> Result<Vec<SubjectRef>, StorageError> {
        let mut subjects: Vec<SubjectRef> = read_realm(&self.working.relations, self.realm())
            .iter()
            .filter(|tuple| tuple.object == *object && tuple.relation == relation)
            .map(|tuple| tuple.subject.clone())
            .collect();
        subjects.sort();
        subjects.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(subjects)
    }
}

#[async_trait]
impl PolicyStore for MemoryUnitOfWork {
    async fn insert_policy(&mut self, policy: &Policy) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let policies = self.working.policies.entry(realm).or_default();
        if policies
            .iter()
            .any(|known| known.client_id == policy.client_id && known.name == policy.name)
        {
            return Ok(false);
        }
        policies.push(policy.clone());
        Ok(true)
    }

    async fn list_policies(&mut self, client_id: &str) -> Result<Vec<Policy>, StorageError> {
        let mut policies: Vec<Policy> = read_realm(&self.working.policies, self.realm())
            .iter()
            .filter(|policy| policy.client_id == client_id)
            .cloned()
            .collect();
        policies.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(policies)
    }

    async fn count_policies(&mut self, client_id: &str, most: u32) -> Result<u64, StorageError> {
        let kept = read_realm(&self.working.policies, self.realm())
            .iter()
            .filter(|policy| policy.client_id == client_id)
            .count();
        Ok(u64::try_from(kept).map_or(u64::from(most), |kept| kept.min(u64::from(most))))
    }

    async fn list_applicable_policies(
        &mut self,
        client_id: &str,
        resource_type: &str,
        action: &str,
    ) -> Result<Vec<Policy>, StorageError> {
        let mut policies = self.list_policies(client_id).await?;
        policies.retain(|policy| policy.resource_type == resource_type && policy.action == action);
        Ok(policies)
    }

    async fn delete_policy(&mut self, client_id: &str, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.realm();
        let policies = self.working.policies.entry(realm).or_default();
        let before = policies.len();
        policies.retain(|policy| !(policy.client_id == client_id && policy.id == id));
        Ok(policies.len() < before)
    }

    async fn lock_definitions(&mut self) -> Result<(), StorageError> {
        // One unit of work at a time: nothing else counts meanwhile.
        Ok(())
    }

    async fn has_policy_for_types(&mut self, types: &[String]) -> Result<bool, StorageError> {
        Ok(read_realm(&self.working.policies, self.realm())
            .iter()
            .any(|policy| types.contains(&policy.resource_type)))
    }

    async fn is_named_by_policy(
        &mut self,
        condition: &str,
        id: Uuid,
    ) -> Result<bool, StorageError> {
        let named = serde_json::Value::String(id.to_string());
        Ok(read_realm(&self.working.policies, self.realm())
            .iter()
            .filter_map(|policy| policy.conditions.as_array())
            .flatten()
            .any(|written| written.get(condition) == Some(&named)))
    }
}
