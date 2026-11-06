//! From the types of the core to what the administration API says.

use api::{
    ClientView, GrantView, GroupView, HeldRoleView, PolicyView, RealmView, RoleView, UserView,
};
use saffui_core::authz::grants::{Grant, HeldRole};
use saffui_core::authz::policy::Policy;
use saffui_core::authz::roles::{Group, Role};
use saffui_core::clients::Client;
use saffui_core::directory::Person;
use saffui_core::instant::write_instant;
use saffui_core::tenancy::Realm;

pub(super) fn show_realm(realm: &Realm, issuer: String) -> RealmView {
    RealmView {
        id: realm.id.as_uuid().to_string(),
        tenant_id: realm.tenant.as_uuid().to_string(),
        name: realm.name.to_string(),
        issuer,
        enabled: realm.enabled,
        created_at: write_instant(realm.created_at),
    }
}

/// A client as an administrator sees it. The digest of its secret is not
/// part of it: nothing about the secret ever leaves.
pub(super) fn show_client(client: &Client) -> ClientView {
    ClientView {
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        public: client.secret_digest.is_none(),
        redirect_uris: client.redirect_uris.clone(),
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        scopes: client.scopes.clone(),
        capabilities: client
            .capabilities
            .iter()
            .map(|granted| granted.name().to_owned())
            .collect(),
        enabled: client.enabled,
        created_at: write_instant(client.created_at),
    }
}

/// A person as an administrator sees them: nothing about their password.
pub(super) fn show_user(person: &Person) -> UserView {
    UserView {
        id: person.id.to_string(),
        username: person.username.clone(),
        email: person.email.clone(),
        email_verified: person.email_verified,
        display_name: person.display_name.clone(),
        enabled: person.enabled,
        created_at: write_instant(person.created_at),
    }
}

pub(super) fn show_role(role: &Role) -> RoleView {
    RoleView {
        id: role.id.to_string(),
        name: role.name.clone(),
        client_id: role.client_id.clone(),
        description: role.description.clone(),
        created_at: write_instant(role.created_at),
    }
}

pub(super) fn show_group(group: &Group) -> GroupView {
    GroupView {
        id: group.id.to_string(),
        name: group.name.clone(),
        description: group.description.clone(),
        created_at: write_instant(group.created_at),
    }
}

pub(super) fn show_grant(grant: &Grant) -> GrantView {
    GrantView {
        valid_from: write_instant(grant.valid_from),
        valid_until: grant.valid_until.map(write_instant),
        granted_by: grant.granted_by.clone(),
        reason: grant.reason.clone(),
        granted_at: write_instant(grant.granted_at),
    }
}

pub(super) fn show_held_role(held: &HeldRole) -> HeldRoleView {
    HeldRoleView {
        role_id: held.role.to_string(),
        name: held.name.clone(),
        client_id: held.client_id.clone(),
        through_group: held.through.map(|group| group.to_string()),
        until: held.until.map(write_instant),
    }
}

pub(super) fn show_policy(policy: &Policy) -> PolicyView {
    PolicyView {
        id: policy.id.to_string(),
        client_id: policy.client_id.clone(),
        name: policy.name.clone(),
        resource_type: policy.resource_type.clone(),
        action: policy.action.clone(),
        effect: policy.effect.name().to_owned(),
        combine: policy.combine.name().to_owned(),
        conditions: policy.conditions.clone(),
        created_at: write_instant(policy.created_at),
    }
}
