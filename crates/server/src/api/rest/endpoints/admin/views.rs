//! From the types of the core to what the administration API says.

use api::{
    ClientView, ConsentView, GrantView, GroupView, HeldRoleView, InitialTokenView, KeyView,
    MapperView, PolicyView, RealmSettingsView, RealmView, RoleView, UserView,
};
use saffui_core::authz::grants::{Grant, HeldRole};
use saffui_core::authz::policy::Policy;
use saffui_core::authz::roles::{Group, Role};
use saffui_core::claims::Mapper;
use saffui_core::clients::Client;
use saffui_core::clients::registration::InitialAccessToken;
use saffui_core::consent::ListedConsent;
use saffui_core::directory::Person;
use saffui_core::instant::write_instant;
use saffui_core::keys::SigningKey;
use saffui_core::tenancy::Realm;
use saffui_core::tenancy::settings::RealmSettings;

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

pub(super) fn show_realm_settings(settings: &RealmSettings) -> RealmSettingsView {
    RealmSettingsView {
        registration: settings.registration.name().to_owned(),
        registrable_scopes: settings.registrable_scopes.clone(),
        max_registered_clients: settings.max_registered_clients,
        max_redirect_uris: settings.max_redirect_uris,
        max_daily_registrations: settings.max_daily_registrations,
    }
}

/// An initial access token as an administrator sees it: never the token.
pub(super) fn show_initial_token(token: &InitialAccessToken) -> InitialTokenView {
    InitialTokenView {
        id: token.id.to_string(),
        uses_left: token.uses_left,
        expires_at: write_instant(token.expires_at),
        created_at: write_instant(token.created_at),
        created_by: token.created_by.clone(),
    }
}

/// A client as an administrator sees it. Neither the digest nor the sealed
/// form of its secret is part of it: nothing about the secret ever leaves.
pub(super) fn show_client(client: &Client) -> ClientView {
    ClientView {
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        public: client.is_public(),
        redirect_uris: client.redirect_uris.clone(),
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        response_types: client
            .response_types
            .iter()
            .map(|kind| kind.name().to_owned())
            .collect(),
        consent: client.requires_consent,
        scopes: client.scopes.clone(),
        capabilities: client
            .capabilities
            .iter()
            .map(|granted| granted.name().to_owned())
            .collect(),
        id_token_signed_response_alg: client
            .id_token_signed_response_alg
            .map(|algorithm| algorithm.name().to_owned()),
        token_endpoint_auth_method: client.auth_method.name().to_owned(),
        token_endpoint_auth_signing_alg: client
            .auth_signing_alg
            .map(|algorithm| algorithm.name().to_owned()),
        request_object_signing_alg: client
            .request_object_signing_alg
            .map(|algorithm| algorithm.name().to_owned()),
        require_signed_request_object: client.require_signed_request_object,
        enabled: client.enabled,
        created_at: write_instant(client.created_at),
    }
}

/// A key as an administrator sees it: never its private half, sealed or not.
pub(super) fn show_key(key: &SigningKey) -> KeyView {
    KeyView {
        kid: key.key_id.clone(),
        alg: key.algorithm.name().to_owned(),
        status: key.status.name().to_owned(),
        public_jwk: key.public_jwk.clone(),
        created_at: write_instant(key.created_at),
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

pub(super) fn show_consent(listed: &ListedConsent) -> ConsentView {
    ConsentView {
        client_id: listed.consent.client_id.clone(),
        scopes: listed.consent.scopes.clone(),
        granted_at: write_instant(listed.consent.granted_at),
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

pub(super) fn show_mapper(mapper: &Mapper) -> MapperView {
    MapperView {
        id: mapper.id.to_string(),
        client_id: mapper.client_id.clone(),
        name: mapper.name.clone(),
        // A closed enum of texts: it is always written.
        definition: serde_json::to_value(&mapper.kind).unwrap_or_default(),
        claim: mapper.claim.clone(),
        targets: mapper
            .targets
            .iter()
            .map(|target| target.name().to_owned())
            .collect(),
        scope: mapper.scope.clone(),
        created_at: write_instant(mapper.created_at),
    }
}
