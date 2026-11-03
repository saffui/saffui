//! From the types of the core to what the administration API says.

use api::{ClientView, RealmView, UserView};
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
