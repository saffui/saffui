//! What the administration API says and hears, written once. The server
//! answers with these types and the command line reads them: a field renamed
//! on one side alone does not compile on the other.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A list, and the window it was cut by. `total` is present only when asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub first: u32,
    pub max: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub issuer: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientView {
    pub client_id: String,
    pub name: String,
    /// Without a secret: an application that runs where none can be kept.
    pub public: bool,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// What it may ask the authorization endpoint to hand back.
    pub response_types: Vec<String>,
    /// Whether each person is asked before it gets a code in their name.
    pub consent: bool,
    pub scopes: Vec<String>,
    pub capabilities: Vec<String>,
    /// The algorithm of its identity tokens. Null: the default of the realm.
    pub id_token_signed_response_alg: Option<String>,
    /// How it proves itself, by the name RFC 7591 gives it.
    pub token_endpoint_auth_method: String,
    /// The one algorithm its assertions are signed in. Null: any it may.
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// A client to create. A field this version does not know is refused: a
/// request that asks for more than it gets must not look accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewClient {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Where people may be sent back. Given, the client is an application
    /// that signs people in, and holds no capability.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Where people may be sent after they sign out.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// What it may ask the authorization endpoint to hand back, each named
    /// once. Empty: a code alone. One with `token` puts an access token in
    /// an address the browser holds: it is named here or nowhere.
    #[serde(default)]
    pub response_types: Vec<String>,
    /// An application that runs where no secret can be kept: it gets none.
    #[serde(default)]
    pub public: bool,
    /// Whether each person is asked before it gets a code in their name.
    #[serde(default)]
    pub consent: bool,
    /// The algorithm of its identity tokens, among those the realm signs in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    /// A public client is `none` and nothing else, and `none` is for it alone;
    /// another names its method, `client_secret_basic` when it names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// The public keys of a client that proves itself with a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    /// Refused: a client gives its keys inline, in `jwks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The one algorithm its assertions may be signed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
}

/// A client that was just created, with the one showing of its secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedClient {
    pub client: ClientView,
    /// Absent for a public application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

// Written by hand: a derived `Debug` would print the secret.
impl fmt::Debug for CreatedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("client", &self.client)
            .field("client_secret", &"..")
            .finish()
    }
}

/// How a client presents its secret from now on: in the Basic scheme or in
/// the form, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAuthMethod {
    pub token_endpoint_auth_method: String,
}

/// The new secret of a client, shown this once.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatedSecret {
    pub client_secret: String,
}

// Written by hand: a derived `Debug` would print the secret.
impl fmt::Debug for RotatedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotatedSecret")
            .field("client_secret", &"..")
            .finish()
    }
}

/// A person, as an administrator sees them. Nothing about a password is
/// ever part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// A person to create. The password, when given, is a first password the
/// administrator hands over: it is hashed on arrival and kept nowhere else.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewUser {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

// Written by hand: a derived `Debug` would print the password.
impl fmt::Debug for NewUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("display_name", &self.display_name)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .finish()
    }
}

/// The verdict on the audit chain of a realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    pub intact: bool,
    /// How many events were verified before the end or the break.
    pub events: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleView {
    pub id: String,
    pub name: String,
    /// The client the role is said to. Null for a role of the realm.
    pub client_id: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRole {
    pub name: String,
    /// Absent, the role is a role of the realm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewGroup {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// How long a grant or a membership stands, and why. Instants are written in
/// RFC 3339. Left out, it starts now and stands until it is taken away.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTerms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A grant or a membership as it was kept. A start asked in the past is
/// the instant it was made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub granted_by: String,
    pub reason: Option<String>,
    pub granted_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyView {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub resource_type: String,
    pub action: String,
    /// `permit` or `deny`.
    pub effect: String,
    /// `all` or `any`.
    pub combine: String,
    pub conditions: serde_json::Value,
    pub created_at: String,
}

/// A policy to write for a client that guards resources.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewPolicy {
    pub name: String,
    pub resource_type: String,
    pub action: String,
    /// `permit` or `deny`.
    pub effect: String,
    /// `all` or `any`. Left out, every condition must hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combine: Option<String>,
    pub conditions: serde_json::Value,
}

/// A mapper of a client: what its tokens say beyond their scopes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MapperView {
    pub id: String,
    pub client_id: String,
    pub name: String,
    /// The kind and its settings, as `{"kind": "attribute", "attribute": "department"}`.
    pub definition: serde_json::Value,
    pub claim: Option<String>,
    /// Among `access_token`, `id_token` and `userinfo`.
    pub targets: Vec<String>,
    /// The scope a grant must carry for it to apply. An audience without one
    /// applies to every grant; a mapper about the person names one, or says nothing.
    pub scope: Option<String>,
    pub created_at: String,
}

/// A mapper to give a client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewMapper {
    pub name: String,
    pub definition: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    pub targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// A signing key of a realm: its public half and whether it still signs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyView {
    pub kid: String,
    pub alg: String,
    /// `active` signs and verifies, `retired` only verifies.
    pub status: String,
    pub public_jwk: serde_json::Value,
    pub created_at: String,
}

/// A key to make: it replaces the active key of its algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewKey {
    pub alg: String,
}

/// The attributes of a person a caller reaches, read and replaced whole.
/// Those whose name starts with `policy.` are read with `policy:read`,
/// written with `policy:write`, and taken away only by a caller that holds both.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attributes {
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSchemaView {
    pub source: String,
    pub types: Vec<String>,
    pub written_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRelationSchema {
    pub source: String,
}

/// A fault of a schema of relations, at the line it is on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaFaultView {
    pub line: usize,
    pub message: String,
}

/// What a person allowed a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentView {
    pub client_id: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
}

/// A role a person holds now, by one way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldRoleView {
    pub role_id: String,
    pub name: String,
    pub client_id: Option<String>,
    /// The group it comes through. Null when it was granted to the person.
    pub through_group: Option<String>,
    /// When this way ends. Null when it does not.
    pub until: Option<String>,
}

/// How a realm lets clients register themselves through the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmSettingsView {
    /// `closed`, `initial_token` or `open`.
    pub registration: String,
    pub registrable_scopes: Vec<String>,
    pub max_registered_clients: u32,
    /// Of each kind: where a person is sent back, and after signing out.
    pub max_redirect_uris: u32,
    pub max_daily_registrations: u32,
}

/// The settings of registration, written whole: a bound left out is its default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRealmSettings {
    /// `closed`, `initial_token` or `open`.
    pub registration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrable_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_registered_clients: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_redirect_uris: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_daily_registrations: Option<u32>,
}

/// An initial access token as an administrator sees it: never the token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialTokenView {
    pub id: String,
    pub uses_left: u32,
    pub expires_at: String,
    pub created_at: String,
    pub created_by: String,
}

/// An initial access token to make: for how many registrations, and for how
/// many seconds from now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewInitialToken {
    pub uses: u32,
    pub expires_in: i64,
}

/// An initial access token that was just made, with the one showing of it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedInitialToken {
    #[serde(flatten)]
    pub view: InitialTokenView,
    pub initial_access_token: String,
}

// Written by hand: a derived `Debug` would print the token.
impl fmt::Debug for CreatedInitialToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedInitialToken")
            .field("view", &self.view)
            .field("initial_access_token", &"..")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientView, CreatedClient, CreatedInitialToken, InitialTokenView, NewUser, RotatedSecret,
    };

    #[test]
    fn a_created_client_does_not_print_its_secret() {
        let created = CreatedClient {
            client: ClientView {
                client_id: "billing".to_owned(),
                name: "Billing".to_owned(),
                public: false,
                redirect_uris: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                response_types: vec!["code".to_owned()],
                consent: false,
                scopes: Vec::new(),
                capabilities: Vec::new(),
                id_token_signed_response_alg: None,
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                token_endpoint_auth_signing_alg: None,
                enabled: true,
                created_at: "2026-10-31T00:00:00Z".to_owned(),
            },
            client_secret: Some("hunter2".to_owned()),
        };

        let printed = format!("{created:?}");

        assert!(printed.contains("billing"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[test]
    fn a_turned_over_secret_does_not_print() {
        let rotated = RotatedSecret {
            client_secret: "hunter2".to_owned(),
        };

        let printed = format!("{rotated:?}");

        assert!(printed.contains("RotatedSecret"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[test]
    fn a_made_initial_token_does_not_print() {
        let created = CreatedInitialToken {
            view: InitialTokenView {
                id: "0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69".to_owned(),
                uses_left: 1,
                expires_at: "2026-11-25T00:00:00Z".to_owned(),
                created_at: "2026-11-24T00:00:00Z".to_owned(),
                created_by: "operator".to_owned(),
            },
            initial_access_token: "hunter2".to_owned(),
        };

        let printed = format!("{created:?}");

        assert!(printed.contains("operator"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[test]
    fn a_person_to_create_does_not_print_their_password() {
        let wanted = NewUser {
            username: "ada".to_owned(),
            email: None,
            display_name: None,
            password: Some("hunter2".to_owned()),
        };

        let printed = format!("{wanted:?}");

        assert!(printed.contains("ada"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
