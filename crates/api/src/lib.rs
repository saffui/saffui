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
    pub scopes: Vec<String>,
    pub capabilities: Vec<String>,
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
    /// An application that runs where no secret can be kept: it gets none.
    #[serde(default)]
    pub public: bool,
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

#[cfg(test)]
mod tests {
    use super::{ClientView, CreatedClient, NewUser};

    #[test]
    fn a_created_client_does_not_print_its_secret() {
        let created = CreatedClient {
            client: ClientView {
                client_id: "billing".to_owned(),
                name: "Billing".to_owned(),
                public: false,
                redirect_uris: Vec::new(),
                scopes: Vec::new(),
                capabilities: Vec::new(),
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
