//! What the administrative plane puts on the wire.
//!
//! A shape of its own wherever the stored record would say too much. Answering
//! with the row carries every switch an entity has, and adding a column then
//! widens a public response without anybody deciding to.

use serde::{Deserialize, Serialize};

/// A realm as a listing shows it.
///
/// Its own shape rather than the stored record. A listing that answered with
/// the row would carry every switch a realm has, and adding a column to the
/// table would silently widen a public response.
#[derive(Debug, Serialize)]
pub struct RealmBrief {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl From<models::entities::realm::RealmModel> for RealmBrief {
    fn from(realm: models::entities::realm::RealmModel) -> Self {
        RealmBrief {
            realm_id: realm.realm_id,
            name: realm.name,
            display_name: realm.display_name,
            enabled: realm.enabled,
        }
    }
}

/// A key as a listing shows it: enough to recognise and revoke, never the
/// stored credential. The public key stays home; a response is not an export.
#[derive(Debug, Serialize)]
pub struct KeyBrief {
    /// base64url without padding of the raw identifier, the spelling the
    /// export format and the revocation path both use.
    pub credential_id: String,
    pub label: String,
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A login as the plane shows it. The agent is given both as it arrived and as
/// this build reads it, so a caller that disagrees with the reading has the
/// string to read for itself.
#[derive(Debug, Serialize)]
pub struct SessionBrief {
    pub session_id: String,
    pub auth_method: Option<String>,
    pub ip_address: Option<String>,
    pub browser: Option<&'static str>,
    pub system: Option<&'static str>,
    pub mobile: bool,
    pub user_agent: Option<String>,
    pub started_at: i64,
    pub auth_time: Option<i64>,
    pub expiration: Option<i64>,
    /// What each client got out of this login, which is what a revocation
    /// names. The offline ones are the grants that outlive the login itself.
    pub grants: Vec<GrantBrief>,
}

#[derive(Debug, Serialize)]
pub struct GrantBrief {
    pub client_id: String,
    pub offline: bool,
    pub expiration: Option<i64>,
}

/// A client as the plane shows it. Never its secret: that is shown once,
/// when it is made, and by its own response.
#[derive(Debug, Serialize)]
pub struct ClientBrief {
    pub client_id: String,
    pub name: String,
    pub enabled: bool,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
}

impl From<models::entities::client::ClientModel> for ClientBrief {
    fn from(client: models::entities::client::ClientModel) -> Self {
        ClientBrief {
            client_id: client.client_id,
            name: client.name,
            enabled: client.enabled.unwrap_or(false),
            confidential: client.public_client != Some(true),
            redirect_uris: client.redirect_uris.unwrap_or_default(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.unwrap_or_default(),
        }
    }
}

/// A person as the plane shows them. Never a credential.
#[derive(Debug, Serialize)]
pub struct UserBrief {
    pub user_id: String,
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: bool,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub phone_number: Option<String>,
    pub required_actions: Vec<models::entities::user::RequiredAction>,
}

impl From<models::entities::user::UserModel> for UserBrief {
    fn from(user: models::entities::user::UserModel) -> Self {
        use models::entities::attributes::string_at;
        use models::entities::user::profile;
        let named = |key: &str| {
            user.attributes
                .as_ref()
                .and_then(|held| string_at(held, key))
                .map(str::to_owned)
        };
        UserBrief {
            given_name: named(profile::FIRST_NAME),
            family_name: named(profile::LAST_NAME),
            user_id: user.user_id,
            user_name: user.user_name,
            enabled: user.enabled,
            email: user.email,
            email_verified: user.email_verified.unwrap_or(false),
            phone_number: user.phone_number,
            required_actions: user.required_actions.unwrap_or_default(),
        }
    }
}

/// What the plane is asked to register or reshape a client as.
#[derive(Debug, Deserialize)]
pub struct ClientSpec {
    pub client_id: Option<String>,
    pub name: Option<String>,
    pub confidential: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
}

/// What the plane is asked to create or reshape a person as.
#[derive(Debug, Deserialize)]
pub struct UserSpec {
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub enabled: Option<bool>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub phone_number: Option<String>,
    pub required_actions: Option<Vec<models::entities::user::RequiredAction>>,
    pub attributes: Option<std::collections::BTreeMap<String, String>>,
    /// On creation only: what they first sign in with.
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordSpec {
    pub password: String,
}
