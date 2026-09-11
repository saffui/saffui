use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKeyConfiguration {
    pub authentication_method: String,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub id_token_signed_response_alg: Option<crypto::provider::SignAlg>,
    pub userinfo_signed_response_alg: Option<crypto::provider::SignAlg>,
    pub request_object_signing_alg: Option<crypto::provider::SignAlg>,
    pub token_endpoint_auth_signing_alg: Option<crypto::provider::SignAlg>,
    pub id_token_encryption: Option<models::entities::client::JweRegistration>,
    pub userinfo_encryption: Option<models::entities::client::JweRegistration>,
    pub request_object_encryption: Option<models::entities::client::JweRegistration>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientKeyCapabilities {
    /// What the realm can sign a response to this client with: the algorithms
    /// of its active keys, the only ones issuance will use.
    pub response_signing_algorithms: Vec<crypto::provider::SignAlg>,
    /// What the client may sign its own requests and assertions with.
    pub client_signing_algorithms: Vec<crypto::provider::SignAlg>,
    pub encryption_algorithms: Vec<models::entities::keys::JweAlgorithm>,
    pub encryption_methods: Vec<models::entities::keys::JweEncryption>,
}

impl From<ClientKeyConfiguration> for services::admin::clients::KeyConfiguration {
    fn from(configuration: ClientKeyConfiguration) -> Self {
        Self {
            authentication_method: configuration.authentication_method,
            jwks: configuration.jwks,
            jwks_uri: configuration.jwks_uri,
            id_token_signed_response_alg: configuration.id_token_signed_response_alg,
            userinfo_signed_response_alg: configuration.userinfo_signed_response_alg,
            request_object_signing_alg: configuration.request_object_signing_alg,
            token_endpoint_auth_signing_alg: configuration.token_endpoint_auth_signing_alg,
            id_token_encryption: configuration.id_token_encryption,
            userinfo_encryption: configuration.userinfo_encryption,
            request_object_encryption: configuration.request_object_encryption,
        }
    }
}

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

/// A login as a realm-wide listing shows it.
///
/// Names who it belongs to, which the per-user listing never has to, and
/// carries no grants: a page over every login in a realm cannot pay a query per
/// row to decorate rows nobody has narrowed down yet.
#[derive(Debug, Serialize)]
pub struct RealmSessionBrief {
    pub session_id: String,
    pub user_id: String,
    /// The name typed at the door, which is what an operator scanning a list
    /// recognises. The identifier beside it is what everything else addresses.
    pub login_username: String,
    pub auth_method: Option<String>,
    pub ip_address: Option<String>,
    pub browser: Option<&'static str>,
    pub system: Option<&'static str>,
    pub started_at: i64,
    pub auth_time: Option<i64>,
    pub expiration: Option<i64>,
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
    pub root_url: Option<String>,
    pub web_origins: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub description: String,
    pub client_uri: Option<String>,
    /// The grants held by an operator's say-so, read back off the same bag the
    /// engines read, so a console shows what the engines will do rather than
    /// what somebody meant to say.
    pub device_grant: bool,
    pub token_exchange: bool,
    /// `off`, `poll` or `ping`.
    pub ciba_delivery: String,
    pub ciba_notification_endpoint: Option<String>,
    /// The client-wide cut: tokens minted before this instant are refused.
    pub not_before: Option<i32>,
    /// RFC 8705's one name, whichever of the three forms holds it. At most
    /// one is ever set: the verifier refuses a plural bag.
    pub tls_san_dns: Option<String>,
    pub tls_san_uri: Option<String>,
    pub tls_subject_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_configuration: Option<ClientKeyConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_capabilities: Option<ClientKeyCapabilities>,
}

impl From<models::entities::client::ClientModel> for ClientBrief {
    fn from(client: models::entities::client::ClientModel) -> Self {
        // The gates are read off the bag by the same functions the engines use,
        // so the console can never disagree with them.
        let held = client.clone();
        ClientBrief {
            client_id: client.client_id,
            name: client.name,
            enabled: client.enabled.unwrap_or(false),
            not_before: client.not_before,
            confidential: client.public_client != Some(true),
            root_url: client.root_url,
            web_origins: client.web_origins.unwrap_or_default(),
            redirect_uris: client.redirect_uris.unwrap_or_default(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.unwrap_or_default(),
            backchannel_logout_uri: client.backchannel_logout_uri,
            frontchannel_logout_uri: client.frontchannel_logout_uri,
            description: client.description,
            client_uri: client.client_uri,
            device_grant: services::device::allows_device(&held),
            token_exchange: matches!(
                bag(&held, services::grant::EXCHANGE_FLAG).as_deref(),
                Some("true")
            ),
            ciba_delivery: match services::ciba::delivery_of(&held) {
                Some(services::ciba::Delivery::Poll) => "poll".to_owned(),
                Some(services::ciba::Delivery::Ping { .. }) => "ping".to_owned(),
                None => "off".to_owned(),
            },
            ciba_notification_endpoint: bag(&held, services::ciba::NOTIFICATION_ENDPOINT_FLAG),
            tls_san_dns: bag(&held, "tls.san_dns"),
            tls_san_uri: bag(&held, "tls.san_uri"),
            tls_subject_dn: bag(&held, "tls.subject_dn"),
            key_configuration: None,
            key_capabilities: None,
        }
    }
}

impl ClientBrief {
    pub fn with_key_details(
        client: models::entities::client::ClientModel,
        response_signing_algorithms: Vec<crypto::provider::SignAlg>,
    ) -> Self {
        let key_configuration = ClientKeyConfiguration {
            authentication_method: if client.public_client == Some(true) {
                "none".to_owned()
            } else {
                client
                    .client_authenticator_type
                    .clone()
                    .unwrap_or_else(|| "client-secret".to_owned())
            },
            jwks: client.jwks.clone().filter(|_| client.jwks_uri.is_none()),
            jwks_uri: client.jwks_uri.clone(),
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            userinfo_signed_response_alg: client.userinfo_signed_response_alg,
            request_object_signing_alg: client.request_object_signing_alg,
            token_endpoint_auth_signing_alg: client.token_endpoint_auth_signing_alg,
            id_token_encryption: client.id_token_encryption,
            userinfo_encryption: client.userinfo_encryption,
            request_object_encryption: client.request_object_encryption,
        };
        let key_capabilities = ClientKeyCapabilities {
            response_signing_algorithms,
            client_signing_algorithms: crypto::provider::SignAlg::ALL.to_vec(),
            encryption_algorithms: models::entities::keys::JweAlgorithm::ALL.to_vec(),
            encryption_methods: models::entities::keys::JweEncryption::ALL.to_vec(),
        };
        let mut brief = Self::from(client);
        brief.key_configuration = Some(key_configuration);
        brief.key_capabilities = Some(key_capabilities);
        brief
    }
}

/// One string off a client's own bag.
fn bag(client: &models::entities::client::ClientModel, key: &str) -> Option<String> {
    client
        .configs
        .as_ref()
        .and_then(|held| held.get(key))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        .map(str::to_owned)
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
    pub created_at: Option<String>,
    /// Where the account's truth lives: local, or a federated directory.
    pub origin: Option<String>,
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
            created_at: user.metadata.created_at.map(|at| at.to_rfc3339()),
            origin: user.user_storage.map(|held| held.as_str().to_owned()),
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
    pub root_url: Option<String>,
    pub web_origins: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    pub description: Option<String>,
    /// The client's home page. Named `client_uri` after the registration
    /// metadata it is, rather than after the label a console puts on it.
    pub client_uri: Option<String>,
    /// The grants held by an operator's say-so. Absent leaves each as it is.
    pub device_grant: Option<bool>,
    pub token_exchange: Option<bool>,
    /// One of `off`, `poll`, `ping`. Anything else is refused rather than read
    /// as the nearest thing.
    pub ciba_delivery: Option<String>,
    pub ciba_notification_endpoint: Option<String>,
    /// Cut every token this client was minted before this instant; 0 lifts
    /// the cut, absent leaves it alone. The future is refused at the door.
    pub not_before: Option<i32>,
    /// RFC 8705's one name. Name at most one; a named empty string turns
    /// certificate authentication off, absent leaves the standing name.
    pub tls_san_dns: Option<String>,
    pub tls_san_uri: Option<String>,
    pub tls_subject_dn: Option<String>,
    pub key_configuration: Option<ClientKeyConfiguration>,
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
    /// Whether the person must replace it at their next sign-in.
    #[serde(default)]
    pub temporary: bool,
}
