//! Clients: what may ask for a token, and how its tokens are protected.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crypto::provider::SignAlg;

use crate::auditable::AuditableModel;
use crate::entities::attributes::AttributesMap;
use crate::entities::keys::{JweAlgorithm, JweEncryption};
use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "protocol")]
    /// The protocol a client speaks.
    pub enum Protocol {
        OpenId => "openid-connect",
        Docker => "docker",
    }
}

/// A bearer credential a client authenticates with.
///
/// A newtype so it cannot be passed where an identifier is expected, with a
/// `Debug` that renders nothing: the way a secret reaches a log is a struct
/// holding one being formatted, not anybody printing the field on purpose.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSecret(String);

impl ClientSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Read the secret. Named so that every place one is read is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// A registered JWE pair: the key-management algorithm and the content
/// encryption it goes with.
///
/// One value rather than two optional fields. The pair rule — content
/// encryption alone is not a registration, and an algorithm alone takes the
/// specified default — is a constraint two fields can only *state*, since
/// `enc` set with no `alg` is representable and means nothing. Here it cannot
/// be written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JweRegistration {
    pub alg: JweAlgorithm,
    pub enc: JweEncryption,
}

impl JweRegistration {
    /// Register `alg`, taking the specified default when no `enc` is named.
    pub fn new(alg: JweAlgorithm, enc: Option<JweEncryption>) -> Self {
        Self {
            alg,
            enc: enc.unwrap_or(JweEncryption::DEFAULT),
        }
    }
}

/// A registered client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientModel {
    pub client_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub consent_required: Option<bool>,
    pub root_url: Option<String>,
    pub web_origins: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    /// Registered post-logout redirect URIs, separate from `redirect_uris` so a
    /// logout destination is not thereby an authorization code destination.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Where a logout token is posted when a login this client took part in
    /// ends, and whether it insists on being told which session.
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    /// The same, loaded by the browser at logout instead of posted to.
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,

    /// Never serialised. The store binds it as a column; a client rendered into
    /// a response must not carry the credential that authenticates it.
    #[serde(skip_serializing)]
    pub registration_token: Option<ClientSecret>,
    #[serde(skip_serializing)]
    pub secret: Option<ClientSecret>,
    /// When the current secret was minted. `None` marks one from before the
    /// lifecycle existed; the first rotation stamps it.
    pub secret_created_at: Option<DateTime<Utc>>,
    /// When the secret stops authenticating. `None` = never expires, which is
    /// what every pre-lifecycle client keeps.
    pub secret_expires_at: Option<DateTime<Utc>>,

    /// What id tokens are signed with. None is the realm's active key, and an
    /// algorithm no key can sign fails issuance rather than downgrading.
    pub id_token_signed_response_alg: Option<SignAlg>,
    /// Signed UserInfo (Core §5.3.2): when set, `/userinfo` answers with an
    /// `application/jwt` JWS signed by a realm key of exactly this algorithm.
    pub userinfo_signed_response_alg: Option<SignAlg>,
    /// Request object signing. Registered under the same refusal rule.
    pub request_object_signing_alg: Option<SignAlg>,
    /// The keys this client signs with, as the JWKS it registered.
    pub jwks: Option<serde_json::Value>,

    /// When set, the id token is encrypted to the client's registered key. Failing
    /// to encrypt fails issuance rather than answering in the clear.
    pub id_token_encryption: Option<JweRegistration>,
    /// When set, `/userinfo` returns a JWE of the claims rather than JSON.
    pub userinfo_encryption: Option<JweRegistration>,
    /// When set, this client's request objects must arrive encrypted with
    /// exactly this pair; a plaintext one from such a client is refused.
    pub request_object_encryption: Option<JweRegistration>,

    pub protocol: Option<Protocol>,
    pub public_client: Option<bool>,
    pub client_authenticator_type: Option<String>,
    pub full_scope_allowed: Option<bool>,
    pub authorization_code_flow_enabled: Option<bool>,
    pub implicit_flow_enabled: Option<bool>,
    pub direct_access_grants_enabled: Option<bool>,
    pub standard_flow_enabled: Option<bool>,
    pub bearer_only: Option<bool>,
    pub front_channel_logout: Option<bool>,
    pub is_surrogate_auth_required: Option<bool>,
    pub not_before: Option<i32>,
    pub configs: Option<AttributesMap>,
    pub service_account_enabled: Option<bool>,
    pub auth_flow_binding_overrides: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

/// The create payload: what a caller may name, which is deliberately little.
///
/// Everything a client is trusted for — its redirect URIs, its flows, its
/// signing and encryption registrations — is set afterwards by an admin who has
/// the capability for it, rather than by whoever posts the creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCreateModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
}

impl ClientCreateModel {
    /// Build a client from the payload. The caller supplies the identifiers and
    /// the audit record, both of which come from the request context.
    pub fn into_model(
        self,
        client_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ClientModel {
        ClientModel {
            client_id,
            realm_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            consent_required: None,
            root_url: None,
            web_origins: None,
            redirect_uris: None,
            post_logout_redirect_uris: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            registration_token: None,
            secret: None,
            secret_created_at: None,
            secret_expires_at: None,
            id_token_signed_response_alg: None,
            userinfo_signed_response_alg: None,
            request_object_signing_alg: None,
            jwks: None,
            id_token_encryption: None,
            userinfo_encryption: None,
            request_object_encryption: None,
            protocol: None,
            public_client: None,
            client_authenticator_type: None,
            full_scope_allowed: None,
            implicit_flow_enabled: None,
            authorization_code_flow_enabled: None,
            direct_access_grants_enabled: None,
            standard_flow_enabled: None,
            bearer_only: None,
            front_channel_logout: None,
            is_surrogate_auth_required: None,
            not_before: None,
            configs: None,
            service_account_enabled: None,
            auth_flow_binding_overrides: None,
            metadata,
        }
    }
}

/// A named set of claims a client may ask for.
///
/// The roles and protocol mappers attached to a scope are *not* fields here.
/// This is loaded on the token issuance path, where a join per scope is paid on
/// every request, and a field that is populated for one caller and absent for
/// every other stops meaning anything. What is attached is read by whoever
/// needs the attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientScopeModel {
    pub client_scope_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub protocol: Protocol,
    pub default_scope: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

/// The create and update payload for a scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientScopeMutationModel {
    pub name: String,
    pub description: String,
    pub protocol: Protocol,
    pub default_scope: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl ClientScopeMutationModel {
    pub fn into_model(
        self,
        client_scope_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ClientScopeModel {
        ClientScopeModel {
            client_scope_id,
            realm_id,
            name: self.name,
            description: self.description,
            protocol: self.protocol,
            default_scope: self.default_scope,
            configs: self.configs,
            metadata,
        }
    }
}

/// A rule turning something the server knows into a claim in a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMapperModel {
    pub mapper_id: String,
    pub realm_id: String,
    pub name: String,
    pub protocol: Protocol,
    pub mapper_type: String,
    pub configs: Option<AttributesMap>,
    pub metadata: AuditableModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMapperMutationModel {
    pub name: String,
    pub protocol: Protocol,
    pub mapper_type: String,
    pub configs: Option<AttributesMap>,
}

impl ProtocolMapperMutationModel {
    pub fn into_model(
        self,
        mapper_id: String,
        realm_id: String,
        metadata: AuditableModel,
    ) -> ProtocolMapperModel {
        ProtocolMapperModel {
            mapper_id,
            realm_id,
            name: self.name,
            protocol: self.protocol,
            mapper_type: self.mapper_type,
            configs: self.configs,
            metadata,
        }
    }
}

/// A client as an export carries it: the row, plus what it is attached to.
///
/// Identifiers rather than entities. A realm export already carries its roles,
/// its scopes and its mappers as sections of the document, so repeating them
/// here would leave an importer with two sources that can disagree. What the
/// document is missing is only the *attachment*, so that is what this holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientExport {
    pub client: ClientModel,
    /// Roles this client owns. Empty means it owns none — an export always
    /// populates this, so absence is never ambiguity.
    pub roles: Vec<String>,
    /// Scopes attached to it. Without these a restored client emits none of the
    /// mapped claims its scopes carry.
    pub client_scopes: Vec<String>,
    /// Mappers attached to the client directly, as opposed to those it inherits
    /// through a scope.
    pub protocol_mappers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    fn client() -> ClientModel {
        ClientCreateModel {
            name: "app".into(),
            display_name: "App".into(),
            description: String::new(),
            enabled: Some(true),
        }
        .into_model(
            "client-1".into(),
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        )
    }

    #[test]
    fn the_protocols_agree_with_their_own_spelling() {
        assert_eq!(Protocol::ALL.len(), 2);
        assert_eq!(Protocol::OpenId.as_str(), "openid-connect");
        assert_eq!(Protocol::Docker.as_str(), "docker");
        assert_round_trips(Protocol::ALL);
    }

    /// Every declared protocol parses. A parser that knew only one of them
    /// would leave the other unreadable from any stored row, which is worse
    /// than not offering it.
    #[test]
    fn every_protocol_can_be_named_in_both_directions() {
        for protocol in Protocol::ALL {
            assert_eq!(Protocol::from_str(protocol.as_str()).unwrap(), *protocol);
            assert!(!protocol.to_string().is_empty());
        }
        assert!(Protocol::from_str("saml").is_err());
        assert!(Protocol::from_str("").is_err());
    }

    /// Content encryption alone is not a registration, so it cannot be held
    /// without an algorithm — and an algorithm alone takes the specified
    /// default rather than nothing.
    #[test]
    fn a_registration_always_carries_both_halves() {
        let defaulted = JweRegistration::new(JweAlgorithm::RsaOaep256, None);
        assert_eq!(defaulted.alg, JweAlgorithm::RsaOaep256);
        assert_eq!(defaulted.enc, JweEncryption::DEFAULT);

        let named = JweRegistration::new(JweAlgorithm::EcdhEs, Some(JweEncryption::A256Gcm));
        assert_eq!(named.enc, JweEncryption::A256Gcm);
    }

    /// A registration survives the wire as one value, so a stored row cannot
    /// come back holding half of it.
    #[test]
    fn a_registration_round_trips_as_one_value() {
        let registration = JweRegistration::new(JweAlgorithm::RsaOaep, None);
        let encoded = serde_json::to_string(&registration).unwrap();
        assert_eq!(
            serde_json::from_str::<JweRegistration>(&encoded).unwrap(),
            registration
        );
        assert!(
            serde_json::from_str::<JweRegistration>(r#"{"enc":"A128GCM"}"#).is_err(),
            "content encryption alone is not a registration"
        );
    }

    /// A created client is trusted with nothing it was not granted: no
    /// redirect URIs, no flows, no secret.
    #[test]
    fn a_created_client_carries_no_grant_it_was_not_given() {
        let client = client();
        assert_eq!(client.client_id, "client-1");
        assert_eq!(client.realm_id, "realm-1");
        assert_eq!(client.metadata.tenant, "acme");
        assert_eq!(client.redirect_uris, None);
        assert_eq!(client.post_logout_redirect_uris, None);
        assert_eq!(client.secret, None);
        assert_eq!(client.registration_token, None);
        assert_eq!(client.id_token_signed_response_alg, None);
        assert_eq!(client.id_token_encryption, None);
        assert_eq!(client.standard_flow_enabled, None);
        assert_eq!(client.service_account_enabled, None);
    }

    /// The two bearer credentials never reach a rendered client. The store
    /// binds them as columns; a response is not where they belong.
    #[test]
    fn a_rendered_client_carries_neither_credential() {
        let client = ClientModel {
            secret: Some(ClientSecret::new("s3cr3t-value".into())),
            registration_token: Some(ClientSecret::new("reg-t0ken".into())),
            ..client()
        };

        let json = serde_json::to_string(&client).unwrap();
        assert!(
            !json.contains("s3cr3t-value"),
            "the secret was rendered: {json}"
        );
        assert!(
            !json.contains("reg-t0ken"),
            "the token was rendered: {json}"
        );
        assert!(json.contains("client-1"), "the rest still renders");
    }

    /// The other way a credential escapes is a log line, and that one happens
    /// by formatting a struct rather than by printing the field.
    #[test]
    fn debug_renders_neither_credential() {
        let secret = ClientSecret::new("s3cr3t-value".into());
        assert_eq!(format!("{secret:?}"), "ClientSecret(<redacted>)");
        assert_eq!(secret.expose(), "s3cr3t-value");

        let client = ClientModel {
            secret: Some(secret),
            registration_token: Some(ClientSecret::new("reg-t0ken".into())),
            ..client()
        };
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("s3cr3t-value"), "{rendered}");
        assert!(!rendered.contains("reg-t0ken"), "{rendered}");
        assert!(rendered.contains("client-1"));
    }

    /// A payload may still carry a secret inwards — that is how one is set —
    /// so only the rendering is one-way.
    #[test]
    fn a_credential_can_still_be_read_from_a_payload() {
        let parsed: ClientSecret = serde_json::from_str("\"s3cr3t-value\"").unwrap();
        assert_eq!(parsed.expose(), "s3cr3t-value");
    }

    /// A scope and a mapper take their identifiers and their audit record from
    /// the caller, for the same reason a client does.
    #[test]
    fn a_scope_and_a_mapper_are_built_from_the_context_not_the_payload() {
        let scope = ClientScopeMutationModel {
            name: "profile".into(),
            description: "Basic profile".into(),
            protocol: Protocol::OpenId,
            default_scope: Some(true),
            configs: None,
        }
        .into_model(
            "scope-1".into(),
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        );
        assert_eq!(scope.client_scope_id, "scope-1");
        assert_eq!(scope.realm_id, "realm-1");
        assert_eq!(scope.metadata.tenant, "acme");
        assert_eq!(scope.protocol, Protocol::OpenId);

        let mapper = ProtocolMapperMutationModel {
            name: "email".into(),
            protocol: Protocol::OpenId,
            mapper_type: "oidc-usermodel-property-mapper".into(),
            configs: None,
        }
        .into_model(
            "mapper-1".into(),
            "realm-1".into(),
            AuditableModel::unassigned(),
        );
        assert_eq!(mapper.mapper_id, "mapper-1");
        assert_eq!(mapper.realm_id, "realm-1");
        assert_eq!(mapper.mapper_type, "oidc-usermodel-property-mapper");
    }

    /// An export carries attachments and no credential: it is written to a file
    /// an operator moves between deployments.
    #[test]
    fn an_export_carries_attachments_and_still_no_credential() {
        let export = ClientExport {
            client: ClientModel {
                secret: Some(ClientSecret::new("s3cr3t-value".into())),
                ..client()
            },
            roles: vec!["admin".into()],
            client_scopes: vec!["profile".into()],
            protocol_mappers: vec!["email".into()],
        };

        let json = serde_json::to_string(&export).unwrap();
        assert!(
            !json.contains("s3cr3t-value"),
            "an export leaked a secret: {json}"
        );
        assert!(json.contains("admin") && json.contains("profile") && json.contains("email"));
    }
}
