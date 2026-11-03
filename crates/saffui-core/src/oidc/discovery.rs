//! The discovery document. It never lies: a field is published the day the
//! realm honors it, and not before.

use serde::Serialize;

use crate::ports::crypto::SignatureAlgorithm;
use crate::settings::Settings;
use crate::tenancy::RealmName;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a member of the document, named by its specification"
)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    /// Where the public keys of the realm are published.
    pub jwks_uri: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    /// Derived from the catalog of algorithms, never from a list written here.
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub authorization_response_iss_parameter_supported: bool,
    pub response_modes_supported: Vec<&'static str>,
    /// Three parameters whose absence from this document would mean yes.
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub claims_parameter_supported: bool,
}

/// The issuer of a realm: the public origin, then the realm, and nothing else.
#[must_use]
pub fn name_issuer(settings: &Settings, realm: &RealmName) -> String {
    format!("{}/realms/{realm}", settings.public_origin)
}

#[must_use]
pub fn describe_provider(settings: &Settings, realm: &RealmName) -> ProviderMetadata {
    let issuer = name_issuer(settings, realm);
    ProviderMetadata {
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        introspection_endpoint: format!("{issuer}/oauth2/introspect"),
        revocation_endpoint: format!("{issuer}/oauth2/revoke"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "client_credentials", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: SignatureAlgorithm::ALL
            .iter()
            .map(|algorithm| algorithm.name())
            .collect(),
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported: vec!["openid", "profile", "email"],
        authorization_response_iss_parameter_supported: true,
        response_modes_supported: vec!["query"],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        claims_parameter_supported: false,
        issuer,
    }
}

#[cfg(test)]
mod tests {
    use super::{describe_provider, name_issuer};
    use crate::settings::{PublicOrigin, Settings};
    use crate::tenancy::RealmName;

    #[test]
    fn the_issuer_is_the_public_origin_then_the_realm() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");

        assert_eq!(
            name_issuer(&settings, &realm),
            "https://id.example.org/realms/acme"
        );
    }

    #[test]
    fn the_keys_and_the_token_endpoint_are_published_under_the_issuer() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");

        let document = describe_provider(&settings, &realm);

        assert_eq!(
            document.jwks_uri,
            "https://id.example.org/realms/acme/oauth2/jwks"
        );
        assert_eq!(
            document.token_endpoint,
            "https://id.example.org/realms/acme/oauth2/token"
        );
        assert_eq!(
            document.authorization_endpoint,
            "https://id.example.org/realms/acme/oauth2/authorize"
        );
        assert_eq!(
            document.userinfo_endpoint,
            "https://id.example.org/realms/acme/oauth2/userinfo"
        );
        assert_eq!(
            document.grant_types_supported,
            ["authorization_code", "client_credentials", "refresh_token"]
        );
        assert_eq!(document.code_challenge_methods_supported, ["S256"]);
        assert!(
            !document.request_parameter_supported && !document.claims_parameter_supported,
            "an absent member would mean yes"
        );
    }
}
