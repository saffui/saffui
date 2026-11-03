//! The discovery document. It never lies: a field is published the day the
//! realm honors it, and not before.

use serde::Serialize;

use crate::settings::Settings;
use crate::tenancy::RealmName;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    /// Where the public keys of the realm are published.
    pub jwks_uri: String,
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
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
        token_endpoint: format!("{issuer}/oauth2/token"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        grant_types_supported: vec!["client_credentials"],
        token_endpoint_auth_methods_supported: vec!["client_secret_basic", "client_secret_post"],
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
        let settings = Settings {
            public_origin: PublicOrigin::parse("https://id.example.org").expect("an origin"),
        };
        let realm = RealmName::parse("acme").expect("a realm name");

        assert_eq!(
            name_issuer(&settings, &realm),
            "https://id.example.org/realms/acme"
        );
    }

    #[test]
    fn the_keys_and_the_token_endpoint_are_published_under_the_issuer() {
        let settings = Settings {
            public_origin: PublicOrigin::parse("https://id.example.org").expect("an origin"),
        };
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
        assert_eq!(document.grant_types_supported, ["client_credentials"]);
    }
}
