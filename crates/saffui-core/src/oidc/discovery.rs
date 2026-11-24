//! The discovery document. It never lies: a field is published the day the
//! realm honors it, and not before.

use serde::Serialize;

use super::token::OFFLINE_ACCESS_SCOPE;
use crate::app::App;
use crate::clients::{AssertionAlgorithm, ClientAuthMethod};
use crate::error::Failure;
use crate::keys::rotate::list_active_algorithms;
use crate::login::assurance::Assurance;
use crate::ports::crypto::SignatureAlgorithm;
use crate::settings::Settings;
use crate::tenancy::RealmName;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::settings::{RegistrationPolicy, read_settings_closed};

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
    pub end_session_endpoint: String,
    /// Published only while the realm lets clients register themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    /// The algorithms the realm has an active key of: derived from its keys,
    /// never from a list written here.
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// What an assertion of a client may be signed in: its secret, or a key
    /// of a signature this build serves. The same at each endpoint.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    /// Only a confidential client is told what a token says.
    pub introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    /// What `acr` may say: the levels a sign-in can reach.
    pub acr_values_supported: Vec<&'static str>,
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

/// The discovery document of a realm, with the algorithms its keys sign in
/// and those this build verifies the keys of clients in.
///
/// # Errors
///
/// Returns [`crate::error::ErrorCode::RealmNotFound`] or the storage failure.
pub async fn read_provider_metadata(app: &App, realm: &str) -> Result<ProviderMetadata, Failure> {
    let (name, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let keys = work.list_signing_keys().await?;
    let signing = list_active_algorithms(app.signer.as_ref(), &keys);
    let verifying: Vec<SignatureAlgorithm> = SignatureAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| app.signer.signs_in(*algorithm))
        .collect();
    let settings = read_settings_closed(work.read_realm_settings().await?);
    let mut document = describe_provider(&app.settings, &name, &signing, &verifying);
    if settings.registration != RegistrationPolicy::Closed {
        document.registration_endpoint = Some(format!("{}/oauth2/register", document.issuer));
    }
    Ok(document)
}

#[must_use]
pub fn describe_provider(
    settings: &Settings,
    realm: &RealmName,
    signing: &[SignatureAlgorithm],
    verifying: &[SignatureAlgorithm],
) -> ProviderMetadata {
    let issuer = name_issuer(settings, realm);
    let methods = ClientAuthMethod::ALL.map(ClientAuthMethod::name).to_vec();
    let confidential: Vec<&'static str> = ClientAuthMethod::ALL
        .into_iter()
        .filter(|method| *method != ClientAuthMethod::None)
        .map(ClientAuthMethod::name)
        .collect();
    let assertion_algorithms: Vec<&'static str> = [AssertionAlgorithm::Hs256]
        .into_iter()
        .chain(verifying.iter().copied().map(AssertionAlgorithm::Signed))
        .map(AssertionAlgorithm::name)
        .collect();
    ProviderMetadata {
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        userinfo_endpoint: format!("{issuer}/oauth2/userinfo"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        introspection_endpoint: format!("{issuer}/oauth2/introspect"),
        revocation_endpoint: format!("{issuer}/oauth2/revoke"),
        end_session_endpoint: format!("{issuer}/oauth2/logout"),
        registration_endpoint: None,
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "client_credentials", "refresh_token"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: signing
            .iter()
            .map(|algorithm| algorithm.name())
            .collect(),
        token_endpoint_auth_methods_supported: methods.clone(),
        token_endpoint_auth_signing_alg_values_supported: assertion_algorithms.clone(),
        introspection_endpoint_auth_methods_supported: confidential,
        introspection_endpoint_auth_signing_alg_values_supported: assertion_algorithms.clone(),
        revocation_endpoint_auth_methods_supported: methods,
        revocation_endpoint_auth_signing_alg_values_supported: assertion_algorithms,
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported: vec!["openid", "profile", "email", "roles", OFFLINE_ACCESS_SCOPE],
        acr_values_supported: Assurance::ALL.map(Assurance::name).to_vec(),
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
    use crate::ports::crypto::SignatureAlgorithm;
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

        let document = describe_provider(
            &settings,
            &realm,
            &[SignatureAlgorithm::Es256],
            &SignatureAlgorithm::ALL,
        );

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
        assert_eq!(document.acr_values_supported, ["1", "2"]);
        assert!(document.scopes_supported.contains(&"offline_access"));
        assert!(
            !document.request_parameter_supported && !document.claims_parameter_supported,
            "an absent member would mean yes"
        );
    }

    #[test]
    fn each_endpoint_that_reads_a_client_says_how_it_may_prove_itself_and_in_what() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");
        let served = [SignatureAlgorithm::Es256, SignatureAlgorithm::Rs256];

        let document = describe_provider(&settings, &realm, &[SignatureAlgorithm::Es256], &served);

        let every = [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "none",
        ];
        assert_eq!(document.token_endpoint_auth_methods_supported, every);
        assert_eq!(document.revocation_endpoint_auth_methods_supported, every);
        assert_eq!(
            document.introspection_endpoint_auth_methods_supported,
            every[..4],
            "a public client is told nothing"
        );
        for signed in [
            &document.token_endpoint_auth_signing_alg_values_supported,
            &document.introspection_endpoint_auth_signing_alg_values_supported,
            &document.revocation_endpoint_auth_signing_alg_values_supported,
        ] {
            assert_eq!(*signed, ["HS256", "ES256", "RS256"], "only what is served");
        }
    }
}
