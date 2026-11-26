//! The discovery document. It never lies: a field is published the day the
//! realm honors it, and not before.

use serde::Serialize;

use super::response::{ResponseMode, ResponseType};
use super::token::OFFLINE_ACCESS_SCOPE;
use crate::app::App;
use crate::claims::rules::list_scope_claims;
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
    /// What the realm may say of a person, as far as it is listed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims_supported: Vec<String>,
    /// What `acr` may say: the levels a sign-in can reach, weakest first.
    /// A list of nothing is never published (Discovery 1.0, section 4.2).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acr_values_supported: Vec<&'static str>,
    pub authorization_response_iss_parameter_supported: bool,
    pub response_modes_supported: Vec<&'static str>,
    /// What a request object may be signed in: the algorithms of the
    /// assertions of a client, never `none`.
    pub request_object_signing_alg_values_supported: Vec<&'static str>,
    /// Each written out. Absent, `request_uri_parameter_supported` would
    /// mean yes, and the two others no.
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub claims_parameter_supported: bool,
    /// A sign-out loads each client that registered an address in a frame,
    /// with `iss` and `sid`, which every identity token carries.
    pub frontchannel_logout_supported: bool,
    pub frontchannel_logout_session_supported: bool,
}

/// The claims a token says of a person: those of the protocol, then those
/// of the scopes. Not those of the mappers: they say how each client is set
/// up, and the list may leave claims out (Discovery 1.0, section 3).
fn list_supported_claims() -> Vec<String> {
    ["sub", "iss", "auth_time", "acr", "amr", "sid"]
        .into_iter()
        .chain(list_scope_claims())
        .map(str::to_owned)
        .collect()
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

/// The discovery document of a realm whose keys sign in `signing`, and
/// which verifies the keys of clients in `verifying`.
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
        response_types_supported: ResponseType::ALL.map(ResponseType::name).to_vec(),
        grant_types_supported: vec![
            "authorization_code",
            "implicit",
            "client_credentials",
            "refresh_token",
        ],
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
        revocation_endpoint_auth_signing_alg_values_supported: assertion_algorithms.clone(),
        code_challenge_methods_supported: vec!["S256"],
        scopes_supported: vec!["openid", "profile", "email", "roles", OFFLINE_ACCESS_SCOPE],
        claims_supported: list_supported_claims(),
        acr_values_supported: Assurance::ALL.map(Assurance::name).to_vec(),
        authorization_response_iss_parameter_supported: true,
        response_modes_supported: ResponseMode::ALL.map(ResponseMode::name).to_vec(),
        request_object_signing_alg_values_supported: assertion_algorithms,
        request_parameter_supported: true,
        request_uri_parameter_supported: false,
        claims_parameter_supported: true,
        frontchannel_logout_supported: true,
        frontchannel_logout_session_supported: true,
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
            [
                "authorization_code",
                "implicit",
                "client_credentials",
                "refresh_token"
            ]
        );
        assert_eq!(
            document.response_types_supported,
            [
                "code",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token"
            ],
            "each served to a client that declares it"
        );
        assert_eq!(
            document.response_modes_supported,
            ["query", "fragment", "form_post"]
        );
        assert_eq!(document.code_challenge_methods_supported, ["S256"]);
        assert_eq!(document.acr_values_supported, ["1", "2"]);
        assert!(document.scopes_supported.contains(&"offline_access"));
        assert!(document.claims_parameter_supported);
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

    #[test]
    fn a_request_object_is_read_by_value_in_what_this_build_serves_and_never_fetched() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");
        let served = [SignatureAlgorithm::Es256, SignatureAlgorithm::EdDsa];

        let document = describe_provider(&settings, &realm, &[SignatureAlgorithm::Es256], &served);

        assert!(document.request_parameter_supported);
        assert!(
            !document.request_uri_parameter_supported,
            "an absent member would mean yes"
        );
        assert_eq!(
            document.request_object_signing_alg_values_supported,
            ["HS256", "ES256", "EdDSA"],
            "never none"
        );
        let written = serde_json::to_value(&document).expect("a document");
        assert!(
            written.get("require_signed_request_object").is_none(),
            "a client says it of itself"
        );
    }

    #[test]
    fn the_claims_supported_are_those_of_the_protocol_and_of_the_scopes() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");

        let document = describe_provider(
            &settings,
            &realm,
            &[SignatureAlgorithm::Es256],
            &[SignatureAlgorithm::Es256],
        );

        let supported = &document.claims_supported;
        for claim in ["sub", "auth_time", "acr", "name", "given_name", "email"] {
            assert!(
                supported.iter().any(|named| named == claim),
                "{claim}: {supported:?}"
            );
        }
        let written = serde_json::to_value(&document).expect("a document");
        assert_eq!(written["claims_parameter_supported"], true);
    }

    #[test]
    fn a_sign_out_is_said_to_load_each_client_in_a_frame_and_nothing_else_is_promised() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");

        let written = serde_json::to_value(describe_provider(
            &settings,
            &realm,
            &[SignatureAlgorithm::Es256],
            &[SignatureAlgorithm::Es256],
        ))
        .expect("a document");

        for told in [
            "frontchannel_logout_supported",
            "frontchannel_logout_session_supported",
        ] {
            assert_eq!(written[told], serde_json::Value::Bool(true), "{told}");
        }
        for unsaid in [
            "backchannel_logout_supported",
            "backchannel_logout_session_supported",
            "check_session_iframe",
        ] {
            assert!(written.get(unsaid).is_none(), "{unsaid}");
        }
        assert_eq!(
            written["end_session_endpoint"],
            "https://id.example.org/realms/acme/oauth2/logout"
        );
    }

    #[test]
    fn a_list_of_no_element_is_left_out_of_the_document() {
        let settings = Settings::reached_directly(
            PublicOrigin::parse("https://id.example.org").expect("an origin"),
        );
        let realm = RealmName::parse("acme").expect("a realm name");
        let mut document = describe_provider(
            &settings,
            &realm,
            &[SignatureAlgorithm::Es256],
            &[SignatureAlgorithm::Es256],
        );
        document.acr_values_supported.clear();
        document.claims_supported.clear();

        let written = serde_json::to_value(&document).expect("a document");

        for left_out in ["acr_values_supported", "claims_supported"] {
            assert!(written.get(left_out).is_none(), "{left_out}");
        }
    }
}
