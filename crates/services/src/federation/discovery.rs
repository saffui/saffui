//! An OpenID provider's discovery document, OpenID Connect Discovery 1.0: an
//! operator names the issuer, and the endpoints come from what the provider
//! publishes rather than from what somebody typed.

use crypto::provider::SignAlg;
use serde::Serialize;
use serde_json::Value;

use super::brokering::{PROVIDER_ASSERTION_ALGORITHM, USERINFO_ENCRYPTIONS};

/// How much of what a provider wrote a refusal repeats.
const QUOTED: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Undiscoverable {
    #[error("{0} is not an issuer: an https address with no query or fragment")]
    NotAnIssuer(String),
    #[error("the discovery document is not a JSON object")]
    NotADocument,
    #[error("the discovery document names another issuer: {0}")]
    AnotherIssuer(String),
    #[error("the discovery document names no {0}")]
    Missing(&'static str),
    #[error("{0} in the discovery document is not an https address")]
    Insecure(&'static str),
    #[error("the provider does not announce the authorization code flow")]
    NoCodeFlow,
    #[error("the provider signs identity tokens with no algorithm this server verifies")]
    NoVerifiableAlgorithm,
}

/// What a setting here may need that the provider does not announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryGap {
    /// No signed assertion at its token endpoint.
    NoPrivateKeyJwt,
    /// Signed assertions, but none under the algorithm a provider's own key
    /// signs with here.
    NoAssertionAlgorithm,
    /// No userinfo encrypted under RSA-OAEP-256 around AES-GCM.
    NoUserinfoEncryption,
    /// No claims request, Core 5.5.
    NoClaimsParameter,
    /// No PKCE under S256.
    NoPkceS256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    /// The identity token algorithms it announces that this server verifies.
    pub id_token_algs: Vec<String>,
    /// The authentication contexts it announces, to pair with the realm's.
    pub acr_values: Vec<String>,
    /// Whether its way back names its issuer, RFC 9207.
    pub iss_parameter: bool,
    pub gaps: Vec<DiscoveryGap>,
}

/// Where an issuer publishes its discovery document: the issuer less any
/// trailing slash, then `/.well-known/openid-configuration`, Discovery 4.
pub fn locate_discovery_document(issuer: &str) -> Result<String, Undiscoverable> {
    let refused = || Undiscoverable::NotAnIssuer(quote(issuer));
    if !commons::address::is_https_or_loopback(issuer) {
        return Err(refused());
    }
    let parsed = url::Url::parse(issuer).map_err(|_| refused())?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(refused());
    }
    Ok(format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
}

/// Read what `issuer` published, refusing a document that speaks for another
/// issuer, Discovery 4.3, or names an endpoint a provider may not be given.
pub fn read_discovery_document(
    issuer: &str,
    document: &str,
) -> Result<DiscoveredProvider, Undiscoverable> {
    let Ok(Value::Object(said)) = serde_json::from_str::<Value>(document) else {
        return Err(Undiscoverable::NotADocument);
    };
    let text = |name: &str| said.get(name).and_then(Value::as_str);
    let named = |name: &str| -> Vec<&str> {
        said.get(name)
            .and_then(Value::as_array)
            .map(|listed| listed.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    };
    match text("issuer") {
        Some(same) if same == issuer => {}
        Some(other) => return Err(Undiscoverable::AnotherIssuer(quote(other))),
        None => return Err(Undiscoverable::Missing("issuer")),
    }
    let endpoint = |name: &'static str| -> Result<String, Undiscoverable> {
        let given = text(name).ok_or(Undiscoverable::Missing(name))?;
        if !commons::address::is_https_or_loopback(given) {
            return Err(Undiscoverable::Insecure(name));
        }
        Ok(given.to_owned())
    };
    let authorization_endpoint = endpoint("authorization_endpoint")?;
    let token_endpoint = endpoint("token_endpoint")?;
    let jwks_uri = endpoint("jwks_uri")?;
    let userinfo_endpoint = match text("userinfo_endpoint") {
        None => None,
        Some(_) => Some(endpoint("userinfo_endpoint")?),
    };
    if !named("response_types_supported").contains(&"code") {
        return Err(Undiscoverable::NoCodeFlow);
    }
    let id_token_algs: Vec<String> = named("id_token_signing_alg_values_supported")
        .into_iter()
        .filter(|name| serde_json::from_value::<SignAlg>(Value::String((*name).to_owned())).is_ok())
        .map(str::to_owned)
        .collect();
    if id_token_algs.is_empty() {
        return Err(Undiscoverable::NoVerifiableAlgorithm);
    }

    let mut gaps = Vec::new();
    if !named("token_endpoint_auth_methods_supported").contains(&"private_key_jwt") {
        gaps.push(DiscoveryGap::NoPrivateKeyJwt);
    } else {
        // Unsaid, the provider has not ruled the algorithm out.
        let signing = named("token_endpoint_auth_signing_alg_values_supported");
        if !signing.is_empty() && !signing.contains(&PROVIDER_ASSERTION_ALGORITHM.name()) {
            gaps.push(DiscoveryGap::NoAssertionAlgorithm);
        }
    }
    if !named("userinfo_encryption_alg_values_supported").contains(&"RSA-OAEP-256")
        || !named("userinfo_encryption_enc_values_supported")
            .iter()
            .any(|content| USERINFO_ENCRYPTIONS.contains(content))
    {
        gaps.push(DiscoveryGap::NoUserinfoEncryption);
    }
    if said.get("claims_parameter_supported") != Some(&Value::Bool(true)) {
        gaps.push(DiscoveryGap::NoClaimsParameter);
    }
    if !named("code_challenge_methods_supported").contains(&"S256") {
        gaps.push(DiscoveryGap::NoPkceS256);
    }

    Ok(DiscoveredProvider {
        issuer: issuer.to_owned(),
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        userinfo_endpoint,
        id_token_algs,
        acr_values: named("acr_values_supported")
            .into_iter()
            .map(str::to_owned)
            .collect(),
        iss_parameter: said.get("authorization_response_iss_parameter_supported")
            == Some(&Value::Bool(true)),
        gaps,
    })
}

fn quote(said: &str) -> String {
    said.chars().take(QUOTED).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://esignet.example";

    /// What eSignet 2.0.0 publishes, moved to an https issuer.
    fn published() -> Value {
        json!({
            "issuer": ISSUER,
            "authorization_endpoint": "https://esignet.example/oauth2/authorize",
            "token_endpoint": "https://esignet.example/oauth2/token",
            "jwks_uri": "https://esignet.example/oauth2/jwks",
            "userinfo_endpoint": "https://esignet.example/oauth2/userinfo",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["PS256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["PS256", "ES256", "ES256K", "EdDSA"],
            "userinfo_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256"],
            "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A256GCM"],
            "claims_parameter_supported": true,
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "acr_values_supported": ["mosip:idp:acr:biometrics", "mosip:idp:acr:knowledge"],
        })
    }

    fn read(document: &Value) -> Result<DiscoveredProvider, Undiscoverable> {
        read_discovery_document(ISSUER, &document.to_string())
    }

    #[test]
    fn an_issuer_publishes_where_discovery_says() {
        for (issuer, located) in [
            (
                "https://esignet.example",
                "https://esignet.example/.well-known/openid-configuration",
            ),
            (
                "https://esignet.example/",
                "https://esignet.example/.well-known/openid-configuration",
            ),
            (
                "https://id.example/realms/main",
                "https://id.example/realms/main/.well-known/openid-configuration",
            ),
            (
                "http://localhost:18080",
                "http://localhost:18080/.well-known/openid-configuration",
            ),
        ] {
            assert_eq!(
                locate_discovery_document(issuer).as_deref(),
                Ok(located),
                "{issuer}"
            );
        }
        for issuer in [
            "",
            "esignet.example",
            "http://esignet.example",
            "https://",
            "https://esignet.example?realm=a",
            "https://esignet.example#top",
            "https://ada@esignet.example",
            "https://:secret@esignet.example",
            "ftp://esignet.example",
        ] {
            assert_eq!(
                locate_discovery_document(issuer),
                Err(Undiscoverable::NotAnIssuer(issuer.to_owned())),
                "{issuer}"
            );
        }
    }

    #[test]
    fn a_national_provider_is_read_as_it_publishes() {
        let found = read(&published()).expect("a provider");
        assert_eq!(found.token_endpoint, "https://esignet.example/oauth2/token");
        assert_eq!(
            found.userinfo_endpoint.as_deref(),
            Some("https://esignet.example/oauth2/userinfo")
        );
        assert_eq!(found.id_token_algs, ["PS256"]);
        assert_eq!(
            found.acr_values,
            ["mosip:idp:acr:biometrics", "mosip:idp:acr:knowledge"]
        );
        assert!(found.iss_parameter);
        assert_eq!(found.gaps, []);
    }

    #[test]
    fn a_document_is_refused_in_every_way_it_can_mislead() {
        let with = |name: &str, value: Value| {
            let mut changed = published();
            changed[name] = value;
            changed
        };
        let without = |name: &str| {
            let mut changed = published();
            changed.as_object_mut().expect("an object").remove(name);
            changed
        };
        assert_eq!(
            read_discovery_document(ISSUER, "not json"),
            Err(Undiscoverable::NotADocument)
        );
        assert_eq!(read(&json!([ISSUER])), Err(Undiscoverable::NotADocument));
        for (document, refusal) in [
            (
                with("issuer", json!("https://esignet.example/")),
                Undiscoverable::AnotherIssuer("https://esignet.example/".to_owned()),
            ),
            (
                with("issuer", json!("https://elsewhere.example")),
                Undiscoverable::AnotherIssuer("https://elsewhere.example".to_owned()),
            ),
            (without("issuer"), Undiscoverable::Missing("issuer")),
            (
                without("authorization_endpoint"),
                Undiscoverable::Missing("authorization_endpoint"),
            ),
            (
                without("token_endpoint"),
                Undiscoverable::Missing("token_endpoint"),
            ),
            (without("jwks_uri"), Undiscoverable::Missing("jwks_uri")),
            (
                with(
                    "token_endpoint",
                    json!("http://esignet.example/oauth2/token"),
                ),
                Undiscoverable::Insecure("token_endpoint"),
            ),
            (
                with(
                    "userinfo_endpoint",
                    json!("http://esignet.example/userinfo"),
                ),
                Undiscoverable::Insecure("userinfo_endpoint"),
            ),
            (
                with("response_types_supported", json!(["id_token"])),
                Undiscoverable::NoCodeFlow,
            ),
            (
                with(
                    "id_token_signing_alg_values_supported",
                    json!(["none", "HS256"]),
                ),
                Undiscoverable::NoVerifiableAlgorithm,
            ),
        ] {
            assert_eq!(read(&document), Err(refusal.clone()), "{refusal}");
        }
        let long = format!("https://{}.example", "a".repeat(400));
        let Err(Undiscoverable::AnotherIssuer(quoted)) = read(&with("issuer", json!(long))) else {
            panic!("another issuer taken");
        };
        assert_eq!(quoted.chars().count(), QUOTED);
    }

    #[test]
    fn what_is_not_announced_is_named() {
        let bare = json!({
            "issuer": ISSUER,
            "authorization_endpoint": "https://esignet.example/authorize",
            "token_endpoint": "https://esignet.example/token",
            "jwks_uri": "https://esignet.example/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        });
        let found = read(&bare).expect("a provider");
        assert_eq!(found.id_token_algs, ["RS256"]);
        assert_eq!(found.userinfo_endpoint, None);
        assert!(!found.iss_parameter);
        assert_eq!(
            found.gaps,
            [
                DiscoveryGap::NoPrivateKeyJwt,
                DiscoveryGap::NoUserinfoEncryption,
                DiscoveryGap::NoClaimsParameter,
                DiscoveryGap::NoPkceS256,
            ]
        );

        let mut elsewhere = published();
        elsewhere["token_endpoint_auth_signing_alg_values_supported"] = json!(["RS256"]);
        elsewhere["userinfo_encryption_enc_values_supported"] = json!(["A128CBC-HS256"]);
        assert_eq!(
            read(&elsewhere).expect("a provider").gaps,
            [
                DiscoveryGap::NoAssertionAlgorithm,
                DiscoveryGap::NoUserinfoEncryption
            ]
        );
        let mut unsaid = published();
        unsaid
            .as_object_mut()
            .expect("an object")
            .remove("token_endpoint_auth_signing_alg_values_supported");
        unsaid["userinfo_encryption_alg_values_supported"] = json!(["RSA-OAEP"]);
        assert_eq!(
            read(&unsaid).expect("a provider").gaps,
            [DiscoveryGap::NoUserinfoEncryption]
        );
    }
}
