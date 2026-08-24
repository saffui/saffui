use serde::{Deserialize, Serialize};
use url::Url;

use crypto::provider::SignAlg;

use crate::broker::BrokerSecret;
use crate::broker::login_state::BrokerLoginRequest;
use crate::entities::attributes::{AttributesMap, bool_at, string_at};

/// The attribute names a provider's configuration is read from.
pub mod keys {
    pub const ISSUER: &str = "issuer";
    pub const AUTHORIZATION_ENDPOINT: &str = "authorizationUrl";
    pub const TOKEN_ENDPOINT: &str = "tokenUrl";
    pub const JWKS_URI: &str = "jwksUrl";
    pub const USERINFO_ENDPOINT: &str = "userInfoUrl";
    pub const CLIENT_ID: &str = "clientId";
    pub const CLIENT_SECRET: &str = "clientSecret";
    pub const SCOPES: &str = "defaultScope";
    pub const SIGNATURE_ALGORITHMS: &str = "signatureAlgorithms";
    pub const VALIDATE_SIGNATURE: &str = "validateSignature";
}

/// Why a provider's configuration cannot be used for a login.
///
/// One variant per failure rather than a key and a sentence, so a caller can act
/// on which check failed without reading the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerConfigError {
    #[error("the provider configuration is missing {0}")]
    Missing(&'static str),
    #[error("{key} must be an absolute https URL naming a host")]
    NotAnHttpsUrl { key: &'static str },
    #[error("{key} names an algorithm this build cannot verify")]
    UnverifiableAlgorithm {
        key: &'static str,
        /// As the operator wrote it. Carried rather than interpolated, so
        /// whoever renders it decides how.
        named: String,
    },
    #[error(
        "signature validation cannot be turned off: an unverified id token is an \
         unauthenticated assertion"
    )]
    SignatureValidationRefused,
}

/// Why an upstream id token is not acceptable.
///
/// Distinguished so an operator log can say which check failed. A browser is
/// told only that the login failed: naming the check tells whoever is probing
/// which constraint to work around next.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdTokenError {
    #[error("the id token has no {0} claim")]
    MissingClaim(&'static str),
    /// The token names another issuer. `got` came off the token, so it is
    /// carried rather than put in the message.
    #[error("the id token was issued by another provider")]
    IssuerMismatch { expected: String, got: String },
    #[error("the id token was not issued to {expected}")]
    AudienceMismatch { expected: String },
    #[error("the id token answers another login")]
    NonceMismatch,
    #[error("the id token has expired")]
    Expired,
}

/// A provider's configuration, parsed and checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcBrokerConfig {
    /// The upstream issuer. Every id token must carry exactly this value.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Where the upstream publishes its signing keys.
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub client_id: String,
    /// Never serialised. It authenticates this deployment to the provider.
    #[serde(skip_serializing)]
    pub client_secret: Option<BrokerSecret>,
    /// Requested scopes, always including `openid`: without it the upstream owes no
    /// id token and the flow degrades to OAuth with nothing to verify.
    pub scopes: Vec<String>,
    /// The algorithms accepted on an upstream id token. Empty means every one
    /// this build can verify, never every one the upstream asserts.
    pub signature_algorithms: Vec<SignAlg>,
}

impl OidcBrokerConfig {
    /// Read a provider's attribute bag.
    ///
    /// Fails closed. Anything this cannot make sense of is an error rather than
    /// a default: a provider that does not parse is a provider nobody can log in
    /// through, which is the safe direction. The unsafe one is a broker running
    /// against an endpoint it guessed.
    pub fn from_attributes(configs: Option<&AttributesMap>) -> Result<Self, BrokerConfigError> {
        let configs = configs.ok_or(BrokerConfigError::Missing(keys::ISSUER))?;

        let required = |key: &'static str| -> Result<String, BrokerConfigError> {
            match string_at(configs, key).map(str::trim) {
                Some(value) if !value.is_empty() => Ok(value.to_owned()),
                _ => Err(BrokerConfigError::Missing(key)),
            }
        };
        let optional = |key: &str| -> Option<String> {
            string_at(configs, key)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };

        // Signature validation is not a toggle. An unverified id token is an
        // unauthenticated assertion, so the flag is honoured only to refuse the
        // provider, never to skip the check.
        if bool_at(configs, keys::VALIDATE_SIGNATURE) == Some(false) {
            return Err(BrokerConfigError::SignatureValidationRefused);
        }

        let issuer = required(keys::ISSUER)?;
        let authorization_endpoint = https_url(
            keys::AUTHORIZATION_ENDPOINT,
            &required(keys::AUTHORIZATION_ENDPOINT)?,
        )?;
        let token_endpoint = https_url(keys::TOKEN_ENDPOINT, &required(keys::TOKEN_ENDPOINT)?)?;
        let jwks_uri = https_url(keys::JWKS_URI, &required(keys::JWKS_URI)?)?;
        let userinfo_endpoint = match optional(keys::USERINFO_ENDPOINT) {
            Some(raw) => Some(https_url(keys::USERINFO_ENDPOINT, &raw)?),
            None => None,
        };

        // `openid` is added rather than demanded, so an operator who wrote
        // "email profile" gets a working provider instead of a puzzle.
        let mut scopes: Vec<String> = optional(keys::SCOPES)
            .map(|raw| raw.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        if !scopes.iter().any(|scope| scope == "openid") {
            scopes.insert(0, "openid".to_owned());
        }

        // An algorithm this build cannot verify is not a weaker check, it is no
        // check.
        let mut signature_algorithms = Vec::new();
        if let Some(raw) = optional(keys::SIGNATURE_ALGORITHMS) {
            for named in raw.split([',', ' ']).filter(|part| !part.is_empty()) {
                let alg = named.trim().parse::<SignAlg>().map_err(|_| {
                    BrokerConfigError::UnverifiableAlgorithm {
                        key: keys::SIGNATURE_ALGORITHMS,
                        named: named.trim().to_owned(),
                    }
                })?;
                signature_algorithms.push(alg);
            }
        }

        Ok(OidcBrokerConfig {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            userinfo_endpoint,
            client_id: required(keys::CLIENT_ID)?,
            client_secret: optional(keys::CLIENT_SECRET).map(BrokerSecret::new),
            scopes,
            signature_algorithms,
        })
    }

    /// The scopes as the `scope` request parameter.
    pub fn scope_parameter(&self) -> String {
        self.scopes.join(" ")
    }

    /// Whether `alg` may sign an id token from this provider.
    ///
    /// An empty allow list means the catalogue, not anything. The upstream does
    /// not get to choose the algorithm its own assertions are checked with.
    pub fn accepts_algorithm(&self, alg: SignAlg) -> bool {
        // Empty means every algorithm the signer knows, and the parameter is
        // that type, so there is nothing left to check. Comparing against the
        // catalogue here would read as a check while accepting the same set:
        // what does the work is that an unverifiable name never parsed into a
        // value in the first place.
        self.signature_algorithms.is_empty() || self.signature_algorithms.contains(&alg)
    }

    /// Build the upstream authorization request.
    ///
    /// Assembled through the URL serialiser rather than by formatting a string.
    /// The endpoint and the scopes come from operator configuration, and a value
    /// holding `&` or `=` would otherwise inject a parameter: overriding
    /// `redirect_uri` is the one an attacker most wants.
    ///
    /// The challenge method is always `S256`. `plain` is in the RFC and is a
    /// no-op against anyone who can read the request, so it is not offered.
    pub fn authorize_url(&self, request: &BrokerLoginRequest) -> Result<String, BrokerConfigError> {
        let mut url = Url::parse(&self.authorization_endpoint).map_err(|_| {
            BrokerConfigError::NotAnHttpsUrl {
                key: keys::AUTHORIZATION_ENDPOINT,
            }
        })?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);
            query.append_pair("redirect_uri", &request.state.redirect_uri);
            query.append_pair("scope", &self.scope_parameter());
            query.append_pair("state", request.raw_state.expose());
            query.append_pair("nonce", request.state.nonce.expose());
            query.append_pair("code_challenge", &request.code_challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        Ok(url.to_string())
    }

    /// Check the claims of an upstream id token.
    ///
    /// The signature is verified before this, against the provider's keys. This
    /// is everything the signature does not establish: a validly signed token
    /// proves only that the upstream issued it, not that it was issued to us,
    /// for this login, and is still valid.
    ///
    /// The nonce is the value stored when the login started, so the caller has
    /// to have consumed the login state first. Checking against a nonce read
    /// from the token would be circular.
    pub fn validate_id_token_claims(
        &self,
        claims: &serde_json::Map<String, serde_json::Value>,
        expected_nonce: &str,
        now: i64,
    ) -> Result<(), IdTokenError> {
        let text = |key: &str| claims.get(key).and_then(|value| value.as_str());

        // A token from another issuer can be validly signed by keys we trust:
        // hosted providers issue under per-tenant issuers from shared keys, so
        // verified does not mean from the provider we mean.
        match text("iss") {
            Some(issuer) if issuer == self.issuer => {}
            Some(issuer) => {
                return Err(IdTokenError::IssuerMismatch {
                    expected: self.issuer.clone(),
                    got: issuer.to_owned(),
                });
            }
            None => return Err(IdTokenError::MissingClaim("iss")),
        }

        // A token minted for another relying party at the same provider is
        // otherwise replayable here.
        let audiences: Vec<&str> = match claims.get("aud") {
            Some(serde_json::Value::String(one)) => vec![one.as_str()],
            Some(serde_json::Value::Array(many)) => {
                many.iter().filter_map(|value| value.as_str()).collect()
            }
            _ => return Err(IdTokenError::MissingClaim("aud")),
        };
        if !audiences.contains(&self.client_id.as_str()) {
            return Err(IdTokenError::AudienceMismatch {
                expected: self.client_id.clone(),
            });
        }
        // With several audiences the authorized party must name us, or a token
        // issued to someone else that merely lists us would pass.
        if audiences.len() > 1 && text("azp") != Some(self.client_id.as_str()) {
            return Err(IdTokenError::AudienceMismatch {
                expected: self.client_id.clone(),
            });
        }

        // Without this, a token from an earlier and legitimately obtained
        // session of the same client is replayable.
        match text("nonce") {
            Some(nonce) if nonce == expected_nonce => {}
            Some(_) => return Err(IdTokenError::NonceMismatch),
            None => return Err(IdTokenError::MissingClaim("nonce")),
        }

        match claims.get("exp").and_then(|value| value.as_i64()) {
            Some(exp) if exp > now => {}
            Some(_) => return Err(IdTokenError::Expired),
            None => return Err(IdTokenError::MissingClaim("exp")),
        }

        // The federated link is keyed on the subject. A token without one
        // identifies nobody, and falling back to an address would key the link
        // on a value the user can change upstream.
        if text("sub").filter(|sub| !sub.is_empty()).is_none() {
            return Err(IdTokenError::MissingClaim("sub"));
        }

        Ok(())
    }
}

/// An endpoint has to be an absolute HTTPS URL that names a host.
///
/// Parsed rather than prefix matched. A plaintext endpoint puts the
/// authorization code, and on the token endpoint the client secret, on the wire
/// in clear. A string that merely starts with the scheme can still name no host
/// at all, and a relative one would be resolved against whatever base the HTTP
/// client happens to hold, which is how a misconfiguration becomes a request to
/// the wrong place.
///
/// The host is not checked separately: `https` is a special scheme, so the
/// parser already refuses `https://` with nothing after it. A second check for
/// it would be a branch no input can reach.
fn https_url(key: &'static str, value: &str) -> Result<String, BrokerConfigError> {
    let url = Url::parse(value).map_err(|_| BrokerConfigError::NotAnHttpsUrl { key })?;
    if url.scheme() != "https" {
        return Err(BrokerConfigError::NotAnHttpsUrl { key });
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::login_state::BrokerLoginDestination;
    use crate::entities::attributes::AttributeValue;
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;
    use serde_json::json;

    fn bag(pairs: &[(&str, &str)]) -> AttributesMap {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), AttributeValue::Str((*v).to_owned())))
            .collect()
    }

    fn complete() -> Vec<(&'static str, &'static str)> {
        vec![
            (keys::ISSUER, "https://idp.example"),
            (
                keys::AUTHORIZATION_ENDPOINT,
                "https://idp.example/authorize",
            ),
            (keys::TOKEN_ENDPOINT, "https://idp.example/token"),
            (keys::JWKS_URI, "https://idp.example/jwks"),
            (keys::CLIENT_ID, "saffui"),
        ]
    }

    fn config() -> OidcBrokerConfig {
        OidcBrokerConfig::from_attributes(Some(&bag(&complete()))).expect("a complete bag parses")
    }

    fn claims(pairs: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        pairs.as_object().unwrap().clone()
    }

    fn valid_claims() -> serde_json::Map<String, serde_json::Value> {
        claims(json!({
            "iss": "https://idp.example",
            "aud": "saffui",
            "nonce": "n-1",
            "exp": 2_000,
            "sub": "upstream-sub-1",
        }))
    }

    /// Every required key is required, and the failure names which one.
    #[test]
    fn a_missing_key_names_itself() {
        assert_eq!(
            OidcBrokerConfig::from_attributes(None).unwrap_err(),
            BrokerConfigError::Missing(keys::ISSUER)
        );

        for key in [
            keys::ISSUER,
            keys::AUTHORIZATION_ENDPOINT,
            keys::TOKEN_ENDPOINT,
            keys::JWKS_URI,
            keys::CLIENT_ID,
        ] {
            let without: Vec<_> = complete().into_iter().filter(|(k, _)| *k != key).collect();
            assert_eq!(
                OidcBrokerConfig::from_attributes(Some(&bag(&without))).unwrap_err(),
                BrokerConfigError::Missing(key),
                "{key} must be required"
            );
        }

        // Whitespace is not a value.
        let blank: Vec<_> = complete()
            .into_iter()
            .map(|(k, v)| {
                if k == keys::CLIENT_ID {
                    (k, "   ")
                } else {
                    (k, v)
                }
            })
            .collect();
        assert_eq!(
            OidcBrokerConfig::from_attributes(Some(&bag(&blank))).unwrap_err(),
            BrokerConfigError::Missing(keys::CLIENT_ID)
        );
    }

    /// An endpoint is parsed, not prefix matched. A string beginning with the
    /// scheme can still name no host, and that endpoint would be resolved
    /// against whatever base the client happens to hold.
    #[test]
    fn an_endpoint_must_parse_and_name_a_host() {
        for bad in [
            "http://idp.example/authorize",
            "https://",
            "https://?query=1",
            "https://#fragment",
            "//idp.example/authorize",
            "/authorize",
            "idp.example/authorize",
            "ftp://idp.example/authorize",
            // An empty value is missing rather than malformed, and is covered
            // by the required-key test.
        ] {
            let broken: Vec<_> = complete()
                .into_iter()
                .map(|(k, v)| {
                    if k == keys::AUTHORIZATION_ENDPOINT {
                        (k, bad)
                    } else {
                        (k, v)
                    }
                })
                .collect();
            assert_eq!(
                OidcBrokerConfig::from_attributes(Some(&bag(&broken))).unwrap_err(),
                BrokerConfigError::NotAnHttpsUrl {
                    key: keys::AUTHORIZATION_ENDPOINT
                },
                "{bad:?} must be refused"
            );
        }
    }

    /// Turning signature validation off refuses the provider rather than
    /// skipping the check.
    #[test]
    fn signature_validation_cannot_be_turned_off() {
        let mut attributes = bag(&complete());
        attributes.insert(
            keys::VALIDATE_SIGNATURE.to_owned(),
            AttributeValue::Bool(false),
        );
        assert_eq!(
            OidcBrokerConfig::from_attributes(Some(&attributes)).unwrap_err(),
            BrokerConfigError::SignatureValidationRefused
        );

        attributes.insert(
            keys::VALIDATE_SIGNATURE.to_owned(),
            AttributeValue::Bool(true),
        );
        assert!(OidcBrokerConfig::from_attributes(Some(&attributes)).is_ok());
    }

    /// `openid` is added rather than demanded, and an algorithm nothing can
    /// verify refuses the provider.
    #[test]
    fn the_scopes_always_carry_openid_and_the_algorithms_are_verifiable() {
        assert_eq!(config().scopes, vec!["openid"]);

        let mut with_scopes = complete();
        with_scopes.push((keys::SCOPES, "email profile"));
        let parsed = OidcBrokerConfig::from_attributes(Some(&bag(&with_scopes))).unwrap();
        assert_eq!(parsed.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(parsed.scope_parameter(), "openid email profile");

        let mut listed = complete();
        listed.push((keys::SIGNATURE_ALGORITHMS, "ES256, RS256"));
        let parsed = OidcBrokerConfig::from_attributes(Some(&bag(&listed))).unwrap();
        assert_eq!(
            parsed.signature_algorithms,
            vec![SignAlg::Es256, SignAlg::Rs256]
        );

        let mut unverifiable = complete();
        unverifiable.push((keys::SIGNATURE_ALGORITHMS, "ES256, HS256"));
        assert_eq!(
            OidcBrokerConfig::from_attributes(Some(&bag(&unverifiable))).unwrap_err(),
            BrokerConfigError::UnverifiableAlgorithm {
                key: keys::SIGNATURE_ALGORITHMS,
                named: "HS256".to_owned()
            }
        );
    }

    /// An empty allow list means the catalogue, not anything. The upstream does
    /// not choose the algorithm its own assertions are checked with.
    #[test]
    fn an_empty_allow_list_is_the_catalogue_and_not_anything() {
        let any = config();
        for alg in SignAlg::ALL {
            assert!(any.accepts_algorithm(alg), "{alg}");
        }

        let mut listed = complete();
        listed.push((keys::SIGNATURE_ALGORITHMS, "ES256"));
        let narrow = OidcBrokerConfig::from_attributes(Some(&bag(&listed))).unwrap();
        assert!(narrow.accepts_algorithm(SignAlg::Es256));
        assert!(!narrow.accepts_algorithm(SignAlg::Rs256));
    }

    /// The client secret authenticates this deployment to the provider, so it
    /// never reaches a rendering of the configuration.
    #[test]
    fn the_client_secret_never_renders() {
        let mut with_secret = complete();
        with_secret.push((keys::CLIENT_SECRET, "s3cr3t-value"));
        let parsed = OidcBrokerConfig::from_attributes(Some(&bag(&with_secret))).unwrap();
        assert_eq!(
            parsed.client_secret.as_ref().map(BrokerSecret::expose),
            Some("s3cr3t-value")
        );

        let json = serde_json::to_string(&parsed).unwrap();
        assert!(!json.contains("s3cr3t-value"), "{json}");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("s3cr3t-value"), "{rendered}");
        assert!(json.contains("https://idp.example"), "the rest renders");
    }

    /// The request is assembled through the serialiser, so a configured value
    /// holding a separator cannot add a parameter of its own.
    #[test]
    fn a_configured_value_cannot_inject_a_parameter() {
        let provider = OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .unwrap();
        let request = BrokerLoginRequest::generate(
            &provider,
            BrokerLoginDestination {
                tenant: "acme".into(),
                realm_id: "acme".into(),
                provider_alias: "idp".into(),
                redirect_uri: "https://saffui.example/cb".into(),
                client_id: None,
                local_redirect_uri: None,
                local_state: None,
                org_id: None,
            },
            100,
        )
        .unwrap();

        let mut hostile = complete();
        hostile.push((keys::SCOPES, "email&redirect_uri=https://evil.example"));
        let config = OidcBrokerConfig::from_attributes(Some(&bag(&hostile))).unwrap();

        let url = config.authorize_url(&request).unwrap();
        let parsed = Url::parse(&url).unwrap();
        let redirects: Vec<String> = parsed
            .query_pairs()
            .filter(|(k, _)| k == "redirect_uri")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(
            redirects,
            vec!["https://saffui.example/cb"],
            "exactly one redirect_uri, and it is ours: {url}"
        );

        let method: Vec<String> = parsed
            .query_pairs()
            .filter(|(k, _)| k == "code_challenge_method")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(method, vec!["S256"], "plain is never offered");

        assert!(url.contains("response_type=code"));
    }

    /// A validly signed token proves only that the upstream issued it. Each
    /// check closes one of the things the signature does not establish.
    #[test]
    fn a_signed_token_still_has_to_answer_this_login() {
        let config = config();
        assert!(
            config
                .validate_id_token_claims(&valid_claims(), "n-1", 1_000)
                .is_ok()
        );

        let mut other_issuer = valid_claims();
        other_issuer.insert("iss".into(), json!("https://evil.example"));
        assert_eq!(
            config.validate_id_token_claims(&other_issuer, "n-1", 1_000),
            Err(IdTokenError::IssuerMismatch {
                expected: "https://idp.example".to_owned(),
                got: "https://evil.example".to_owned()
            })
        );

        let mut other_audience = valid_claims();
        other_audience.insert("aud".into(), json!("another-client"));
        assert_eq!(
            config.validate_id_token_claims(&other_audience, "n-1", 1_000),
            Err(IdTokenError::AudienceMismatch {
                expected: "saffui".to_owned()
            })
        );

        let mut other_nonce = valid_claims();
        other_nonce.insert("nonce".into(), json!("n-2"));
        assert_eq!(
            config.validate_id_token_claims(&other_nonce, "n-1", 1_000),
            Err(IdTokenError::NonceMismatch)
        );

        assert_eq!(
            config.validate_id_token_claims(&valid_claims(), "n-1", 2_000),
            Err(IdTokenError::Expired),
            "the instant of expiry is expired"
        );
        assert!(
            config
                .validate_id_token_claims(&valid_claims(), "n-1", 1_999)
                .is_ok()
        );
    }

    /// Every claim the check depends on is required, so a token that simply
    /// omits one does not pass by default.
    #[test]
    fn an_omitted_claim_is_not_a_pass() {
        let config = config();
        for claim in ["iss", "aud", "nonce", "exp", "sub"] {
            let mut without = valid_claims();
            without.remove(claim);
            assert_eq!(
                config.validate_id_token_claims(&without, "n-1", 1_000),
                Err(IdTokenError::MissingClaim(claim)),
                "{claim} must be required"
            );
        }

        let mut empty_subject = valid_claims();
        empty_subject.insert("sub".into(), json!(""));
        assert_eq!(
            config.validate_id_token_claims(&empty_subject, "n-1", 1_000),
            Err(IdTokenError::MissingClaim("sub")),
            "a subject nobody wrote identifies nobody"
        );
    }

    /// With several audiences the authorized party has to name us, or a token
    /// issued to someone else that merely lists us would pass.
    #[test]
    fn several_audiences_need_an_authorized_party_naming_us() {
        let config = config();

        let mut many = valid_claims();
        many.insert("aud".into(), json!(["saffui", "another-client"]));
        assert_eq!(
            config.validate_id_token_claims(&many, "n-1", 1_000),
            Err(IdTokenError::AudienceMismatch {
                expected: "saffui".to_owned()
            }),
            "listing us is not enough"
        );

        many.insert("azp".into(), json!("another-client"));
        assert_eq!(
            config.validate_id_token_claims(&many, "n-1", 1_000),
            Err(IdTokenError::AudienceMismatch {
                expected: "saffui".to_owned()
            })
        );

        many.insert("azp".into(), json!("saffui"));
        assert!(config.validate_id_token_claims(&many, "n-1", 1_000).is_ok());

        // A single audience needs no authorized party.
        let mut one = valid_claims();
        one.insert("aud".into(), json!(["saffui"]));
        assert!(config.validate_id_token_claims(&one, "n-1", 1_000).is_ok());
    }
}
