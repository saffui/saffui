use serde_json::json;

use crypto::jose::jws::{ES256, JwsHeader, serialize_compact};

use crate::broker::BrokerSecret;
use crate::entities::attributes::{AttributesMap, string_at};

/// Apple's own token endpoint is the audience, and it is fixed.
const AUDIENCE: &str = "https://appleid.apple.com";

/// The ceiling Apple enforces, a little over six months. An assertion asking
/// for longer is refused outright, so the request fails rather than quietly
/// getting a shorter one.
pub const MAX_LIFETIME_SECS: i64 = 15_777_000;

/// What is actually asked for. Well inside the ceiling, because the assertion is
/// minted per login: a long life buys nothing and only widens the window in
/// which a leaked assertion is usable.
pub const LIFETIME_SECS: i64 = 3_600;

/// The attribute names for the three values Apple issues with the key.
pub mod keys {
    /// The developer team identifier, which is the assertion's issuer.
    pub const TEAM_ID: &str = "appleTeamId";
    /// The identifier of the key, which goes in the header so Apple knows which
    /// of your keys signed this.
    pub const KEY_ID: &str = "appleKeyId";
    /// The key itself, PEM encoded. Secret material.
    pub const PRIVATE_KEY: &str = "applePrivateKey";
}

/// Why an assertion could not be minted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppleSecretError {
    #[error("the Apple provider configuration is missing {0}")]
    Missing(&'static str),
    #[error("an Apple client secret may live at most {max} seconds, not {requested}")]
    LifetimeTooLong { requested: i64, max: i64 },
    #[error("an assertion has to outlive the request it is sent with")]
    LifetimeNotPositive { requested: i64 },
    /// Deliberately carrying nothing. What failed is a signing operation on a
    /// private key, and the detail belongs in whatever the signer logs rather
    /// than in a value that travels.
    #[error("the Apple assertion could not be signed")]
    Signing,
}

/// The values needed to mint an assertion, checked for presence.
///
/// Derives neither `Debug` nor `Serialize`, and holds the key in a newtype that
/// renders nothing. Either alone would do; both means adding a derive later does
/// not quietly put a private key in a log line.
#[derive(Clone)]
pub struct AppleSecretConfig {
    pub team_id: String,
    pub key_id: String,
    /// PEM encoded private key.
    pub private_key: BrokerSecret,
    /// The service identifier registered with Apple, which is the client
    /// identifier and the assertion's subject.
    pub client_id: String,
}

impl AppleSecretConfig {
    /// Read the three values from a provider's attribute bag.
    ///
    /// All three are required together. A partial configuration cannot mint
    /// anything, and letting it through produces a provider that looks
    /// configured and fails at the token endpoint with an error from Apple
    /// rather than from here.
    pub fn from_attributes(
        configs: Option<&AttributesMap>,
        client_id: &str,
    ) -> Result<Self, AppleSecretError> {
        let configs = configs.ok_or(AppleSecretError::Missing(keys::TEAM_ID))?;
        let need = |key: &'static str| -> Result<String, AppleSecretError> {
            string_at(configs, key)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .ok_or(AppleSecretError::Missing(key))
        };

        Ok(AppleSecretConfig {
            team_id: need(keys::TEAM_ID)?,
            key_id: need(keys::KEY_ID)?,
            private_key: BrokerSecret::new(need(keys::PRIVATE_KEY)?),
            client_id: client_id.to_owned(),
        })
    }

    /// Mint an assertion valid from `now` for `lifetime_secs`.
    ///
    /// `now` is a parameter rather than read from the clock, so the result is
    /// reproducible and the expiry is testable. The expiry is the one property
    /// that matters here, and a wall clock call is exactly what would make it
    /// untestable.
    ///
    /// The life is bounded at both ends. Past the ceiling Apple refuses it. At
    /// zero or below the assertion is already expired when it is minted, which
    /// produces a login that fails with an error from Apple about a secret this
    /// server generated a moment earlier.
    pub fn mint(&self, now: i64, lifetime_secs: i64) -> Result<String, AppleSecretError> {
        if lifetime_secs <= 0 {
            return Err(AppleSecretError::LifetimeNotPositive {
                requested: lifetime_secs,
            });
        }
        if lifetime_secs > MAX_LIFETIME_SECS {
            return Err(AppleSecretError::LifetimeTooLong {
                requested: lifetime_secs,
                max: MAX_LIFETIME_SECS,
            });
        }

        let mut header = JwsHeader::new();
        // Apple identifies the signing key by this alone. Without it every
        // assertion is refused, and the refusal says nothing useful.
        header
            .set_claim("kid", Some(json!(self.key_id)))
            .map_err(|_| AppleSecretError::Signing)?;

        let claims = json!({
            "iss": self.team_id,
            "iat": now,
            "exp": now + lifetime_secs,
            "aud": AUDIENCE,
            // Apple checks this against the client identifier in the token
            // request, so a mismatch is a login that fails only in production.
            "sub": self.client_id,
        });

        let signer = ES256
            .signer_from_pem(self.private_key.expose().as_bytes())
            .map_err(|_| AppleSecretError::Signing)?;

        serialize_compact(
            serde_json::to_string(&claims)
                .map_err(|_| AppleSecretError::Signing)?
                .as_bytes(),
            &header,
            &signer,
        )
        .map_err(|_| AppleSecretError::Signing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::attributes::AttributeValue;
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};

    fn key_pem() -> String {
        let pair = EcKeyPair::generate(EcCurve::P256).expect("a P-256 key");
        String::from_utf8(pair.to_pem_private_key()).expect("PEM is text")
    }

    fn bag() -> AttributesMap {
        AttributesMap::from([
            (
                keys::TEAM_ID.to_owned(),
                AttributeValue::Str("TEAM123456".to_owned()),
            ),
            (
                keys::KEY_ID.to_owned(),
                AttributeValue::Str("KEY7890".to_owned()),
            ),
            (keys::PRIVATE_KEY.to_owned(), AttributeValue::Str(key_pem())),
        ])
    }

    fn config() -> AppleSecretConfig {
        match AppleSecretConfig::from_attributes(Some(&bag()), "com.example.service") {
            Ok(config) => config,
            Err(error) => panic!("a complete bag should parse: {error}"),
        }
    }

    fn payload(assertion: &str) -> serde_json::Value {
        let part = assertion.split('.').nth(1).expect("a compact assertion");
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(part.as_bytes())
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("JSON claims")
    }

    fn header_of(assertion: &str) -> serde_json::Value {
        let part = assertion.split('.').next().expect("a compact assertion");
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(part.as_bytes())
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("JSON header")
    }

    /// All three values are required together, and the failure names which one
    /// is absent.
    #[test]
    fn a_partial_configuration_mints_nothing() {
        assert_eq!(
            AppleSecretConfig::from_attributes(None, "com.example.service")
                .err()
                .expect("a missing bag fails"),
            AppleSecretError::Missing(keys::TEAM_ID)
        );

        for key in [keys::TEAM_ID, keys::KEY_ID, keys::PRIVATE_KEY] {
            let mut without = bag();
            without.remove(key);
            assert_eq!(
                AppleSecretConfig::from_attributes(Some(&without), "com.example.service")
                    .err()
                    .expect("a missing key fails"),
                AppleSecretError::Missing(key),
                "{key} must be required"
            );

            let mut blank = bag();
            blank.insert(key.to_owned(), AttributeValue::Str("   ".to_owned()));
            assert_eq!(
                AppleSecretConfig::from_attributes(Some(&blank), "com.example.service")
                    .err()
                    .expect("a blank key fails"),
                AppleSecretError::Missing(key),
                "whitespace is not a value for {key}"
            );
        }
    }

    /// The assertion carries what Apple checks, and the expiry follows the
    /// instant it was minted at rather than a clock nobody controls.
    #[test]
    fn the_assertion_says_what_apple_checks() {
        let assertion = config().mint(1_000, LIFETIME_SECS).unwrap();

        let claims = payload(&assertion);
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], "com.example.service");
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["iat"], 1_000);
        assert_eq!(claims["exp"], 1_000 + LIFETIME_SECS);

        // Apple identifies the signing key by this alone.
        assert_eq!(header_of(&assertion)["kid"], "KEY7890");
        assert_eq!(header_of(&assertion)["alg"], "ES256");

        assert_eq!(assertion.split('.').count(), 3, "a compact assertion");
    }

    /// The life is bounded at both ends. Past the ceiling Apple refuses it; at
    /// zero or below the assertion is expired the moment it is minted, and the
    /// login fails with an error about a secret generated a moment earlier.
    #[test]
    fn a_life_outside_the_bounds_is_refused() {
        let config = config();

        assert_eq!(
            config.mint(1_000, MAX_LIFETIME_SECS + 1).unwrap_err(),
            AppleSecretError::LifetimeTooLong {
                requested: MAX_LIFETIME_SECS + 1,
                max: MAX_LIFETIME_SECS
            }
        );
        assert!(
            config.mint(1_000, MAX_LIFETIME_SECS).is_ok(),
            "the ceiling itself is allowed"
        );

        for refused in [0, -1, i64::MIN] {
            assert_eq!(
                config.mint(1_000, refused).unwrap_err(),
                AppleSecretError::LifetimeNotPositive { requested: refused },
                "a life of {refused} is already over"
            );
        }
        assert!(config.mint(1_000, 1).is_ok());
    }

    /// The private key never renders, whichever way one tries.
    #[test]
    fn the_private_key_never_renders() {
        let config = config();
        let pem = config.private_key.expose().to_owned();
        assert!(pem.contains("PRIVATE KEY"), "the fixture is a real key");

        assert_eq!(
            format!("{:?}", config.private_key),
            "BrokerSecret(<redacted>)"
        );

        // And the assertion itself carries the signature, never the key.
        let assertion = config.mint(1_000, LIFETIME_SECS).unwrap();
        assert!(!assertion.contains("PRIVATE KEY"));
    }

    /// Two assertions minted at different instants differ, so nothing is cached
    /// past the expiry it was minted with.
    #[test]
    fn each_minting_stamps_its_own_instant() {
        let config = config();
        let early = config.mint(1_000, LIFETIME_SECS).unwrap();
        let later = config.mint(2_000, LIFETIME_SECS).unwrap();

        assert_ne!(early, later);
        assert_eq!(payload(&early)["exp"], 1_000 + LIFETIME_SECS);
        assert_eq!(payload(&later)["exp"], 2_000 + LIFETIME_SECS);
    }

    /// A key that is not one is refused rather than producing an assertion Apple
    /// cannot verify.
    #[test]
    fn a_key_that_is_not_one_is_refused() {
        let mut broken = bag();
        broken.insert(
            keys::PRIVATE_KEY.to_owned(),
            AttributeValue::Str(
                "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----".to_owned(),
            ),
        );
        let Ok(config) = AppleSecretConfig::from_attributes(Some(&broken), "com.example.service")
        else {
            panic!("the bag is complete, only the key is not a key")
        };
        assert_eq!(
            config.mint(1_000, LIFETIME_SECS).unwrap_err(),
            AppleSecretError::Signing
        );
    }
}
