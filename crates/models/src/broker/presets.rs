//! Ready made upstream provider configurations.
//!
//! Each is a thin set of defaults over the generic broker rather than a separate
//! implementation. The protocol is the same everywhere; what differs is a
//! handful of endpoints and one provider's idea of a client secret.
//!
//! They exist because getting an issuer or a key set URL wrong produces a
//! provider that configures cleanly and fails at the first login, and because a
//! preset is the difference between an operator supplying two values and an
//! operator supplying seven.
//!
//! A preset fills only what is fixed for that provider. The client identifier
//! and its secret always come from the operator: those are per deployment
//! registrations, and a default there would be a shared credential.

use crate::broker::oidc_config::keys;
use crate::str_enum::str_enum;

str_enum! {
    /// The providers with built in defaults.
    pub enum BrokerPreset {
        Google => "google",
        MicrosoftEntra => "microsoft",
        Apple => "apple",
        GitHub => "github",
        GitLab => "gitlab",
        Facebook => "facebook",
    }
}

impl BrokerPreset {
    /// The configuration entries this provider fixes.
    ///
    /// Written out rather than discovered when a provider is created. Discovery
    /// is one more network call on a path where a failure means the provider
    /// cannot be created at all, and these publish endpoints that have been
    /// stable for years. A provider whose endpoints move is reconfigured by an
    /// operator, which is visible, rather than silently re-pointed by whatever
    /// answered a discovery request.
    pub fn defaults(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Google => &[
                (keys::ISSUER, "https://accounts.google.com"),
                (
                    keys::AUTHORIZATION_ENDPOINT,
                    "https://accounts.google.com/o/oauth2/v2/auth",
                ),
                (keys::TOKEN_ENDPOINT, "https://oauth2.googleapis.com/token"),
                (keys::JWKS_URI, "https://www.googleapis.com/oauth2/v3/certs"),
                (
                    keys::USERINFO_ENDPOINT,
                    "https://openidconnect.googleapis.com/v1/userinfo",
                ),
                (keys::SCOPES, "openid email profile"),
                (keys::SIGNATURE_ALGORITHMS, "RS256"),
            ],
            // Endpoints deliberately absent: its endpoints and its issuer both
            // embed a directory identifier, so there is no correct fixed value
            // and a wrong default is worse than none.
            Self::MicrosoftEntra => &[
                (keys::SCOPES, "openid email profile"),
                (keys::SIGNATURE_ALGORITHMS, "RS256"),
            ],
            Self::Apple => &[
                (keys::ISSUER, "https://appleid.apple.com"),
                (
                    keys::AUTHORIZATION_ENDPOINT,
                    "https://appleid.apple.com/auth/authorize",
                ),
                (keys::TOKEN_ENDPOINT, "https://appleid.apple.com/auth/token"),
                (keys::JWKS_URI, "https://appleid.apple.com/auth/keys"),
                // Apple returns a name only on the very first authorization and
                // only when asked; the address is what the linking rules need.
                (keys::SCOPES, "openid email"),
                (keys::SIGNATURE_ALGORITHMS, "RS256"),
            ],
            // OAuth 2.0 rather than OpenID Connect: no id token and no key set.
            // Listed so it is recognised and an operator is told why it cannot be
            // used here, rather than finding out at the first login.
            Self::GitHub => &[],
            // A real OpenID Connect provider, unlike the one above. These are the
            // hosted endpoints; a self managed instance serves the same paths
            // under its own host, and overriding the issuer without the rest
            // verifies tokens against the wrong keys, so they come as a set.
            Self::GitLab => &[
                (keys::ISSUER, "https://gitlab.com"),
                (
                    keys::AUTHORIZATION_ENDPOINT,
                    "https://gitlab.com/oauth/authorize",
                ),
                (keys::TOKEN_ENDPOINT, "https://gitlab.com/oauth/token"),
                (keys::JWKS_URI, "https://gitlab.com/oauth/discovery/keys"),
                (keys::USERINFO_ENDPOINT, "https://gitlab.com/oauth/userinfo"),
                (keys::SCOPES, "openid email profile"),
                (keys::SIGNATURE_ALGORITHMS, "RS256"),
            ],
            Self::Facebook => &[
                (keys::ISSUER, "https://www.facebook.com"),
                (
                    keys::AUTHORIZATION_ENDPOINT,
                    "https://www.facebook.com/v18.0/dialog/oauth",
                ),
                (
                    keys::TOKEN_ENDPOINT,
                    "https://graph.facebook.com/v18.0/oauth/access_token",
                ),
                (
                    keys::JWKS_URI,
                    "https://www.facebook.com/.well-known/oauth/openid/jwks/",
                ),
                (keys::SCOPES, "openid email"),
                (keys::SIGNATURE_ALGORITHMS, "RS256"),
            ],
        }
    }

    /// Whether this provider can be brokered as OpenID Connect at all.
    ///
    /// One of them cannot: it is OAuth 2.0 and issues no id token, so there is
    /// nothing to verify and no assertion of who logged in, only an access token
    /// to trade for a profile call. Saying so when the provider is configured
    /// beats letting an operator find out when the first user tries.
    pub fn is_oidc(self) -> bool {
        // Named rather than inferred from having no fixed defaults. That would
        // hold today by coincidence, and it ties whether a provider speaks the
        // protocol to whether anyone wrote endpoints down for it.
        !matches!(self, Self::GitHub)
    }

    /// Whether this provider's client secret is an assertion the server mints
    /// and rotates rather than a fixed string.
    ///
    /// Apple hands out a signing key and expects a short lived assertion. A
    /// deployment that mints one and stores it as a literal works until it
    /// silently stops, on a date nobody wrote down.
    pub fn secret_is_a_minted_assertion(self) -> bool {
        matches!(self, Self::Apple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::oidc_config::OidcBrokerConfig;
    use crate::entities::attributes::{AttributeValue, AttributesMap};

    fn bag(preset: BrokerPreset) -> AttributesMap {
        let mut attributes: AttributesMap = preset
            .defaults()
            .iter()
            .map(|(k, v)| ((*k).to_owned(), AttributeValue::Str((*v).to_owned())))
            .collect();
        attributes.insert(
            keys::CLIENT_ID.to_owned(),
            AttributeValue::Str("saffui".to_owned()),
        );
        attributes
    }

    #[test]
    fn the_presets_agree_with_their_own_spelling() {
        assert_eq!(BrokerPreset::ALL.len(), 6);
        assert_eq!(BrokerPreset::MicrosoftEntra.as_str(), "microsoft");
        crate::str_enum::assert_round_trips(BrokerPreset::ALL);
    }

    /// A preset never fills a credential. Those are per deployment
    /// registrations, and a default there would be a shared credential.
    #[test]
    fn no_preset_supplies_a_credential() {
        for preset in BrokerPreset::ALL {
            for (key, _) in preset.defaults() {
                assert_ne!(*key, keys::CLIENT_ID, "{preset}");
                assert_ne!(*key, keys::CLIENT_SECRET, "{preset}");
            }
        }
    }

    /// Every preset that claims to be usable produces a configuration that
    /// parses, once the operator adds the client identifier. This is the whole
    /// value of a preset: an issuer or a key set URL written wrong configures
    /// cleanly and fails at the first login.
    #[test]
    fn every_usable_preset_parses_with_only_a_client_id_added() {
        for preset in BrokerPreset::ALL {
            let parsed = OidcBrokerConfig::from_attributes(Some(&bag(*preset)));
            if *preset == BrokerPreset::MicrosoftEntra {
                assert!(
                    parsed.is_err(),
                    "the directory endpoints have to be supplied"
                );
                continue;
            }
            if !preset.is_oidc() {
                assert!(
                    parsed.is_err(),
                    "{preset} is not brokered as OpenID Connect"
                );
                continue;
            }
            let parsed = parsed.unwrap_or_else(|e| panic!("{preset} should parse: {e}"));
            assert!(parsed.scopes.contains(&"openid".to_owned()), "{preset}");
            assert!(!parsed.signature_algorithms.is_empty(), "{preset}");
        }
    }

    /// A preset an operator reads shows the scopes actually requested. The
    /// parser adds the identity scope when it is absent, so leaving it out of
    /// the table changes nothing at run time and makes the preset read as if it
    /// asked for less than it does.
    #[test]
    fn every_usable_preset_lists_the_identity_scope() {
        for preset in BrokerPreset::ALL.iter().filter(|p| p.is_oidc()) {
            let scopes = preset
                .defaults()
                .iter()
                .find(|(key, _)| *key == keys::SCOPES)
                .map(|(_, value)| *value)
                .unwrap_or_else(|| panic!("{preset} names no scopes"));
            assert!(
                scopes.split_whitespace().any(|scope| scope == "openid"),
                "{preset} lists {scopes:?}"
            );
        }
    }

    /// Exactly one provider is not brokered as OpenID Connect, and exactly one
    /// mints its own secret. Counted rather than asserted per provider, since
    /// the failure is a provider nobody classified.
    #[test]
    fn exactly_one_provider_sits_outside_each_rule() {
        assert_eq!(BrokerPreset::ALL.iter().filter(|p| !p.is_oidc()).count(), 1);
        assert!(!BrokerPreset::GitHub.is_oidc());

        assert_eq!(
            BrokerPreset::ALL
                .iter()
                .filter(|p| p.secret_is_a_minted_assertion())
                .count(),
            1
        );
        assert!(BrokerPreset::Apple.secret_is_a_minted_assertion());
    }

    /// Every endpoint a preset fixes is an absolute HTTPS URL. A preset exists
    /// to be the value nobody has to check, so it is checked here once.
    #[test]
    fn every_fixed_endpoint_is_an_absolute_https_url() {
        for preset in BrokerPreset::ALL {
            for (key, value) in preset.defaults() {
                if matches!(
                    *key,
                    keys::ISSUER
                        | keys::AUTHORIZATION_ENDPOINT
                        | keys::TOKEN_ENDPOINT
                        | keys::JWKS_URI
                        | keys::USERINFO_ENDPOINT
                ) {
                    let url = url::Url::parse(value)
                        .unwrap_or_else(|_| panic!("{preset} {key} is not a URL: {value}"));
                    assert_eq!(url.scheme(), "https", "{preset} {key}");
                    assert!(url.host_str().is_some(), "{preset} {key}");
                }
            }
        }
    }
}
