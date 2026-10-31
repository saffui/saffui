//! The discovery document. It never lies: a field is published the day the
//! realm honors it, and not before.

use serde::Serialize;

use crate::settings::Settings;
use crate::tenancy::RealmName;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderMetadata {
    pub issuer: String,
}

/// The issuer of a realm: the public origin, then the realm, and nothing else.
#[must_use]
pub fn name_issuer(settings: &Settings, realm: &RealmName) -> String {
    format!("{}/realms/{realm}", settings.public_origin)
}

#[must_use]
pub fn describe_provider(settings: &Settings, realm: &RealmName) -> ProviderMetadata {
    ProviderMetadata {
        issuer: name_issuer(settings, realm),
    }
}

#[cfg(test)]
mod tests {
    use super::name_issuer;
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
}
