//! The desktop-ticket door, as configuration.
//!
//! The exchange itself lives with the listener; what this module owns is the
//! realm's say-so: whether the door answers, and which service principal the
//! deployment's keytab must speak for.

use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::brokering::RealmSpnegoModel;

/// Why a spnego bag could not be read as a door.
#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

/// What the door needs, parsed fail-closed at the plane: what decides whether
/// somebody signs in is refused at the write, not at their sign-in.
#[derive(Debug, Clone, PartialEq)]
pub struct SpnegoSettings {
    /// The service the keytab speaks for, `HTTP/host@REALM` whole: the realm
    /// tail is what ties an accepted client principal to this door.
    pub service_principal: String,
}

impl SpnegoSettings {
    pub fn parse(spnego: &RealmSpnegoModel) -> Result<Self, Unusable> {
        let bag = spnego
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a door names its service principal"))?;
        let service_principal = bag
            .get("service_principal")
            .and_then(AttributeValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(Unusable::Missing(
                "service_principal names what the keytab speaks for",
            ))?
            .to_owned();
        if !service_principal.contains('/') || !service_principal.contains('@') {
            return Err(Unusable::Malformed(
                "service_principal is service/host@REALM, whole",
            ));
        }
        Ok(Self { service_principal })
    }

    /// The Kerberos realm the service lives in, which is the realm an
    /// accepted client principal must come from: cross-realm trust is a
    /// decision, and nobody has made it here.
    pub fn kerberos_realm(&self) -> &str {
        self.service_principal
            .rsplit('@')
            .next()
            .unwrap_or_default()
    }
}

/// Keep only what a bag may hold, spelled: an unknown key is a typo the
/// operator finds now, not at somebody's sign-in.
pub fn check_bag(bag: &AttributesMap) -> Result<(), Unusable> {
    const KNOWN: [&str; 1] = ["service_principal"];
    for key in bag.keys() {
        if !KNOWN.contains(&key.as_str()) {
            return Err(Unusable::Malformed("the bag holds a key no door reads"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;

    fn row(bag: &[(&str, &str)]) -> RealmSpnegoModel {
        RealmSpnegoModel {
            realm_id: "main".into(),
            enabled: Some(true),
            configs: Some(
                bag.iter()
                    .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).into())))
                    .collect(),
            ),
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        }
    }

    /// The bag parses whole or refuses whole, and the realm tail is readable.
    #[test]
    fn a_bag_parses_whole_or_refuses_whole() {
        let good = row(&[("service_principal", "HTTP/id.example@EXAMPLE.ORG")]);
        let settings = SpnegoSettings::parse(&good).expect("a whole principal parses");
        assert_eq!(settings.kerberos_realm(), "EXAMPLE.ORG");

        let bare = row(&[("service_principal", "HTTP/id.example")]);
        assert!(SpnegoSettings::parse(&bare).is_err(), "no realm tail held");

        let empty = row(&[]);
        assert!(SpnegoSettings::parse(&empty).is_err());

        let stray = row(&[
            ("service_principal", "HTTP/id.example@EXAMPLE.ORG"),
            ("keytab", "/etc/krb5.keytab"),
        ]);
        assert!(
            check_bag(stray.configs.as_ref().unwrap()).is_err(),
            "a key no door reads was kept"
        );
    }
}
