use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::brokering::UserFederationModel;

/// Where the sealed bind secret lives in the bag; the clear key never lands.
pub const SEALED_BIND: &str = "bind_password_sealed";
pub const CLEAR_BIND: &str = "bind_password";
/// What the sealed bind secret is scoped to.
pub const PURPOSE: &str = "user-federation-bind";
/// The one row a realm holds, which is also the seal's name.
pub const SINGLETON: &str = "federation";

/// The place a username lands in the search filter.
pub const USERNAME_MARK: &str = "{username}";

/// A directory connection, read the way a login will read it.
#[derive(Debug, Clone)]
pub struct LdapSettings {
    pub url: String,
    pub bind_dn: String,
    pub users_dn: String,
    /// RFC 4515, with [`USERNAME_MARK`] where the asked name lands, escaped.
    pub user_filter: String,
    pub username_attribute: String,
    pub email_attribute: String,
    pub first_name_attribute: String,
    pub last_name_attribute: String,
}

/// Why a federation bag could not be read as a directory.
#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

impl LdapSettings {
    /// Read the bag fail-closed: what decides whether somebody signs in is
    /// parsed at the door, not at their sign-in.
    pub fn parse(federation: &UserFederationModel) -> Result<Self, Unusable> {
        let bag = federation
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a directory names its connection"))?;
        let text = |key: &'static str| {
            bag.get(key)
                .and_then(AttributeValue::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let url = text("url")
            .ok_or(Unusable::Missing("url names the directory"))?
            .to_owned();
        if !url.starts_with("ldap://") && !url.starts_with("ldaps://") {
            return Err(Unusable::Malformed("url is ldap:// or ldaps://"));
        }
        let bind_dn = text("bind_dn")
            .ok_or(Unusable::Missing("bind_dn names who searches"))?
            .to_owned();
        let users_dn = text("users_dn")
            .ok_or(Unusable::Missing("users_dn names where people live"))?
            .to_owned();
        let user_filter = text("user_filter").unwrap_or("(uid={username})").to_owned();
        if !user_filter.contains(USERNAME_MARK) {
            return Err(Unusable::Malformed(
                "user_filter carries {username} where the asked name lands",
            ));
        }
        let attribute = |key: &'static str, resting: &str| text(key).unwrap_or(resting).to_owned();
        Ok(Self {
            url,
            bind_dn,
            users_dn,
            user_filter,
            username_attribute: attribute("username_attribute", "uid"),
            email_attribute: attribute("email_attribute", "mail"),
            first_name_attribute: attribute("first_name_attribute", "givenName"),
            last_name_attribute: attribute("last_name_attribute", "sn"),
        })
    }

    /// The search filter for one asked name, escaped so the name is a value
    /// and never more filter: RFC 4515 §3.
    pub fn filter_for(&self, username: &str) -> String {
        self.user_filter.replace(USERNAME_MARK, &escaped(username))
    }
}

/// RFC 4515 escaping: the five bytes that would let a name grow the filter.
fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'\\' => out.push_str("\\5c"),
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            0 => out.push_str("\\00"),
            other => out.push(other as char),
        }
    }
    out
}

/// Strip what an answer never carries: even sealed, the bytes are the
/// deployment's, and the clear key should never have landed.
pub fn presentable(mut federation: UserFederationModel) -> UserFederationModel {
    if let Some(bag) = federation.configs.as_mut() {
        bag.remove(SEALED_BIND);
        bag.remove(CLEAR_BIND);
    }
    federation
}

/// Keep only what a bag may hold, spelled: an unknown key is a typo the
/// operator finds now, not at somebody's sign-in.
pub fn check_bag(bag: &AttributesMap) -> Result<(), Unusable> {
    const KNOWN: [&str; 10] = [
        "url",
        "bind_dn",
        CLEAR_BIND,
        SEALED_BIND,
        "users_dn",
        "user_filter",
        "username_attribute",
        "email_attribute",
        "first_name_attribute",
        "last_name_attribute",
    ];
    for key in bag.keys() {
        if !KNOWN.contains(&key.as_str()) {
            return Err(Unusable::Malformed(
                "the bag holds a key no directory reads",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five bytes stay values; a plain name passes through whole.
    #[test]
    fn a_name_never_grows_the_filter() {
        let mut federation = UserFederationModel {
            realm_id: "main".into(),
            enabled: Some(true),
            configs: Some(AttributesMap::from([
                ("url".to_owned(), AttributeValue::Str("ldap://x".into())),
                ("bind_dn".to_owned(), AttributeValue::Str("cn=admin".into())),
                (
                    "users_dn".to_owned(),
                    AttributeValue::Str("ou=users".into()),
                ),
            ])),
            metadata: models::auditable::AuditableModel::unassigned(),
        };
        let settings = LdapSettings::parse(&federation).expect("a readable bag");
        assert_eq!(settings.filter_for("bob"), "(uid=bob)");
        assert_eq!(
            settings.filter_for("*)(uid=admin"),
            "(uid=\\2a\\29\\28uid=admin)"
        );

        // A filter without the mark is refused at the door.
        federation.configs.as_mut().expect("the bag").insert(
            "user_filter".to_owned(),
            AttributeValue::Str("(uid=bob)".into()),
        );
        assert!(LdapSettings::parse(&federation).is_err());
    }
}
