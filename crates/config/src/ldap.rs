use std::net::SocketAddr;

use crate::ConfigError;

const BIND: &str = "LDAP_BIND";
const REALM: &str = "LDAP_REALM";
const BASE_DN: &str = "LDAP_BASE_DN";

/// The LDAP front: a second, read-only door to one realm's people, for
/// software that speaks directory and nothing newer.
#[derive(Debug, Clone, PartialEq)]
pub struct LdapFront {
    pub bind: SocketAddr,
    pub realm_id: String,
    pub base_dn: String,
}

impl LdapFront {
    /// Absent bind address means no front, which is the resting state: a
    /// listener is a surface, and a deployment should ask for it by name.
    /// A bind address without the realm and base it answers for is a
    /// refusal, not a guess.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(bind) = crate::optional(BIND) else {
            return Ok(None);
        };
        let bind: SocketAddr = bind.parse().map_err(|_| ConfigError::Invalid {
            key: format!("{}{BIND}", crate::PREFIX),
            expected: "socket address like 0.0.0.0:3389".to_owned(),
        })?;
        Ok(Some(Self {
            bind,
            realm_id: crate::required(REALM)?,
            base_dn: crate::required(BASE_DN)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clear, env_guard, set};

    #[test]
    fn absent_means_off_and_present_means_the_whole_story() {
        let _guard = env_guard();

        clear(&[BIND, REALM, BASE_DN]);
        assert_eq!(LdapFront::from_env().unwrap(), None);

        set(BIND, "127.0.0.1:3389");
        assert!(LdapFront::from_env().is_err(), "a door with no realm held");

        set(REALM, "main");
        set(BASE_DN, "dc=id,dc=example");
        assert_eq!(
            LdapFront::from_env().unwrap(),
            Some(LdapFront {
                bind: "127.0.0.1:3389".parse().unwrap(),
                realm_id: "main".into(),
                base_dn: "dc=id,dc=example".into(),
            })
        );

        set(BIND, "not-an-address");
        assert!(LdapFront::from_env().is_err());

        clear(&[BIND, REALM, BASE_DN]);
    }
}
