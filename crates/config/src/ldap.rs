use std::net::SocketAddr;
use std::path::PathBuf;

use crate::ConfigError;

const BIND: &str = "LDAP_BIND";
const REALM: &str = "LDAP_REALM";
const BASE_DN: &str = "LDAP_BASE_DN";
const TLS_CERT: &str = "LDAP_TLS_CERT";
const TLS_KEY: &str = "LDAP_TLS_KEY";
const DANGER_PLAINTEXT: &str = "LDAP_DANGER_PLAINTEXT";

/// The LDAP front: a second, read-only door to one realm's people, for
/// software that speaks directory and nothing newer.
#[derive(Debug, Clone, PartialEq)]
pub struct LdapFront {
    pub bind: SocketAddr,
    pub realm_id: String,
    pub base_dn: String,
    /// The certificate and key the listener seals with, or nothing when the
    /// operator has said, by name, that plaintext is what they want.
    pub tls: Option<TlsPaths>,
}

/// Where the listener's certificate and private key live, PEM both.
#[derive(Debug, Clone, PartialEq)]
pub struct TlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl LdapFront {
    /// Absent bind address means no front, which is the resting state: a
    /// listener is a surface, and a deployment should ask for it by name.
    /// A bind address without the realm and base it answers for is a
    /// refusal, not a guess.
    ///
    /// The transport is part of the story: a bind carries a password, so
    /// the listener seals unless the deployment says `danger_plaintext` the
    /// way the federation side already must. Half a key pair is a refusal.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(bind) = crate::optional(BIND) else {
            return Ok(None);
        };
        let bind: SocketAddr = bind.parse().map_err(|_| ConfigError::Invalid {
            key: format!("{}{BIND}", crate::PREFIX),
            expected: "socket address like 0.0.0.0:3389".to_owned(),
        })?;
        let tls = match (crate::optional(TLS_CERT), crate::optional(TLS_KEY)) {
            (Some(certificate), Some(key)) => Some(TlsPaths {
                certificate: certificate.into(),
                key: key.into(),
            }),
            (None, None) => {
                if crate::optional(DANGER_PLAINTEXT).as_deref() != Some("true") {
                    return Err(ConfigError::Invalid {
                        key: format!("{}{TLS_CERT}", crate::PREFIX),
                        expected: format!(
                            "a certificate (with {}{TLS_KEY}), or {}{DANGER_PLAINTEXT}=true to \
                             say plaintext binds are wanted",
                            crate::PREFIX,
                            crate::PREFIX
                        ),
                    });
                }
                None
            }
            (Some(_), None) => {
                return Err(ConfigError::Invalid {
                    key: format!("{}{TLS_KEY}", crate::PREFIX),
                    expected: "the private key that goes with the certificate".to_owned(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::Invalid {
                    key: format!("{}{TLS_CERT}", crate::PREFIX),
                    expected: "the certificate that goes with the key".to_owned(),
                });
            }
        };
        Ok(Some(Self {
            bind,
            realm_id: crate::required(REALM)?,
            base_dn: crate::required(BASE_DN)?,
            tls,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clear, env_guard, set};

    const EVERY: &[&str] = &[BIND, REALM, BASE_DN, TLS_CERT, TLS_KEY, DANGER_PLAINTEXT];

    #[test]
    fn absent_means_off_and_present_means_the_whole_story() {
        let _guard = env_guard();

        clear(EVERY);
        assert_eq!(LdapFront::from_env().unwrap(), None);

        set(BIND, "127.0.0.1:3389");
        set(DANGER_PLAINTEXT, "true");
        assert!(LdapFront::from_env().is_err(), "a door with no realm held");

        set(REALM, "main");
        set(BASE_DN, "dc=id,dc=example");
        assert_eq!(
            LdapFront::from_env().unwrap(),
            Some(LdapFront {
                bind: "127.0.0.1:3389".parse().unwrap(),
                realm_id: "main".into(),
                base_dn: "dc=id,dc=example".into(),
                tls: None,
            })
        );

        set(BIND, "not-an-address");
        assert!(LdapFront::from_env().is_err());

        clear(EVERY);
    }

    #[test]
    fn plaintext_is_asked_for_by_name_and_half_a_key_pair_is_refused() {
        let _guard = env_guard();

        clear(EVERY);
        set(BIND, "127.0.0.1:3389");
        set(REALM, "main");
        set(BASE_DN, "dc=id,dc=example");

        // No certificate and no admission: the deployment does not start.
        let refused = LdapFront::from_env().expect_err("plaintext without the word held");
        assert!(
            refused.to_string().contains("DANGER_PLAINTEXT"),
            "{refused}"
        );

        // The admission, spelled exactly. Anything else is not it.
        set(DANGER_PLAINTEXT, "yes");
        assert!(LdapFront::from_env().is_err(), "'yes' is not the admission");
        set(DANGER_PLAINTEXT, "true");
        assert!(LdapFront::from_env().unwrap().unwrap().tls.is_none());

        // A full pair seals, with or without the admission left behind.
        set(TLS_CERT, "/etc/saffui/ldap.crt");
        set(TLS_KEY, "/etc/saffui/ldap.key");
        let sealed = LdapFront::from_env().unwrap().unwrap();
        assert_eq!(
            sealed.tls,
            Some(TlsPaths {
                certificate: "/etc/saffui/ldap.crt".into(),
                key: "/etc/saffui/ldap.key".into(),
            })
        );

        // Half a pair is a mistake said out loud, not a fallback to plaintext.
        clear(&[TLS_KEY]);
        assert!(LdapFront::from_env().is_err(), "a certificate alone held");
        clear(&[TLS_CERT]);
        set(TLS_KEY, "/etc/saffui/ldap.key");
        assert!(LdapFront::from_env().is_err(), "a key alone held");

        clear(EVERY);
    }
}
