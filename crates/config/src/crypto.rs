//! Building a [`CryptoConfig`] from the environment.

use crypto::provider::CryptoConfig;

use crate::ConfigError;

/// Read the crypto configuration.
///
/// Nothing is discovered and nothing is guessed: FIPS is off unless asked for,
/// and the key store is the software one unless a token is named.
pub fn from_env() -> Result<CryptoConfig, ConfigError> {
    Ok(CryptoConfig {
        fips_required: crate::flag("CRYPTO_FIPS_REQUIRED", false)?,
        pkcs11: pkcs11_from_env()?,
    })
}

/// The token, when one is configured.
///
/// The module path is what decides. A PIN or a slot on their own configure
/// nothing, and silently ignoring them would leave an operator believing the
/// token is in use — so they are an error instead.
fn pkcs11_from_env() -> Result<Option<crypto::provider::Pkcs11Config>, ConfigError> {
    let Some(module) = crate::optional("CRYPTO_PKCS11_MODULE") else {
        for orphan in ["CRYPTO_PKCS11_PIN", "CRYPTO_PKCS11_SLOT"] {
            if crate::optional(orphan).is_some() {
                return Err(ConfigError::Missing {
                    key: format!("{}CRYPTO_PKCS11_MODULE", crate::PREFIX),
                });
            }
        }
        return Ok(None);
    };

    Ok(Some(crypto::provider::Pkcs11Config {
        module,
        slot: match crate::optional("CRYPTO_PKCS11_SLOT") {
            Some(_) => Some(crate::parse_or("CRYPTO_PKCS11_SLOT", 0u64)?),
            None => None,
        },
        pin: crate::secret("CRYPTO_PKCS11_PIN")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::{clear, env_guard, set};

    /// Nothing set is the software store with FIPS off.
    #[test]
    fn an_empty_environment_is_the_default() {
        let _guard = env_guard();

        clear(&["CRYPTO_FIPS_REQUIRED"]);

        let config = from_env().unwrap();

        assert!(!config.fips_required);
    }

    /// FIPS is read, and a value that is neither is refused.
    #[test]
    fn fips_is_read_and_checked() {
        let _guard = env_guard();

        for (written, expected) in [("true", true), ("1", true), ("no", false), ("FALSE", false)] {
            set("CRYPTO_FIPS_REQUIRED", written);
            assert_eq!(from_env().unwrap().fips_required, expected, "{written}");
        }

        set("CRYPTO_FIPS_REQUIRED", "perhaps");
        assert!(matches!(from_env(), Err(ConfigError::Invalid { .. })));

        clear(&["CRYPTO_FIPS_REQUIRED"]);
    }

    /// A token is used only when its module is named.
    #[test]
    fn a_token_needs_its_module_named() {
        let _guard = env_guard();

        clear(&[
            "CRYPTO_PKCS11_MODULE",
            "CRYPTO_PKCS11_PIN",
            "CRYPTO_PKCS11_SLOT",
        ]);
        assert!(from_env().unwrap().pkcs11.is_none());

        // A PIN alone configures nothing. Ignoring it would leave an operator
        // believing the token is in use.
        set("CRYPTO_PKCS11_PIN", "1234");
        assert!(matches!(from_env(), Err(ConfigError::Missing { .. })));

        set("CRYPTO_PKCS11_MODULE", "/opt/lib/token.so");
        let token = from_env().unwrap().pkcs11.unwrap();
        assert_eq!(token.module, "/opt/lib/token.so");
        assert_eq!(token.slot, None);

        set("CRYPTO_PKCS11_SLOT", "7");
        assert_eq!(from_env().unwrap().pkcs11.unwrap().slot, Some(7));

        set("CRYPTO_PKCS11_SLOT", "first");
        assert!(matches!(from_env(), Err(ConfigError::Invalid { .. })));

        clear(&[
            "CRYPTO_PKCS11_MODULE",
            "CRYPTO_PKCS11_PIN",
            "CRYPTO_PKCS11_SLOT",
        ]);
    }
}
