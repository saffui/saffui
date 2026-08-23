//! Building each crate's configuration from the environment.
//!
//! Every variable is read under one prefix, every secret goes through a
//! reference rather than being written inline, and a value that is set but
//! cannot be read is a named failure — not a default quietly taking its place.

use std::str::FromStr;

use secrecy::SecretBox;

pub mod crypto;
pub mod jobs;
pub mod serving;

/// The prefix every variable shares.
pub const PREFIX: &str = "SAFFUI_";

/// Why the configuration could not be built.
///
/// Each names the variable. None carries a value: a secret resolved from one of
/// these would otherwise reach a startup log through the error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{key} is required and not set")]
    Missing { key: String },

    #[error("{key} is set but not a valid {expected}")]
    Invalid { key: String, expected: String },

    #[error("{key}: {source}")]
    Secret {
        key: String,
        source: commons::secret::SecretError,
    },
}

/// A required value.
pub fn required(key: &str) -> Result<String, ConfigError> {
    match read(key) {
        Some(value) => Ok(value),
        None => Err(ConfigError::Missing { key: full(key) }),
    }
}

/// A value that may be absent. Blank counts as absent, since an operator who
/// exported an empty variable did not supply a value.
pub fn optional(key: &str) -> Option<String> {
    read(key)
}

/// A parsed value, or `default` when the variable is not set.
///
/// A variable that *is* set and cannot be parsed is an error. The alternative —
/// falling back to the default — hands the deployment a value the operator did
/// not choose and says nothing, so a typo in a timeout becomes a capacity
/// surprise weeks later.
pub fn parse_or<T>(key: &str, default: T) -> Result<T, ConfigError>
where
    T: FromStr,
{
    match read(key) {
        None => Ok(default),
        Some(value) => value.parse().map_err(|_| ConfigError::Invalid {
            key: full(key),
            expected: std::any::type_name::<T>()
                .rsplit("::")
                .next()
                .unwrap_or("value")
                .to_string(),
        }),
    }
}

/// A required secret, resolved from its reference.
pub fn secret(key: &str) -> Result<SecretBox<String>, ConfigError> {
    let reference = required(key)?;

    commons::secret::resolve(&reference).map_err(|source| ConfigError::Secret {
        key: full(key),
        source,
    })
}

/// A secret that may be absent.
pub fn optional_secret(key: &str) -> Result<Option<SecretBox<String>>, ConfigError> {
    match read(key) {
        None => Ok(None),
        Some(reference) => commons::secret::resolve(&reference)
            .map(Some)
            .map_err(|source| ConfigError::Secret {
                key: full(key),
                source,
            }),
    }
}

/// A boolean, spelled the way operators spell them.
///
/// Lenient about spelling and strict about validity: `1`, `yes` and `on` all
/// mean true, and anything outside the list is an error rather than a silent
/// false — which is how a flag meant to enable something ends up disabled.
pub fn flag(key: &str, default: bool) -> Result<bool, ConfigError> {
    let Some(value) = read(key) else {
        return Ok(default);
    };

    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid {
            key: full(key),
            expected: "boolean".to_string(),
        }),
    }
}

fn full(key: &str) -> String {
    format!("{PREFIX}{key}")
}

fn read(key: &str) -> Option<String> {
    std::env::var(full(key))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard};

    use secrecy::ExposeSecret;

    /// Held for the duration of any test that writes the environment.
    ///
    /// The environment is one per process and `from_env` reads fixed names, so
    /// tests of it cannot be kept apart by naming — two running at once see
    /// each other's variables. Poisoning is stepped over on purpose: one failed
    /// test should not turn every later one red for a reason that is not theirs.
    static ENV: Mutex<()> = Mutex::new(());

    pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Set a variable for the duration of a test.
    pub(crate) fn set(key: &str, value: &str) {
        // SAFETY: the key belongs to one test, so no other thread reads it.
        unsafe { std::env::set_var(full(key), value) };
    }

    pub(crate) fn clear(keys: &[&str]) {
        for key in keys {
            // SAFETY: as above.
            unsafe { std::env::remove_var(full(key)) };
        }
    }

    /// Every variable is read under the prefix, so nothing reaches an unrelated
    /// one that happens to share a name.
    #[test]
    fn a_variable_is_read_under_the_prefix() {
        let _guard = env_guard();

        set("READ_UNDER_PREFIX", "value");
        assert_eq!(optional("READ_UNDER_PREFIX").as_deref(), Some("value"));

        // SAFETY: a name this test owns.
        unsafe { std::env::set_var("READ_WITHOUT_PREFIX", "other") };
        assert_eq!(optional("READ_WITHOUT_PREFIX"), None);

        clear(&["READ_UNDER_PREFIX"]);
    }

    /// Blank is absent: an exported but empty variable supplied no value.
    #[test]
    fn a_blank_variable_is_absent() {
        let _guard = env_guard();

        for blank in ["", "   ", "\t"] {
            set("BLANK", blank);
            assert_eq!(optional("BLANK"), None, "{blank:?}");
            assert!(matches!(
                required("BLANK"),
                Err(ConfigError::Missing { .. })
            ));
        }

        clear(&["BLANK"]);
    }

    /// Surrounding space is not part of a value.
    #[test]
    fn a_value_is_trimmed() {
        let _guard = env_guard();

        set("TRIMMED", "  8080  ");

        assert_eq!(optional("TRIMMED").as_deref(), Some("8080"));
        assert_eq!(parse_or::<u16>("TRIMMED", 1).unwrap(), 8080);

        clear(&["TRIMMED"]);
    }

    /// Unset takes the default; set-but-unreadable is an error.
    ///
    /// This is the whole difference from a reader that falls back: an operator
    /// who wrote a value and got a different one has a deployment that is not
    /// what they configured, with nothing anywhere saying so.
    #[test]
    fn an_unreadable_value_is_an_error_and_not_a_default() {
        let _guard = env_guard();

        clear(&["PARSED"]);
        assert_eq!(parse_or("PARSED", 16u32).unwrap(), 16);

        set("PARSED", "32");
        assert_eq!(parse_or("PARSED", 16u32).unwrap(), 32);

        for wrong in ["sixteen", "1O", "-1", "3.5", "16 32"] {
            set("PARSED", wrong);
            let error = parse_or("PARSED", 16u32).unwrap_err();

            assert!(
                matches!(error, ConfigError::Invalid { .. }),
                "{wrong:?} fell back to the default"
            );
            assert!(error.to_string().contains("SAFFUI_PARSED"), "{wrong:?}");
        }

        clear(&["PARSED"]);
    }

    /// A flag is read the way an operator writes one, and refused otherwise.
    #[test]
    fn a_flag_is_lenient_in_spelling_and_strict_in_validity() {
        let _guard = env_guard();

        clear(&["FLAG"]);
        assert!(flag("FLAG", true).unwrap());

        for written in ["true", "TRUE", "1", "yes", "On"] {
            set("FLAG", written);
            assert!(flag("FLAG", false).unwrap(), "{written}");
        }
        for written in ["false", "0", "no", "OFF"] {
            set("FLAG", written);
            assert!(!flag("FLAG", true).unwrap(), "{written}");
        }

        // Not a silent false, which is how a flag meant to turn something on
        // leaves it off.
        for written in ["y", "enabled", "2", "oui"] {
            set("FLAG", written);
            assert!(
                matches!(flag("FLAG", false), Err(ConfigError::Invalid { .. })),
                "{written} was read as a boolean"
            );
        }

        clear(&["FLAG"]);
    }

    /// A secret arrives as a reference and comes back resolved.
    #[test]
    fn a_secret_is_resolved_from_its_reference() {
        let _guard = env_guard();

        set("SECRET_ENV_SOURCE", "the-value");
        set("SECRET", &format!("env:{PREFIX}SECRET_ENV_SOURCE"));

        assert_eq!(secret("SECRET").unwrap().expose_secret(), "the-value");
        assert_eq!(
            optional_secret("SECRET").unwrap().unwrap().expose_secret(),
            "the-value"
        );

        clear(&["SECRET", "SECRET_ENV_SOURCE"]);
        assert!(matches!(secret("SECRET"), Err(ConfigError::Missing { .. })));
        assert!(optional_secret("SECRET").unwrap().is_none());
    }

    /// An unresolvable reference names the variable and never the value.
    #[test]
    fn a_secret_error_names_the_variable_only() {
        let _guard = env_guard();

        set("BAD_SECRET", "file:/no/such/secret");

        let error = secret("BAD_SECRET").unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, ConfigError::Secret { .. }));
        assert!(message.contains("SAFFUI_BAD_SECRET"));
        assert!(message.contains("/no/such/secret"));

        clear(&["BAD_SECRET"]);
    }
}
