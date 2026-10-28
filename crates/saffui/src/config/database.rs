//! How the database is reached. The connection string may carry a password:
//! it is read from the environment only, never from an option, and no error
//! here repeats it.

use std::path::PathBuf;

use pgcore::connect::{ConnectionPlan, ConnectionPolicyError, TlsMode, plan_connection};
use pgcore::pool::PoolSettings;

use crate::config::serving::{Setting, Unreadable, resolve_setting};

/// The connection string of the role a node serves under.
pub(crate) const DATABASE_URL: &str = "SAFFUI_DATABASE_URL";
/// The connection string of the role that owns the schema, for `migrate`.
pub(crate) const MIGRATION_DATABASE_URL: &str = "SAFFUI_MIGRATION_DATABASE_URL";
pub(crate) const DATABASE_TLS_OPTION: &str = "--database-tls";
pub(crate) const DATABASE_TLS: &str = "SAFFUI_DATABASE_TLS";
pub(crate) const DATABASE_CA_FILE: &str = "SAFFUI_DATABASE_CA_FILE";

pub(crate) const DATABASE_POOL_SIZE: Setting<usize> = Setting {
    option: "--database-pool-size",
    variable: "SAFFUI_DATABASE_POOL_SIZE",
    default: 20,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DatabaseSettingsError {
    #[error("{0} is required: the connection string of the database")]
    Missing(&'static str),
    #[error("{}: {:?} is not a TLS mode, expected disable, require or verify-full", .0.setting, .0.value)]
    UnreadableTlsMode(Unreadable),
    #[error("{}: {:?} is not a number of connections above zero", .0.setting, .0.value)]
    UnreadablePoolSize(Unreadable),
    #[error("{variable}: {source}")]
    Policy {
        variable: &'static str,
        source: ConnectionPolicyError,
    },
}

/// Resolves the connection named by `url_variable` under the one policy.
pub(crate) fn resolve_connection(
    url_variable: &'static str,
    tls_option: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<ConnectionPlan, DatabaseSettingsError> {
    let url = read_variable(url_variable).ok_or(DatabaseSettingsError::Missing(url_variable))?;
    let tls_mode = match tls_option {
        Some(value) => Some((DATABASE_TLS_OPTION, value.to_owned())),
        None => read_variable(DATABASE_TLS).map(|value| (DATABASE_TLS, value)),
    }
    .map(|(setting, value)| {
        value
            .parse::<TlsMode>()
            .map_err(|()| DatabaseSettingsError::UnreadableTlsMode(Unreadable { setting, value }))
    })
    .transpose()?;
    let ca_file = read_variable(DATABASE_CA_FILE).map(PathBuf::from);
    plan_connection(&url, tls_mode, ca_file)
        .map(|plan| plan.named("saffui"))
        .map_err(|source| DatabaseSettingsError::Policy {
            variable: url_variable,
            source,
        })
}

pub(crate) fn resolve_pool_settings(
    pool_size_option: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<PoolSettings, DatabaseSettingsError> {
    let max_size = resolve_setting(&DATABASE_POOL_SIZE, pool_size_option, read_variable)
        .map_err(DatabaseSettingsError::UnreadablePoolSize)?;
    if max_size == 0 {
        return Err(DatabaseSettingsError::UnreadablePoolSize(Unreadable {
            setting: DATABASE_POOL_SIZE.variable,
            value: "0".to_owned(),
        }));
    }
    Ok(PoolSettings {
        max_size,
        ..PoolSettings::default()
    })
}

#[cfg(test)]
mod tests {
    use super::{DATABASE_URL, DatabaseSettingsError, resolve_connection, resolve_pool_settings};

    fn only(name: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |asked| (asked == name).then(|| value.to_owned())
    }

    #[test]
    fn a_missing_connection_string_is_named_by_its_variable() {
        let missing = resolve_connection(DATABASE_URL, None, |_| None);
        assert!(matches!(
            missing,
            Err(DatabaseSettingsError::Missing("SAFFUI_DATABASE_URL"))
        ));
    }

    #[test]
    fn a_refusal_of_the_policy_never_repeats_the_connection_string() {
        let secret = "host=db.internal user=saffui_app password=hunter2";
        let refused = resolve_connection(DATABASE_URL, None, only(DATABASE_URL, secret))
            .expect_err("a remote host without a TLS mode");

        let told = refused.to_string();
        assert!(told.contains("SAFFUI_DATABASE_URL"), "{told}");
        assert!(!told.contains("hunter2"), "{told}");
    }

    #[test]
    fn an_unknown_tls_mode_is_named_with_where_it_was_read() {
        let refused = resolve_connection(
            DATABASE_URL,
            Some("prefer"),
            only(DATABASE_URL, "host=127.0.0.1"),
        )
        .expect_err("a mode that is not one of the three");

        assert_eq!(
            refused.to_string(),
            "--database-tls: \"prefer\" is not a TLS mode, expected disable, require or verify-full"
        );
    }

    #[test]
    fn a_pool_of_zero_connections_is_refused() {
        assert!(resolve_pool_settings(Some("0"), |_| None).is_err());
        assert_eq!(
            resolve_pool_settings(None, |_| None)
                .map(|pool| pool.max_size)
                .ok(),
            Some(20)
        );
    }
}
