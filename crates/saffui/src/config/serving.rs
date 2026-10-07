//! How `serve` is set: where each plane listens, and how long it keeps
//! serving once asked to stop. Each setting is read from its option, then
//! from its environment variable, then from its default.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use server::serve::DEFAULT_DRAIN_DELAY_SECONDS;

/// The three places the value of one setting can come from.
pub(crate) struct Setting<T> {
    pub(crate) option: &'static str,
    pub(crate) variable: &'static str,
    pub(crate) default: T,
}

pub(crate) const DATA_PLANE: Setting<SocketAddr> = Setting {
    option: "--listen",
    variable: "SAFFUI_LISTEN",
    default: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
};

pub(crate) const OPS_PLANE: Setting<SocketAddr> = Setting {
    option: "--ops-listen",
    variable: "SAFFUI_OPS_LISTEN",
    default: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
};

/// In whole seconds. 0 stops the data plane the moment readiness fails.
pub(crate) const DRAIN_DELAY: Setting<u64> = Setting {
    option: "--drain-delay",
    variable: "SAFFUI_DRAIN_DELAY",
    default: DEFAULT_DRAIN_DELAY_SECONDS,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServingSettings {
    pub(crate) data: SocketAddr,
    pub(crate) ops: SocketAddr,
    pub(crate) drain_delay_seconds: u64,
}

/// A value that cannot be read, and the option or variable it was read from.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unreadable {
    pub(crate) setting: &'static str,
    pub(crate) value: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServingSettingsError {
    /// A value that is not a socket address.
    UnreadableAddress(Unreadable),
    /// A value that is not a whole number of seconds.
    UnreadableDelay(Unreadable),
    /// One address given to both planes.
    SharedAddress(SocketAddr),
}

impl fmt::Display for ServingSettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug form of a value: read from the environment, it reaches a terminal escaped.
        match self {
            Self::UnreadableAddress(Unreadable { setting, value }) => write!(
                formatter,
                "{setting}: {value:?} is not a socket address, expected IP:PORT"
            ),
            Self::UnreadableDelay(Unreadable { setting, value }) => write!(
                formatter,
                "{setting}: {value:?} is not a whole number of seconds"
            ),
            Self::SharedAddress(address) => write!(
                formatter,
                "the data plane ({}, {}) and the operations plane ({}, {}) cannot share {address}",
                DATA_PLANE.option, DATA_PLANE.variable, OPS_PLANE.option, OPS_PLANE.variable
            ),
        }
    }
}

/// Resolves every setting of `serve`. The environment is a parameter, so the
/// rule is tested without touching the process.
pub(crate) fn resolve_serving_settings(
    listen_option: Option<&str>,
    ops_listen_option: Option<&str>,
    drain_delay_option: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<ServingSettings, ServingSettingsError> {
    let data = resolve_setting(&DATA_PLANE, listen_option, &read_variable)
        .map_err(ServingSettingsError::UnreadableAddress)?;
    let ops = resolve_setting(&OPS_PLANE, ops_listen_option, &read_variable)
        .map_err(ServingSettingsError::UnreadableAddress)?;
    let drain_delay_seconds = resolve_setting(&DRAIN_DELAY, drain_delay_option, &read_variable)
        .map_err(ServingSettingsError::UnreadableDelay)?;

    // Port 0 asks the system for a free port: two such addresses never collide.
    if data.port() != 0 && data == ops {
        return Err(ServingSettingsError::SharedAddress(data));
    }
    Ok(ServingSettings {
        data,
        ops,
        drain_delay_seconds,
    })
}

fn resolve_setting<T: FromStr + Copy>(
    setting: &Setting<T>,
    option_value: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<T, Unreadable> {
    let (source, value) = if let Some(value) = option_value {
        (setting.option, value.to_owned())
    } else if let Some(value) = read_variable(setting.variable) {
        (setting.variable, value)
    } else {
        return Ok(setting.default);
    };
    value.parse().map_err(|_| Unreadable {
        setting: source,
        value,
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{ServingSettingsError, Unreadable, resolve_serving_settings};

    fn no_variable(_name: &str) -> Option<String> {
        None
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    fn unreadable(setting: &'static str, value: &str) -> Unreadable {
        Unreadable {
            setting,
            value: value.to_owned(),
        }
    }

    #[test]
    fn nothing_given_resolves_to_two_loopback_addresses_and_a_delay_of_5_seconds() {
        let settings =
            resolve_serving_settings(None, None, None, no_variable).expect("the defaults resolve");

        assert_eq!(settings.data, address("127.0.0.1:8080"));
        assert_eq!(settings.ops, address("127.0.0.1:8081"));
        assert_eq!(settings.drain_delay_seconds, 5);
    }

    #[test]
    fn a_variable_is_used_when_its_option_is_absent() {
        let read_variable = |name: &str| match name {
            "SAFFUI_LISTEN" => Some("127.0.0.1:7001".to_owned()),
            "SAFFUI_OPS_LISTEN" => Some("127.0.0.1:7002".to_owned()),
            "SAFFUI_DRAIN_DELAY" => Some("9".to_owned()),
            _ => None,
        };

        let settings = resolve_serving_settings(None, None, None, read_variable)
            .expect("the variables resolve");

        assert_eq!(settings.data, address("127.0.0.1:7001"));
        assert_eq!(settings.ops, address("127.0.0.1:7002"));
        assert_eq!(settings.drain_delay_seconds, 9);
    }

    #[test]
    fn an_option_wins_over_its_variable() {
        // Every variable holds a value that cannot be read: read first, it would refuse.
        let read_variable = |_name: &str| Some("not a value".to_owned());

        let settings = resolve_serving_settings(
            Some("127.0.0.1:7001"),
            Some("127.0.0.1:7002"),
            Some("9"),
            read_variable,
        )
        .expect("the options resolve");

        assert_eq!(settings.data, address("127.0.0.1:7001"));
        assert_eq!(settings.ops, address("127.0.0.1:7002"));
        assert_eq!(settings.drain_delay_seconds, 9);
    }

    #[test]
    fn an_unreadable_address_is_refused_with_the_setting_it_came_from() {
        assert_eq!(
            resolve_serving_settings(Some("nope"), None, None, no_variable),
            Err(ServingSettingsError::UnreadableAddress(unreadable(
                "--listen", "nope"
            )))
        );

        let read_variable =
            |name: &str| (name == "SAFFUI_OPS_LISTEN").then(|| "localhost".to_owned());
        assert_eq!(
            resolve_serving_settings(None, None, None, read_variable),
            Err(ServingSettingsError::UnreadableAddress(unreadable(
                "SAFFUI_OPS_LISTEN",
                "localhost"
            )))
        );
    }

    #[test]
    fn a_delay_that_is_not_a_whole_number_of_seconds_is_refused_with_its_setting() {
        for value in ["soon", "1.5", "-1", "5s"] {
            assert_eq!(
                resolve_serving_settings(None, None, Some(value), no_variable),
                Err(ServingSettingsError::UnreadableDelay(unreadable(
                    "--drain-delay",
                    value
                )))
            );
        }

        let read_variable = |name: &str| (name == "SAFFUI_DRAIN_DELAY").then(|| "soon".to_owned());
        assert_eq!(
            resolve_serving_settings(None, None, None, read_variable),
            Err(ServingSettingsError::UnreadableDelay(unreadable(
                "SAFFUI_DRAIN_DELAY",
                "soon"
            )))
        );
    }

    #[test]
    fn a_delay_of_0_is_accepted() {
        let settings = resolve_serving_settings(None, None, Some("0"), no_variable)
            .expect("a delay of 0 resolves");

        assert_eq!(settings.drain_delay_seconds, 0);
    }

    #[test]
    fn an_empty_variable_is_unreadable_and_does_not_fall_back_to_the_default() {
        let read_variable = |name: &str| (name == "SAFFUI_LISTEN").then(String::new);
        assert_eq!(
            resolve_serving_settings(None, None, None, read_variable),
            Err(ServingSettingsError::UnreadableAddress(unreadable(
                "SAFFUI_LISTEN",
                ""
            )))
        );

        let read_variable = |name: &str| (name == "SAFFUI_DRAIN_DELAY").then(String::new);
        assert_eq!(
            resolve_serving_settings(None, None, None, read_variable),
            Err(ServingSettingsError::UnreadableDelay(unreadable(
                "SAFFUI_DRAIN_DELAY",
                ""
            )))
        );
    }

    #[test]
    fn one_address_for_both_planes_is_refused() {
        assert_eq!(
            resolve_serving_settings(
                Some("127.0.0.1:7001"),
                Some("127.0.0.1:7001"),
                None,
                no_variable
            ),
            Err(ServingSettingsError::SharedAddress(address(
                "127.0.0.1:7001"
            )))
        );
    }

    #[test]
    fn port_0_given_to_both_planes_is_not_one_address_shared() {
        let settings =
            resolve_serving_settings(Some("127.0.0.1:0"), Some("127.0.0.1:0"), None, no_variable)
                .expect("each plane gets a free port of its own");

        assert_eq!(settings.data, address("127.0.0.1:0"));
        assert_eq!(settings.ops, address("127.0.0.1:0"));
    }
}
