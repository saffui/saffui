//! The public origin. It has no default: every issuer starts with it, and an
//! issuer guessed wrong once is in every token ever minted.

use saffui_core::settings::{PublicOrigin, PublicOriginError};

use crate::config::serving::Unreadable;

pub(crate) const PUBLIC_ORIGIN_OPTION: &str = "--public-origin";
pub(crate) const PUBLIC_ORIGIN: &str = "SAFFUI_PUBLIC_ORIGIN";

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicOriginSettingError {
    #[error(
        "{PUBLIC_ORIGIN_OPTION} or {PUBLIC_ORIGIN} is required: where the public reaches this deployment"
    )]
    Missing,
    #[error("{}: {:?} is not a public origin: {reason}", .unreadable.setting, .unreadable.value)]
    Unreadable {
        unreadable: Unreadable,
        reason: PublicOriginError,
    },
}

pub(crate) fn resolve_public_origin(
    option: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<PublicOrigin, PublicOriginSettingError> {
    let (setting, value) = match option {
        Some(value) => (PUBLIC_ORIGIN_OPTION, value.to_owned()),
        None => (
            PUBLIC_ORIGIN,
            read_variable(PUBLIC_ORIGIN).ok_or(PublicOriginSettingError::Missing)?,
        ),
    };
    PublicOrigin::parse(&value).map_err(|reason| PublicOriginSettingError::Unreadable {
        unreadable: Unreadable { setting, value },
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::{PublicOriginSettingError, resolve_public_origin};

    #[test]
    fn the_option_wins_over_the_variable() {
        let origin = resolve_public_origin(Some("https://a.example.org"), |_| {
            Some("https://b.example.org".to_owned())
        })
        .expect("an origin");

        assert_eq!(origin.as_str(), "https://a.example.org");
    }

    #[test]
    fn there_is_no_default() {
        assert!(matches!(
            resolve_public_origin(None, |_| None),
            Err(PublicOriginSettingError::Missing)
        ));
    }

    #[test]
    fn an_origin_with_a_path_is_refused_and_named_with_where_it_was_read() {
        let refused =
            resolve_public_origin(None, |_| Some("https://id.example.org/auth".to_owned()))
                .expect_err("an origin with a path");

        assert_eq!(
            refused.to_string(),
            "SAFFUI_PUBLIC_ORIGIN: \"https://id.example.org/auth\" is not a public origin: expected https://host or https://host:port, the host in lower case"
        );
    }
}
