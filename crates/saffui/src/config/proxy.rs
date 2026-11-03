//! The proxies in front of the deployment. Only a peer in one of these
//! ranges is believed when it says who a request comes from.

use saffui_core::settings::{AddressRange, AddressRangeError};

pub(crate) const TRUSTED_PROXIES: &str = "SAFFUI_TRUSTED_PROXIES";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "{TRUSTED_PROXIES}: {written:?}: {reason}. Write addresses or ranges (10.0.0.0/8) separated by commas"
)]
pub(crate) struct TrustedProxiesError {
    written: String,
    reason: AddressRangeError,
}

/// Reads the proxies whose word on the caller is believed. Unset, none is:
/// the peer of a connection is then the caller.
pub(crate) fn resolve_trusted_proxies(
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<Vec<AddressRange>, TrustedProxiesError> {
    let Some(written) = read_variable(TRUSTED_PROXIES) else {
        return Ok(Vec::new());
    };
    written
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            AddressRange::parse(entry).map_err(|reason| TrustedProxiesError {
                written: entry.to_owned(),
                reason,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use saffui_core::settings::{AddressRange, AddressRangeError};

    use super::{TRUSTED_PROXIES, TrustedProxiesError, resolve_trusted_proxies};

    #[test]
    fn the_trusted_proxies_are_addresses_or_ranges_and_nothing_is_trusted_unsaid() {
        let read = |written: Option<&'static str>| {
            resolve_trusted_proxies(move |name| {
                (name == TRUSTED_PROXIES)
                    .then_some(written)
                    .flatten()
                    .map(str::to_owned)
            })
        };
        let range = |written: &str| AddressRange::parse(written).expect("a range");

        assert_eq!(read(None), Ok(Vec::new()));
        assert_eq!(
            read(Some("10.0.0.1, ::1, 172.16.0.0/12")),
            Ok(vec![
                range("10.0.0.1"),
                range("::1"),
                range("172.16.0.0/12")
            ])
        );
        let refused = read(Some("10.0.0.1, 0.0.0.0/0")).expect_err("a range too wide");
        assert_eq!(
            refused,
            TrustedProxiesError {
                written: "0.0.0.0/0".to_owned(),
                reason: AddressRangeError::TooWide,
            }
        );
        assert!(
            refused.to_string().contains("SAFFUI_TRUSTED_PROXIES"),
            "{refused}"
        );
    }
}
