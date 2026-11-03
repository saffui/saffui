//! The proxies in front of the deployment. Only a peer named here is
//! believed when it says who a request comes from.

pub(crate) const TRUSTED_PROXIES: &str = "SAFFUI_TRUSTED_PROXIES";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{TRUSTED_PROXIES}: {0:?} is not an address: write addresses separated by commas")]
pub(crate) struct TrustedProxiesError(String);

/// Reads the proxies whose word on the caller is believed. Unset, none is:
/// the peer of a connection is then the caller.
pub(crate) fn resolve_trusted_proxies(
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<Vec<std::net::IpAddr>, TrustedProxiesError> {
    let Some(written) = read_variable(TRUSTED_PROXIES) else {
        return Ok(Vec::new());
    };
    written
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse()
                .map_err(|_| TrustedProxiesError(entry.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{TRUSTED_PROXIES, TrustedProxiesError, resolve_trusted_proxies};

    #[test]
    fn the_trusted_proxies_are_addresses_and_nothing_is_trusted_unsaid() {
        let read = |written: Option<&'static str>| {
            resolve_trusted_proxies(move |name| {
                (name == TRUSTED_PROXIES)
                    .then_some(written)
                    .flatten()
                    .map(str::to_owned)
            })
        };

        assert_eq!(read(None), Ok(Vec::new()));
        assert_eq!(
            read(Some("10.0.0.1, ::1")),
            Ok(vec![
                "10.0.0.1".parse().expect("an address"),
                "::1".parse().expect("an address")
            ])
        );
        assert_eq!(
            read(Some("10.0.0.0/8")),
            Err(TrustedProxiesError("10.0.0.0/8".to_owned())),
            "a range is not read as an address: it is refused, not guessed"
        );
    }
}
