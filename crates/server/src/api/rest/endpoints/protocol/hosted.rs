//! Fetching a request object the client hosts, OIDC Core §6.2.
//!
//! The address is checked at resolution and the connection is made to exactly
//! the address that passed, so a name that answers publicly once and privately
//! a moment later does not get a second chance. Nothing is followed, nothing
//! unbounded is read, and only what a client registered is ever asked for.

use config::serving::Egress;
use std::net::IpAddr;
use std::time::Duration;

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

/// How long the whole fetch gets. A browser is waiting on it.
const PATIENCE: Duration = Duration::from_secs(5);

/// The most that will be read. A request object is a handful of claims; past
/// this it is something else.
const CEILING: u64 = 64 * 1024;

/// A resolver that hands back only addresses outside this deployment.
///
/// The check belongs here and not before the request: checked earlier, the
/// name would be resolved twice and the second answer is the one dialled.
#[derive(Debug)]
struct Outward(DefaultResolver, Egress);

impl Resolver for Outward {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let resolved = self.0.resolve(uri, config, timeout)?;
        // Every address, not the first: a name answering with one public and
        // one private address would otherwise be reachable by retry.
        if self.1 == Egress::Outward
            && resolved
                .iter()
                .any(|address| !reaches_outward(address.ip()))
        {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(resolved)
    }
}

/// Whether this address is somewhere other than the deployment itself.
fn reaches_outward(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(held) => {
            !held.is_loopback()
                && !held.is_private()
                && !held.is_link_local()
                && !held.is_broadcast()
                && !held.is_documentation()
                && !held.is_unspecified()
                && !held.is_multicast()
                // 100.64/10, which a deployment behind a carrier NAT shares.
                && !(held.octets()[0] == 100 && (64..128).contains(&held.octets()[1]))
                // 192.0.0/24 and 198.18/15, reserved for protocol assignments
                // and for benchmarking between two routers.
                && !(held.octets()[0] == 192 && held.octets()[1] == 0 && held.octets()[2] == 0)
                && !(held.octets()[0] == 198 && (18..20).contains(&held.octets()[1]))
        }
        IpAddr::V6(held) => {
            !held.is_loopback()
                && !held.is_unspecified()
                && !held.is_multicast()
                // fc00::/7, the unique local addresses.
                && held.octets()[0] & 0xfe != 0xfc
                // fe80::/10, link local.
                && !(held.octets()[0] == 0xfe && held.octets()[1] & 0xc0 == 0x80)
                // An address embedding a v4 one is judged as that address.
                && held
                    .to_ipv4_mapped()
                    .is_none_or(|held| reaches_outward(IpAddr::V4(held)))
        }
    }
}

/// Whether this URI may be dialled at all, by its scheme.
///
/// The object is signed, so its integrity does not rest on the transport. Its
/// contents do: a request object carries what the person is being asked about.
/// A deployment reaching outward sends that across the open internet or not at
/// all; one dialling its own network has already said the network is its own.
fn may_dial(uri: &str, egress: Egress) -> bool {
    uri.starts_with("https://") || (egress == Egress::Anywhere && uri.starts_with("http://"))
}

/// What the client hosts at this URI, or nothing.
pub async fn fetch(uri: String, egress: Egress) -> Option<String> {
    if !may_dial(&uri, egress) {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let agent = ureq::Agent::with_parts(
            ureq::Agent::config_builder()
                .timeout_global(Some(PATIENCE))
                // A redirect is a second address the client did not register.
                .max_redirects(0)
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .provider(ureq::tls::TlsProvider::NativeTls)
                        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                        .build(),
                )
                .build(),
            ureq::unversioned::transport::DefaultConnector::new(),
            Outward(DefaultResolver::default(), egress),
        );
        let mut response = agent.get(&uri).call().ok()?;
        if response.status() != 200 {
            return None;
        }
        response
            .body_mut()
            .with_config()
            .limit(CEILING)
            .read_to_string()
            .ok()
    })
    .await
    .ok()
    .flatten()
}

/// Read the key set a client publishes, and keep it, when it is due.
///
/// Before the check and not after it: a client that rotated its keys presents
/// a signature this server cannot verify yet, and re-reading only once that
/// has failed makes the first request after every rotation fail.
pub async fn refresh_client_keys(
    transaction: &deadpool_postgres::Transaction<'_>,
    client_id: &str,
    egress: Egress,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some(uri) = services::client::keys_due(transaction, client_id, now).await else {
        return;
    };
    let Some(document) = fetch(uri, egress).await else {
        return;
    };
    // Left alone when it cannot be read. The set already kept is the last one
    // that was readable, which verifies more than nothing does.
    if let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&document) {
        services::client::keep_keys(transaction, client_id, &jwks, now).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_inside_the_deployment_is_reachable() {
        for named in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                !reaches_outward(named.parse().unwrap()),
                "{named} was treated as somewhere else"
            );
        }
    }

    #[test]
    fn plain_http_is_dialled_only_inside_the_deployment() {
        for (named, outward, anywhere) in [
            ("https://app.example/object", true, true),
            ("http://app.example/object", false, true),
            ("ftp://app.example/object", false, false),
            ("file:///etc/passwd", false, false),
            ("/object", false, false),
        ] {
            assert_eq!(
                may_dial(named, Egress::Outward),
                outward,
                "{named}, outward"
            );
            assert_eq!(
                may_dial(named, Egress::Anywhere),
                anywhere,
                "{named}, anywhere"
            );
        }
    }

    #[test]
    fn a_public_address_is_reachable() {
        for named in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                reaches_outward(named.parse().unwrap()),
                "{named} was treated as this deployment"
            );
        }
    }
}
