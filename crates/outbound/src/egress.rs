//! Calls this deployment makes outward, under the egress policy: one agent that
//! reaches nothing inside the deployment, and what is fetched with it.

use config::serving::Egress;
use std::net::IpAddr;
use std::time::Duration;
use store::tenancy::{Tenancy, TenantContext};

use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

/// How long the whole fetch gets. A browser is waiting on it.
pub const PATIENCE: Duration = Duration::from_secs(5);

/// The most that will be read. A request object is a handful of claims; past
/// this it is something else.
const CEILING: u64 = 64 * 1024;

/// The most a status list will be read to as served: its statuses travel
/// compressed, a few kilobytes for most lists.
const LIST_CEILING: u64 = 1024 * 1024;

/// What a certificate revocation list must stay under to be read: some twenty
/// octets a serial revoked, and room for the lists of a busy authority.
const REVOCATION_CEILING: u64 = 4 * 1024 * 1024;

/// A resolver that hands back only addresses outside this deployment.
///
/// The check belongs here and not before the request: checked earlier, the
/// name would be resolved twice and the second answer is the one dialled.
#[derive(Debug)]
pub struct Outward(pub DefaultResolver, pub Egress);

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
pub(crate) fn reaches_outward(address: IpAddr) -> bool {
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
pub fn may_dial(uri: &str, egress: Egress) -> bool {
    uri.starts_with("https://") || (egress == Egress::Anywhere && uri.starts_with("http://"))
}

/// An agent that dials outward and nowhere else.
///
/// One builder rather than one per sink. A sink that assembles its own is a
/// sink that can forget the resolver, and a fetch without it is how a server
/// is made to reach its own network on somebody else's behalf. The wait is the
/// caller's: a browser held up by a fetch and a gateway taking a message do not
/// deserve the same patience.
///
/// Both halves of the TLS configuration are named rather than defaulted. The
/// library prefers a provider this build does not carry, and a default it
/// cannot honour is a panic at the first https call. It also trusts a root set
/// of its own over the platform's, and a deployment that added an authority to
/// its system store would find it ignored.
pub fn outward_agent(egress: Egress, patience: Duration) -> ureq::Agent {
    agent(egress, patience, true)
}

/// The same agent, handing back an answer whatever its status: a server
/// speaking OAuth says what went wrong in the body of a 400, and a caller that
/// must tell "not yet" from "no" has to read it.
pub fn outward_agent_reading_refusals(egress: Egress, patience: Duration) -> ureq::Agent {
    agent(egress, patience, false)
}

fn agent(egress: Egress, patience: Duration, status_as_error: bool) -> ureq::Agent {
    ureq::Agent::with_parts(
        ureq::Agent::config_builder()
            .timeout_global(Some(patience))
            .http_status_as_error(status_as_error)
            // A redirect is a second address nobody registered.
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
    )
}

/// What the client hosts at this URI, or nothing.
pub async fn fetch(uri: String, egress: Egress) -> Option<String> {
    fetch_within(uri, egress, None, CEILING).await
}

/// What an issuer publishes at a status list's address, asked for as the
/// media type its format names, or nothing.
pub async fn fetch_status_list(
    uri: String,
    egress: Egress,
    asked_as: Option<&'static str>,
) -> Option<String> {
    fetch_within(uri, egress, asked_as, LIST_CEILING).await
}

/// Whether a revocation list may be read at this address, by its scheme.
///
/// Over plain http as readily as https, whatever the deployment dials: a
/// revocation list is public, names nobody who presents, and is believed for
/// its authority's signature alone, which is why authorities publish them in
/// the clear (RFC 5280 §4.2.1.13).
pub fn may_read_revocations_at(uri: &str) -> bool {
    let scheme = uri.to_ascii_lowercase();
    scheme.starts_with("https://") || scheme.starts_with("http://")
}

/// What an authority publishes at a revocation list's address, or nothing.
/// The resolver still reaches nothing inside a deployment that dials outward.
pub async fn fetch_revocation_list(uri: String, egress: Egress) -> Option<Vec<u8>> {
    if !may_read_revocations_at(&uri) {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let agent = outward_agent(egress, PATIENCE);
        let mut response = agent
            .get(&uri)
            .header("Accept", "application/pkix-crl")
            .call()
            .ok()?;
        if response.status() != 200 {
            return None;
        }
        response
            .body_mut()
            .with_config()
            .limit(REVOCATION_CEILING)
            .read_to_vec()
            .ok()
    })
    .await
    .ok()
    .flatten()
}

async fn fetch_within(
    uri: String,
    egress: Egress,
    asked_as: Option<&'static str>,
    ceiling: u64,
) -> Option<String> {
    if !may_dial(&uri, egress) {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let agent = outward_agent(egress, PATIENCE);
        let mut asked = agent.get(&uri);
        if let Some(media_type) = asked_as {
            asked = asked.header("Accept", media_type);
        }
        let mut response = asked.call().ok()?;
        if response.status() != 200 {
            return None;
        }
        response
            .body_mut()
            .with_config()
            .limit(ceiling)
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
///
/// The reading is claimed first, on a transaction of its own committed at
/// once, so however many requests name the client together its host is asked
/// once while a reading is kept, whether or not each of them is then refused.
/// No transaction is open while the host answers, so no pooled connection
/// waits on it.
pub async fn refresh_client_keys(
    tenancy: &Tenancy,
    context: &TenantContext,
    client_id: &str,
    egress: Egress,
    now: chrono::DateTime<chrono::Utc>,
) {
    let claimed = async {
        let transaction = tenancy.begin(context).await.ok()?;
        let uri = services::client::claim_keys_read(&transaction, client_id, now).await?;
        transaction.commit().await.ok()?;
        Some(uri)
    }
    .await;
    let Some(uri) = claimed else {
        return;
    };
    let Some(document) = fetch(uri, egress).await else {
        return;
    };
    // Left alone when it cannot be read. The set already kept is the last one
    // that was readable, which verifies more than nothing does.
    let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&document) else {
        return;
    };
    let Ok(transaction) = tenancy.begin(context).await else {
        return;
    };
    if services::client::keep_keys(&transaction, client_id, &jwks, now).await {
        let _ = transaction.commit().await;
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

    /// A revocation list is read over plain http, and under the default
    /// policy an address answering with this machine is never dialled at all.
    #[tokio::test]
    async fn a_revocation_list_inside_the_deployment_is_read_from_inside_alone() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("an address").port();
        for host in ["127.0.0.1", "localhost"] {
            let uri = format!("http://{host}:{port}/issuing.crl");
            assert_eq!(
                fetch_revocation_list(uri, Egress::Outward).await,
                None,
                "{host}"
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "the list's host was dialled"
        );

        let served = tokio::spawn(async move {
            let (mut asking, _) = listener.accept().await.expect("a caller");
            let mut asked = [0u8; 1024];
            let _ = asking.read(&mut asked).await;
            asking
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: close\r\n\r\nlist")
                .await
                .expect("answered");
        });
        let uri = format!("http://127.0.0.1:{port}/issuing.crl");
        assert_eq!(
            fetch_revocation_list(uri, Egress::Anywhere).await,
            Some(b"list".to_vec())
        );
        served.await.expect("served");
    }

    #[test]
    fn a_revocation_list_is_read_over_http_or_https_alone() {
        for (named, read) in [
            ("http://ca.example/issuing.crl", true),
            ("https://ca.example/issuing.crl", true),
            ("HTTP://ca.example/issuing.crl", true),
            (
                "ldap://ca.example/cn=issuing?certificateRevocationList",
                false,
            ),
            ("ftp://ca.example/issuing.crl", false),
            ("file:///etc/passwd", false),
            ("/issuing.crl", false),
            ("", false),
        ] {
            assert_eq!(may_read_revocations_at(named), read, "{named}");
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
