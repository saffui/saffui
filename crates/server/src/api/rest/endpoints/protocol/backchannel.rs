use std::time::Duration;

use services::logout::Notice;

/// How long one client gets to answer. §2.8 says not to wait on clients;
/// this is how long "not" is.
const PATIENCE: Duration = Duration::from_secs(5);

/// Post every notice, all at once, and say how each went.
pub async fn deliver(notices: Vec<Notice>) {
    if notices.is_empty() {
        return;
    }
    tracing::info!(clients = notices.len(), "telling clients a login ended");
    let posting = notices.into_iter().map(|notice| {
        tokio::task::spawn_blocking(move || {
            // Both named rather than defaulted. The library prefers a TLS
            // provider this build does not carry, and a default it cannot
            // honour is a panic at the first https call. It also trusts a
            // root set of its own over the platform's, and a deployment that
            // added an authority to its system store would find it ignored.
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(PATIENCE))
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .provider(ureq::tls::TlsProvider::NativeTls)
                        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                        .build(),
                )
                .build()
                .new_agent();
            let outcome = agent
                .post(&notice.uri)
                .send_form([("logout_token", notice.logout_token.as_str())]);
            match outcome {
                Ok(response) => tracing::info!(
                    client_id = %notice.client_id,
                    status = response.status().as_u16(),
                    "logout told"
                ),
                Err(error) => tracing::warn!(
                    client_id = %notice.client_id,
                    error = %error,
                    "logout not told"
                ),
            }
        })
    });
    for handle in posting {
        // A telling that could not even be attempted is a client left
        // believing a login is live, so it is on the record like any other.
        if let Err(why) = handle.await {
            tracing::warn!(why = %why, "a logout could not be told at all");
        }
    }
}
