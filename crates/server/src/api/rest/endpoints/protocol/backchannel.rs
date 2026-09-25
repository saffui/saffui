use std::time::Duration;

use config::serving::Egress;
use services::oidc::logout::Notice;

use outbound::egress::{may_dial, outward_agent};

/// How long one client gets to answer. §2.8 says not to wait on clients;
/// this is how long "not" is.
const PATIENCE: Duration = Duration::from_secs(5);

/// Post every notice, all at once, and say how each went.
///
/// Where a notice goes is a client's own registration, so it is dialled the way
/// every other address a client supplies is: the egress policy decides the
/// scheme, the resolver refuses addresses inside the deployment, and no
/// redirect is followed. A client that registered somewhere this deployment
/// will not dial goes untold, on the record, rather than turning a logout into
/// a request the deployment makes to itself.
pub async fn deliver(notices: Vec<Notice>, egress: Egress) {
    if notices.is_empty() {
        return;
    }
    tracing::info!(clients = notices.len(), "telling clients a login ended");
    let posting = notices.into_iter().map(|notice| {
        tokio::task::spawn_blocking(move || {
            if !may_dial(&notice.uri, egress) {
                tracing::warn!(
                    client_id = %notice.client_id,
                    "a logout address is not one this egress policy dials"
                );
                return;
            }
            let agent = outward_agent(egress, PATIENCE);
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
