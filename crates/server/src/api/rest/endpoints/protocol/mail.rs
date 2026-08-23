//! Sending what a step produced, once the caller has committed.

use services::messaging::Outgoing;

use crate::api::config::Sealing;

/// Send it, and say nothing back.
///
/// A message that did not go out is on the record and nothing else: the caller
/// is told the same either way, or whether an address exists is readable from
/// how this server answers.
pub async fn deliver(sealing: &Sealing, outgoing: Outgoing) {
    let Some(sender) = sealing.sender.as_deref() else {
        tracing::warn!("a step produced a message and this deployment sends nothing");
        return;
    };
    if sender
        .send(&outgoing.settings, &outgoing.message)
        .await
        .is_err()
    {
        tracing::warn!(to = outgoing.message.to, "a message was not sent");
    }
}
