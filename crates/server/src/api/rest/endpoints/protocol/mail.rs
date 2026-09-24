use auth::messaging::Outgoing;
use chrono::Utc;
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use models::messaging::Delivery;
use store::providers::events::deliveries;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;

/// Send it, record the attempt, and say whether it went out.
///
/// A request that produced the message tells its caller the same either way, or
/// whether an address exists is readable from how this server answers: only a job
/// that tries again reads the answer.
///
/// The record is a row and not only a log line. A person saying the link never
/// arrived otherwise leaves nothing behind that outlives the log.
pub async fn deliver(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    outgoing: Outgoing,
) -> bool {
    let outcome = match sealing.sender.as_deref() {
        None => {
            tracing::warn!("a step produced a message and this deployment sends nothing");
            Err("this deployment sends nothing".to_owned())
        }
        Some(sender) => sender
            .send(&outgoing.settings, &outgoing.message)
            .await
            .map_err(|why| why.to_string()),
    };
    if let Err(why) = &outcome {
        tracing::warn!(to = outgoing.message.to, why, "a message was not sent");
    }
    let delivered = outcome.is_ok();

    let Ok(drawn) = drawn_id(sealing.provider.as_ref()) else {
        return delivered;
    };
    let receipt = Delivery {
        delivery_id: drawn,
        user_id: outgoing.about.user_id,
        purpose: outgoing.about.purpose,
        recipient: outgoing.message.to,
        attempted_at: Utc::now(),
        delivered,
        detail: outcome.err(),
    };
    // Its own transaction, because the one that produced the message committed
    // before anything was sent. A receipt that cannot be written is logged and
    // dropped: it is a record of the send, not a part of it.
    let Ok(transaction) = tenancy.begin(context).await else {
        tracing::warn!("a delivery could not be recorded");
        return delivered;
    };
    if deliveries::record(&transaction, &receipt).await.is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!("a delivery could not be recorded");
    }
    delivered
}

fn drawn_id(provider: &dyn CryptoProvider) -> Result<String, ()> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    Ok(HEXLOWER.encode(&drawn))
}
