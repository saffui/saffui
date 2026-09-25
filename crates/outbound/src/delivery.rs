//! A message on its way out: sent by whatever this deployment sends with, and
//! the attempt kept as a receipt either way.

use auth::messaging::{Outgoing, OutgoingText};
use chrono::Utc;
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use models::messaging::Delivery;
use store::tenancy::{Tenancy, TenantContext};

use crate::Sealing;

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
    if services::messaging::delivery::record_delivery(&transaction, &receipt)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!("a delivery could not be recorded");
    }
    delivered
}

/// Send a text, and say nothing back. The mail rail's twin: the attempt is a
/// row either way, because a person saying the code never came otherwise
/// leaves nothing behind that outlives the log.
pub async fn deliver_text(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    outgoing: OutgoingText,
) {
    let outcome = match sealing.texter.as_deref() {
        None => {
            tracing::warn!("a step produced a text and this deployment sends none");
            Err("this deployment sends no texts".to_owned())
        }
        Some(texter) => texter
            .text(&outgoing.settings, &outgoing.text)
            .await
            .map_err(|why| why.to_string()),
    };
    if let Err(why) = &outcome {
        tracing::warn!(to = outgoing.text.to, why, "a text was not sent");
    }

    let Ok(drawn) = drawn_id(sealing.provider.as_ref()) else {
        return;
    };
    let receipt = Delivery {
        delivery_id: drawn,
        user_id: outgoing.about.user_id,
        purpose: outgoing.about.purpose,
        recipient: outgoing.text.to,
        attempted_at: Utc::now(),
        delivered: outcome.is_ok(),
        detail: outcome.err(),
    };
    // Its own transaction, for the reason the mail receipt takes one.
    let Ok(transaction) = tenancy.begin(context).await else {
        tracing::warn!("a delivery could not be recorded");
        return;
    };
    if services::messaging::delivery::record_delivery(&transaction, &receipt)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!("a delivery could not be recorded");
    }
}

/// Send whichever kind one step produced.
pub async fn deliver_outbound(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    outbound: auth::messaging::Outbound,
) {
    match outbound {
        auth::messaging::Outbound::Mail(outgoing) => {
            deliver(sealing, tenancy, context, outgoing).await;
        }
        auth::messaging::Outbound::Text(outgoing) => {
            deliver_text(sealing, tenancy, context, outgoing).await;
        }
    }
}

fn drawn_id(provider: &dyn CryptoProvider) -> Result<String, ()> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    Ok(HEXLOWER.encode(&drawn))
}
