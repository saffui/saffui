use auth::messaging::OutgoingText;
use chrono::Utc;
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Pool;
use models::messaging::Delivery;
use store::providers::deliveries;
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;

/// Send a text, and say nothing back. The mail rail's twin: the attempt is a
/// row either way, because a person saying the code never came otherwise
/// leaves nothing behind that outlives the log.
pub async fn deliver_text(
    sealing: &Sealing,
    pool: &Pool,
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
    let Ok(mut connection) = pool.get().await else {
        tracing::warn!("a delivery could not be recorded");
        return;
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, context).await else {
        tracing::warn!("a delivery could not be recorded");
        return;
    };
    if deliveries::record(&transaction, &receipt).await.is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!("a delivery could not be recorded");
    }
}

/// Send whichever kind one step produced.
pub async fn deliver_outbound(
    sealing: &Sealing,
    pool: &Pool,
    tenancy: &Tenancy,
    context: &TenantContext,
    outbound: auth::messaging::Outbound,
) {
    match outbound {
        auth::messaging::Outbound::Mail(outgoing) => {
            super::mail::deliver(sealing, pool, tenancy, context, outgoing).await;
        }
        auth::messaging::Outbound::Text(outgoing) => {
            deliver_text(sealing, pool, tenancy, context, outgoing).await;
        }
    }
}

fn drawn_id(provider: &dyn CryptoProvider) -> Result<String, ()> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    Ok(HEXLOWER.encode(&drawn))
}
