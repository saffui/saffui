//! A message on its way out: sent by whatever this deployment sends with, and
//! the attempt kept as a receipt either way.

use auth::messaging::{About, Outgoing, OutgoingText};
use chrono::Utc;
use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use models::entities::sim_swap::WhenUnanswered;
use models::messaging::{Channel, Delivery};
use services::oidc::sign_in::Held;
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
    keep_receipt(
        sealing,
        tenancy,
        context,
        outgoing.about,
        outgoing.message.to,
        Channel::Mail,
        outcome.err(),
    )
    .await;
    delivered
}

/// Which way a message went, or why a code went nowhere on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    By(Channel),
    Nowhere,
    /// The carrier's answer held the code before any way was tried.
    Held(Held),
}

/// Send a text or a code, and say which way it went, if any went.
///
/// Where the realm runs the carrier's guard, the carrier is asked first and a
/// code to a SIM that changed goes nowhere. A code to go by WhatsApp is tried
/// there first, and the realm's gateway carries it when WhatsApp refuses; a
/// text is the gateway's alone. Each attempt keeps a receipt of its own, the
/// mail rail's rule: a person saying the code never came otherwise leaves
/// nothing behind that outlives the log.
pub async fn deliver_text(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    outgoing: OutgoingText,
) -> Sent {
    let OutgoingText {
        settings,
        text,
        whatsapp,
        guard,
        about,
    } = outgoing;

    if let Some(guard) = &guard {
        let meant = if whatsapp.is_some() {
            Channel::WhatsApp
        } else {
            Channel::Sms
        };
        let held = match crate::camara::sim_changed(
            sealing.provider.as_ref(),
            guard,
            &text.to,
            sealing.egress,
        )
        .await
        {
            Ok(false) => None,
            Ok(true) => Some((
                Held::SimSwapped,
                format!(
                    "held: the carrier says the SIM behind this number changed within {} hours",
                    guard.max_age_hours
                ),
            )),
            Err(why) => {
                tracing::warn!(to = text.to, why = %why, "the carrier gave no answer about a SIM");
                match guard.when_unanswered {
                    WhenUnanswered::Hold => Some((
                        Held::Unanswered,
                        format!("held: the carrier gave no answer ({})", why.0),
                    )),
                    WhenUnanswered::Send => {
                        note_silence(tenancy, context, &about, &text.to).await;
                        None
                    }
                }
            }
        };
        if let Some((why, detail)) = held {
            keep_receipt(
                sealing,
                tenancy,
                context,
                about,
                text.to,
                meant,
                Some(detail),
            )
            .await;
            return Sent::Held(why);
        }
    }

    if let Some(code) = &whatsapp {
        let outcome = match sealing.whatsapp.as_deref() {
            None => Err("this deployment sends nothing over WhatsApp".to_owned()),
            Some(sender) => sender
                .send_code(&code.settings, &text.to, &code.code, &code.language)
                .await
                .map_err(|why| why.to_string()),
        };
        if let Err(why) = &outcome {
            tracing::warn!(to = text.to, why, "a WhatsApp code was not sent");
        }
        let delivered = outcome.is_ok();
        keep_receipt(
            sealing,
            tenancy,
            context,
            about.clone(),
            text.to.clone(),
            Channel::WhatsApp,
            outcome.err(),
        )
        .await;
        if delivered {
            return Sent::By(Channel::WhatsApp);
        }
    }
    // Nothing behind a refused WhatsApp code, whose receipt is written.
    if whatsapp.is_some() && settings.is_none() {
        return Sent::Nowhere;
    }

    let outcome = match (sealing.texter.as_deref(), settings.as_ref()) {
        (None, _) => {
            tracing::warn!("a step produced a text and this deployment sends none");
            Err("this deployment sends no texts".to_owned())
        }
        (Some(_), None) => Err("this realm names no SMS gateway".to_owned()),
        (Some(texter), Some(settings)) => texter
            .text(settings, &text)
            .await
            .map_err(|why| why.to_string()),
    };
    if let Err(why) = &outcome {
        tracing::warn!(to = text.to, why, "a text was not sent");
    }
    let delivered = outcome.is_ok();
    keep_receipt(
        sealing,
        tenancy,
        context,
        about,
        text.to,
        Channel::Sms,
        outcome.err(),
    )
    .await;
    if delivered {
        Sent::By(Channel::Sms)
    } else {
        Sent::Nowhere
    }
}

/// Send whichever kind one step produced, and say which way it went.
pub async fn deliver_outbound(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    outbound: auth::messaging::Outbound,
) -> Sent {
    match outbound {
        auth::messaging::Outbound::Mail(outgoing) => {
            if deliver(sealing, tenancy, context, outgoing).await {
                Sent::By(Channel::Mail)
            } else {
                Sent::Nowhere
            }
        }
        auth::messaging::Outbound::Text(outgoing) => {
            deliver_text(sealing, tenancy, context, outgoing).await
        }
    }
}

/// Keep the receipt of one attempt, in its own transaction: the one that
/// produced the message committed before anything was sent. A receipt that
/// cannot be written is logged and dropped: it is a record of the send, not a
/// part of it.
async fn keep_receipt(
    sealing: &Sealing,
    tenancy: &Tenancy,
    context: &TenantContext,
    about: About,
    recipient: String,
    channel: Channel,
    detail: Option<String>,
) {
    let Ok(drawn) = drawn_id(sealing.provider.as_ref()) else {
        return;
    };
    let receipt = Delivery {
        delivery_id: drawn,
        user_id: about.user_id,
        purpose: about.purpose,
        recipient,
        attempted_at: Utc::now(),
        delivered: detail.is_none(),
        detail,
        channel: Some(channel),
    };
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

/// Record, where a failed sign-in is recorded, that a code went out without
/// the carrier's word because the realm sends on silence.
async fn note_silence(tenancy: &Tenancy, context: &TenantContext, about: &About, recipient: &str) {
    let Ok(transaction) = tenancy.begin(context).await else {
        tracing::warn!("a carrier's silence could not be recorded");
        return;
    };
    if services::messaging::delivery::note_carrier_silence(
        &transaction,
        &about.user_id,
        &about.purpose,
        recipient,
        Utc::now(),
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!("a carrier's silence could not be recorded");
    }
}

fn drawn_id(provider: &dyn CryptoProvider) -> Result<String, ()> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    Ok(HEXLOWER.encode(&drawn))
}
