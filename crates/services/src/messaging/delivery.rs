//! How a message leaves a realm: the settings it is sent with, and the receipt
//! each attempt leaves behind.

use crypto::envelope::Envelope;
use models::entities::mail::MailSettings;
use models::entities::sms::SmsSettings;
use models::messaging::Delivery;
use store::providers::events::deliveries;
use store::providers::realms::{mail, sms};
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the receipt could not be kept")]
pub struct Unrecorded;

/// How the realm sends mail, opened with its own key. Nothing when it holds no
/// settings, or when its keyring or its settings could not be read: a realm
/// that cannot say how it mails, mails nothing.
pub async fn read_mail_settings(
    transaction: &UnitOfWork,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> Option<MailSettings> {
    let ring = store::keyring::load(transaction, envelope, tenant, realm_id)
        .await
        .ok()?;
    mail::load(transaction, &ring, envelope)
        .await
        .ok()
        .flatten()
}

/// How the realm sends texts, opened with its own key, on the same terms as
/// its mail settings.
pub async fn read_sms_settings(
    transaction: &UnitOfWork,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> Option<SmsSettings> {
    let ring = store::keyring::load(transaction, envelope, tenant, realm_id)
        .await
        .ok()?;
    sms::load(transaction, &ring, envelope).await.ok().flatten()
}

/// Whether the realm could send a code either way, which is whether a person
/// has another way to ask for. A realm that cannot be read offers none.
pub async fn carries_both_ways(transaction: &UnitOfWork) -> bool {
    store::providers::realms::whatsapp::held_beside_a_gateway(transaction)
        .await
        .unwrap_or(false)
}

/// Record, where a failed sign-in is recorded, that a code went out without
/// the carrier's word, because the realm sends on silence.
pub async fn note_carrier_silence(
    transaction: &UnitOfWork,
    user_id: &str,
    step: &str,
    recipient: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Unrecorded> {
    store::providers::events::login_events::record(
        transaction,
        now.timestamp(),
        &store::providers::events::login_events::LoginEventWrite {
            kind: "sim_swap_unanswered",
            user_id: Some(user_id),
            detail: Some(serde_json::json!({ "to": recipient, "step": step, "sent": true })),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| Unrecorded)
}

/// Keep the receipt of one attempt to send, delivered or not.
pub async fn record_delivery(
    transaction: &UnitOfWork,
    receipt: &Delivery,
) -> Result<(), Unrecorded> {
    deliveries::record(transaction, receipt)
        .await
        .map_err(|_| Unrecorded)
}
