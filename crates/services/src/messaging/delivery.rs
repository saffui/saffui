//! How a message leaves a realm: the settings it is sent with, and the receipt
//! each attempt leaves behind.

use crypto::envelope::Envelope;
use models::entities::mail::MailSettings;
use models::messaging::Delivery;
use store::providers::events::deliveries;
use store::providers::realms::mail;
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

/// Keep the receipt of one attempt to send, delivered or not.
pub async fn record_delivery(
    transaction: &UnitOfWork,
    receipt: &Delivery,
) -> Result<(), Unrecorded> {
    deliveries::record(transaction, receipt)
        .await
        .map_err(|_| Unrecorded)
}
