use crypto::envelope::Envelope;
use deadpool_postgres::Transaction;
use models::entities::sms::SmsSettings;
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::sms;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm has no SMS settings")]
    NotFound,
    #[error("the gateway wants an http or https URL")]
    NotAGateway,
    #[error("the settings could not be read or written")]
    Unwritable,
}

pub async fn read(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<SmsSettings, Unsettable> {
    sms::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NotFound)
}

/// What an administrator wrote. A token left out keeps the one held; an empty
/// one forgets it.
pub struct Wanted {
    pub url: String,
    pub sender: String,
    pub token: Option<String>,
}

pub async fn write(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    wanted: Wanted,
) -> Result<(), Unsettable> {
    if !(wanted.url.starts_with("https://") || wanted.url.starts_with("http://")) {
        return Err(Unsettable::NotAGateway);
    }
    let token = match wanted.token {
        Some(token) if token.is_empty() => None,
        Some(token) => Some(SecretBox::new(Box::new(token))),
        None => sms::load(transaction, ring, envelope)
            .await
            .map_err(|_| Unsettable::Unwritable)?
            .and_then(|held| held.token),
    };

    sms::keep(
        transaction,
        ring,
        envelope,
        &SmsSettings {
            url: wanted.url,
            sender: wanted.sender,
            token,
        },
    )
    .await
    .map_err(|_| Unsettable::Unwritable)
}

pub async fn forget(transaction: &Transaction<'_>) -> Result<(), Unsettable> {
    sms::forget(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}
