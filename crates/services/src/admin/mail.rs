use crypto::envelope::Envelope;
use deadpool_postgres::Transaction;
use models::entities::mail::{MailCredentials, MailSettings};
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::mail;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm has no mail settings")]
    NotFound,
    /// A username changed without a password is half a credential.
    #[error("a username without a password is half a credential")]
    HalfACredential,
    #[error("the settings could not be read or written")]
    Unwritable,
}

pub async fn read(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<MailSettings, Unsettable> {
    mail::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NotFound)
}

/// What an administrator wrote. A password left out keeps the one held, and
/// only for the same user.
pub struct Wanted {
    pub host: String,
    pub port: u16,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: Option<String>,
    pub implicit_tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub async fn write(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    wanted: Wanted,
) -> Result<(), Unsettable> {
    let held = mail::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    let credentials = match (wanted.username, wanted.password) {
        (Some(username), Some(password)) => Some(MailCredentials {
            username,
            password: SecretBox::new(Box::new(password)),
        }),
        (Some(username), None) => Some(
            held.and_then(|held| held.credentials)
                .filter(|held| held.username == username)
                .ok_or(Unsettable::HalfACredential)?,
        ),
        (None, _) => None,
    };

    mail::keep(
        transaction,
        ring,
        envelope,
        &MailSettings {
            host: wanted.host,
            port: wanted.port,
            from_address: wanted.from_address,
            from_name: wanted.from_name,
            reply_to: wanted.reply_to,
            implicit_tls: wanted.implicit_tls,
            credentials,
        },
    )
    .await
    .map_err(|_| Unsettable::Unwritable)
}

pub async fn forget(transaction: &Transaction<'_>) -> Result<(), Unsettable> {
    mail::forget(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}
