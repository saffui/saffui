use crypto::envelope::Envelope;
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::realms::ussd;
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm has no USSD gateway")]
    NotFound,
    #[error("a gateway secret is at least sixteen characters")]
    TooShort,
    #[error("the settings could not be read or written")]
    Unwritable,
}

/// Whether a gateway is named at all: what a reader may know, which is
/// never the secret.
pub async fn held(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<bool, Unsettable> {
    Ok(ussd::load_secret(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .is_some())
}

pub async fn write(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    secret: String,
) -> Result<(), Unsettable> {
    // Short enough to guess is short enough to approve sign-ins with.
    if secret.chars().count() < 16 {
        return Err(Unsettable::TooShort);
    }
    ussd::keep_secret(
        transaction,
        ring,
        envelope,
        &SecretBox::new(Box::new(secret)),
    )
    .await
    .map_err(|_| Unsettable::Unwritable)
}

pub async fn forget(transaction: &UnitOfWork) -> Result<(), Unsettable> {
    ussd::forget_secret(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}
