//! The doorbell over a USSD gateway: the secret the gateway proves itself
//! with, the person a dialling number names, and the screen each gateway
//! session was shown.

use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use models::entities::user::UserModel;
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::directory::users;
use store::providers::realms::ussd;
use store::tenancy::UnitOfWork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the bridge could not be read or written")]
pub struct Unbridged;

/// The secret the realm's gateway presents, when the realm named one.
pub async fn read_gateway_secret(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<Option<SecretBox<String>>, Unbridged> {
    ussd::load_secret(transaction, ring, envelope)
        .await
        .map_err(|_| Unbridged)
}

/// The one account that proved this number, while it may still sign in.
pub async fn read_dialling_person(
    transaction: &UnitOfWork,
    number: &str,
) -> Result<Option<UserModel>, Unbridged> {
    Ok(users::sole_by_proven_phone(transaction, number)
        .await
        .map_err(|_| Unbridged)?
        .filter(|held| held.enabled))
}

/// Tie the request a screen showed to the gateway session that showed it, so
/// the digit that comes back decides that request and no other.
pub async fn anchor_screen(
    transaction: &UnitOfWork,
    session_id: &str,
    user_id: &str,
    request_digest: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), Unbridged> {
    ussd::anchor(transaction, session_id, user_id, request_digest, expires_at)
        .await
        .map_err(|_| Unbridged)
}

/// Take back what the session's last screen showed, once: whose it was and
/// the request's digest.
pub async fn take_anchor(
    transaction: &UnitOfWork,
    session_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<(String, Vec<u8>)>, Unbridged> {
    ussd::take_anchor(transaction, session_id, now)
        .await
        .map_err(|_| Unbridged)
}
