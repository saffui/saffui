use deadpool_postgres::Transaction;
use store::providers::webauthn::{self, EnrolledCredential};

use crate::admin::users;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreachable {
    #[error("no such user")]
    NoSuchUser,
    #[error("no such credential")]
    NotFound,
    #[error("the store could not be read")]
    Unreadable,
}

/// The keys this person may present.
///
/// The person is read first, so an empty list means "no keys" and never "no
/// such person".
pub async fn of_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<Vec<EnrolledCredential>, Unreachable> {
    users::get(transaction, user_id)
        .await
        .map_err(|_| Unreachable::NoSuchUser)?;
    webauthn::of_user(transaction, user_id)
        .await
        .map_err(|_| Unreachable::Unreadable)
}

/// Revoke one of this person's keys, reaching no further than them.
pub async fn revoke(
    transaction: &Transaction<'_>,
    user_id: &str,
    credential_id: &[u8],
) -> Result<(), Unreachable> {
    users::get(transaction, user_id)
        .await
        .map_err(|_| Unreachable::NoSuchUser)?;
    webauthn::revoke(transaction, user_id, credential_id)
        .await
        .map_err(|_| Unreachable::Unreadable)?
        .then_some(())
        .ok_or(Unreachable::NotFound)
}
