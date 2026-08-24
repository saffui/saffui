use deadpool_postgres::Transaction;
use models::sessions::records::{ClientSessionModel, UserSessionModel};
use store::providers::sessions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreachable {
    #[error("no such session")]
    NotFound,
    #[error("this client holds nothing from that session")]
    NoSuchGrant,
    #[error("the store could not be read")]
    Unreadable,
}

/// What one person has open, newest first, each with what the clients got.
pub async fn of_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<Vec<(UserSessionModel, Vec<ClientSessionModel>)>, Unreachable> {
    let open = sessions::load_for_user(transaction, user_id)
        .await
        .map_err(|_| Unreachable::Unreadable)?;
    let mut held = Vec::with_capacity(open.len());
    for session in open {
        let grants = sessions::client_sessions_of(transaction, &session.session_id)
            .await
            .map_err(|_| Unreachable::Unreadable)?;
        held.push((session, grants));
    }
    Ok(held)
}

/// End one login of this person, and everything any client got out of it.
///
/// Named through the person it belongs to, so an identifier from somebody
/// else's listing reaches nothing.
pub async fn close(
    transaction: &Transaction<'_>,
    user_id: &str,
    session_id: &str,
) -> Result<(), Unreachable> {
    named_session(transaction, user_id, session_id).await?;
    sessions::close(transaction, session_id)
        .await
        .map_err(|_| Unreachable::Unreadable)?;
    Ok(())
}

/// Take back what one client got out of one login, leaving the login and every
/// other client alone.
pub async fn revoke_grant(
    transaction: &Transaction<'_>,
    user_id: &str,
    session_id: &str,
    client_id: &str,
) -> Result<(), Unreachable> {
    named_session(transaction, user_id, session_id).await?;
    let taken = sessions::close_client_session_of(transaction, session_id, client_id)
        .await
        .map_err(|_| Unreachable::Unreadable)?;
    taken.then_some(()).ok_or(Unreachable::NoSuchGrant)
}

async fn named_session(
    transaction: &Transaction<'_>,
    user_id: &str,
    session_id: &str,
) -> Result<UserSessionModel, Unreachable> {
    sessions::load(transaction, session_id)
        .await
        .map_err(|_| Unreachable::Unreadable)?
        .filter(|session| session.user_id == user_id)
        .ok_or(Unreachable::NotFound)
}
