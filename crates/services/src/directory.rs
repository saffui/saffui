//! The people of a realm, as the doors that are not the plane look them up and
//! write them back.

use models::entities::user::UserModel;
use store::error::StoreResult;
use store::providers::directory::users;
use store::providers::protocol::sessions;
use store::tenancy::UnitOfWork;

/// One person of this realm, by identifier, whatever their state.
pub async fn read_person(
    transaction: &UnitOfWork,
    user_id: &str,
) -> Result<Option<UserModel>, crate::realm::Unreadable> {
    users::load(transaction, user_id)
        .await
        .map_err(|_| crate::realm::Unreadable)
}

/// Write a person back, saying whether there was one to write. A write that
/// switches them off ends every login they hold, offline grants included: the
/// tokens minted from those logins stop wherever a login is asked after, and
/// switching the person back on revives none of it.
pub async fn keep_person(
    transaction: &UnitOfWork,
    person: &UserModel,
    was_enabled: bool,
) -> StoreResult<bool> {
    let kept = users::update(transaction, person).await?;
    if was_enabled && !person.enabled {
        sessions::end_all_of_user(transaction, &person.user_id).await?;
    }
    Ok(kept)
}
