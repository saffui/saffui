//! The people of a realm, as the doors that are not the plane look them up.

use models::entities::user::UserModel;
use store::providers::directory::users;
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
