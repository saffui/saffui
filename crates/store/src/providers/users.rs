use deadpool_postgres::Transaction;
use models::entities::user::{RequiredAction, UserModel, UserStorage};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant, realm_id, user_id, user_name, email, email_verified, \
                       phone_number, phone_number_verified, enabled, is_service_account, \
                       service_account_client_link, user_storage, required_actions, \
                       not_before, attributes, created_by, created_at, updated_by, \
                       updated_at, version";

/// Record a user.
///
/// The realm and the tenant come from the transaction, so a model naming another
/// pair is refused by the rules rather than written where nobody will look.
pub async fn create(transaction: &Transaction<'_>, user: &UserModel) -> StoreResult<()> {
    let attributes = attributes_json(user)?;
    let set = WriteSet::insert(vec![
        col("tenant", &user.metadata.tenant),
        col("realm_id", &user.realm_id),
        col("user_id", &user.user_id),
        col("user_name", &user.user_name),
        col("email", &user.email),
        col("email_verified", &user.email_verified),
        col("phone_number", &user.phone_number),
        col("phone_number_verified", &user.phone_number_verified),
        col("enabled", &user.enabled),
        col("is_service_account", &user.is_service_account),
        col(
            "service_account_client_link",
            &user.service_account_client_link,
        ),
        col("user_storage", &user.user_storage),
        col("required_actions", &user.required_actions),
        col("not_before", &user.not_before),
        col("attributes", &attributes),
        col("created_by", &user.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("users", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One user of this realm, by identifier.
pub async fn load(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<Option<UserModel>> {
    one(transaction, "user_id = $1", user_id).await
}

/// One user by the name they sign in with.
pub async fn load_by_name(
    transaction: &Transaction<'_>,
    user_name: &str,
) -> StoreResult<Option<UserModel>> {
    one(transaction, "user_name = $1", user_name).await
}

/// One user by address.
///
/// A realm that allows two users to share an address has no single answer here,
/// so this takes the first and the caller that permits sharing must not use it
/// to resolve a login.
pub async fn load_by_email(
    transaction: &Transaction<'_>,
    email: &str,
) -> StoreResult<Option<UserModel>> {
    one(transaction, "email = $1", email).await
}

/// One user by phone number, which is a login identifier where it is used.
pub async fn load_by_phone(
    transaction: &Transaction<'_>,
    phone_number: &str,
) -> StoreResult<Option<UserModel>> {
    one(transaction, "phone_number = $1", phone_number).await
}

/// Whether the name is taken in this realm.
/// The account a client acts as when it acts for itself.
///
/// Keyed on the link rather than on a name built from the client id. A name is
/// a thing an administrator can edit, and an account reached by rebuilding its
/// name would silently become somebody else's the moment one was.
pub async fn load_service_account(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<UserModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM users \
         WHERE service_account_client_link = $1 AND is_service_account IS TRUE"
    );
    Ok(transaction
        .query_opt(statement.as_str(), &[&client_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

pub async fn name_taken(transaction: &Transaction<'_>, user_name: &str) -> StoreResult<bool> {
    exists(transaction, "user_name = $1", user_name).await
}

/// Whether the address is in use in this realm.
pub async fn email_taken(transaction: &Transaction<'_>, email: &str) -> StoreResult<bool> {
    exists(transaction, "email = $1", email).await
}

/// Write what an update carries onto a stored user.
///
/// The stamp and the version are the statement's own. The identifiers and the
/// name are not written: a realm's users are addressed by them, so an update
/// that moved one would be a different user wearing the same row.
pub async fn update(transaction: &Transaction<'_>, user: &UserModel) -> StoreResult<bool> {
    let attributes = attributes_json(user)?;
    let set = WriteSet::update(
        vec![
            col("email", &user.email),
            col("email_verified", &user.email_verified),
            col("phone_number", &user.phone_number),
            col("phone_number_verified", &user.phone_number_verified),
            col("enabled", &user.enabled),
            col("required_actions", &user.required_actions),
            col("not_before", &user.not_before),
            col("attributes", &attributes),
            col("updated_by", &user.metadata.updated_by),
        ],
        vec![col("user_id", &user.user_id)],
    );

    let statement = statement::update("users", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );

    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Remove a user, and say whether there was one to remove.
/// Strike one required action, done or not: the caller says it no longer
/// stands. Says whether the user was there, not whether the action was.
/// Mark this person's address as checked, or unchecked.
pub async fn set_email_verified(
    transaction: &Transaction<'_>,
    user_id: &str,
    verified: bool,
) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE users SET email_verified = $2 WHERE user_id = $1",
            &[&user_id, &verified],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

pub async fn clear_required_action(
    transaction: &Transaction<'_>,
    user_id: &str,
    action: RequiredAction,
) -> StoreResult<bool> {
    let cleared = transaction
        .execute(
            "UPDATE users SET required_actions = array_remove(required_actions, $2) \
             WHERE user_id = $1",
            &[&user_id, &action],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(cleared > 0)
}

pub async fn delete(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM users WHERE user_id = $1", &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// How many users this realm has.
pub async fn count(transaction: &Transaction<'_>) -> StoreResult<i64> {
    Ok(transaction
        .query_one("SELECT count(*) FROM users", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// One page of this realm's users, with the total when it was asked for.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<UserModel>> {
    let rows = transaction
        .query(query.select(COLUMNS, "users").as_str(), &query.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("users").as_str(), &query.params())
                .await
                .map_err(|_| StoreError::Backend)?
                .get::<_, i64>(0),
        )
    } else {
        None
    };

    Ok(Page::new(
        rows.into_iter().map(read).collect(),
        query.window(),
        total,
    ))
}

async fn one(
    transaction: &Transaction<'_>,
    predicate: &str,
    value: &str,
) -> StoreResult<Option<UserModel>> {
    let statement = format!("SELECT {COLUMNS} FROM users WHERE {predicate} LIMIT 1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&value])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

async fn exists(transaction: &Transaction<'_>, predicate: &str, value: &str) -> StoreResult<bool> {
    let statement = format!("SELECT count(*) FROM users WHERE {predicate}");
    let found: i64 = transaction
        .query_one(statement.as_str(), &[&value])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

fn attributes_json(user: &UserModel) -> StoreResult<Option<serde_json::Value>> {
    user.attributes
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn read(row: Row) -> UserModel {
    UserModel {
        user_id: row.get("user_id"),
        realm_id: row.get("realm_id"),
        user_name: row.get("user_name"),
        enabled: row.get("enabled"),
        email: row.get::<_, Option<String>>("email").unwrap_or_default(),
        email_verified: row.get("email_verified"),
        phone_number: row.get("phone_number"),
        phone_number_verified: row.get("phone_number_verified"),
        required_actions: row.get::<_, Option<Vec<RequiredAction>>>("required_actions"),
        not_before: row.get("not_before"),
        user_storage: row.get::<_, Option<UserStorage>>("user_storage"),
        attributes: row
            .get::<_, Option<serde_json::Value>>("attributes")
            .and_then(|value| serde_json::from_value(value).ok()),
        is_service_account: row.get("is_service_account"),
        service_account_client_link: row.get("service_account_client_link"),
        metadata: models::auditable::AuditableModel {
            tenant: row.get("tenant"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_by: row.get("updated_by"),
            updated_at: row.get("updated_at"),
            version: row.get("version"),
        },
    }
}
