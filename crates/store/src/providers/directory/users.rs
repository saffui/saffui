use crate::tenancy::UnitOfWork;
use models::entities::user::{RequiredAction, UserModel, UserStorage};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
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
pub async fn create(transaction: &UnitOfWork, user: &UserModel) -> StoreResult<()> {
    let attributes = attributes_json(user)?;
    crate::providers::events::outbox::emit(
        transaction,
        crate::providers::events::outbox::USER_CREATED,
        &user.user_id,
        &event_payload(user),
    )
    .await?;
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
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// One user of this realm, by identifier.
pub async fn load(transaction: &UnitOfWork, user_id: &str) -> StoreResult<Option<UserModel>> {
    one(transaction, "user_id = $1", user_id).await
}

/// One user by the name they sign in with.
pub async fn load_by_name(
    transaction: &UnitOfWork,
    user_name: &str,
) -> StoreResult<Option<UserModel>> {
    one(transaction, "user_name = $1", user_name).await
}

/// Resolve an exact account id first, then an exact username in this realm.
pub async fn load_by_id_or_name(
    transaction: &UnitOfWork,
    named: &str,
) -> StoreResult<Option<UserModel>> {
    if let Some(user) = load(transaction, named).await? {
        return Ok(Some(user));
    }
    load_by_name(transaction, named).await
}

/// One user by address.
///
/// A realm that allows two users to share an address has no single answer here,
/// so this takes the first and the caller that permits sharing must not use it
/// to resolve a login.
pub async fn load_by_email(
    transaction: &UnitOfWork,
    email: &str,
) -> StoreResult<Option<UserModel>> {
    one(transaction, "email = $1", email).await
}

/// The one user holding this address, or nothing when nobody or several do.
///
/// The login resolver's read: an address two accounts share names neither,
/// and saying which existed would say more than an unknown name does.
pub async fn sole_by_email(
    transaction: &UnitOfWork,
    email: &str,
) -> StoreResult<Option<UserModel>> {
    let statement = format!("SELECT {COLUMNS} FROM users WHERE email = $1 LIMIT 2");
    let mut rows = transaction
        .query(statement.as_str(), &[&email])
        .await
        .map_err(|_| StoreError::Backend)?;
    if rows.len() != 1 {
        return Ok(None);
    }
    Ok(Some(read(rows.remove(0))))
}

/// The one account this proven number names, or nothing.
///
/// Proven only, and sole only: a number nobody proved identifies nobody,
/// and one two accounts share names neither, for the reason an address
/// does not.
pub async fn sole_by_proven_phone(
    transaction: &UnitOfWork,
    phone_number: &str,
) -> StoreResult<Option<UserModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM users \
         WHERE phone_number = $1 AND phone_number_verified = true LIMIT 2"
    );
    let mut rows = transaction
        .query(statement.as_str(), &[&phone_number])
        .await
        .map_err(|_| StoreError::Backend)?;
    if rows.len() != 1 {
        return Ok(None);
    }
    Ok(Some(read(rows.remove(0))))
}

/// One user by phone number, which is a login identifier where it is used.
pub async fn load_by_phone(
    transaction: &UnitOfWork,
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
/// Every person of this realm the directory owns: the mirrors a sync pass
/// walks.
pub async fn shadows(transaction: &UnitOfWork) -> StoreResult<Vec<UserModel>> {
    let statement =
        format!("SELECT {COLUMNS} FROM users WHERE user_storage = 'ldap' ORDER BY user_id ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

pub async fn load_service_account(
    transaction: &UnitOfWork,
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

pub async fn name_taken(transaction: &UnitOfWork, user_name: &str) -> StoreResult<bool> {
    exists(transaction, "user_name = $1", user_name).await
}

/// Whether the address is in use in this realm.
pub async fn email_taken(transaction: &UnitOfWork, email: &str) -> StoreResult<bool> {
    exists(transaction, "email = $1", email).await
}

/// Write what an update carries onto a stored user.
///
/// The stamp and the version are the statement's own. The identifiers and the
/// name are not written: a realm's users are addressed by them, so an update
/// that moved one would be a different user wearing the same row.
pub async fn update(transaction: &UnitOfWork, user: &UserModel) -> StoreResult<bool> {
    let previous = transaction
        .query_opt(
            "SELECT email, email_verified FROM users WHERE user_id = $1 FOR UPDATE",
            &[&user.user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let mut payload = event_payload(user);
    // The address a change moves away from, for the notice that address is owed:
    // once this statement has run, the row holds only the new one.
    if let Some(previous) = previous.filter(|row| row.get::<_, String>("email") != user.email) {
        payload["previous_email"] = serde_json::json!(previous.get::<_, String>("email"));
        payload["previous_email_verified"] =
            serde_json::json!(previous.get::<_, Option<bool>>("email_verified") == Some(true));
    }
    crate::providers::events::outbox::emit(
        transaction,
        crate::providers::events::outbox::USER_UPDATED,
        &user.user_id,
        &payload,
    )
    .await?;
    let attributes = attributes_json(user)?;
    let set = WriteSet::update(
        vec![
            // The name travels with updates now that it is the person's and
            // not the identity: the realm's switch upstream decides whether a
            // caller may actually change it.
            col("user_name", &user.user_name),
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
        .map_err(refuse_broken_rule)?;
    Ok(changed > 0)
}

/// Remove a user, and say whether there was one to remove.
/// Strike one required action, done or not: the caller says it no longer
/// stands. Says whether the user was there, not whether the action was.
/// Mark this person's address as checked, or unchecked.
pub async fn set_email_verified(
    transaction: &UnitOfWork,
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

/// Write the phone this account holds, and whether it is proven.
///
/// One statement for both facts, because they move together: a fresh number
/// is unproven by definition, and proving one must not race an edit that
/// swapped it for another.
pub async fn set_phone(
    transaction: &UnitOfWork,
    user_id: &str,
    phone_number: Option<&str>,
    verified: bool,
) -> StoreResult<bool> {
    let written = transaction
        .execute(
            "UPDATE users SET phone_number = $2, phone_number_verified = $3 WHERE user_id = $1",
            &[&user_id, &phone_number, &verified],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(written > 0)
}

/// Put an instruction on a person, once: an action already standing is not
/// stacked twice, so a login that keeps finding the same stale password does
/// not grow the list on every round.
pub async fn require_action(
    transaction: &UnitOfWork,
    user_id: &str,
    action: RequiredAction,
) -> StoreResult<bool> {
    let written = transaction
        .execute(
            "UPDATE users SET required_actions = \
                 array_append(coalesce(required_actions, '{}'), $2) \
             WHERE user_id = $1 AND NOT ($2 = ANY(coalesce(required_actions, '{}')))",
            &[&user_id, &action],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(written > 0)
}

pub async fn clear_required_action(
    transaction: &UnitOfWork,
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

pub async fn delete(transaction: &UnitOfWork, user_id: &str) -> StoreResult<bool> {
    crate::providers::events::outbox::emit(
        transaction,
        crate::providers::events::outbox::USER_DELETED,
        user_id,
        &serde_json::json!({}),
    )
    .await?;
    let removed = transaction
        .execute("DELETE FROM users WHERE user_id = $1", &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// How many users this realm has.
pub async fn count(transaction: &UnitOfWork) -> StoreResult<i64> {
    Ok(transaction
        .query_one("SELECT count(*) FROM users", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// One page of this realm's users, with the total when it was asked for.
/// The one person whose attribute bag holds this exact string value, for
/// the reconciliation questions a provisioner asks (externalId above all).
pub async fn load_by_attribute(
    transaction: &UnitOfWork,
    key: &str,
    value: &str,
) -> StoreResult<Option<UserModel>> {
    let document = serde_json::json!({ key: { "Str": value } });
    let statement = format!("SELECT {COLUMNS} FROM users WHERE attributes @> $1::jsonb LIMIT 1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&document])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Which groups this person stands in.
/// The names of every group a person stands in, the groups above them
/// included.
///
/// The walk up `parent_id` is what makes a sub-group mean something: its
/// members stand in every group above it, the same reading `effective_roles`
/// gives. `UNION` inside the walk, so a malformed chain terminates.
///
/// `DISTINCT` on the name is not the second mechanism that walk's comment
/// warns about: the `UNION` settles identifiers, and this settles names, which
/// two different groups are free to share. One round trip, because this is
/// read while a token is being minted.
pub async fn group_names_of(transaction: &UnitOfWork, user_id: &str) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "WITH RECURSIVE standing AS ( \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN users_groups ug ON ug.group_id = g.group_id \
                 WHERE ug.user_id = $1 \
                 UNION \
                 SELECT g.group_id, g.parent_id FROM groups g \
                 JOIN standing s ON g.group_id = s.parent_id \
             ) \
             SELECT DISTINCT g.name FROM groups g \
             JOIN standing s ON s.group_id = g.group_id \
             ORDER BY g.name ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("name"))
        .collect())
}

pub async fn groups_of(transaction: &UnitOfWork, user_id: &str) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT group_id FROM users_groups WHERE user_id = $1 ORDER BY group_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("group_id"))
        .collect())
}

pub async fn list(
    transaction: &UnitOfWork,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<UserModel>> {
    let rows = transaction
        .query(
            query.select(COLUMNS, "users").as_str(),
            &query.page_params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("users").as_str(), &query.bound())
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
    transaction: &UnitOfWork,
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

async fn exists(transaction: &UnitOfWork, predicate: &str, value: &str) -> StoreResult<bool> {
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

fn event_payload(user: &UserModel) -> serde_json::Value {
    serde_json::json!({
        "user_name": user.user_name,
        "email": user.email,
        "enabled": user.enabled,
    })
}
