//! The realm directory.
//!
//! The rules on this table key on the tenant alone. A realm's own boundary is
//! enforced on the tables that hang off it, so a transaction listing realms is
//! scoped to a tenant rather than to one of them.

use deadpool_postgres::Transaction;
use models::entities::realm::{RealmModel, SslEnforcement};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant, realm_id, name, display_name, enabled, ssl_enforcement, \
                       created_by, created_at, updated_by, updated_at, version";

/// Record a realm.
///
/// The tenant comes from the transaction, so a model naming another is refused
/// by the rules rather than written under a name nobody would look for it by.
pub async fn create(transaction: &Transaction<'_>, realm: &RealmModel) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &realm.metadata.tenant),
        col("realm_id", &realm.realm_id),
        col("name", &realm.name),
        col("display_name", &realm.display_name),
        col("enabled", &realm.enabled),
        col("ssl_enforcement", &realm.ssl_enforcement),
        col("created_by", &realm.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("realms", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One realm of this tenant, by its identifier.
pub async fn load(
    transaction: &Transaction<'_>,
    realm_id: &str,
) -> StoreResult<Option<RealmModel>> {
    let statement = format!("SELECT {COLUMNS} FROM realms WHERE realm_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&realm_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Whether a name is taken in this tenant.
///
/// A realm's name is what its issuer is built from, so two realms answering to
/// one name is two issuers nothing can tell apart.
pub async fn name_taken(transaction: &Transaction<'_>, name: &str) -> StoreResult<bool> {
    let found: i64 = transaction
        .query_one("SELECT count(*) FROM realms WHERE name = $1", &[&name])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

/// One page of this tenant's realms, with the total when it was asked for.
///
/// The count runs the same filters as the page. One that did not would report a
/// total for a set the caller is not reading.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<RealmModel>> {
    let rows = transaction
        .query(query.select(COLUMNS, "realms").as_str(), &query.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("realms").as_str(), &query.params())
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

fn read(row: Row) -> RealmModel {
    RealmModel {
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        enabled: row.get("enabled"),
        ssl_enforcement: row.get::<_, Option<SslEnforcement>>("ssl_enforcement"),
        registration_allowed: None,
        register_email_as_username: None,
        verify_email: None,
        login_with_email_allowed: None,
        duplicated_email_allowed: None,
        edit_user_name_allowed: None,
        reset_password_allowed: None,
        remember_me: None,
        password_policy: None,
        revoke_refresh_token: None,
        refresh_token_max_reuse: None,
        access_token_lifespan: None,
        action_tokens_lifespan: None,
        access_code_lifespan: None,
        access_code_lifespan_user_action: None,
        access_code_lifespan_login: None,
        master_admin_client: None,
        events_enabled: None,
        admin_events_enabled: None,
        not_before: None,
        attributes: None,
        acr_loa_map: None,
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
